from __future__ import annotations

import contextlib
import json
import hashlib
import multiprocessing
import os
from pathlib import Path
import socket
import stat
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from banodoco_local.bootstrap import (
    BootstrapConfig,
    BootstrapError,
    CompatibilityError,
    DuplicateOwnerError,
    LegacyRootCollisionError,
    SourceProfile,
    _rollback_failed_bootstrap,
    bootstrap,
    connect,
    down,
    doctor,
    restart,
    _recover_aborted_predecessor_resolution as launcher_recover_predecessor,
)
from banodoco_local.paths import RuntimePaths
from banodoco_local.cli import _json_value
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.store import RealmStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.handoff_recovery import recover_aborted_predecessor_resolution
from runtime_protocol.orderly_handoff import RECORD_VERSION, digest


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
    capability_digest="caps-v1",
)


def _valid_resolution_journal(support, handoff_id, *, state="COMPLETE"):
    value = {
        "version": 1,
        "state": state,
        "handoff_id": handoff_id,
        "aborted_record_path": str(
            support / f"orderly-handoff-record-{handoff_id}.json"
        ),
        "aborted_record_digest": "sha256:" + "1" * 64,
        "cleanup_receipt_digest": "sha256:" + "2" * 64,
        "predecessor_active_ref_digest": "sha256:" + "3" * 64,
        "predecessor_record_path": str(support / "orderly-handoff-record-old.json"),
        "predecessor_record_digest": "sha256:" + "4" * 64,
        "archived_active_reference_path": str(
            support / f"orderly-handoff-predecessor-active-{handoff_id}.json"
        ),
        "active_reference_file_sha256": "5" * 64,
        "active_reference_archived": state == "COMPLETE",
        "successor_request_pointer_path": str(
            support / "orderly-handoff-request.json"
        ),
        "successor_request_pointer_sha256": "6" * 64,
        "successor_request_pointer_byte_length": 10,
        "successor_request_pointer_device": 1,
        "successor_request_pointer_inode": 1,
        "successor_request_pointer_mode": 0o600,
        "successor_request_pointer_uid": os.getuid(),
        "successor_request_quarantine_path": str(
            support / f".orderly-handoff-request-clearing-{handoff_id}.json"
        ),
    }
    value["resolution_digest"] = digest(value)
    return value


def _write_adopted_record(path, *, handoff_id, realm_root, support_root):
    value = {
        "version": RECORD_VERSION,
        "state": "ADOPTED",
        "handoff_id": handoff_id,
        "realm_id": "configured-realm",
        "realm_root": str(realm_root),
        "support_root": str(support_root),
        "deadline_monotonic": 9_999_999_999.0,
        "deadline_unix_ms": 9_999_999_999_999,
        "nonce_digest": "sha256:" + "1" * 64,
        "sealed_record_digest": "sha256:" + "2" * 64,
        "old_owner": {"pid": 1, "birth_id": "birth-a"},
        "export": {"receipt_evidence_digest": "sha256:" + "3" * 64},
        "export_sealed_digest": "sha256:" + "4" * 64,
        "adopter": {"pid": 2, "birth_id": "birth-b", "runtime_instance_id": "runtime-b"},
        "owner_a_released": True,
        "new_owner": {"pid": 2, "birth_id": "birth-b", "runtime_instance_id": "runtime-b"},
        "result": {"state": "resumed"},
        "finalization": {
            "final_ack": {
                "request_digest": "sha256:" + "5" * 64,
                "worker_ack_digest": "sha256:" + "6" * 64,
                "host_ack_digest": "sha256:" + "7" * 64,
            },
            "ready_surfaces": True,
        },
        "publication_predecessor_digest": "sha256:" + "8" * 64,
        "predecessor_active_ref_digest": None,
    }
    value["record_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def _write_active_reference(
    path, *, handoff_id, record_path, record_digest, pid, birth_id, instance_id
):
    value = {
        "version": 1,
        "state": "ADOPTED",
        "handoff_id": handoff_id,
        "record_path": str(record_path),
        "record_digest": record_digest,
        "pid": pid,
        "birth_id": birth_id,
        "runtime_instance_id": instance_id,
    }
    value["reference_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def _complete_cleanup_proof():
    expected, rows = [], []
    for offset, role in enumerate(("worker", "host", "engine", "engine_listener"), 1):
        identity = {"pid": 700 + offset, "birth_id": f"birth-{role}"}
        identity_digest = digest(identity)
        expected.append({"role": role, "identity": identity, "identity_digest": identity_digest})
        rows.append({
            "role": role, "pid": identity["pid"],
            "expected_birth_id": identity["birth_id"],
            "identity_digest": identity_digest, "observed_birth_id": None,
            "associated_alive": False, "absent": True,
        })
    census = {
        "process_rows": rows,
        "listener": {
            "host": "127.0.0.1", "port": 8188,
            "expected_owner_pid": expected[-1]["identity"]["pid"],
            "expected_owner_birth_id": expected[-1]["identity"]["birth_id"],
            "observed_owner_pid": None, "owner_absent": True, "port_free": True,
        },
        "uncertainties": [],
    }
    census["census_digest"] = digest(census)
    return {
        "version": 1, "runtime_instance_id": "runtime-c",
        "receipt_evidence_digest": "sha256:" + "9" * 64,
        "expected_processes": expected,
        "graph_and_engine_listener_absent": True,
        "authority_descriptors_closed": True, "worker_credential_revoked": True,
        "catalog_neutral": True, "discovery_absent": True,
        "replacement_graph_not_launched": True, "final_census": census,
        "complete": True,
    }


def _write_aborted_record(path, *, handoff_id, realm_root, support_root, predecessor):
    cleanup = _complete_cleanup_proof()
    sealed_receipt = {
        "version": "runtime.local-worker-receipt/v3",
        "evidence_digest": cleanup["receipt_evidence_digest"],
        "engine_binding": {
            "endpoint": "http://127.0.0.1:8188",
            "socket_owner_pid": cleanup["expected_processes"][-1]["identity"]["pid"],
        },
        **{row["role"]: row["identity"] for row in cleanup["expected_processes"]},
    }
    value = {
        "version": RECORD_VERSION, "state": "ABORTED", "handoff_id": handoff_id,
        "realm_id": "configured-realm", "realm_root": str(realm_root),
        "support_root": str(support_root), "deadline_monotonic": 9_999_999_999.0,
        "deadline_unix_ms": 9_999_999_999_999,
        "nonce_digest": "sha256:" + "1" * 64,
        "sealed_record_digest": "sha256:" + "2" * 64,
        "old_owner": {"pid": 1, "birth_id": "birth-b"},
        "export": {"receipt": sealed_receipt},
        "export_sealed_digest": "sha256:" + "4" * 64,
        "adopter": {"pid": 2, "birth_id": "birth-c", "runtime_instance_id": "runtime-c"},
        "predecessor_active_ref_digest": predecessor,
        "abort_reason": "owner_c_start_failed", "cleanup_receipt": cleanup,
        "cleanup_receipt_digest": digest(cleanup),
    }
    value["record_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


class FakeConnection:
    def __init__(self, boundary):
        self.boundary = boundary

    def handshake(self, **kwargs):
        self.boundary.handshakes.append(kwargs)

    def provision_actor(self, **kwargs):
        self.boundary.provisions.append(kwargs)
        return {"scope": kwargs["scope"], "actor_id": kwargs["actor_id"]}

    def select_realm(self, **kwargs):
        self.boundary.selections.append(kwargs)


class FakeBoundary:
    def __init__(self):
        self.creates = []
        self.starts = []
        self.calls = []
        self.connects = []
        self.provisions = []
        self.selections = []
        self.handshakes = []
        self.alive = set()
        self.valid_owner = True
        self.next_pid = 41001
        self.restart_calls = 0
        self.last_restart_kwargs = None

    def start(self, **kwargs):
        self.calls.append("start")
        self.starts.append(kwargs)
        realm_root = kwargs["realm_root"]
        realm_root.mkdir(parents=True, exist_ok=True)
        (realm_root / "workspace.sqlite3").touch()
        pid = self.next_pid
        self.next_pid += 1
        self.alive.add(pid)
        return {
            "endpoint": "http://127.0.0.1:43100",
            "pid": pid,
            "runtime_instance_id": f"instance-{pid}",
            "coordinator_epoch": 1,
            "protocol_version": "workspace.v1",
            "schema_version": "workspace-schema-v1",
            "capability_digest": "caps-v1",
        }

    def create(self, **kwargs):
        self.calls.append("create")
        self.creates.append(kwargs)
        realm_root = kwargs["realm_root"]
        RealmStore.initialize(
            realm_root,
            realm_id=kwargs["realm_id"],
            display_name=kwargs["display_name"],
        ).close()
        return {"state": "created", "realm_id": kwargs["realm_id"], "root": str(realm_root)}

    def connect(self, **kwargs):
        self.connects.append(kwargs)
        return FakeConnection(self)

    def health(self, **kwargs):
        return kwargs["pid"] in self.alive

    def validate_owner(self, **kwargs):
        return self.valid_owner

    def endpoint_metadata(self, **_kwargs):
        if not self.starts:
            return {}
        pid = max(self.alive) if self.alive else self.next_pid - 1
        return {
            "runtime_instance_id": f"instance-{pid}",
            "realm_id": str(self.starts[-1]["realm_id"]),
            "status": "ok",
        }

    def is_pid_alive(self, pid):
        return pid in self.alive

    def restart(self, **kwargs):
        self.restart_calls += 1
        self.last_restart_kwargs = dict(kwargs)
        self.alive.discard(kwargs["pid"])
        return self.start(realm_id=kwargs.get("realm_id", "ignored"), realm_root=Path(tempfile.mkdtemp()) / "realm", owner_lock=Path("/tmp/lock"), source_profile=PROFILE)

    def stop_owner(self, **kwargs):
        self.restart_calls += 1
        self.alive.discard(kwargs["pid"])
        return {"status": "stopped"}


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = RuntimePaths.sandbox(self.temp.name)
        self.boundary = FakeBoundary()
        self.config = BootstrapConfig(source_profile=PROFILE)

    def tearDown(self):
        self.temp.cleanup()

    def _configure(self, *, realm_id="configured-realm"):
        self.paths.ensure_support_dirs()
        root = self.paths.realms_dir / realm_id
        self.boundary.create(
            realm_id=realm_id,
            realm_root=root,
            display_name="Astrid Workspace",
            source_profile=PROFILE,
        )
        self.paths.catalog_path.write_text(json.dumps({
            "version": 1,
            "selected_realm_id": realm_id,
            "realms": [{
                "realm_id": realm_id,
                "display_name": "Astrid Workspace",
                "data_root": str(root),
            }],
            "source_profiles": {},
        }))
        self.boundary.calls.clear()
        self.boundary.creates.clear()
        return root

    def _fresh_launcher_state(self, directory):
        paths = RuntimePaths.sandbox(str(Path(directory).resolve()))
        boundary = FakeBoundary()
        config = BootstrapConfig(source_profile=PROFILE)
        paths.ensure_support_dirs()
        realm_root = paths.realms_dir / "configured-realm"
        boundary.create(
            realm_id="configured-realm",
            realm_root=realm_root,
            display_name="Astrid Workspace",
            source_profile=PROFILE,
        )
        paths.catalog_path.write_text(json.dumps({
            "version": 1,
            "selected_realm_id": "configured-realm",
            "realms": [{
                "realm_id": "configured-realm",
                "display_name": "Astrid Workspace",
                "data_root": str(realm_root),
            }],
            "source_profiles": {},
        }))
        bootstrap(paths, boundary, config)
        return paths, boundary, config, realm_root

    def _fresh_resolution_state(self, directory, checkpoint):
        paths, boundary, config, realm_root = self._fresh_launcher_state(directory)
        support = paths.runtime_support
        discovery = json.loads(paths.discovery_path.read_text())
        predecessor_path = support / "orderly-handoff-record-old.json"
        predecessor = _write_adopted_record(
            predecessor_path,
            handoff_id="old",
            realm_root=realm_root,
            support_root=support,
        )
        active_path = support / "orderly-handoff-adopted-owner.json"
        active = _write_active_reference(
            active_path,
            handoff_id="old",
            record_path=predecessor_path,
            record_digest=predecessor["record_digest"],
            pid=discovery["pid"],
            birth_id=discovery["process_birth_id"],
            instance_id=discovery["runtime_instance_id"],
        )
        successor_path = support / "orderly-handoff-record-new.json"
        successor = _write_aborted_record(
            successor_path,
            handoff_id="new",
            realm_root=realm_root,
            support_root=support,
            predecessor=active["reference_digest"],
        )
        pointer_path = support / "orderly-handoff-request.json"
        pointer_path.write_text(json.dumps({
            "version": "runtime.local-worker-handoff-transfer/v1",
            "handoff_id": "new",
            "record_path": str(successor_path),
            "socket_path": str(support / "coordinator.sock"),
            "coordinator_pid": os.getpid(),
            "coordinator_birth_id": "coordinator-birth",
        }), encoding="utf-8")
        pointer_path.chmod(0o600)
        pointer_raw = pointer_path.read_bytes()
        pointer_info = pointer_path.lstat()
        archive_path = support / "orderly-handoff-predecessor-active-new.json"
        quarantine_path = support / ".orderly-handoff-request-clearing-new.json"
        journal_path = support / "orderly-handoff-predecessor-resolution-new.json"
        journal = {
            "version": 1,
            "state": "PREPARED",
            "handoff_id": "new",
            "aborted_record_path": str(successor_path),
            "aborted_record_digest": successor["record_digest"],
            "cleanup_receipt_digest": successor["cleanup_receipt_digest"],
            "predecessor_active_ref_digest": active["reference_digest"],
            "predecessor_record_path": str(predecessor_path),
            "predecessor_record_digest": predecessor["record_digest"],
            "archived_active_reference_path": str(archive_path),
            "active_reference_file_sha256": hashlib.sha256(
                active_path.read_bytes()
            ).hexdigest(),
            "active_reference_archived": False,
            "successor_request_pointer_path": str(pointer_path),
            "successor_request_pointer_sha256": hashlib.sha256(pointer_raw).hexdigest(),
            "successor_request_pointer_byte_length": len(pointer_raw),
            "successor_request_pointer_device": pointer_info.st_dev,
            "successor_request_pointer_inode": pointer_info.st_ino,
            "successor_request_pointer_mode": stat.S_IMODE(pointer_info.st_mode),
            "successor_request_pointer_uid": pointer_info.st_uid,
            "successor_request_quarantine_path": str(quarantine_path),
        }
        if checkpoint != "prepared-active":
            os.rename(active_path, archive_path)
        if checkpoint.startswith("complete-"):
            journal["state"] = "COMPLETE"
            journal["active_reference_archived"] = True
        journal["resolution_digest"] = digest(journal)
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        journal_path.chmod(0o600)
        if checkpoint in {"complete-quarantine", "complete-restored-link"}:
            os.rename(pointer_path, quarantine_path)
            if checkpoint == "complete-restored-link":
                os.link(quarantine_path, pointer_path)
        elif checkpoint == "complete-idempotent":
            pointer_path.unlink()
        return {
            "paths": paths,
            "boundary": boundary,
            "config": config,
            "realm_root": realm_root,
            "support": support,
            "journal_path": journal_path,
            "archive_path": archive_path,
            "active_path": active_path,
            "pointer_path": pointer_path,
            "quarantine_path": quarantine_path,
        }

    @staticmethod
    def _launcher_routes(paths, boundary, config, realm_root):
        def daemon_start():
            daemon = RuntimeDaemon(realm_root, support_root=paths.runtime_support).start()
            daemon.stop()
            return daemon

        return {
            "bootstrap": (
                lambda: bootstrap(paths, boundary, config), BootstrapError,
                "banodoco_local.bootstrap.bootstrap",
            ),
            "restart-false": (
                lambda: restart(paths, boundary, config, preserve_worker=False),
                BootstrapError,
                "banodoco_local.bootstrap.restart[preserve_worker=false]",
            ),
            "restart-true": (
                lambda: restart(paths, boundary, config, preserve_worker=True),
                BootstrapError,
                "banodoco_local.bootstrap.restart[preserve_worker=true]",
            ),
            "down": (
                lambda: down(paths, boundary), BootstrapError,
                "banodoco_local.bootstrap.down",
            ),
            "launcher-recovery": (
                lambda: launcher_recover_predecessor(paths), BootstrapError,
                "banodoco_local.bootstrap._recover_aborted_predecessor_resolution",
            ),
            "runtime-daemon": (
                daemon_start, ConflictError,
                "runtime_protocol.daemon.RuntimeDaemon.start+stop",
            ),
        }

    @staticmethod
    def _support_snapshot(support):
        result = {}
        for path in support.iterdir():
            observed = path.lstat()
            raw = path.read_bytes() if stat.S_ISREG(observed.st_mode) else None
            result[path.name] = (
                observed.st_mode,
                observed.st_uid,
                observed.st_dev,
                observed.st_ino,
                raw,
            )
        return result

    @staticmethod
    def _authority_evidence(support):
        candidates = []
        paths = list(support.iterdir())
        credentials = support.parent / "credentials"
        if credentials.is_dir() and not credentials.is_symlink():
            paths.extend(credentials.rglob("*"))
        for path in sorted(paths, key=lambda item: str(item)):
            name = (
                path.name if path.parent == support
                else str(path.relative_to(support.parent))
            )
            observed = path.lstat()
            kind = (
                "regular" if stat.S_ISREG(observed.st_mode)
                else "symlink" if stat.S_ISLNK(observed.st_mode)
                else "directory" if stat.S_ISDIR(observed.st_mode)
                else "fifo" if stat.S_ISFIFO(observed.st_mode)
                else "socket" if stat.S_ISSOCK(observed.st_mode)
                else "other"
            )
            raw = None
            stable = False
            if kind == "regular":
                descriptor = os.open(
                    path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    opened = os.fstat(descriptor)
                    chunks = []
                    while True:
                        chunk = os.read(descriptor, 65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    final = os.fstat(descriptor)
                    raw = b"".join(chunks)
                    stable = (
                        (opened.st_dev, opened.st_ino, opened.st_size,
                         opened.st_mtime_ns, opened.st_ctime_ns)
                        == (final.st_dev, final.st_ino, final.st_size,
                            final.st_mtime_ns, final.st_ctime_ns)
                        and (opened.st_dev, opened.st_ino)
                        == (observed.st_dev, observed.st_ino)
                    )
                finally:
                    os.close(descriptor)
            value = None
            if raw:
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                    value = decoded if isinstance(decoded, dict) else None
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            binding = None if value is None else {
                key: value.get(key) for key in (
                    "handoff_id", "aborted_record_path", "predecessor_record_path",
                    "archived_active_reference_path",
                    "successor_request_pointer_path",
                    "successor_request_quarantine_path", "record_path",
                ) if key in value
            }
            candidates.append({
                "candidate_id": name,
                "path": str(path),
                "type": kind,
                "device": observed.st_dev,
                "inode": observed.st_ino,
                "mode": stat.S_IMODE(observed.st_mode),
                "uid": observed.st_uid,
                "byte_length": None if raw is None else len(raw),
                "raw_sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
                "nofollow_stable": stable,
                "schema": None if value is None else value.get("version"),
                "state": None if value is None else value.get("state"),
                "declared_digest": None if value is None else next((
                    value.get(key) for key in (
                        "resolution_digest", "record_digest", "reference_digest"
                    ) if key in value
                ), None),
                "binding": binding,
            })
        return candidates

    @staticmethod
    def _run_route_supervised(
        operation, expected_error, boundary, custody_events, *, timeout_seconds=30.0
    ):
        """Run one real route in a killable fork and return its measured trace."""

        context = multiprocessing.get_context("fork")
        receive, send = context.Pipe(duplex=False)

        def child():
            failure = None
            result_type = None
            try:
                result = operation()
                result_type = type(result).__name__
            except BaseException as exc:
                failure = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "matches_expected_outer": isinstance(exc, expected_error),
                }
            payload = {
                "failure": failure,
                "result_type": result_type,
                "custody_operations": custody_events,
                "lifecycle_after": {
                    "alive_pids": sorted(boundary.alive),
                    "launch_count": len(boundary.starts),
                    "restart_or_stop_count": boundary.restart_calls,
                    "calls": list(boundary.calls),
                },
            }
            try:
                send.send(payload)
            finally:
                send.close()

        started = time.monotonic_ns()
        deadline = started + int(timeout_seconds * 1_000_000_000)
        process = context.Process(target=child)
        process.start()
        send.close()
        payload = None
        timed_out = not receive.poll(timeout_seconds)
        if not timed_out:
            try:
                payload = receive.recv()
            except EOFError:
                payload = None
        receive.close()
        if timed_out:
            process.terminate()
        process.join(5.0)
        if process.is_alive():
            process.kill()
            process.join(5.0)
        finished = time.monotonic_ns()
        if payload is None:
            payload = {
                "failure": None,
                "result_type": None,
                "custody_operations": [],
                "lifecycle_after": None,
            }
        payload.update({
            "started_monotonic_ns": started,
            "finished_monotonic_ns": finished,
            "deadline_monotonic_ns": deadline,
            "duration_ns": finished - started,
            "timed_out": timed_out,
            "supervisor_exit_code": process.exitcode,
            "supervisor_signal": (
                -process.exitcode
                if process.exitcode is not None and process.exitcode < 0 else None
            ),
        })
        return payload

    def test_first_launch_writes_catalog_discovery_without_synthesizing_activation(self):
        realm_root = self._configure()
        result = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "started")
        self.assertEqual(result.realm_root, realm_root.resolve())
        self.assertEqual(result.support_root, self.paths.app_support)
        serialized = _json_value(result)
        self.assertEqual(serialized["realm_root"], str(realm_root.resolve()))
        self.assertEqual(serialized["support_root"], str(self.paths.app_support))
        self.assertEqual(result.credential_file, self.paths.credentials_dir / "astrid.json")
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(self.boundary.calls, ["start"])
        self.assertEqual(len(self.boundary.creates), 0)
        self.assertEqual(result.realm_id, json.loads(self.paths.discovery_path.read_text())["active_realm"])
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["selected_realm_id"], result.realm_id)
        self.assertEqual(len(catalog["realms"]), 1)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.assertNotIn("token", json.dumps(discovery))
        credential = json.loads((self.paths.credentials_dir / "astrid.json").read_text())
        self.assertEqual(credential["scope"], "astrid")
        self.assertEqual(len(credential["token"]), 64)
        mode = stat.S_IMODE((self.paths.credentials_dir / "astrid.json").stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertNotIn("activation_manifest", catalog["realms"][0])
        source_manifest = self.paths.source_profiles_dir / "astrid.json"
        self.assertEqual(json.loads(source_manifest.read_text()), PROFILE.as_dict())
        self.assertEqual(stat.S_IMODE(source_manifest.stat().st_mode), 0o600)

    def test_second_launch_reconnects_same_owner_and_actor(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        updated = SourceProfile(
            profile="astrid",
            runtime_checkout="/checkouts/runtime-pinned",
            source_checkout="/checkouts/astrid-pinned",
            capability_digest="caps-v1",
        )
        second = bootstrap(self.paths, self.boundary, BootstrapConfig(source_profile=updated))
        self.assertEqual(second.status, "reconnected")
        self.assertEqual(first.realm_id, second.realm_id)
        self.assertEqual(first.actor_id, second.actor_id)
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(len(self.boundary.connects), 2)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(json.loads((self.paths.source_profiles_dir / "astrid.json").read_text()), updated.as_dict())
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["source_profiles"]["astrid"], updated.as_dict())

    def test_stale_discovery_restarts_without_second_realm(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        second = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(second.realm_id, first.realm_id)
        self.assertEqual(len(self.boundary.starts), 2)
        self.assertEqual(json.loads(self.paths.catalog_path.read_text())["selected_realm_id"], first.realm_id)

    def test_unresolved_handoff_gate_blocks_before_stale_discovery_mutation(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        discovery_before = self.paths.discovery_path.read_bytes()
        for gate_name, payload in (
            ("orderly-handoff-request.json", b"not-json\n"),
            ("orderly-handoff-cleanup-uncertain.json", b"not-json\n"),
        ):
            with self.subTest(gate=gate_name):
                gate = self.paths.runtime_support / gate_name
                gate.write_bytes(payload)
                with self.assertRaisesRegex(BootstrapError, "unresolved orderly handoff"):
                    bootstrap(self.paths, self.boundary, self.config)
                self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
                self.assertEqual(len(self.boundary.starts), 1)
                gate.unlink()

    def test_unexpected_sigkill_of_adopted_owner_latches_audit_before_discovery_mutation(self):
        self._configure()
        support = self.paths.runtime_support
        handoff_id = "handoff-loss"
        record = support / f"orderly-handoff-record-{handoff_id}.json"
        record_value = _write_adopted_record(
            record,
            handoff_id=handoff_id,
            realm_root=self.paths.realms_dir / "configured-realm",
            support_root=support,
        )
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        boundary = LocalRuntimeBoundary()
        birth = boundary.process_birth_identity(process.pid)
        active = support / "orderly-handoff-adopted-owner.json"
        _write_active_reference(
            active, handoff_id=handoff_id, record_path=record,
            record_digest=record_value["record_digest"], pid=process.pid,
            birth_id=birth, instance_id="runtime-b",
        )
        stale_discovery = b'{"pid":999999,"runtime_instance_id":"stale"}\n'
        self.paths.discovery_path.write_bytes(stale_discovery)
        process.kill()
        process.wait(timeout=5)
        with self.assertRaisesRegex(BootstrapError, "adopted Runtime owner was lost"):
            bootstrap(self.paths, boundary, self.config)
        marker = support / "orderly-handoff-cleanup-uncertain.json"
        self.assertEqual(
            json.loads(marker.read_text())["reason"],
            "unexpected_post_adopted_owner_loss",
        )
        self.assertEqual(self.paths.discovery_path.read_bytes(), stale_discovery)
        self.assertTrue(record.exists())
        self.assertTrue(active.exists())

    def test_verified_normal_down_resolves_active_adopted_reference(self):
        class BirthBoundary(FakeBoundary):
            def process_birth_identity(self, pid):
                return f"birth-{pid}" if pid in self.alive else None

        self.boundary = BirthBoundary()
        self._configure()
        launched = bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        handoff_id = "handoff-normal-stop"
        record = self.paths.runtime_support / f"orderly-handoff-record-{handoff_id}.json"
        record_value = _write_adopted_record(
            record,
            handoff_id=handoff_id,
            realm_root=self.paths.realms_dir / "configured-realm",
            support_root=self.paths.runtime_support,
        )
        active = self.paths.runtime_support / "orderly-handoff-adopted-owner.json"
        _write_active_reference(
            active, handoff_id=handoff_id, record_path=record,
            record_digest=record_value["record_digest"], pid=discovery["pid"],
            birth_id=discovery["process_birth_id"],
            instance_id=discovery["runtime_instance_id"],
        )
        stopped = down(self.paths, self.boundary)
        self.assertEqual(stopped["status"], "stopped")
        self.assertFalse(active.exists())
        receipt = (
            self.paths.runtime_support
            / f"orderly-handoff-normal-stop-{handoff_id}.json"
        )
        self.assertTrue(json.loads(receipt.read_text())["process_absent"])
        self.assertTrue(record.exists())

    def test_active_adopted_owner_fails_closed_when_birth_is_unavailable(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        handoff_id = "handoff-no-birth"
        record = self.paths.runtime_support / f"orderly-handoff-record-{handoff_id}.json"
        record_value = _write_adopted_record(
            record,
            handoff_id=handoff_id,
            realm_root=self.paths.realms_dir / "configured-realm",
            support_root=self.paths.runtime_support,
        )
        active = self.paths.runtime_support / "orderly-handoff-adopted-owner.json"
        _write_active_reference(
            active, handoff_id=handoff_id, record_path=record,
            record_digest=record_value["record_digest"], pid=discovery["pid"],
            birth_id=discovery["process_birth_id"],
            instance_id=discovery["runtime_instance_id"],
        )
        discovery_before = self.paths.discovery_path.read_bytes()
        with self.assertRaisesRegex(BootstrapError, "adopted Runtime owner was lost"):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)

    def test_digest_valid_but_malformed_adopted_tombstone_is_rejected(self):
        class BirthBoundary(FakeBoundary):
            def process_birth_identity(self, pid):
                return f"birth-{pid}" if pid in self.alive else None

        self.boundary = BirthBoundary()
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        discovery = json.loads(self.paths.discovery_path.read_text())
        handoff_id = "handoff-malformed"
        record = self.paths.runtime_support / f"orderly-handoff-record-{handoff_id}.json"
        record_value = _write_adopted_record(
            record,
            handoff_id=handoff_id,
            realm_root=self.paths.realms_dir / "configured-realm",
            support_root=self.paths.runtime_support,
        )
        record_value.pop("finalization")
        record_value["record_digest"] = digest({
            key: value for key, value in record_value.items() if key != "record_digest"
        })
        record.write_text(json.dumps(record_value), encoding="utf-8")
        active = self.paths.runtime_support / "orderly-handoff-adopted-owner.json"
        _write_active_reference(
            active, handoff_id=handoff_id, record_path=record,
            record_digest=record_value["record_digest"], pid=discovery["pid"],
            birth_id=discovery["process_birth_id"],
            instance_id=discovery["runtime_instance_id"],
        )
        discovery_before = self.paths.discovery_path.read_bytes()
        with self.assertRaisesRegex(BootstrapError, "tombstone is invalid"):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)

    def test_startup_replays_each_predecessor_resolution_crash_cut(self):
        for cut in ("before_prepared", "after_prepared", "after_archive"):
            with self.subTest(cut=cut), tempfile.TemporaryDirectory() as directory:
                paths = RuntimePaths.sandbox(str(Path(directory).resolve()))
                boundary = FakeBoundary()
                config = BootstrapConfig(source_profile=PROFILE)
                paths.ensure_support_dirs()
                realm_root = paths.realms_dir / "configured-realm"
                boundary.create(
                    realm_id="configured-realm", realm_root=realm_root,
                    display_name="Astrid Workspace", source_profile=PROFILE,
                )
                paths.catalog_path.write_text(json.dumps({
                    "version": 1, "selected_realm_id": "configured-realm",
                    "realms": [{
                        "realm_id": "configured-realm", "display_name": "Astrid Workspace",
                        "data_root": str(realm_root),
                    }],
                    "source_profiles": {},
                }))
                bootstrap(paths, boundary, config)
                discovery = json.loads(paths.discovery_path.read_text())
                predecessor_path = paths.runtime_support / "orderly-handoff-record-old.json"
                predecessor = _write_adopted_record(
                    predecessor_path, handoff_id="old", realm_root=realm_root,
                    support_root=paths.runtime_support,
                )
                active_path = paths.runtime_support / "orderly-handoff-adopted-owner.json"
                active_value = _write_active_reference(
                    active_path, handoff_id="old", record_path=predecessor_path,
                    record_digest=predecessor["record_digest"], pid=discovery["pid"],
                    birth_id=discovery["process_birth_id"],
                    instance_id=discovery["runtime_instance_id"],
                )
                successor_path = paths.runtime_support / "orderly-handoff-record-new.json"
                successor = _write_aborted_record(
                    successor_path, handoff_id="new", realm_root=realm_root,
                    support_root=paths.runtime_support,
                    predecessor=active_value["reference_digest"],
                )
                pointer = paths.runtime_support / "orderly-handoff-request.json"
                pointer.write_text(json.dumps({
                    "version": "runtime.local-worker-handoff-transfer/v1",
                    "handoff_id": "new", "record_path": str(successor_path),
                    "socket_path": str(paths.runtime_support / "coordinator.sock"),
                    "coordinator_pid": os.getpid(),
                    "coordinator_birth_id": "coordinator-birth",
                }), encoding="utf-8")
                pointer.chmod(0o600)
                archive_path = paths.runtime_support / "orderly-handoff-predecessor-active-new.json"
                resolution_path = paths.runtime_support / "orderly-handoff-predecessor-resolution-new.json"
                if cut != "before_prepared":
                    active_raw = active_path.read_bytes()
                    pointer_raw = pointer.read_bytes()
                    pointer_info = pointer.lstat()
                    resolution = {
                        "version": 1, "state": "PREPARED", "handoff_id": "new",
                        "aborted_record_path": str(successor_path),
                        "aborted_record_digest": successor["record_digest"],
                        "cleanup_receipt_digest": successor["cleanup_receipt_digest"],
                        "predecessor_active_ref_digest": active_value["reference_digest"],
                        "predecessor_record_path": str(predecessor_path),
                        "predecessor_record_digest": predecessor["record_digest"],
                        "archived_active_reference_path": str(archive_path),
                        "active_reference_file_sha256": hashlib.sha256(active_raw).hexdigest(),
                        "active_reference_archived": False,
                        "successor_request_pointer_path": str(pointer),
                        "successor_request_pointer_sha256": hashlib.sha256(
                            pointer_raw
                        ).hexdigest(),
                        "successor_request_pointer_byte_length": len(pointer_raw),
                        "successor_request_pointer_device": pointer_info.st_dev,
                        "successor_request_pointer_inode": pointer_info.st_ino,
                        "successor_request_pointer_mode": stat.S_IMODE(
                            pointer_info.st_mode
                        ),
                        "successor_request_pointer_uid": pointer_info.st_uid,
                        "successor_request_quarantine_path": str(
                            paths.runtime_support
                            / ".orderly-handoff-request-clearing-new.json"
                        ),
                    }
                    resolution["resolution_digest"] = digest(resolution)
                    resolution_path.write_text(json.dumps(resolution), encoding="utf-8")
                    resolution_path.chmod(0o600)
                    if cut == "after_archive":
                        os.rename(active_path, archive_path)
                result = bootstrap(paths, boundary, config)
                self.assertEqual(result.status, "reconnected")
                self.assertFalse(pointer.exists())
                self.assertFalse(active_path.exists())
                self.assertTrue(archive_path.exists())
                completed = json.loads(resolution_path.read_text())
                self.assertEqual(completed["state"], "COMPLETE")

    def test_all_launcher_entry_points_fail_closed_on_malformed_journal(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        journal = (
            self.paths.runtime_support
            / "orderly-handoff-predecessor-resolution-malformed.json"
        )
        journal.write_bytes(b"{malformed")
        journal.chmod(0o600)
        discovery_before = self.paths.discovery_path.read_bytes()
        catalog_before = self.paths.catalog_path.read_bytes()
        starts_before = len(self.boundary.starts)
        interrupts_before = self.boundary.restart_calls
        operations = (
            lambda: bootstrap(self.paths, self.boundary, self.config),
            lambda: restart(
                self.paths, self.boundary, self.config, preserve_worker=False
            ),
            lambda: restart(
                self.paths, self.boundary, self.config, preserve_worker=True
            ),
            lambda: down(self.paths, self.boundary),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    BootstrapError, "predecessor resolution replay failed closed"
                ):
                    operation()
                self.assertEqual(journal.read_bytes(), b"{malformed")
                self.assertEqual(
                    self.paths.discovery_path.read_bytes(), discovery_before
                )
                self.assertEqual(self.paths.catalog_path.read_bytes(), catalog_before)
                self.assertEqual(len(self.boundary.starts), starts_before)
                self.assertEqual(self.boundary.restart_calls, interrupts_before)

    def test_runtime_v28_all_routes_authoritative_matrix(self):
        import runtime_protocol.handoff_recovery as recovery_module

        routes = (
            "bootstrap", "restart-false", "restart-true", "down",
            "launcher-recovery", "runtime-daemon",
        )
        hostile_cases = (
            "malformed", "duplicate-key", "non-object", "missing", "extra",
            "wrong-type", "wrong-digest", "wrong-state", "filename-mismatch",
            "noncanonical-path", "bad-digest-shape", "wrong-archive-flag",
            "bool-numeric", "unreadable", "oversized", "wrong-owner",
            "wrong-mode", "symlink", "directory", "fifo", "socket",
            "two-invalid", "valid-plus-invalid", "two-prepared",
            "quarantine-malformed", "quarantine-wrong-mode",
            "quarantine-symlink", "quarantine-unbound", "quarantine-multiple",
            "quarantine-public-ambiguous", "quarantine-custody-mismatch",
            "journal-set-race", "journal-inode-race", "pointer-inode-race",
        )
        positive_cases = (
            "prepared-active", "prepared-archive", "complete-pointer",
            "complete-quarantine", "complete-restored-link",
            "complete-idempotent",
        )
        expected_rows = sorted(
            [f"hostile:{case}:{route}" for case in hostile_cases for route in routes]
            + [f"positive:{case}:{route}" for case in positive_cases for route in routes]
        )
        expected_row_set_digest = "sha256:" + hashlib.sha256(json.dumps(
            expected_rows, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")).hexdigest()
        repository_root = Path(__file__).resolve().parents[1]
        inventory_paths = (
            "banodoco_local/bootstrap.py", "banodoco_local/cli.py",
            "banodoco_local/runtime_boundary.py", "runtime_protocol/auth.py",
            "runtime_protocol/cli.py", "runtime_protocol/daemon.py",
            "runtime_protocol/handoff_recovery.py", "runtime_protocol/lifecycle.py",
            "runtime_protocol/local_worker.py",
            "runtime_protocol/local_worker_composition.py",
            "runtime_protocol/local_worker_handoff.py",
            "runtime_protocol/orderly_handoff.py", "runtime_protocol/server.py",
            "tests/test_bootstrap.py", "tests/test_credential_generation_snapshot.py",
            "tests/test_local_worker_composition.py",
            "tests/test_local_worker_handoff.py", "tests/test_local_worker_placement.py",
            "tests/test_orderly_handoff_record.py", "tests/test_runtime_boundary.py",
            "tests/test_runtime_e2e.py", "tests/test_runtime_lifecycle.py",
        )
        source_inventory = {
            relative: hashlib.sha256(
                (repository_root / relative).read_bytes()
            ).hexdigest()
            for relative in inventory_paths
        }
        source_inventory_digest = "sha256:" + hashlib.sha256(json.dumps(
            source_inventory, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        normative_bindings = {
            "review_hold_sha256":
                "f4d46e3284e289bb801a9663a635ec23db163d8f18a393252b9761640167cd03",
            "closure_checklist_sha256":
                "cf59d7ac07bb2fc669d506568a9cac9926446f812973a300fa89ec496acf95e3",
        }
        candidate_identity = {
            "source_inventory_digest": source_inventory_digest,
            "expected_row_set_digest": expected_row_set_digest,
            "executed_row_set_digest": expected_row_set_digest,
            **normative_bindings,
        }
        receipt_rows = []
        matrix_errors = []

        def evidence_digest(value):
            return "sha256:" + hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")).hexdigest()

        def rehash(value):
            value["resolution_digest"] = digest({
                key: item for key, item in value.items()
                if key != "resolution_digest"
            })

        def write_journal(support, handoff_id, value, mode=0o600):
            path = support / (
                f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
            )
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(mode)
            return path

        def lifecycle_observation(boundary):
            return {
                "alive_pids": sorted(boundary.alive),
                "launch_count": len(boundary.starts),
                "restart_or_stop_count": boundary.restart_calls,
                "calls": list(boundary.calls),
            }

        def custody_instrumentation(stack, events, support):
            originals = {
                "rename": recovery_module._rename_pointer_to_quarantine,
                "remove": recovery_module._remove_exact_quarantine,
                "restore": recovery_module._restore_quarantined_replacement,
                "fsync": recovery_module._fsync_directory,
                "link": recovery_module.os.link,
                "unlink": recovery_module.os.unlink,
            }

            def directory_identity(path):
                observed = path.lstat()
                return {
                    "path": str(path), "device": observed.st_dev,
                    "inode": observed.st_ino, "mode": stat.S_IMODE(observed.st_mode),
                    "uid": observed.st_uid,
                }

            def append_event(operation, phase, **fields):
                protected_snapshot = self._authority_evidence(support)
                events.append({
                    "sequence": len(events) + 1,
                    "monotonic_ns": time.monotonic_ns(),
                    "operation": operation,
                    "phase": phase,
                    "directory_identity": directory_identity(support),
                    "protected_snapshot": protected_snapshot,
                    "protected_snapshot_digest": evidence_digest(protected_snapshot),
                    **fields,
                })

            def rename(pointer, quarantine):
                append_event(
                    "rename-no-replace", "begin",
                    source=pointer.name, destination=quarantine.name,
                )
                try:
                    result = originals["rename"](pointer, quarantine)
                except BaseException as exc:
                    append_event(
                        "rename-no-replace", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("rename-no-replace", "return", result="ok")
                return result

            def remove(support, quarantine, resolution, **kwargs):
                append_event(
                    "remove-exact-quarantine", "begin",
                    candidate_id=quarantine.name,
                )
                try:
                    result = originals["remove"](
                        support, quarantine, resolution, **kwargs
                    )
                except BaseException as exc:
                    append_event(
                        "remove-exact-quarantine", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("remove-exact-quarantine", "return", result="ok")
                return result

            def restore(pointer, quarantine):
                append_event(
                    "restore-no-replace-hard-link", "begin",
                    source=quarantine.name, destination=pointer.name,
                )
                try:
                    result = originals["restore"](pointer, quarantine)
                except BaseException as exc:
                    append_event(
                        "restore-no-replace-hard-link", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("restore-no-replace-hard-link", "return", result="ok")
                return result

            def fsync(path):
                append_event(
                    "fsync-directory", "begin",
                    candidate_id=path.name,
                )
                try:
                    result = originals["fsync"](path)
                except BaseException as exc:
                    append_event(
                        "fsync-directory", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("fsync-directory", "return", result="ok")
                return result

            def link(source, destination, *args, **kwargs):
                append_event(
                    "link", "begin", source=str(source), destination=str(destination)
                )
                try:
                    result = originals["link"](source, destination, *args, **kwargs)
                except BaseException as exc:
                    append_event(
                        "link", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("link", "return", result="ok")
                return result

            def unlink(path, *args, **kwargs):
                append_event("unlink", "begin", path=str(path))
                try:
                    result = originals["unlink"](path, *args, **kwargs)
                except BaseException as exc:
                    append_event(
                        "unlink", "exception",
                        exception={"type": type(exc).__name__, "message": str(exc)},
                    )
                    raise
                append_event("unlink", "return", result="ok")
                return result

            stack.enter_context(mock.patch.object(
                recovery_module, "_rename_pointer_to_quarantine", side_effect=rename
            ))
            stack.enter_context(mock.patch.object(
                recovery_module, "_remove_exact_quarantine", side_effect=remove
            ))
            stack.enter_context(mock.patch.object(
                recovery_module, "_restore_quarantined_replacement", side_effect=restore
            ))
            stack.enter_context(mock.patch.object(
                recovery_module, "_fsync_directory", side_effect=fsync
            ))
            stack.enter_context(mock.patch.object(
                recovery_module.os, "link", side_effect=link
            ))
            stack.enter_context(mock.patch.object(
                recovery_module.os, "unlink", side_effect=unlink
            ))
            for function_name in (
                "_json_object", "_owner_json", "_validate_resolution",
                "_scan_resolutions", "_scan_quarantines", "_pointer_snapshot",
                "_clear_pointer", "_recover_locked",
            ):
                original = getattr(recovery_module, function_name)

                def observed_gate(*args, __name=function_name,
                                  __original=original, **kwargs):
                    try:
                        result = __original(*args, **kwargs)
                    except BaseException as exc:
                        append_event(
                            f"gate:{__name}", "exception",
                            exception={
                                "type": type(exc).__name__,
                                "message": str(exc),
                            },
                        )
                        raise
                    if __name == "_recover_locked":
                        append_event(
                            f"gate:{__name}", "return",
                            result_state=(
                                result.get("state")
                                if isinstance(result, dict) else None
                            ),
                        )
                    return result

                stack.enter_context(mock.patch.object(
                    recovery_module, function_name, side_effect=observed_gate
                ))

        expected_gate_by_case = {
            **{case: "gate:_json_object" for case in (
                "malformed", "duplicate-key", "non-object", "unreadable",
                "two-invalid", "valid-plus-invalid", "quarantine-malformed",
            )},
            **{case: "gate:_validate_resolution" for case in (
                "missing", "extra", "wrong-type", "wrong-digest", "wrong-state",
                "filename-mismatch", "noncanonical-path", "bad-digest-shape",
                "wrong-archive-flag", "bool-numeric",
            )},
            **{case: "gate:_owner_json" for case in (
                "oversized", "wrong-owner", "wrong-mode", "symlink", "directory",
                "fifo", "socket", "quarantine-wrong-mode", "quarantine-symlink",
            )},
            **{case: "gate:_scan_resolutions" for case in (
                "two-prepared", "journal-set-race", "journal-inode-race",
            )},
            **{case: "gate:_scan_quarantines" for case in (
                "quarantine-unbound", "quarantine-multiple",
            )},
            "quarantine-public-ambiguous": "gate:_recover_locked",
            "quarantine-custody-mismatch": "gate:_clear_pointer",
            "pointer-inode-race": "gate:_recover_locked",
        }

        def emitted_gate(events, *, positive=False):
            phase = "return" if positive else "exception"
            return next((
                event for event in events
                if event["operation"].startswith("gate:")
                and event["phase"] == phase
            ), None)

        for case in hostile_cases:
            for route in routes:
                row_id = f"hostile:{case}:{route}"
                with self.subTest(row_id=row_id), tempfile.TemporaryDirectory() as directory:
                    realistic = case in {
                        "quarantine-public-ambiguous",
                        "quarantine-custody-mismatch",
                        "pointer-inode-race",
                    }
                    if realistic:
                        checkpoint = (
                            "prepared-active" if case == "pointer-inode-race"
                            else "complete-quarantine"
                        )
                        fixture = self._fresh_resolution_state(directory, checkpoint)
                        paths = fixture["paths"]
                        boundary = fixture["boundary"]
                        config = fixture["config"]
                        realm_root = fixture["realm_root"]
                        support = fixture["support"]
                    else:
                        paths, boundary, config, realm_root = self._fresh_launcher_state(
                            directory
                        )
                        support = paths.runtime_support
                        fixture = None
                    sockets = []
                    patches = []
                    valid = _valid_resolution_journal(support, "case")
                    journal = support / "orderly-handoff-predecessor-resolution-case.json"
                    static_support = True
                    validator = "resolution-journal"

                    if case == "malformed":
                        journal.write_bytes(b"{malformed")
                        journal.chmod(0o600)
                    elif case == "duplicate-key":
                        journal.write_bytes(b'{"version":1,"version":1}')
                        journal.chmod(0o600)
                    elif case == "non-object":
                        journal.write_bytes(b"[]")
                        journal.chmod(0o600)
                    elif case == "missing":
                        valid.pop("cleanup_receipt_digest")
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "extra":
                        valid["extra"] = True
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "wrong-type":
                        valid["successor_request_pointer_inode"] = "1"
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "wrong-digest":
                        valid["resolution_digest"] = "sha256:" + "0" * 64
                        write_journal(support, "case", valid)
                    elif case == "wrong-state":
                        valid["state"] = "ADOPTED"
                        valid["active_reference_archived"] = False
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "filename-mismatch":
                        valid["handoff_id"] = "other"
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "noncanonical-path":
                        valid["aborted_record_path"] = (
                            str(support) + "/./orderly-handoff-record-case.json"
                        )
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "bad-digest-shape":
                        valid["cleanup_receipt_digest"] = "sha256:" + "A" * 64
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "wrong-archive-flag":
                        valid["active_reference_archived"] = False
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "bool-numeric":
                        valid["successor_request_pointer_device"] = True
                        rehash(valid)
                        write_journal(support, "case", valid)
                    elif case == "unreadable":
                        journal.write_bytes(b"\xff\xfe")
                        journal.chmod(0o600)
                    elif case == "oversized":
                        journal.write_bytes(b" " * (1024 * 1024 + 1))
                        journal.chmod(0o600)
                    elif case == "wrong-owner":
                        write_journal(support, "case", valid)
                        identity = (journal.lstat().st_dev, journal.lstat().st_ino)
                        real_fstat = recovery_module.os.fstat

                        def wrong_owner(descriptor, identity=identity):
                            observed = real_fstat(descriptor)
                            if (observed.st_dev, observed.st_ino) != identity:
                                return observed
                            return SimpleNamespace(
                                st_mode=observed.st_mode,
                                st_uid=observed.st_uid + 1,
                                st_dev=observed.st_dev,
                                st_ino=observed.st_ino,
                                st_size=observed.st_size,
                                st_mtime_ns=observed.st_mtime_ns,
                                st_ctime_ns=observed.st_ctime_ns,
                            )
                        patches.append(mock.patch.object(
                            recovery_module.os, "fstat", side_effect=wrong_owner
                        ))
                    elif case == "wrong-mode":
                        write_journal(support, "case", valid, 0o644)
                    elif case == "symlink":
                        outside = support.parent / "outside-resolution.json"
                        outside.write_text(json.dumps(valid), encoding="utf-8")
                        journal.symlink_to(outside)
                    elif case == "directory":
                        journal.mkdir()
                    elif case == "fifo":
                        os.mkfifo(journal, 0o600)
                    elif case == "socket":
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        current = os.getcwd()
                        try:
                            os.chdir(support)
                            sock.bind(journal.name)
                        finally:
                            os.chdir(current)
                        sockets.append(sock)
                    elif case == "two-invalid":
                        for handoff_id in ("one", "two"):
                            path = support / (
                                f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
                            )
                            path.write_bytes(b"{bad")
                            path.chmod(0o600)
                    elif case == "valid-plus-invalid":
                        write_journal(support, "case", valid)
                        path = support / "orderly-handoff-predecessor-resolution-bad.json"
                        path.write_bytes(b"{bad")
                        path.chmod(0o600)
                    elif case == "two-prepared":
                        write_journal(
                            support, "one",
                            _valid_resolution_journal(support, "one", state="PREPARED")
                        )
                        write_journal(
                            support, "two",
                            _valid_resolution_journal(support, "two", state="PREPARED")
                        )
                    elif case.startswith("quarantine-") and not realistic:
                        validator = "quarantine-binding"
                        quarantine = support / ".orderly-handoff-request-clearing-case.json"
                        if case == "quarantine-malformed":
                            quarantine.write_bytes(b"{bad")
                            quarantine.chmod(0o600)
                        elif case == "quarantine-wrong-mode":
                            quarantine.write_bytes(b"{}")
                            quarantine.chmod(0o644)
                        elif case == "quarantine-symlink":
                            outside = support.parent / "outside-quarantine.json"
                            outside.write_bytes(b"{}")
                            quarantine.symlink_to(outside)
                        elif case == "quarantine-unbound":
                            quarantine.write_bytes(b"{}")
                            quarantine.chmod(0o600)
                        else:
                            for handoff_id in ("one", "two"):
                                write_journal(
                                    support, handoff_id,
                                    _valid_resolution_journal(
                                        support, handoff_id, state="COMPLETE"
                                    )
                                )
                                candidate = support / (
                                    f".orderly-handoff-request-clearing-{handoff_id}.json"
                                )
                                candidate.write_bytes(b"{}")
                                candidate.chmod(0o600)
                    elif case == "quarantine-public-ambiguous":
                        validator = "quarantine-public-custody"
                        fixture["pointer_path"].write_bytes(
                            fixture["quarantine_path"].read_bytes()
                        )
                        fixture["pointer_path"].chmod(0o600)
                        # Recovery must enter the coordinator lock to compare
                        # the two names.  Lock creation is receipt evidence,
                        # not a custody mutation.
                        static_support = False
                    elif case == "quarantine-custody-mismatch":
                        validator = "quarantine-exact-identity"
                        fixture["quarantine_path"].write_bytes(b"{}")
                        static_support = False
                    elif case == "journal-set-race":
                        validator = "stable-journal-enumeration"
                        write_journal(support, "case", valid)
                        real_paths = recovery_module._resolution_paths
                        calls = {"count": 0}

                        def changing_paths(root):
                            calls["count"] += 1
                            if calls["count"] == 3:
                                added = root / (
                                    "orderly-handoff-predecessor-resolution-added.json"
                                )
                                added.write_bytes(b"{bad")
                                added.chmod(0o600)
                            return real_paths(root)
                        patches.append(mock.patch.object(
                            recovery_module, "_resolution_paths",
                            side_effect=changing_paths,
                        ))
                        static_support = False
                    elif case == "journal-inode-race":
                        validator = "stable-journal-inode"
                        write_journal(support, "case", valid)
                        real_owner_json = recovery_module._owner_json
                        swapped = {"done": False}

                        def swapping_owner_json(path, label):
                            observed = real_owner_json(path, label)
                            if path == journal and not swapped["done"]:
                                alternate = support / ".replacement-resolution.json"
                                alternate.write_bytes(observed.raw)
                                alternate.chmod(0o600)
                                os.replace(alternate, journal)
                                swapped["done"] = True
                            return observed
                        patches.append(mock.patch.object(
                            recovery_module, "_owner_json",
                            side_effect=swapping_owner_json,
                        ))
                        static_support = False
                    elif case == "pointer-inode-race":
                        validator = "pre-lock-pointer-identity"
                        real_signature = recovery_module._scan_signature
                        swapped = {"done": False}

                        def swapping_signature(*args):
                            signature = real_signature(*args)
                            if not swapped["done"]:
                                raw = fixture["pointer_path"].read_bytes()
                                alternate = support / ".replacement-pointer.json"
                                alternate.write_bytes(raw)
                                alternate.chmod(0o600)
                                os.replace(alternate, fixture["pointer_path"])
                                swapped["done"] = True
                            return signature
                        patches.append(mock.patch.object(
                            recovery_module, "_scan_signature",
                            side_effect=swapping_signature,
                        ))
                        static_support = False

                    operation, expected_error, executor = self._launcher_routes(
                        paths, boundary, config, realm_root
                    )[route]
                    before_support = self._support_snapshot(support)
                    before_authority = self._authority_evidence(support)
                    before_lifecycle = lifecycle_observation(boundary)
                    custody_events = []
                    with contextlib.ExitStack() as stack:
                        custody_instrumentation(stack, custody_events, support)
                        for patcher in patches:
                            stack.enter_context(patcher)
                        execution = self._run_route_supervised(
                            operation, expected_error, boundary, custody_events
                        )
                    started = execution["started_monotonic_ns"]
                    finished = execution["finished_monotonic_ns"]
                    deadline = execution["deadline_monotonic_ns"]
                    failure = execution["failure"]
                    custody_events = execution["custody_operations"]
                    gate_event = emitted_gate(custody_events)
                    for sock in sockets:
                        sock.close()
                    after_authority = self._authority_evidence(support)
                    after_lifecycle = execution["lifecycle_after"]
                    if failure is None:
                        matrix_errors.append(f"{row_id}: unexpectedly accepted")
                    elif not failure["matches_expected_outer"]:
                        matrix_errors.append(
                            f"{row_id}: wrong failure type {failure['type']}"
                        )
                    if gate_event is None:
                        matrix_errors.append(f"{row_id}: no emitted inner gate")
                    elif gate_event["operation"] != expected_gate_by_case[case]:
                        matrix_errors.append(
                            f"{row_id}: inner gate {gate_event['operation']} != "
                            f"{expected_gate_by_case[case]}"
                        )
                    if execution["timed_out"]:
                        matrix_errors.append(f"{row_id}: supervisor timeout")
                    if before_lifecycle != after_lifecycle:
                        matrix_errors.append(f"{row_id}: lifecycle mutated")
                    if static_support and before_support != self._support_snapshot(support):
                        matrix_errors.append(f"{row_id}: support custody mutated")
                    receipt_rows.append({
                        "row_id": row_id,
                        "candidate_identity": {
                            **candidate_identity,
                            "route": route,
                            "state_case": case,
                            "root": str(Path(directory).resolve()),
                        },
                        "expectation": "reject-before-lifecycle-mutation",
                        "validator": validator,
                        "validator_source":
                            "runtime_protocol/handoff_recovery.py::_recover_locked",
                        "expected_inner_gate": expected_gate_by_case[case],
                        "observed_inner_gate": (
                            gate_event["operation"] if gate_event else None
                        ),
                        "observed_inner_exception": (
                            gate_event.get("exception") if gate_event else None
                        ),
                        "gate": route,
                        "executor": executor,
                        "failure": failure,
                        "failure_code": (
                            f"{failure['type']}:{validator}" if failure else "missing-rejection"
                        ),
                        "outcome": "rejected" if failure else "unexpected-acceptance",
                        "timed_out": execution["timed_out"],
                        "finished_monotonic_ns": finished,
                        "supervisor_exit_code": execution["supervisor_exit_code"],
                        "supervisor_signal": execution["supervisor_signal"],
                        "started_monotonic_ns": started,
                        "deadline_monotonic_ns": deadline,
                        "duration_ns": finished - started,
                        "candidates_before": before_authority,
                        "candidates_after": after_authority,
                        "lifecycle_before": before_lifecycle,
                        "lifecycle_after": after_lifecycle,
                        "protected_state_digests": {
                            "pre": evidence_digest({
                                "candidates": before_authority,
                                "lifecycle": before_lifecycle,
                            }),
                            "cut": evidence_digest(custody_events),
                            "post": evidence_digest({
                                "candidates": after_authority,
                                "lifecycle": after_lifecycle,
                            }),
                        },
                        "process_observation": {
                            "runner_pid": os.getpid(),
                            "runner_uid": os.getuid(),
                            "route_executor": executor,
                            "launch_count_before": before_lifecycle["launch_count"],
                            "launch_count_after": after_lifecycle["launch_count"],
                            "external_process_expected": False,
                        },
                        "mutation_observation": {
                            "lifecycle_changed": before_lifecycle != after_lifecycle,
                            "candidate_evidence_changed": (
                                before_authority != after_authority
                            ),
                            "locks_before": [
                                item for item in before_authority
                                if item["candidate_id"].endswith(".lock")
                            ],
                            "locks_after": [
                                item for item in after_authority
                                if item["candidate_id"].endswith(".lock")
                            ],
                        },
                        "custody_operations": custody_events,
                    })

        for case in positive_cases:
            for route in routes:
                row_id = f"positive:{case}:{route}"
                with self.subTest(row_id=row_id), tempfile.TemporaryDirectory() as directory:
                    fixture = self._fresh_resolution_state(directory, case)
                    paths = fixture["paths"]
                    boundary = fixture["boundary"]
                    support = fixture["support"]
                    operation, _expected_error, executor = self._launcher_routes(
                        paths, boundary, fixture["config"], fixture["realm_root"]
                    )[route]
                    before_authority = self._authority_evidence(support)
                    before_lifecycle = lifecycle_observation(boundary)
                    custody_events = []
                    with contextlib.ExitStack() as stack:
                        custody_instrumentation(stack, custody_events, support)
                        execution = self._run_route_supervised(
                            operation, Exception, boundary, custody_events
                        )
                    started = execution["started_monotonic_ns"]
                    finished = execution["finished_monotonic_ns"]
                    deadline = execution["deadline_monotonic_ns"]
                    failure = execution["failure"]
                    custody_events = execution["custody_operations"]
                    gate_event = emitted_gate(custody_events, positive=True)
                    after_authority = self._authority_evidence(support)
                    after_lifecycle = execution["lifecycle_after"]
                    completed = json.loads(fixture["journal_path"].read_text())
                    positive_checks = {
                        "no_failure": failure is None,
                        "complete_state": completed["state"] == "COMPLETE",
                        "archive_flag": completed["active_reference_archived"] is True,
                        "archive_present": fixture["archive_path"].exists(),
                        "active_absent": not fixture["active_path"].exists(),
                        "pointer_absent": not fixture["pointer_path"].exists(),
                        "quarantine_absent": not fixture["quarantine_path"].exists(),
                        "within_deadline": not execution["timed_out"],
                        "inner_gate_returned": gate_event is not None,
                    }
                    for check, passed in positive_checks.items():
                        if not passed:
                            matrix_errors.append(f"{row_id}: failed {check}")
                    receipt_rows.append({
                        "row_id": row_id,
                        "candidate_identity": {
                            **candidate_identity,
                            "route": route,
                            "state_case": case,
                            "root": str(Path(directory).resolve()),
                        },
                        "expectation": "replay-to-complete",
                        "validator": "resolution-and-quarantine-replay",
                        "validator_source":
                            "runtime_protocol/handoff_recovery.py::_recover_locked",
                        "expected_inner_gate": "gate:_recover_locked",
                        "observed_inner_gate": (
                            gate_event["operation"] if gate_event else None
                        ),
                        "observed_inner_exception": None,
                        "gate": route,
                        "executor": executor,
                        "failure": failure,
                        "failure_code": (
                            f"{failure['type']}:positive-replay" if failure
                            else "accepted-positive"
                        ),
                        "outcome": "accepted" if failure is None else "failed-positive",
                        "timed_out": execution["timed_out"],
                        "finished_monotonic_ns": finished,
                        "supervisor_exit_code": execution["supervisor_exit_code"],
                        "supervisor_signal": execution["supervisor_signal"],
                        "started_monotonic_ns": started,
                        "deadline_monotonic_ns": deadline,
                        "duration_ns": finished - started,
                        "candidates_before": before_authority,
                        "candidates_after": after_authority,
                        "lifecycle_before": before_lifecycle,
                        "lifecycle_after": after_lifecycle,
                        "protected_state_digests": {
                            "pre": evidence_digest({
                                "candidates": before_authority,
                                "lifecycle": before_lifecycle,
                            }),
                            "cut": evidence_digest(custody_events),
                            "post": evidence_digest({
                                "candidates": after_authority,
                                "lifecycle": after_lifecycle,
                            }),
                        },
                        "process_observation": {
                            "runner_pid": os.getpid(),
                            "runner_uid": os.getuid(),
                            "route_executor": executor,
                            "launch_count_before": before_lifecycle["launch_count"],
                            "launch_count_after": after_lifecycle["launch_count"],
                            "external_process_expected": False,
                        },
                        "mutation_observation": {
                            "lifecycle_changed": (
                                before_lifecycle != after_lifecycle
                            ),
                            "candidate_evidence_changed": (
                                before_authority != after_authority
                            ),
                            "locks_before": [
                                item for item in before_authority
                                if item["candidate_id"].endswith(".lock")
                            ],
                            "locks_after": [
                                item for item in after_authority
                                if item["candidate_id"].endswith(".lock")
                            ],
                        },
                        "custody_operations": custody_events,
                    })

        executed_rows = sorted(row["row_id"] for row in receipt_rows)
        self.assertEqual(executed_rows, expected_rows)
        self.assertEqual(len(executed_rows), len(set(executed_rows)))
        executed_row_set_digest = evidence_digest(executed_rows)
        self.assertEqual(executed_row_set_digest, expected_row_set_digest)
        for row in receipt_rows:
            row["row_evidence_digest"] = evidence_digest(row)
        receipt = {
            "schema": "runtime.lifecycle-route-matrix-receipt/v2.8",
            "matrix_digest": expected_row_set_digest,
            "expected_row_set_digest": expected_row_set_digest,
            "executed_row_set_digest": executed_row_set_digest,
            "source_inventory": source_inventory,
            "source_inventory_digest": source_inventory_digest,
            "normative_bindings": normative_bindings,
            "expected_row_ids": expected_rows,
            "executed_row_ids": executed_rows,
            "expected_row_count": len(expected_rows),
            "executed_row_count": len(executed_rows),
            "unique_row_count": len(set(executed_rows)),
            "matrix_complete": not matrix_errors,
            "matrix_errors": matrix_errors,
            "rows": sorted(receipt_rows, key=lambda row: row["row_id"]),
        }
        receipt["receipt_digest"] = evidence_digest(receipt)
        receipt_path = os.environ.get("X3_RUNTIME_V28_RECEIPT")
        if receipt_path:
            serialized = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ) + "\n"
            Path(receipt_path).write_text(serialized, encoding="utf-8")
        self.assertEqual(matrix_errors, [])

    def test_runtime_v29_checklist_complete_supervised_matrix(self):
        import runtime_protocol.handoff_recovery as recovery_module

        routes = (
            "bootstrap", "restart-false", "restart-true", "down",
            "launcher-recovery", "runtime-daemon",
        )
        hostile_cases = (
            "active-archive-ambiguity",
            "alternate-active-reference",
            "journal-removal-race",
            "quarantine-insertion-race",
            "quarantine-removal-race",
            "quarantine-replacement-race",
            "quarantine-repopulation-public",
            "quarantine-no-replace-preexisting",
            "quarantine-no-replace-concurrent",
            "remove-unlink-exact-before",
            "remove-unlink-exact-after",
            "remove-unlink-swapped-before",
            "remove-unlink-swapped-delete",
            "dual-unlink-exact-before",
            "dual-unlink-exact-after",
            "dual-unlink-swapped-before",
            "dual-unlink-swapped-delete",
        )
        positive_cases = ("same-b-retry",)
        extension_expected = sorted(
            [f"hostile:{case}:{route}" for case in hostile_cases for route in routes]
            + [f"positive:{case}:{route}" for case in positive_cases for route in routes]
        )

        def canonical_digest(value):
            return "sha256:" + hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")).hexdigest()

        repository_root = Path(__file__).resolve().parents[1]
        run_name = repository_root.parent.name
        run_root = repository_root.parents[2] / "runs" / run_name
        evidence_root = run_root / "evidence"
        binding_files = {
            "v28_hold": evidence_root
            / "X3-remediation-v2.8-runtime-exact-review-HOLD.md",
            "closure_checklist": evidence_root
            / "X3-remediation-v2.4-runtime-281-75-closure-checklist.md",
            "normative_amendment": evidence_root
            / "X3-finalizing-normative-amendment-v2.3.md",
            "acceptance_matrix_amendment": evidence_root
            / "X3-finalizing-acceptance-matrix-amendment-v2.3.md",
            "predecessor_acceptance_matrix": evidence_root
            / "X3-revised-handoff-acceptance-matrix.md",
            "v28_freeze_bundle": evidence_root
            / "X3-remediation-v2.8-runtime-freeze-bundle.json",
            "v28_authoritative_receipt": evidence_root
            / "X3-remediation-v2.8-runtime-route-matrix-receipt.json",
        }
        normative_bindings = {
            name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in binding_files.items()
        }
        expected_bindings = {
            "v28_hold": "sha256:d114c44da6b5d78e76a58fc28d71375830c183d13360bac9b5b206d76ccb6584",
            "closure_checklist": "sha256:cf59d7ac07bb2fc669d506568a9cac9926446f812973a300fa89ec496acf95e3",
            "normative_amendment": "sha256:7995464a42c74027ecce8593e03d4350b2f8014ebfe43b56bc5d7ac89531b9dc",
            "acceptance_matrix_amendment": "sha256:bb8203b9d89c93435122f969671d1fe82effe6b7f7b52468594469145a22b6eb",
            "predecessor_acceptance_matrix": "sha256:5af694f2acea33647dc457ce52106672a7428c8ad8840c1e84c61c503a0dae5f",
            "v28_freeze_bundle": "sha256:b3a60354b21e11191e64ea3c0924f0667cd2943072a380a5285297d734718c5b",
            "v28_authoritative_receipt": "sha256:7265355264703da92df5016eecaac91bdf69e2f8ca2fd408465bef565da132bf",
        }
        self.assertEqual(normative_bindings, expected_bindings)

        with tempfile.TemporaryDirectory() as baseline_directory:
            baseline_path = Path(baseline_directory) / "v28-supervised.json"
            with mock.patch.dict(
                os.environ, {"X3_RUNTIME_V28_RECEIPT": str(baseline_path)}
            ):
                self.test_runtime_v28_all_routes_authoritative_matrix()
            baseline_receipt = json.loads(baseline_path.read_text(encoding="utf-8"))

        receipt_rows = list(baseline_receipt["rows"])
        matrix_errors = []

        def write_complete_journal(support, handoff_id="case"):
            value = _valid_resolution_journal(support, handoff_id, state="COMPLETE")
            path = support / (
                f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
            )
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            return path

        def lifecycle(boundary):
            return {
                "alive_pids": sorted(boundary.alive),
                "launch_count": len(boundary.starts),
                "restart_or_stop_count": boundary.restart_calls,
                "calls": list(boundary.calls),
            }

        def append_event(events, support, operation, phase, **fields):
            snapshot = self._authority_evidence(support)
            events.append({
                "sequence": len(events) + 1,
                "monotonic_ns": time.monotonic_ns(),
                "operation": operation,
                "phase": phase,
                "protected_snapshot": snapshot,
                "protected_snapshot_digest": canonical_digest(snapshot),
                **fields,
            })

        def instrument(stack, events, support):
            for function_name in (
                "_json_object", "_owner_json", "_validate_resolution",
                "_scan_resolutions", "_scan_quarantines", "_pointer_snapshot",
                "_clear_pointer", "_remove_exact_quarantine",
                "_restore_quarantined_replacement", "resolve_aborted_predecessor",
                "_retire_exact_quarantine", "_recover_locked",
            ):
                original = getattr(recovery_module, function_name)

                def observed(*args, __name=function_name,
                             __original=original, **kwargs):
                    try:
                        result = __original(*args, **kwargs)
                    except BaseException as exc:
                        append_event(
                            events, support, f"gate:{__name}", "exception",
                            exception={
                                "type": type(exc).__name__, "message": str(exc),
                            },
                        )
                        raise
                    if __name == "_recover_locked":
                        append_event(
                            events, support, f"gate:{__name}", "return",
                            result_state=(
                                result.get("state")
                                if isinstance(result, dict) else None
                            ),
                        )
                    return result

                stack.enter_context(mock.patch.object(
                    recovery_module, function_name, side_effect=observed
                ))
            for function_name in (
                "_atomic_rename_noreplace", "_rename_pointer_to_quarantine",
                "_fsync_directory",
            ):
                original = getattr(recovery_module, function_name)

                def custody(*args, __name=function_name,
                            __original=original, **kwargs):
                    append_event(events, support, f"custody:{__name}", "begin")
                    try:
                        result = __original(*args, **kwargs)
                    except BaseException as exc:
                        append_event(
                            events, support, f"custody:{__name}", "exception",
                            exception={
                                "type": type(exc).__name__, "message": str(exc),
                            },
                        )
                        raise
                    append_event(events, support, f"custody:{__name}", "return")
                    return result

                stack.enter_context(mock.patch.object(
                    recovery_module, function_name, side_effect=custody
                ))

        def first_gate(events, phase="exception"):
            return next((
                event for event in events
                if event["operation"].startswith("gate:")
                and event["phase"] == phase
            ), None)

        for case in (*hostile_cases, *positive_cases):
            for route in routes:
                row_class = "positive" if case in positive_cases else "hostile"
                row_id = f"{row_class}:{case}:{route}"
                with self.subTest(row_id=row_id), tempfile.TemporaryDirectory() as directory:
                    cut_case = "-unlink-" in case
                    if case.startswith("remove-unlink-"):
                        checkpoint = "complete-quarantine"
                    elif case.startswith("dual-unlink-"):
                        checkpoint = "complete-restored-link"
                    elif case in {
                        "active-archive-ambiguity", "alternate-active-reference",
                        "quarantine-no-replace-concurrent", "same-b-retry",
                    }:
                        checkpoint = "prepared-active"
                    elif case in {
                        "quarantine-insertion-race",
                        "quarantine-no-replace-preexisting",
                    }:
                        checkpoint = "complete-pointer"
                    elif case in {
                        "quarantine-removal-race", "quarantine-replacement-race",
                        "quarantine-repopulation-public",
                    }:
                        checkpoint = "complete-quarantine"
                    else:
                        checkpoint = None

                    if checkpoint is None:
                        paths, boundary, config, realm_root = self._fresh_launcher_state(
                            directory
                        )
                        support = paths.runtime_support
                        fixture = None
                    else:
                        fixture = self._fresh_resolution_state(directory, checkpoint)
                        paths = fixture["paths"]
                        boundary = fixture["boundary"]
                        config = fixture["config"]
                        realm_root = fixture["realm_root"]
                        support = fixture["support"]
                    operation, expected_outer, executor = self._launcher_routes(
                        paths, boundary, config, realm_root
                    )[route]
                    patches = []
                    expected_gate = None
                    expectation = "reject-before-lifecycle-mutation"

                    if case == "active-archive-ambiguity":
                        fixture["archive_path"].write_bytes(
                            fixture["active_path"].read_bytes()
                        )
                        fixture["archive_path"].chmod(0o600)
                        expected_gate = "gate:resolve_aborted_predecessor"
                    elif case == "alternate-active-reference":
                        alternate = json.loads(fixture["active_path"].read_text())
                        alternate["handoff_id"] = "alternate"
                        alternate["reference_digest"] = digest({
                            key: value for key, value in alternate.items()
                            if key != "reference_digest"
                        })
                        fixture["active_path"].write_text(json.dumps(alternate))
                        fixture["active_path"].chmod(0o600)
                        expected_gate = "gate:resolve_aborted_predecessor"
                    elif case == "journal-removal-race":
                        journal = write_complete_journal(support)
                        original_owner = recovery_module._owner_json
                        removed = {"done": False}

                        def remove_after_read(path, label):
                            result = original_owner(path, label)
                            if path == journal and not removed["done"]:
                                journal.unlink()
                                removed["done"] = True
                            return result
                        patches.append(mock.patch.object(
                            recovery_module, "_owner_json", side_effect=remove_after_read
                        ))
                        expected_gate = "gate:_scan_resolutions"
                    elif case in {"quarantine-insertion-race", "quarantine-removal-race"}:
                        original_paths = recovery_module._quarantine_paths
                        calls = {"count": 0}

                        def changing_quarantines(root):
                            calls["count"] += 1
                            if calls["count"] == 3:
                                if case == "quarantine-insertion-race":
                                    candidate = root / ".orderly-handoff-request-clearing-raced.json"
                                    candidate.write_bytes(b"{}")
                                    candidate.chmod(0o600)
                                else:
                                    fixture["quarantine_path"].unlink()
                            return original_paths(root)
                        patches.append(mock.patch.object(
                            recovery_module, "_quarantine_paths",
                            side_effect=changing_quarantines,
                        ))
                        expected_gate = "gate:_scan_quarantines"
                    elif case == "quarantine-replacement-race":
                        quarantine = fixture["quarantine_path"]
                        original_owner = recovery_module._owner_json
                        replaced = {"done": False}

                        def replace_after_read(path, label):
                            result = original_owner(path, label)
                            if path == quarantine and not replaced["done"]:
                                replacement = support / ".replacement-quarantine.json"
                                replacement.write_bytes(result.raw)
                                replacement.chmod(0o600)
                                os.replace(replacement, quarantine)
                                replaced["done"] = True
                            return result
                        patches.append(mock.patch.object(
                            recovery_module, "_owner_json", side_effect=replace_after_read
                        ))
                        expected_gate = "gate:_scan_quarantines"
                    elif case == "quarantine-repopulation-public":
                        fixture["pointer_path"].write_bytes(b'{"alternate":"public"}')
                        fixture["pointer_path"].chmod(0o600)
                        expected_gate = "gate:_pointer_snapshot"
                    elif case == "quarantine-no-replace-preexisting":
                        fixture["quarantine_path"].write_bytes(b'{"alternate":"target"}')
                        fixture["quarantine_path"].chmod(0o600)
                        expected_gate = "gate:_recover_locked"
                    elif case == "quarantine-no-replace-concurrent":
                        original_rename = recovery_module._rename_pointer_to_quarantine

                        def insert_then_rename(pointer, quarantine):
                            quarantine.write_bytes(b'{"alternate":"target"}')
                            quarantine.chmod(0o600)
                            return original_rename(pointer, quarantine)
                        patches.append(mock.patch.object(
                            recovery_module, "_rename_pointer_to_quarantine",
                            side_effect=insert_then_rename,
                        ))
                        expected_gate = "gate:_clear_pointer"
                    elif case == "same-b-retry":
                        expectation = "same-b-first-and-second-replay"
                        expected_gate = "gate:_recover_locked"
                    elif cut_case:
                        expected_gate = "gate:_retire_exact_quarantine"

                    before = self._authority_evidence(support)
                    before_lifecycle = lifecycle(boundary)
                    events = []

                    def cut_sequence():
                        target = fixture["quarantine_path"]
                        exact = "-exact-" in case
                        before_cut = self._authority_evidence(support)
                        instrumented_rename = recovery_module._atomic_rename_noreplace
                        fired = {"done": False}
                        replacement_identity = {"device": None, "inode": None}

                        def material_present():
                            return any(
                                item["device"] == replacement_identity["device"]
                                and item["inode"] == replacement_identity["inode"]
                                for item in self._authority_evidence(support)
                            )

                        def cut_retirement(source, destination):
                            candidate = Path(source)
                            if candidate != target or fired["done"]:
                                return instrumented_rename(source, destination)
                            fired["done"] = True
                            selected = self._authority_evidence(support)
                            if not exact:
                                replacement = support / ".unlink-swap.json"
                                replacement.write_bytes(target.read_bytes())
                                replacement.chmod(0o600)
                                replacement_stat = replacement.lstat()
                                replacement_identity.update({
                                    "device": replacement_stat.st_dev,
                                    "inode": replacement_stat.st_ino,
                                })
                                os.replace(replacement, target)
                            append_event(
                                events, support, "injection:final-retirement", "cut",
                                selected_before=selected, exact=exact,
                                cut_position=(
                                    "after" if case.endswith("-after")
                                    or case.endswith("-delete") else "before"
                                ),
                                source=str(source), destination=str(destination),
                                replacement_identity=dict(replacement_identity),
                            )
                            if case.endswith("-before"):
                                raise OSError("v2.9 cut before final retirement")
                            result = instrumented_rename(source, destination)
                            raise OSError("v2.9 cut after final retirement")

                        with mock.patch.object(
                            recovery_module, "_atomic_rename_noreplace",
                            side_effect=cut_retirement,
                        ):
                            try:
                                operation()
                            except Exception as exc:
                                append_event(
                                    events, support, "cut-route", "exception",
                                    exception={
                                        "type": type(exc).__name__,
                                        "message": str(exc),
                                    },
                                )
                        cut_snapshot = self._authority_evidence(support)
                        append_event(
                            events, support, "cut-snapshot", "observed",
                            before_cut_digest=canonical_digest(before_cut),
                            cut_snapshot_digest=canonical_digest(cut_snapshot),
                        )
                        if not exact:
                            if not material_present():
                                raise AssertionError(
                                    "swapped final-retirement inode was destroyed"
                                )
                            first_failure = None
                            try:
                                recover_aborted_predecessor_resolution(support)
                            except Exception as exc:
                                first_failure = type(exc).__name__
                            append_event(
                                events, support, "first-replay", "observed",
                                failure_type=first_failure,
                            )
                            if not material_present():
                                raise AssertionError(
                                    "first replay destroyed swapped custody"
                                )
                            second_failure = None
                            try:
                                recover_aborted_predecessor_resolution(support)
                            except Exception as exc:
                                second_failure = type(exc).__name__
                            append_event(
                                events, support, "second-replay", "observed",
                                failure_type=second_failure,
                            )
                            if not material_present():
                                raise AssertionError(
                                    "second replay destroyed swapped custody"
                                )
                        else:
                            recover_aborted_predecessor_resolution(support)
                            append_event(events, support, "first-replay", "return")
                            recover_aborted_predecessor_resolution(support)
                            append_event(events, support, "second-replay", "return")

                    def same_b_sequence():
                        operation()
                        append_event(events, support, "same-b-first", "return")
                        recover_aborted_predecessor_resolution(support)
                        append_event(events, support, "same-b-second", "return")

                    executed_operation = (
                        cut_sequence if cut_case
                        else same_b_sequence if case == "same-b-retry"
                        else operation
                    )
                    with contextlib.ExitStack() as stack:
                        instrument(stack, events, support)
                        for patcher in patches:
                            stack.enter_context(patcher)
                        execution = self._run_route_supervised(
                            executed_operation, expected_outer, boundary, events,
                            timeout_seconds=30.0,
                        )
                    after = self._authority_evidence(support)
                    after_lifecycle = execution["lifecycle_after"]
                    events = execution["custody_operations"]
                    gate = first_gate(
                        events, "return" if case == "same-b-retry" else "exception"
                    )
                    failure = execution["failure"]
                    row_errors = []
                    if execution["timed_out"]:
                        row_errors.append("supervisor-timeout")
                    if execution["supervisor_exit_code"] != 0:
                        row_errors.append(
                            f"supervisor-exit:{execution['supervisor_exit_code']}"
                        )
                    if cut_case or case == "same-b-retry":
                        if failure is not None:
                            row_errors.append(
                                f"sequence-failure:{failure['type']}:{failure['message']}"
                            )
                    else:
                        if failure is None:
                            row_errors.append("unexpected-acceptance")
                        elif not failure["matches_expected_outer"]:
                            row_errors.append(f"wrong-outer:{failure['type']}")
                    if gate is None:
                        row_errors.append("missing-observed-inner-gate")
                    elif expected_gate and gate["operation"] != expected_gate:
                        row_errors.append(
                            f"wrong-inner:{gate['operation']}!={expected_gate}"
                        )
                    if row_class == "hostile" and not cut_case \
                            and before_lifecycle != after_lifecycle:
                        row_errors.append("lifecycle-mutated")
                    matrix_errors.extend(f"{row_id}:{error}" for error in row_errors)
                    row = {
                        "row_id": row_id,
                        "row_class": row_class,
                        "case": case,
                        "route": route,
                        "executor": executor,
                        "expectation": expectation,
                        "expected_inner_gate": expected_gate,
                        "observed_inner_gate": gate["operation"] if gate else None,
                        "observed_inner_exception": (
                            gate.get("exception") if gate else None
                        ),
                        "failure": failure,
                        "row_errors": row_errors,
                        "started_monotonic_ns": execution["started_monotonic_ns"],
                        "finished_monotonic_ns": execution["finished_monotonic_ns"],
                        "deadline_monotonic_ns": execution["deadline_monotonic_ns"],
                        "duration_ns": execution["duration_ns"],
                        "timed_out": execution["timed_out"],
                        "supervisor_exit_code": execution["supervisor_exit_code"],
                        "supervisor_signal": execution["supervisor_signal"],
                        "candidates_before": before,
                        "candidates_after": after,
                        "lifecycle_before": before_lifecycle,
                        "lifecycle_after": after_lifecycle,
                        "custody_operations": events,
                        "protected_state_digests": {
                            "pre": canonical_digest(before),
                            "cut": canonical_digest(events),
                            "post": canonical_digest(after),
                        },
                        "normative_bindings": normative_bindings,
                    }
                    row["row_evidence_digest"] = canonical_digest(row)
                    receipt_rows.append(row)

        source_inventory = {
            relative: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in repository_root.rglob("*.py")
            if (
                (relative := str(path.relative_to(repository_root))).startswith(
                    ("banodoco_local/", "runtime_protocol/", "tests/")
                )
            )
        }
        source_inventory_digest = canonical_digest(source_inventory)
        for row in receipt_rows:
            row["normative_bindings"] = normative_bindings
            row["source_inventory_digest"] = source_inventory_digest
            if "candidate_identity" in row:
                row["candidate_identity"] = {
                    **row["candidate_identity"],
                    "v29_normative_bindings": normative_bindings,
                    "v29_source_inventory_digest": source_inventory_digest,
                }
            row["row_evidence_digest"] = canonical_digest({
                key: value
                for key, value in row.items()
                if key != "row_evidence_digest"
            })

        all_expected = sorted(baseline_receipt["expected_row_ids"] + extension_expected)
        all_executed = sorted(row["row_id"] for row in receipt_rows)
        if all_executed != all_expected:
            matrix_errors.append("expected/executed row-set mismatch")
        if len(all_executed) != len(set(all_executed)):
            matrix_errors.append("duplicate row IDs")
        receipt = {
            "schema": "runtime.lifecycle-route-matrix-receipt/v2.9",
            "normative_bindings": normative_bindings,
            "source_inventory": source_inventory,
            "source_inventory_digest": source_inventory_digest,
            "v28_baseline_receipt_digest": baseline_receipt["receipt_digest"],
            "expected_row_ids": all_expected,
            "executed_row_ids": all_executed,
            "expected_row_count": len(all_expected),
            "executed_row_count": len(all_executed),
            "passed_row_count": sum(not row.get("row_errors") for row in receipt_rows),
            "failed_row_count": sum(bool(row.get("row_errors")) for row in receipt_rows),
            "skipped_row_count": 0,
            "matrix_digest": canonical_digest(all_expected),
            "matrix_complete": not matrix_errors,
            "matrix_errors": matrix_errors,
            "rows": sorted(receipt_rows, key=lambda row: row["row_id"]),
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        receipt_path = os.environ.get("X3_RUNTIME_V29_RECEIPT")
        if receipt_path:
            Path(receipt_path).write_text(
                json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True,
                ) + "\n",
                encoding="utf-8",
            )
        self.assertEqual(matrix_errors, [])

    def test_both_restart_modes_refuse_unresolved_handoff_before_owner_mutation(self):
        for preserve in (False, True):
            with self.subTest(preserve_worker=preserve):
                if not self.paths.discovery_path.exists():
                    self._configure(realm_id=f"realm-{preserve}")
                    bootstrap(self.paths, self.boundary, self.config)
                pointer = self.paths.runtime_support / "orderly-handoff-request.json"
                pointer.write_bytes(b"unresolved\n")
                discovery_before = self.paths.discovery_path.read_bytes()
                catalog_before = self.paths.catalog_path.read_bytes()
                restart_calls = self.boundary.restart_calls
                with self.assertRaisesRegex(BootstrapError, "unresolved orderly handoff"):
                    restart(
                        self.paths,
                        self.boundary,
                        self.config,
                        preserve_worker=preserve,
                    )
                self.assertEqual(pointer.read_bytes(), b"unresolved\n")
                self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
                self.assertEqual(self.paths.catalog_path.read_bytes(), catalog_before)
                self.assertEqual(self.boundary.restart_calls, restart_calls)
                pointer.unlink()

    def test_restart_reuses_selected_realm(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        result = restart(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "restarted")
        self.assertEqual(result.realm_id, first.realm_id)
        self.assertEqual(self.boundary.restart_calls, 1)

    def test_preserve_worker_restart_uses_one_owner_transition_without_stop(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        result = restart(
            self.paths,
            self.boundary,
            self.config,
            preserve_worker=True,
        )
        self.assertEqual(result.status, "restarted")
        self.assertEqual(result.realm_id, first.realm_id)
        self.assertEqual(self.boundary.restart_calls, 1)
        self.assertTrue(self.boundary.last_restart_kwargs["preserve_worker"])
        self.assertTrue(self.boundary.last_restart_kwargs["require_health"])

    def test_restart_and_down_share_unreconciled_attempt_refusal(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        timestamp = "2026-09-24T00:00:00Z"
        connection = sqlite3.connect(root / "realm.sqlite3")
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
            "VALUES ('p', 'configured-realm', 'p', 'P', '{}', ?, ?)",
            (timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) "
            "VALUES ('r', 'p', 'test', '{}', 'running', ?, ?)",
            (timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, created_at, updated_at) "
            "VALUES ('t', 'r', 'test', '{}', 'queued', ?, ?)",
            (timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
            "VALUES ('a', 't', 'l', 1, 'e', '2000-01-01T00:00:00Z', 0, 1)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(BootstrapError, "active or unreconciled"):
            restart(self.paths, self.boundary, self.config)
        with self.assertRaisesRegex(BootstrapError, "active or unreconciled"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_down_refuses_wrong_endpoint_instance_without_signal(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.endpoint_metadata = lambda **_kwargs: {
            "runtime_instance_id": "different-instance",
            "realm_id": "configured-realm",
            "status": "degraded",
        }
        with self.assertRaisesRegex(BootstrapError, "endpoint identity"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)
        self.assertTrue(self.paths.discovery_path.exists())

    def test_down_accepts_degraded_but_identity_matching_endpoint(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        original = self.boundary.endpoint_metadata()
        self.boundary.endpoint_metadata = lambda **_kwargs: {**original, "status": "degraded"}
        result = down(self.paths, self.boundary)
        self.assertEqual(result["status"], "stopped")
        self.assertFalse(self.paths.discovery_path.exists())

    def test_down_refuses_stopped_status_when_worker_cleanup_gate_exists(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)

        def uncertain_stop(**kwargs):
            self.boundary.alive.discard(kwargs["pid"])
            marker = self.paths.runtime_support / "orderly-handoff-cleanup-uncertain.json"
            marker.write_text(json.dumps({
                "version": 1,
                "state": "cleanup_uncertain",
                "reason": "ConflictError",
            }))

        self.boundary.stop_owner = uncertain_stop
        with self.assertRaisesRegex(BootstrapError, "uncertain local Worker graph cleanup"):
            down(self.paths, self.boundary)
        self.assertTrue(self.paths.discovery_path.exists())
        self.assertTrue(self.paths.instance_lock_path.exists())

    def test_down_refuses_wrong_discovery_root_without_signal(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        wrong = Path(self.temp.name) / "wrong-realm"
        wrong.mkdir()
        discovery = json.loads(self.paths.discovery_path.read_text())
        discovery["realm_root"] = str(wrong.resolve())
        self.paths.discovery_path.write_text(json.dumps(discovery))
        with self.assertRaisesRegex(BootstrapError, "discovery realm root"):
            down(self.paths, self.boundary)
        self.assertEqual(self.boundary.restart_calls, 0)

    def test_down_holds_bootstrap_mutex_through_stop_owner(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        observed = []

        def fenced_stop(**kwargs):
            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import fcntl,sys; f=open(sys.argv[1],'a+'); "
                    "\ntry: fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)"
                    "\nexcept BlockingIOError: raise SystemExit(7)"
                    "\nraise SystemExit(0)",
                    str(self.paths.bootstrap_lock_path),
                ],
                check=False,
            )
            observed.append(probe.returncode)
            self.boundary.alive.discard(kwargs["pid"])

        self.boundary.stop_owner = fenced_stop
        result = down(self.paths, self.boundary)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(observed, [7])

    def test_down_never_cleans_up_new_owner_published_during_stop(self):
        root = self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        replacement = {
            "pid": 49999,
            "endpoint": "http://127.0.0.1:49999",
            "runtime_instance_id": "replacement-instance",
            "process_birth_id": "replacement-birth",
            "active_realm": "configured-realm",
            "realm_root": str(root.resolve()),
        }

        def replace_owner(**kwargs):
            self.boundary.alive.discard(kwargs["pid"])
            self.paths.discovery_path.write_text(json.dumps(replacement))
            self.paths.instance_lock_path.write_text(json.dumps({
                **replacement, "realm_id": "configured-realm",
            }))

        self.boundary.stop_owner = replace_owner
        with self.assertRaisesRegex(BootstrapError, "changed during stop"):
            down(self.paths, self.boundary)
        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), replacement)
        self.assertEqual(
            json.loads(self.paths.instance_lock_path.read_text())["runtime_instance_id"],
            "replacement-instance",
        )

    def test_legacy_collision_refuses_parallel_empty_realm_with_exact_action(self):
        legacy = self.paths.home / ".astrid"
        legacy.mkdir(parents=True)
        with self.assertRaises(LegacyRootCollisionError) as caught:
            bootstrap(self.paths, self.boundary, self.config)
        self.assertIn("Legacy realm roots are unsupported", str(caught.exception))
        self.assertEqual(len(self.boundary.starts), 0)
        self.assertFalse(self.paths.catalog_path.exists())

    def test_incompatible_live_owner_fails_closed_without_mutation(self):
        self._configure(realm_id="realm")
        self.paths.runtime_support.mkdir(parents=True, exist_ok=True)
        self.paths.discovery_path.write_text(json.dumps({
            "protocol_version": "old", "schema_version": "old", "active_realm": "realm", "pid": 99,
        }))
        self.boundary.alive.add(99)
        before = self.paths.discovery_path.read_bytes()
        with self.assertRaises(CompatibilityError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.discovery_path.read_bytes(), before)
        self.assertEqual(len(self.boundary.starts), 0)

    def test_duplicate_owner_refuses_when_lock_validation_fails(self):
        self._configure()
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.valid_owner = False
        with self.assertRaises(DuplicateOwnerError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(len(self.boundary.starts), 1)

    def test_connect_is_side_effect_free_when_stopped(self):
        with self.assertRaisesRegex(Exception, "banodoco-local up --profile astrid"):
            connect(self.paths, self.boundary, self.config)
        self.assertFalse(self.paths.runtime_support.exists())

    def test_selected_missing_realm_never_uses_fresh_create(self):
        self.paths.ensure_support_dirs()
        self.paths.catalog_path.write_text(json.dumps({
            "version": 1,
            "selected_realm_id": "existing-realm",
            "realms": [{
                "realm_id": "existing-realm",
                "display_name": "Existing",
                "data_root": str((self.paths.realms_dir / "existing-realm").resolve()),
            }],
            "source_profiles": {},
        }))

        class ExistingBoundary(FakeBoundary):
            def start(self, **kwargs):
                self.calls.append("start")
                raise BootstrapError("existing realm is missing")

            def create(self, **kwargs):
                raise AssertionError("selected existing realm was provisioned")

        boundary = ExistingBoundary()
        with self.assertRaisesRegex(BootstrapError, "Realm-root identity is unavailable"):
            bootstrap(self.paths, boundary, self.config)
        self.assertEqual(boundary.calls, [])
        self.assertFalse(self.paths.realms_dir.joinpath("existing-realm").exists())

    def test_configured_realm_handoff_failure_preserves_explicit_selection(self):
        class FailingHandoffBoundary(FakeBoundary):
            def start(self, **kwargs):
                super().start(**kwargs)
                raise RuntimeError("admission handoff failed")

        boundary = FailingHandoffBoundary()
        self.boundary = boundary
        root = self._configure()
        with self.assertRaisesRegex(RuntimeError, "admission handoff failed"):
            bootstrap(self.paths, boundary, self.config)
        self.assertEqual(boundary.calls, ["start"])
        self.assertTrue(root.is_dir())
        self.assertTrue(self.paths.catalog_path.exists())
        self.assertFalse(self.paths.discovery_path.exists())
        self.assertFalse(self.paths.instance_lock_path.exists())

    def test_failed_candidate_rollback_preserves_incumbent_support_metadata(self):
        self.paths.ensure_support_dirs()
        incumbent = {
            "pid": 99,
            "runtime_instance_id": "incumbent",
            "active_realm": "realm-1",
        }
        self.paths.discovery_path.write_text(json.dumps(incumbent))
        self.paths.instance_lock_path.write_text(json.dumps(incumbent))

        class CandidateBoundary:
            class Process:
                pid = 123

            _process = Process()

            def stop(self):
                return None

        _rollback_failed_bootstrap(
            self.paths,
            CandidateBoundary(),
            realm_root=self.paths.realms_dir / "realm-1",
            new_realm=False,
            credential_before=None,
        )

        self.assertEqual(json.loads(self.paths.discovery_path.read_text()), incumbent)
        self.assertEqual(json.loads(self.paths.instance_lock_path.read_text()), incumbent)

    def test_doctor_is_side_effect_free(self):
        report = doctor(self.paths, self.boundary)
        self.assertFalse(report["healthy"])
        self.assertEqual(report["state"], "stopped")
        self.assertFalse(self.paths.runtime_support.exists())

    def test_source_manifest_is_validated_and_recorded(self):
        self.paths.source_profiles_dir.mkdir(parents=True)
        manifest = self.paths.source_profiles_dir / "astrid.json"
        manifest.write_text(json.dumps(PROFILE.as_dict()))
        profile = SourceProfile.load(manifest)
        self.assertEqual(profile.profile, "astrid")
        self.assertEqual(profile.digest, SourceProfile.from_mapping(PROFILE.as_dict()).digest)


if __name__ == "__main__":
    unittest.main()
