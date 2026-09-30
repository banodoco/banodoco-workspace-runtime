from __future__ import annotations

import sqlite3
import os
import json
import subprocess
import socket
import shutil
import tempfile
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

try:
    import fcntl
except ImportError:  # pragma: no cover - supported beta host is POSIX
    fcntl = None

from runtime_protocol.errors import ConflictError, RealmAdmissionError, RuntimeErrorBase
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence
from runtime_protocol.store import RealmStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.catalog import process_birth_identity
from runtime_protocol.cli import (
    _abort_failed_adopter_after_cleanup,
    _complete_adopter_publication,
    _owned_handoff_request,
    _resolve_aborted_predecessor,
)
from runtime_protocol.orderly_handoff import HandoffRecord, RECORD_VERSION, digest
from runtime_protocol.handoff_recovery import recover_aborted_predecessor_resolution
from banodoco_local.bootstrap import (
    _recover_aborted_predecessor_resolution as launcher_recover_predecessor,
)


def _final_ack_evidence():
    return {
        "request_digest": "sha256:" + "1" * 64,
        "worker_ack_digest": "sha256:" + "2" * 64,
        "host_ack_digest": "sha256:" + "3" * 64,
    }


def _final_ack_response():
    return {**_final_ack_evidence(), "ack": {"worker_phase": "finalized"}}


def _complete_cleanup_proof():
    expected = []
    rows = []
    for offset, role in enumerate(("worker", "host", "engine", "engine_listener"), 1):
        identity = {"pid": 400 + offset, "birth_id": f"birth-{role}"}
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
        "version": 1,
        "runtime_instance_id": "runtime-b",
        "receipt_evidence_digest": "sha256:" + "9" * 64,
        "expected_processes": expected,
        "graph_and_engine_listener_absent": True,
        "authority_descriptors_closed": True,
        "worker_credential_revoked": True,
        "catalog_neutral": True,
        "discovery_absent": True,
        "replacement_graph_not_launched": True,
        "final_census": census,
        "complete": True,
    }


def _write_adopted_record(path, support, *, handoff_id, pid, birth, instance):
    value = {
        "version": RECORD_VERSION, "state": "ADOPTED", "handoff_id": handoff_id,
        "realm_id": "realm-1", "realm_root": str(support.parent / "realm"),
        "support_root": str(support), "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int((time.time() + 30) * 1000),
        "nonce_digest": "sha256:" + "1" * 64,
        "sealed_record_digest": "sha256:" + "2" * 64,
        "old_owner": {"pid": 1, "birth_id": "birth-a"},
        "export": {"receipt_evidence_digest": "sha256:" + "3" * 64},
        "export_sealed_digest": "sha256:" + "4" * 64,
        "adopter": {"pid": pid, "birth_id": birth, "runtime_instance_id": instance},
        "predecessor_active_ref_digest": None, "owner_a_released": True,
        "new_owner": {"pid": pid, "birth_id": birth, "runtime_instance_id": instance},
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
    }
    value["record_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def _write_aborted_record(path, support, *, handoff_id, predecessor_digest):
    cleanup = _complete_cleanup_proof()
    sealed_receipt = {
        "version": "runtime.local-worker-receipt/v3",
        "evidence_digest": cleanup["receipt_evidence_digest"],
        "engine_binding": {
            "endpoint": "http://127.0.0.1:8188",
            "socket_owner_pid": cleanup["expected_processes"][-1]["identity"]["pid"],
        },
        **{
            row["role"]: row["identity"]
            for row in cleanup["expected_processes"]
        },
    }
    value = {
        "version": RECORD_VERSION, "state": "ABORTED", "handoff_id": handoff_id,
        "realm_id": "realm-1", "realm_root": str(support.parent / "realm"),
        "support_root": str(support), "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int((time.time() + 30) * 1000),
        "nonce_digest": "sha256:" + "1" * 64,
        "sealed_record_digest": "sha256:" + "2" * 64,
        "old_owner": {"pid": 1, "birth_id": "birth-b"},
        "export": {"receipt": sealed_receipt},
        "export_sealed_digest": "sha256:" + "4" * 64,
        "adopter": {"pid": 2, "birth_id": "birth-c", "runtime_instance_id": "runtime-c"},
        "predecessor_active_ref_digest": predecessor_digest,
        "abort_reason": "owner_c_start_failed",
        "cleanup_receipt": cleanup,
        "cleanup_receipt_digest": digest(cleanup),
    }
    value["record_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def _write_handoff_pointer(support, *, handoff_id, record_path, raw=None):
    pointer = support / "orderly-handoff-request.json"
    value = {
        "version": "runtime.local-worker-handoff-transfer/v1",
        "handoff_id": handoff_id,
        "record_path": str(record_path),
        "socket_path": str(support / "coordinator.sock"),
        "coordinator_pid": os.getpid(),
        "coordinator_birth_id": "coordinator-birth",
    }
    pointer.write_bytes(
        raw if raw is not None else json.dumps(value).encode("utf-8")
    )
    pointer.chmod(0o600)
    return pointer, value


def _write_committed_record(
    path, support, *, handoff_id, predecessor_digest, old_owner
):
    value = {
        "version": RECORD_VERSION,
        "state": "COMMITTED_ORPHAN",
        "handoff_id": handoff_id,
        "realm_id": "realm-1",
        "realm_root": str(support.parent / "realm"),
        "support_root": str(support),
        "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int((time.time() + 30) * 1000),
        "nonce_digest": "sha256:" + "1" * 64,
        "sealed_record_digest": "sha256:" + "2" * 64,
        "old_owner": old_owner,
        "export": {"receipt_evidence_digest": "sha256:" + "3" * 64},
        "export_sealed_digest": "sha256:" + "4" * 64,
        "adopter": None,
        "predecessor_active_ref_digest": predecessor_digest,
        "owner_a_released": True,
    }
    value["record_digest"] = digest(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return value


def _resolution_fixture(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    predecessor_path = support / "orderly-handoff-record-old.json"
    predecessor = _write_adopted_record(
        predecessor_path,
        support,
        handoff_id="old",
        pid=999999,
        birth="old-birth",
        instance="runtime-b",
    )
    active_value = {
        "version": 1,
        "state": "ADOPTED",
        "handoff_id": "old",
        "record_path": str(predecessor_path),
        "record_digest": predecessor["record_digest"],
        "pid": 999999,
        "birth_id": "old-birth",
        "runtime_instance_id": "runtime-b",
    }
    active_value["reference_digest"] = digest(active_value)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(active_value), encoding="utf-8")
    active.chmod(0o600)
    successor_path = support / "orderly-handoff-record-new.json"
    aborted = _write_aborted_record(
        successor_path,
        support,
        handoff_id="new",
        predecessor_digest=active_value["reference_digest"],
    )
    pointer, pointer_value = _write_handoff_pointer(
        support, handoff_id="new", record_path=successor_path
    )
    return {
        "root": root,
        "support": support,
        "active": active,
        "active_value": active_value,
        "successor": HandoffRecord(successor_path),
        "successor_path": successor_path,
        "aborted": aborted,
        "pointer": pointer,
        "pointer_value": pointer_value,
    }


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


def test_owned_handoff_accepts_stable_record_and_separate_owner_only_socket(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    rendezvous = Path(tempfile.mkdtemp(prefix="x3-rv-", dir="/tmp"))
    rendezvous.chmod(0o700)
    handoff_id = "handoff-1"
    record_path = support / f"orderly-handoff-record-{handoff_id}.json"
    record_path.write_text("{}", encoding="utf-8")
    record_path.chmod(0o600)
    socket_path = rendezvous / "coordinator.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    daemon = SimpleNamespace(
        instance_id="runtime-a",
        root=tmp_path / "realm",
        service=SimpleNamespace(realm={"id": "realm-1"}),
        runtime_identity=lambda: {"runtime_instance_id": "runtime-a"},
    )
    old_owner = {
        "pid": os.getpid(),
        "birth_id": process_birth_identity(),
        "runtime_instance_id": "runtime-a",
        "runtime": daemon.runtime_identity(),
    }
    record = {
        "version": "runtime.local-worker-handoff-record/v1",
        "state": "OWNED",
        "handoff_id": handoff_id,
        "realm_id": "realm-1",
        "realm_root": str(daemon.root),
        "support_root": str(support),
        "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int((time.time() + 30) * 1000),
        "nonce_digest": None,
        "sealed_record_digest": None,
        "old_owner": old_owner,
        "export": None,
        "export_sealed_digest": None,
        "adopter": None,
        "predecessor_active_ref_digest": None,
        "record_digest": "sha256:" + "0" * 64,
    }
    pointer = {
        "version": "runtime.local-worker-handoff-transfer/v1",
        "handoff_id": handoff_id,
        "record_path": str(record_path),
        "socket_path": str(socket_path),
        "coordinator_pid": os.getpid(),
        "coordinator_birth_id": process_birth_identity(),
    }
    try:
        observed_pointer, observed_record, observed_socket = _owned_handoff_request(
            pointer, record, daemon=daemon, support_root=support
        )
        assert observed_pointer == pointer
        assert observed_record == record
        assert observed_socket == socket_path
        wrong = {**pointer, "record_path": str(rendezvous / record_path.name)}
        with pytest.raises(RuntimeErrorBase, match="rendezvous paths"):
            _owned_handoff_request(wrong, record, daemon=daemon, support_root=support)
    finally:
        listener.close()
        shutil.rmtree(rendezvous)


def _realm(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root, realm_id="realm-lifecycle").close()
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
        "VALUES ('project', 'realm-lifecycle', 'project', 'Project', '{}', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) "
        "VALUES ('run', 'project', 'test', '{}', 'running', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO tasks(id, run_id, capability, spec_json, status, created_at, updated_at) "
        "VALUES ('task', 'run', 'test', '{}', 'queued', ?, ?)",
        (timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    return root


@pytest.mark.parametrize(
    "lease_expires_at, expected_expired",
    [
        ("2000-01-01T00:00:00Z", True),
        ("not-a-time", None),
    ],
)
def test_unsettled_attempt_blocks_even_when_expired_or_uncertain(
    tmp_path, lease_expires_at, expected_expired
):
    root = _realm(tmp_path)
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
        "VALUES ('attempt', 'task', 'lease', 1, 'executor', ?, 0, 1)",
        (lease_expires_at,),
    )
    connection.commit()
    connection.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["unreconciled_attempts"][0]["lease_expired"] is expected_expired
    with pytest.raises(ConflictError, match="active or unreconciled"):
        with interruption_fence(root):
            pass


@pytest.mark.parametrize("binding_status", ["claimed", "stale"])
def test_claimed_or_stale_execution_binding_blocks_interruption(tmp_path, binding_status):
    root = _realm(tmp_path)
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO execution_bindings("
        "binding_id, task_id, run_id, session_id, runtime_epoch, capability_id, "
        "target_kind, resolved_target_json, status, created_at, updated_at"
        ") VALUES ('binding', 'task', 'run', 'session', 1, 'test', 'local', '{}', ?, ?, ?)",
        (binding_status, timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["claimed_or_stale_bindings"][0]["status"] == binding_status


@pytest.mark.parametrize("task_status", ["running", "cancel_requested", "CANCEL_REQUESTED"])
def test_active_or_cancellation_requested_task_blocks_interruption(tmp_path, task_status):
    root = _realm(tmp_path)
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute("UPDATE tasks SET status=? WHERE id='task'", (task_status,))
    connection.commit()
    connection.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["active_tasks"] == [{"task_id": "task", "status": task_status}]
    with pytest.raises(ConflictError, match="active or unreconciled"):
        with interruption_fence(root):
            pass


def test_interruption_fence_serializes_with_admission_and_claim_writes(tmp_path):
    root = _realm(tmp_path)
    database = root / "realm.sqlite3"
    with interruption_fence(root, timeout_seconds=0.05) as report:
        assert report["safe"] is True
        contender = sqlite3.connect(database, timeout=0.01)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            contender.close()

    contender = sqlite3.connect(database, timeout=0.05)
    try:
        contender.execute("BEGIN IMMEDIATE")
        contender.rollback()
    finally:
        contender.close()


def test_interruption_observation_rejects_symlink_realm_alias(tmp_path):
    root = _realm(tmp_path)
    alias = tmp_path / "realm-alias"
    alias.symlink_to(root, target_is_directory=True)
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(RealmAdmissionError, match="symlink"):
        inspect_interruption_state(alias)
    assert (root / "realm.sqlite3").read_bytes() == before


def _handoff_publication_daemon(events, *, finalize_error=None):
    daemon = object.__new__(RuntimeDaemon)
    daemon.handoff_pending = True
    daemon.instance_id = "runtime-b"
    daemon.root = __import__("pathlib").Path("/realm")
    daemon.service = SimpleNamespace(
        realm={"id": "realm-1", "display_name": "Realm"},
        catalog_admission=lambda instance_id: (
            events.append(("admission", instance_id))
            or {"runtime_epoch": 2, "runtime_instance_id": instance_id}
        ),
    )

    def finalize(handoff_id):
        events.append(("finalize", handoff_id))
        if finalize_error:
            raise finalize_error
        return _final_ack_response()

    daemon.local_worker_launcher = SimpleNamespace(finalize_orderly_handoff=finalize)
    daemon._handoff_finalized_id = None
    daemon._handoff_final_ack = None
    daemon._handoff_ready_surface_id = None
    daemon._handoff_claim_arm = None
    daemon._handoff_claims_id = None
    catalog = {
        "version": 1,
        "realms": [],
        "selected_realm_id": "realm-1",
    }

    def register(**kwargs):
        events.append(("catalog", kwargs["readiness"]))
        catalog["realms"] = [{
            "realm_id": kwargs["realm_id"],
            "readiness": kwargs["readiness"],
            "runtime_instance_id": kwargs["runtime_instance_id"],
        }]

    daemon.catalog = SimpleNamespace(register=register, read=lambda: catalog)
    discovery = {}

    def publish(**kwargs):
        events.append(("discovery", kwargs["worker_pending"]))
        discovery.update({
            "runtime_instance_id": "runtime-b",
            "pid": os.getpid(),
            "process_birth_id": process_birth_identity(),
            "worker_credential_pending": kwargs["worker_pending"],
        })

    daemon._publish_discovery = publish
    daemon.discovery = SimpleNamespace(read=lambda: discovery)
    admission = ["handoff_pending"]

    def set_admission_mode(mode):
        events.append(("http", mode))
        admission[0] = mode

    daemon.httpd = SimpleNamespace(
        set_admission_mode=set_admission_mode,
        admission_snapshot=lambda: (admission[0], None, {}),
    )
    daemon.runtime_identity = lambda: {"runtime_instance_id": "runtime-b"}
    return daemon


def test_finalize_failure_never_publishes_ready_authority():
    events = []
    daemon = _handoff_publication_daemon(
        events, finalize_error=ConflictError("injected finalize failure")
    )
    with pytest.raises(ConflictError, match="injected finalize"):
        daemon.finalize_orderly_handoff("handoff-1")
    assert events == [("finalize", "handoff-1")]
    assert daemon.handoff_pending is True


def test_runtime_final_ack_retry_returns_exact_cached_evidence_without_worker_replay():
    events = []
    daemon = _handoff_publication_daemon(events)
    first = daemon.finalize_orderly_handoff("handoff-1")
    second = daemon.finalize_orderly_handoff("handoff-1")
    assert first == second == _final_ack_response()
    assert events == [("finalize", "handoff-1")]


def test_final_ack_and_ready_surfaces_precede_durable_adopted_claim_admission():
    events = []
    daemon = _handoff_publication_daemon(events)
    daemon.finalize_orderly_handoff("handoff-1")
    daemon.publish_orderly_handoff_surfaces("handoff-1")
    assert events == [
        ("finalize", "handoff-1"),
        ("admission", "runtime-b"),
        ("catalog", "ready"),
        ("discovery", False),
    ]
    assert daemon.handoff_pending is True
    assert daemon.httpd.admission_snapshot()[0] == "handoff_pending"
    owner = {
        "pid": os.getpid(),
        "birth_id": process_birth_identity(),
        "runtime_instance_id": "runtime-b",
    }
    finalizing = {
        "state": "FINALIZING",
        "handoff_id": "handoff-1",
        "record_digest": "sha256:" + "3" * 64,
        "adopter": owner,
        "new_owner": {**owner, "runtime": daemon.runtime_identity()},
        "finalization": {"final_ack": _final_ack_evidence(), "ready_surfaces": True},
    }
    daemon.arm_orderly_handoff_claims("handoff-1", finalizing)
    daemon.open_orderly_handoff_claims("handoff-1", {
        "state": "ADOPTED",
        "handoff_id": "handoff-1",
        "publication_predecessor_digest": finalizing["record_digest"],
        "adopter": owner,
        "new_owner": {**owner, "runtime": daemon.runtime_identity()},
        "finalization": {"final_ack": _final_ack_evidence(), "ready_surfaces": True},
    })
    assert events[-1] == ("http", "ready")
    assert daemon.handoff_pending is False


def test_ready_surfaces_or_adopted_record_alone_never_open_claim_admission():
    events = []
    daemon = _handoff_publication_daemon(events)
    daemon.finalize_orderly_handoff("handoff-1")
    daemon.publish_orderly_handoff_surfaces("handoff-1")
    before = list(events)
    owner = {
        "pid": os.getpid(),
        "birth_id": process_birth_identity(),
        "runtime_instance_id": "runtime-b",
    }
    finalizing = {
            "state": "FINALIZING",
            "handoff_id": "handoff-1",
            "record_digest": "sha256:" + "3" * 64,
            "adopter": owner,
            "new_owner": {**owner, "runtime": daemon.runtime_identity()},
            "finalization": {"final_ack": _final_ack_evidence(), "ready_surfaces": True},
    }
    daemon.arm_orderly_handoff_claims("handoff-1", finalizing)
    with pytest.raises(ConflictError, match="armed claim gate"):
        daemon.open_orderly_handoff_claims("handoff-1", {
            "state": "ADOPTED",
            "handoff_id": "handoff-1",
            "publication_predecessor_digest": "sha256:" + "f" * 64,
        })
    assert events == before
    assert daemon.httpd.admission_snapshot()[0] == "handoff_pending"


@pytest.mark.parametrize(
    "failure_stage,expected",
    [
        ("finalize", ["to_finalizing", "finalize"]),
        ("checkpoint_ack", ["to_finalizing", "finalize", "checkpoint_ack"]),
        ("surfaces", ["to_finalizing", "finalize", "checkpoint_ack", "surfaces"]),
        (
            "checkpoint_surfaces",
            ["to_finalizing", "finalize", "checkpoint_ack", "surfaces", "checkpoint_surfaces"],
        ),
        ("arm", ["to_finalizing", "finalize", "checkpoint_ack", "surfaces", "checkpoint_surfaces", "arm"]),
        (
            "adopted",
            ["to_finalizing", "finalize", "checkpoint_ack", "surfaces", "checkpoint_surfaces", "arm", "adopted"],
        ),
        (
            "gate",
            ["to_finalizing", "finalize", "checkpoint_ack", "surfaces", "checkpoint_surfaces", "arm", "adopted", "gate"],
        ),
    ],
)
def test_finalizing_fault_cuts_never_execute_a_later_publication_stage(
    failure_stage, expected
):
    events = []

    def event(stage):
        events.append(stage)
        if stage == failure_stage:
            raise ConflictError(f"injected {stage}")

    class Record:
        def read(self):
            return {"state": "COMMITTED_ORPHAN"}

        def transition(self, *, expected_state, new_state, **_kwargs):
            stage = "to_finalizing" if new_state == "FINALIZING" else "adopted"
            event(stage)
            if new_state == "FINALIZING":
                return {
                    "record_digest": "sha256:" + "1" * 64,
                    "finalization": {"final_ack": None, "ready_surfaces": False},
                }
            return {
                "state": "ADOPTED",
                "handoff_id": "handoff-1",
                "record_digest": "sha256:" + "4" * 64,
            }

        def checkpoint_finalizing(self, *, final_ack, ready_surfaces, **_kwargs):
            stage = "checkpoint_surfaces" if ready_surfaces else "checkpoint_ack"
            event(stage)
            return {
                "record_digest": "sha256:" + ("3" if ready_surfaces else "2") * 64,
                "finalization": {
                    "final_ack": final_ack,
                    "ready_surfaces": ready_surfaces,
                },
            }

    daemon = SimpleNamespace(
        instance_id="runtime-b",
        runtime_identity=lambda: {"runtime_instance_id": "runtime-b"},
        finalize_orderly_handoff=lambda _handoff_id: (
            event("finalize") or _final_ack_response()
        ),
        publish_orderly_handoff_surfaces=lambda _handoff_id: event("surfaces"),
        arm_orderly_handoff_claims=lambda _handoff_id, _record: event("arm"),
        open_orderly_handoff_claims=lambda _handoff_id, _record: event("gate"),
    )
    with pytest.raises(ConflictError, match="injected"):
        _complete_adopter_publication(
            daemon,
            Record(),
            {
                "handoff_id": "handoff-1",
                "sealed_record_digest": "sha256:" + "a" * 64,
                "adopter_record_digest": "sha256:" + "b" * 64,
                "deadline_monotonic": time.monotonic() + 2,
            },
            {"state": "resumed"},
        )
    assert events == expected


def test_finalizing_retries_an_exact_lost_final_ack_before_publication():
    events = []
    attempts = [0]

    class Record:
        def read(self):
            return {"state": "COMMITTED_ORPHAN"}

        def transition(self, *, new_state, **_kwargs):
            events.append(new_state)
            return {
                "record_digest": "sha256:" + ("1" if new_state == "FINALIZING" else "4") * 64,
                "state": new_state,
                "handoff_id": "handoff-1",
                "finalization": {"final_ack": None, "ready_surfaces": False},
            }

        def checkpoint_finalizing(self, *, ready_surfaces, **_kwargs):
            events.append("surface_checkpoint" if ready_surfaces else "ack_checkpoint")
            return {
                "record_digest": "sha256:" + ("3" if ready_surfaces else "2") * 64,
                "finalization": {
                    "final_ack": _final_ack_evidence(),
                    "ready_surfaces": ready_surfaces,
                },
            }

    def finalize(_handoff_id):
        attempts[0] += 1
        events.append("finalize")
        if attempts[0] == 1:
            raise TimeoutError("lost final ack")
        return _final_ack_response()

    daemon = SimpleNamespace(
        instance_id="runtime-b",
        runtime_identity=lambda: {"runtime_instance_id": "runtime-b"},
        finalize_orderly_handoff=finalize,
        publish_orderly_handoff_surfaces=lambda _handoff_id: events.append("surfaces"),
        arm_orderly_handoff_claims=lambda _handoff_id, _record: events.append("arm"),
        open_orderly_handoff_claims=lambda _handoff_id, _record: events.append("gate"),
    )
    _complete_adopter_publication(
        daemon,
        Record(),
        {
            "handoff_id": "handoff-1",
            "sealed_record_digest": "sha256:" + "a" * 64,
            "adopter_record_digest": "sha256:" + "b" * 64,
            "deadline_monotonic": time.monotonic() + 2,
        },
        {"state": "resumed"},
    )
    assert events == [
        "FINALIZING", "finalize", "finalize", "ack_checkpoint", "surfaces",
        "surface_checkpoint", "arm", "ADOPTED", "gate",
    ]


def test_same_bound_b_resumes_from_durable_final_ack_checkpoint():
    runtime_identity = {"runtime_instance_id": "runtime-b"}
    owner = {
        "pid": os.getpid(),
        "birth_id": process_birth_identity(),
        "runtime_instance_id": "runtime-b",
        "runtime": runtime_identity,
    }
    adopter = {key: owner[key] for key in ("pid", "birth_id", "runtime_instance_id")}
    result = {"state": "resumed"}

    class Record:
        current = {
            "state": "COMMITTED_ORPHAN",
            "handoff_id": "handoff-1",
            "sealed_record_digest": "sha256:" + "a" * 64,
            "adopter": adopter,
        }

        def read(self):
            return dict(self.current)

        def transition(self, *, new_state, updates=None, **_kwargs):
            self.current = {
                **self.current,
                **dict(updates or {}),
                "state": new_state,
                "record_digest": "sha256:" + ("1" if new_state == "FINALIZING" else "4") * 64,
            }
            return dict(self.current)

        def checkpoint_finalizing(self, *, ready_surfaces, **_kwargs):
            self.current = {
                **self.current,
                "record_digest": "sha256:" + ("3" if ready_surfaces else "2") * 64,
                "finalization": {
                    "final_ack": _final_ack_evidence(),
                    "ready_surfaces": ready_surfaces,
                },
            }
            return dict(self.current)

    record = Record()
    fail_surfaces = [True]
    events = []

    def surfaces(_handoff_id):
        events.append("surfaces")
        if fail_surfaces[0]:
            raise OSError("lost surface publication response")

    daemon = SimpleNamespace(
        instance_id="runtime-b",
        runtime_identity=lambda: runtime_identity,
        finalize_orderly_handoff=lambda _handoff_id: (
            events.append("finalize") or _final_ack_response()
        ),
        publish_orderly_handoff_surfaces=surfaces,
        arm_orderly_handoff_claims=lambda _handoff_id, _record: events.append("arm"),
        open_orderly_handoff_claims=lambda _handoff_id, _record: events.append("gate"),
    )
    frame = {
        "handoff_id": "handoff-1",
        "sealed_record_digest": "sha256:" + "a" * 64,
        "adopter_record_digest": "sha256:" + "b" * 64,
        "deadline_monotonic": time.monotonic() + 2,
    }
    with pytest.raises(OSError, match="lost surface"):
        _complete_adopter_publication(daemon, record, frame, result)
    assert record.current["state"] == "FINALIZING"
    assert record.current["finalization"] == {
        "final_ack": _final_ack_evidence(),
        "ready_surfaces": False,
    }
    fail_surfaces[0] = False
    _complete_adopter_publication(daemon, record, frame, result)
    assert events.count("finalize") == 1
    assert record.current["state"] == "ADOPTED"
    assert events[-2:] == ["arm", "gate"]


def test_failed_b_writes_aborted_only_after_verified_cleanup():
    events = []

    class Record:
        def read(self):
            return {
                "state": "FINALIZING",
                "record_digest": "sha256:" + "4" * 64,
            }

        def transition(self, **kwargs):
            events.append(("transition", kwargs))

    daemon = SimpleNamespace(
        stop=lambda: events.append(("cleanup", None)),
        last_handoff_cleanup_proof=_complete_cleanup_proof,
    )
    assert _abort_failed_adopter_after_cleanup(
        daemon,
        Record(),
        {
            "handoff_id": "handoff-1",
            "sealed_record_digest": "sha256:" + "a" * 64,
        },
    ) is None
    assert [item[0] for item in events] == ["cleanup", "transition"]
    assert events[1][1]["expected_state"] == "FINALIZING"
    assert events[1][1]["new_state"] == "ABORTED"
    updates = events[1][1]["updates"]
    assert updates["cleanup_receipt"] == _complete_cleanup_proof()
    assert updates["cleanup_receipt_digest"] == digest(_complete_cleanup_proof())


def test_failed_b_cleanup_uncertainty_preserves_custody_state_and_blocks_aborted():
    events = []

    def fail_cleanup():
        events.append("cleanup")
        raise ConflictError("local Worker graph cleanup is uncertain")

    record = SimpleNamespace(
        read=lambda: events.append("read") or {"state": "FINALIZING"},
        transition=lambda **_kwargs: events.append("transition"),
    )
    error = _abort_failed_adopter_after_cleanup(
        SimpleNamespace(stop=fail_cleanup),
        record,
        {
            "handoff_id": "handoff-1",
            "sealed_record_digest": "sha256:" + "a" * 64,
        },
    )
    assert isinstance(error, ConflictError)
    assert events == ["read", "cleanup"]


def test_post_adopted_gate_invariant_latches_operator_audit_and_retains_record(tmp_path):
    events = []
    record_path = tmp_path / "orderly-handoff-record.json"
    record_path.write_text("{}", encoding="utf-8")

    class Record:
        path = record_path

        def read(self):
            return {
                "state": "ADOPTED",
                "handoff_id": "handoff-1",
                "record_digest": "sha256:" + "4" * 64,
            }

        def transition(self, **_kwargs):
            events.append("transition")

    daemon = SimpleNamespace(
        latch_orderly_handoff_operator_audit=lambda **kwargs: events.append(
            ("audit", kwargs)
        ),
        stop=lambda: events.append(("cleanup", None)),
        last_handoff_cleanup_proof=_complete_cleanup_proof,
    )
    error = _abort_failed_adopter_after_cleanup(
        daemon,
        Record(),
        {
            "handoff_id": "handoff-1",
            "sealed_record_digest": "sha256:" + "a" * 64,
        },
    )
    assert isinstance(error, RuntimeErrorBase)
    assert [item[0] if isinstance(item, tuple) else item for item in events] == [
        "audit", "cleanup",
    ]
    assert record_path.exists()


def test_actual_post_adopted_exception_cleanup_retains_terminal_gate_across_process(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=support).start()
    record_path = support / "orderly-handoff-record-adopted.json"
    record_path.write_text("{}", encoding="utf-8")
    record_path.chmod(0o600)

    class Record:
        path = record_path

        def read(self):
            return {
                "state": "ADOPTED",
                "handoff_id": "handoff-adopted",
                "record_digest": "sha256:" + "4" * 64,
            }

    error = _abort_failed_adopter_after_cleanup(
        daemon,
        Record(),
        {
            "handoff_id": "handoff-adopted",
            "sealed_record_digest": "sha256:" + "a" * 64,
        },
    )
    assert isinstance(error, RuntimeErrorBase)
    marker = support / "orderly-handoff-cleanup-uncertain.json"
    assert marker.exists()
    assert record_path.exists()
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from runtime_protocol.daemon import RuntimeDaemon; "
                "from runtime_protocol.errors import ConflictError; "
                "root,support=map(Path,sys.argv[1:]); "
                "\ntry: RuntimeDaemon(root,support_root=support).start()"
                "\nexcept ConflictError: raise SystemExit(23)"
                "\nraise SystemExit(24)"
            ),
            str(root),
            str(support),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 23, completed.stderr
    assert record_path.exists()


def test_direct_runtime_start_latches_dead_active_owner_before_discovery_mutation(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    record_path = support / "orderly-handoff-record-old.json"
    record = _write_adopted_record(
        record_path, support, handoff_id="old", pid=999999,
        birth="dead-birth", instance="runtime-b",
    )
    reference = {
        "version": 1, "state": "ADOPTED", "handoff_id": "old",
        "record_path": str(record_path), "record_digest": record["record_digest"],
        "pid": 999999, "birth_id": "dead-birth",
        "runtime_instance_id": "runtime-b",
    }
    reference["reference_digest"] = digest(reference)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(reference), encoding="utf-8")
    active.chmod(0o600)
    with pytest.raises(ConflictError, match="adopted Runtime owner was lost"):
        RuntimeDaemon(root, support_root=support).start()
    marker = json.loads(
        (support / "orderly-handoff-cleanup-uncertain.json").read_text()
    )
    assert marker["active_reference_digest"] == reference["reference_digest"]
    assert not (support / "discovery.json").exists()


def test_direct_runtime_handoff_start_requires_exact_predecessor_chain(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    record_path = support / "orderly-handoff-record-old.json"
    birth = process_birth_identity()
    record = _write_adopted_record(
        record_path, support, handoff_id="old", pid=os.getpid(),
        birth=birth, instance="runtime-b",
    )
    reference = {
        "version": 1, "state": "ADOPTED", "handoff_id": "old",
        "record_path": str(record_path), "record_digest": record["record_digest"],
        "pid": os.getpid(), "birth_id": birth,
        "runtime_instance_id": "runtime-b",
    }
    reference["reference_digest"] = digest(reference)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(reference), encoding="utf-8")
    active.chmod(0o600)
    left, right = socket.socketpair()
    try:
        daemon = RuntimeDaemon(
            root, support_root=support, inherited_listener_fd=left.fileno(),
            handoff_predecessor_active_ref_digest=reference["reference_digest"],
            handoff_predecessor_old_owner={"pid": os.getpid(), "birth_id": birth},
        )
        daemon._assert_active_adoption_start_allowed()
        wrong = RuntimeDaemon(
            root, support_root=support, inherited_listener_fd=left.fileno(),
            handoff_predecessor_active_ref_digest="sha256:" + "0" * 64,
            handoff_predecessor_old_owner={"pid": os.getpid(), "birth_id": birth},
        )
        with pytest.raises(ConflictError, match="predecessor owner binding"):
            wrong._assert_active_adoption_start_allowed()
    finally:
        left.close()
        right.close()


@pytest.mark.skipif(fcntl is None, reason="POSIX owner-lock regression")
def test_authenticated_adopter_start_does_not_reacquire_held_recovery_locks(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    birth = process_birth_identity()
    predecessor_path = support / "orderly-handoff-record-old.json"
    predecessor = _write_adopted_record(
        predecessor_path,
        support,
        handoff_id="old",
        pid=os.getpid(),
        birth=birth,
        instance="runtime-b",
    )
    reference = {
        "version": 1,
        "state": "ADOPTED",
        "handoff_id": "old",
        "record_path": str(predecessor_path),
        "record_digest": predecessor["record_digest"],
        "pid": os.getpid(),
        "birth_id": birth,
        "runtime_instance_id": "runtime-b",
    }
    reference["reference_digest"] = digest(reference)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(reference), encoding="utf-8")
    active.chmod(0o600)
    handoff_id = "new"
    record_path = support / f"orderly-handoff-record-{handoff_id}.json"
    committed = _write_committed_record(
        record_path,
        support,
        handoff_id=handoff_id,
        predecessor_digest=reference["reference_digest"],
        old_owner={"pid": os.getpid(), "birth_id": birth},
    )
    _write_handoff_pointer(
        support, handoff_id=handoff_id, record_path=record_path
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    lock_descriptors = []
    extra_descriptors = []
    extra_sockets = []
    try:
        for name in ("bootstrap.lock", "orderly-handoff-coordinator.lock"):
            descriptor = os.open(support / name, os.O_RDWR | os.O_CREAT, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            lock_descriptors.append(descriptor)
        script = """
import json, os, sys
from pathlib import Path
from runtime_protocol.daemon import RuntimeDaemon
root, support = map(Path, sys.argv[1:3])
config = json.loads(sys.argv[3])
record_path = config.get("record_path")
if record_path is not None and config.get("record_path_is_path", True):
    record_path = Path(record_path)
listener_fd = config.get("fd_override", int(sys.argv[4]))
expected_listener = config.get("expected_listener")
if expected_listener is not None and config.get("listener_as_tuple", True):
    expected_listener = tuple(expected_listener)
daemon = RuntimeDaemon(
    root, support_root=support, inherited_listener_fd=listener_fd,
    handoff_predecessor_active_ref_digest=config.get("predecessor"),
    handoff_predecessor_old_owner=config.get("old_owner"),
    handoff_id=config.get("handoff_id"),
    handoff_record_path=record_path,
    handoff_record_path_raw=config.get("record_path_raw"),
    handoff_record_digest=config.get("record_digest"),
    handoff_expected_listener=expected_listener,
).start()
try:
    assert daemon.handoff_pending
finally:
    daemon.stop()
"""
        exact = {
            "handoff_id": handoff_id,
            "record_path": str(record_path),
            "record_path_raw": str(record_path),
            "record_digest": committed["record_digest"],
            "predecessor": reference["reference_digest"],
            "old_owner": {"pid": os.getpid(), "birth_id": birth},
            "expected_listener": list(listener.getsockname()),
        }
        pipe_read, pipe_write = os.pipe()
        extra_descriptors.extend((pipe_read, pipe_write))
        regular_fd = os.open(tmp_path / "not-a-listener", os.O_RDWR | os.O_CREAT, 0o600)
        extra_descriptors.append(regular_fd)
        dormant = socket.socket()
        dormant.bind(("127.0.0.1", 0))
        wrong_listener = socket.socket()
        wrong_listener.bind(("127.0.0.1", 0))
        wrong_listener.listen()
        connected_left, connected_right = socket.socketpair()
        extra_sockets.extend((dormant, wrong_listener, connected_left, connected_right))
        cases = []
        for key in exact:
            missing = dict(exact)
            missing[key] = None
            cases.append((f"missing-{key}", missing))
        cases.extend([
            ("missing-old-owner-pid", {**exact, "old_owner": {"birth_id": birth}}),
            ("missing-old-owner-birth", {**exact, "old_owner": {"pid": os.getpid()}}),
            ("wrong-id", {**exact, "handoff_id": "other"}),
            ("wrong-path", {**exact, "record_path": str(support / "other.json")}),
            ("wrong-record-digest", {**exact, "record_digest": "sha256:" + "0" * 64}),
            ("wrong-predecessor", {**exact, "predecessor": "sha256:" + "0" * 64}),
            ("wrong-owner-pid", {**exact, "old_owner": {"pid": os.getpid() + 1, "birth_id": birth}}),
            ("wrong-owner-birth", {**exact, "old_owner": {"pid": os.getpid(), "birth_id": "wrong"}}),
            ("empty-id", {**exact, "handoff_id": ""}),
            ("empty-digest", {**exact, "record_digest": ""}),
            ("whitespace-id", {**exact, "handoff_id": "   "}),
            ("whitespace-birth", {**exact, "old_owner": {"pid": os.getpid(), "birth_id": "  "}}),
            ("malformed-record-digest", {**exact, "record_digest": "sha256:nothex"}),
            ("malformed-predecessor", {**exact, "predecessor": "sha256:nothex"}),
            ("noncanonical-path", {**exact, "record_path": str(support / "nested" / ".." / record_path.name)}),
            ("string-path", {**exact, "record_path_is_path": False}),
            ("redundant-separator-path", {**exact, "record_path_raw": str(support) + "//" + record_path.name}),
            ("dot-component-path", {**exact, "record_path_raw": str(support) + "/./" + record_path.name}),
            ("trailing-separator-path", {**exact, "record_path_raw": str(record_path) + "/"}),
            ("bool-fd", {**exact, "fd_override": True}),
            ("string-fd", {**exact, "fd_override": "7"}),
            ("small-fd", {**exact, "fd_override": 2}),
            ("wrong-id-type", {**exact, "handoff_id": 7}),
            ("wrong-record-digest-type", {**exact, "record_digest": ["bad"]}),
            ("wrong-predecessor-type", {**exact, "predecessor": {"bad": True}}),
            ("wrong-owner-type", {**exact, "old_owner": [os.getpid(), birth]}),
            ("bool-owner-pid", {**exact, "old_owner": {"pid": True, "birth_id": birth}}),
            ("wrong-listener-endpoint", {**exact, "expected_listener": ["127.0.0.1", listener.getsockname()[1] + 1]}),
            ("wrong-listener-type", {**exact, "listener_as_tuple": False}),
            ("closed-listener-fd", {**exact, "fd_override": 999999}),
            ("regular-file-fd", {**exact, "fd_override": regular_fd}),
            ("pipe-fd", {**exact, "fd_override": pipe_read}),
            ("non-listening-socket", {**exact, "fd_override": dormant.fileno()}),
            ("connected-socket", {**exact, "fd_override": connected_left.fileno()}),
            ("wrong-listening-socket", {**exact, "fd_override": wrong_listener.fileno()}),
            ("multi-partial", {**exact, "handoff_id": None, "record_digest": None}),
        ])
        protected = {
            path.name: (path.lstat().st_ino, path.read_bytes())
            for path in support.iterdir()
            if path.is_file() and path.name not in {
                "bootstrap.lock", "orderly-handoff-coordinator.lock"
            }
        }
        for case_id, config in cases:
            rejected = subprocess.run(
                [
                    sys.executable, "-c", script, str(root), str(support),
                    json.dumps(config), str(listener.fileno()),
                ],
                cwd=Path(__file__).parents[1],
                pass_fds=(
                    listener.fileno(), *extra_descriptors,
                    *(item.fileno() for item in extra_sockets),
                ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert rejected.returncode != 0, case_id
            assert not (support / "discovery.json").exists(), case_id
            after = {
                path.name: (path.lstat().st_ino, path.read_bytes())
                for path in support.iterdir()
                if path.is_file() and path.name not in {
                    "bootstrap.lock", "orderly-handoff-coordinator.lock"
                }
            }
            assert after == protected, case_id
        accepted = subprocess.run(
            [
                sys.executable, "-c", script, str(root), str(support),
                json.dumps(exact), str(listener.fileno()),
            ],
            cwd=Path(__file__).parents[1],
            pass_fds=(listener.fileno(),),
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert accepted.returncode == 0, accepted.stderr
    finally:
        listener.close()
        for item in extra_sockets:
            item.close()
        for descriptor in extra_descriptors:
            os.close(descriptor)
        for descriptor in reversed(lock_descriptors):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def test_cleanup_complete_successor_abort_archives_and_clears_predecessor_idempotently(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    predecessor_path = support / "orderly-handoff-record-old.json"
    predecessor = _write_adopted_record(
        predecessor_path, support, handoff_id="old", pid=999999,
        birth="old-birth", instance="runtime-b",
    )
    active_value = {
        "version": 1, "state": "ADOPTED", "handoff_id": "old",
        "record_path": str(predecessor_path),
        "record_digest": predecessor["record_digest"], "pid": 999999,
        "birth_id": "old-birth", "runtime_instance_id": "runtime-b",
    }
    active_value["reference_digest"] = digest(active_value)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(active_value), encoding="utf-8")
    active.chmod(0o600)
    successor_path = support / "orderly-handoff-record-new.json"
    aborted = _write_aborted_record(
        successor_path, support, handoff_id="new",
        predecessor_digest=active_value["reference_digest"],
    )
    successor = HandoffRecord(successor_path)
    pointer, _ = _write_handoff_pointer(
        support, handoff_id="new", record_path=successor_path
    )
    _resolve_aborted_predecessor(support, handoff_record=successor, aborted=aborted)
    assert not active.exists()
    archived = support / "orderly-handoff-predecessor-active-new.json"
    assert archived.read_bytes() == json.dumps(active_value).encode("utf-8")
    resolution = support / "orderly-handoff-predecessor-resolution-new.json"
    value = json.loads(resolution.read_text())
    assert value["predecessor_record_digest"] == predecessor["record_digest"]
    assert predecessor_path.exists()
    assert successor_path.exists()
    assert not pointer.exists()
    _resolve_aborted_predecessor(support, handoff_record=successor, aborted=aborted)


@pytest.mark.parametrize("cut,replacement", [
    ("after_prepared", False),
    ("after_archive", False),
    ("after_archive", True),
])
def test_predecessor_resolution_crash_replay_never_clears_alternate_reference(
    tmp_path, monkeypatch, cut, replacement
):
    import runtime_protocol.handoff_recovery as recovery_module

    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    predecessor_path = support / "orderly-handoff-record-old.json"
    predecessor = _write_adopted_record(
        predecessor_path, support, handoff_id="old", pid=999999,
        birth="old-birth", instance="runtime-b",
    )
    active_value = {
        "version": 1, "state": "ADOPTED", "handoff_id": "old",
        "record_path": str(predecessor_path),
        "record_digest": predecessor["record_digest"], "pid": 999999,
        "birth_id": "old-birth", "runtime_instance_id": "runtime-b",
    }
    active_value["reference_digest"] = digest(active_value)
    active = support / "orderly-handoff-adopted-owner.json"
    active.write_text(json.dumps(active_value), encoding="utf-8")
    active.chmod(0o600)
    successor_path = support / "orderly-handoff-record-new.json"
    aborted = _write_aborted_record(
        successor_path, support, handoff_id="new",
        predecessor_digest=active_value["reference_digest"],
    )
    successor = HandoffRecord(successor_path)
    pointer, _ = _write_handoff_pointer(
        support, handoff_id="new", record_path=successor_path
    )
    real_atomic = recovery_module.atomic_json_write

    def cut_write(path, value):
        if path.name.startswith("orderly-handoff-predecessor-resolution-"):
            if cut == "after_prepared" and value.get("state") == "PREPARED":
                real_atomic(path, value)
                raise OSError("crash after prepared")
            if cut == "after_archive" and value.get("state") == "COMPLETE":
                raise OSError("crash after archive")
        return real_atomic(path, value)

    monkeypatch.setattr(recovery_module, "atomic_json_write", cut_write)
    with pytest.raises(OSError, match="crash after"):
        _resolve_aborted_predecessor(
            support, handoff_record=successor, aborted=aborted
        )
    monkeypatch.setattr(recovery_module, "atomic_json_write", real_atomic)
    if replacement:
        alternate = {
            **active_value,
            "pid": 888888,
            "birth_id": "alternate-birth",
            "runtime_instance_id": "runtime-alternate",
        }
        alternate["reference_digest"] = digest({
            key: item for key, item in alternate.items()
            if key != "reference_digest"
        })
        active.write_text(json.dumps(alternate), encoding="utf-8")
        active.chmod(0o600)
        before = active.read_bytes()
        with pytest.raises(RuntimeErrorBase, match="changed|custody"):
            _resolve_aborted_predecessor(
                support, handoff_record=successor, aborted=aborted
            )
        assert active.read_bytes() == before
    else:
        _resolve_aborted_predecessor(
            support, handoff_record=successor, aborted=aborted
        )
        assert not active.exists()
        assert not pointer.exists()
        resolution = json.loads((
            support / "orderly-handoff-predecessor-resolution-new.json"
        ).read_text())
        assert resolution["state"] == "COMPLETE"
        _resolve_aborted_predecessor(
            support, handoff_record=successor, aborted=aborted
        )


@pytest.mark.parametrize("cut", ["prepared", "archived"])
def test_direct_runtime_start_replays_predecessor_resolution_before_launch(
    tmp_path, monkeypatch, cut
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_atomic = recovery_module.atomic_json_write

    def cut_write(path, value):
        if path.name.startswith("orderly-handoff-predecessor-resolution-"):
            if cut == "prepared" and value.get("state") == "PREPARED":
                real_atomic(path, value)
                raise OSError("cut after prepared")
            if cut == "archived" and value.get("state") == "COMPLETE":
                raise OSError("cut after archive")
        return real_atomic(path, value)

    monkeypatch.setattr(recovery_module, "atomic_json_write", cut_write)
    with pytest.raises(OSError, match="cut after"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "atomic_json_write", real_atomic)

    daemon = RuntimeDaemon(
        fixture["root"], support_root=fixture["support"]
    ).start()
    try:
        assert not fixture["pointer"].exists()
        assert not fixture["active"].exists()
        resolution = json.loads(
            (
                fixture["support"]
                / "orderly-handoff-predecessor-resolution-new.json"
            ).read_text()
        )
        assert resolution["state"] == "COMPLETE"
        assert (fixture["support"] / "discovery.json").exists()
    finally:
        daemon.stop()


def test_direct_runtime_start_rejects_malformed_journal_before_support_mutation(
    tmp_path
):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    journal = support / "orderly-handoff-predecessor-resolution-bad.json"
    journal.write_bytes(b"{malformed")
    journal.chmod(0o600)
    before = {
        path.name: (
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
        )
        for path in support.iterdir()
    }
    with pytest.raises(ConflictError, match="pending audit"):
        RuntimeDaemon(root, support_root=support).start()
    after = {
        path.name: (
            path.lstat().st_dev,
            path.lstat().st_ino,
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
        )
        for path in support.iterdir()
    }
    assert after == before
    assert not (support / "discovery.json").exists()
    assert not (support / "bootstrap.lock").exists()
    assert not (support / "orderly-handoff-coordinator.lock").exists()


def test_direct_runtime_start_rejects_alternate_reference_without_mutation(
    tmp_path, monkeypatch
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_atomic = recovery_module.atomic_json_write

    def cut_write(path, value):
        if (
            path.name.startswith("orderly-handoff-predecessor-resolution-")
            and value.get("state") == "PREPARED"
        ):
            real_atomic(path, value)
            raise OSError("cut after prepared")
        return real_atomic(path, value)

    monkeypatch.setattr(recovery_module, "atomic_json_write", cut_write)
    with pytest.raises(OSError, match="cut after prepared"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "atomic_json_write", real_atomic)
    alternate = {
        **fixture["active_value"],
        "pid": 888888,
        "birth_id": "alternate-birth",
        "runtime_instance_id": "runtime-alternate",
    }
    alternate["reference_digest"] = digest(
        {key: item for key, item in alternate.items() if key != "reference_digest"}
    )
    fixture["active"].write_text(json.dumps(alternate), encoding="utf-8")
    fixture["active"].chmod(0o600)
    active_before = fixture["active"].read_bytes()
    pointer_before = fixture["pointer"].read_bytes()
    journal = (
        fixture["support"] / "orderly-handoff-predecessor-resolution-new.json"
    )
    journal_before = journal.read_bytes()
    with pytest.raises(ConflictError, match="pending audit"):
        RuntimeDaemon(
            fixture["root"], support_root=fixture["support"]
        ).start()
    assert fixture["active"].read_bytes() == active_before
    assert fixture["pointer"].read_bytes() == pointer_before
    assert journal.read_bytes() == journal_before
    assert not (fixture["support"] / "discovery.json").exists()


@pytest.mark.parametrize("replacement", ["semantic-bytes", "same-bytes-new-inode"])
def test_completed_resolution_pointer_clear_is_exact_byte_and_inode_cas(
    tmp_path, monkeypatch, replacement
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_clear = recovery_module._clear_pointer

    def cut_clear(*_args, **_kwargs):
        raise OSError("cut before pointer clear")

    monkeypatch.setattr(recovery_module, "_clear_pointer", cut_clear)
    with pytest.raises(OSError, match="cut before pointer clear"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    original_raw = fixture["pointer"].read_bytes()
    if replacement == "semantic-bytes":
        semantically_equal = json.dumps(
            fixture["pointer_value"], sort_keys=True, indent=2
        ).encode("utf-8") + b"\n"
        assert json.loads(semantically_equal) == json.loads(original_raw)
        assert semantically_equal != original_raw
        original_inode = fixture["pointer"].lstat().st_ino
        fixture["pointer"].write_bytes(semantically_equal)
        fixture["pointer"].chmod(0o600)
        assert fixture["pointer"].lstat().st_ino == original_inode
    else:
        replacement_path = fixture["support"] / "replacement-pointer.json"
        replacement_path.write_bytes(original_raw)
        replacement_path.chmod(0o600)
        original_inode = fixture["pointer"].lstat().st_ino
        os.replace(replacement_path, fixture["pointer"])
        assert fixture["pointer"].lstat().st_ino != original_inode
    pointer_before = fixture["pointer"].read_bytes()
    pointer_identity = (
        fixture["pointer"].lstat().st_dev,
        fixture["pointer"].lstat().st_ino,
    )
    archive = (
        fixture["support"] / "orderly-handoff-predecessor-active-new.json"
    )
    journal = (
        fixture["support"] / "orderly-handoff-predecessor-resolution-new.json"
    )
    archive_before = archive.read_bytes()
    journal_before = journal.read_bytes()
    with pytest.raises(ConflictError, match="pointer changed"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    assert fixture["pointer"].read_bytes() == pointer_before
    assert (
        fixture["pointer"].lstat().st_dev,
        fixture["pointer"].lstat().st_ino,
    ) == pointer_identity
    assert archive.read_bytes() == archive_before
    assert journal.read_bytes() == journal_before


def test_exact_pointer_clear_fsyncs_parent_and_replay_is_idempotent(
    tmp_path, monkeypatch
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_fsync = recovery_module.os.fsync
    fsynced_directories = []

    def observed_fsync(descriptor):
        observed = os.fstat(descriptor)
        if (
            observed.st_dev == fixture["support"].stat().st_dev
            and observed.st_ino == fixture["support"].stat().st_ino
        ):
            fsynced_directories.append((observed.st_dev, observed.st_ino))
        return real_fsync(descriptor)

    monkeypatch.setattr(recovery_module.os, "fsync", observed_fsync)
    completed = _resolve_aborted_predecessor(
        fixture["support"],
        handoff_record=fixture["successor"],
        aborted=fixture["aborted"],
    )
    assert completed["state"] == "COMPLETE"
    assert not fixture["pointer"].exists()
    assert fsynced_directories
    assert _resolve_aborted_predecessor(
        fixture["support"],
        handoff_record=fixture["successor"],
        aborted=fixture["aborted"],
    ) == completed


def test_pointer_swap_at_quarantine_boundary_preserves_replacement(tmp_path, monkeypatch):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_rename = recovery_module._rename_pointer_to_quarantine
    original_raw = fixture["pointer"].read_bytes()
    original_inode = fixture["pointer"].lstat().st_ino
    replacement = fixture["support"] / "replacement-pointer.json"
    replacement.write_bytes(original_raw)
    replacement.chmod(0o600)
    replacement_inode = replacement.lstat().st_ino

    def swap_then_rename(pointer_path, quarantine_path):
        os.replace(replacement, pointer_path)
        real_rename(pointer_path, quarantine_path)

    monkeypatch.setattr(
        recovery_module, "_rename_pointer_to_quarantine", swap_then_rename
    )
    with pytest.raises(ConflictError, match="quarantined.*custody"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    assert fixture["pointer"].read_bytes() == original_raw
    assert fixture["pointer"].lstat().st_ino == replacement_inode
    assert fixture["pointer"].lstat().st_ino != original_inode
    assert not list(fixture["support"].glob(".orderly-handoff-request-clearing-*"))


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize("replacement", [False, True])
def test_complete_resolution_replays_crash_after_quarantine_move(
    tmp_path, monkeypatch, entrypoint, replacement
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    original_raw = fixture["pointer"].read_bytes()
    original_inode = fixture["pointer"].lstat().st_ino
    real_rename = recovery_module._rename_pointer_to_quarantine
    if replacement:
        alternate = fixture["support"] / "alternate-pointer.json"
        alternate.write_bytes(original_raw)
        alternate.chmod(0o600)
        alternate_inode = alternate.lstat().st_ino
        def swap_then_move(pointer_path, quarantine_path):
            os.replace(alternate, pointer_path)
            real_rename(pointer_path, quarantine_path)

        monkeypatch.setattr(
            recovery_module, "_rename_pointer_to_quarantine", swap_then_move
        )
    real_remove = recovery_module._remove_exact_quarantine
    monkeypatch.setattr(
        recovery_module,
        "_remove_exact_quarantine",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("crash after quarantine move")
        ),
    )
    with pytest.raises(OSError, match="crash after quarantine move"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(
        recovery_module, "_rename_pointer_to_quarantine", real_rename
    )
    monkeypatch.setattr(recovery_module, "_remove_exact_quarantine", real_remove)
    assert not fixture["pointer"].exists()
    quarantines = list(
        fixture["support"].glob(".orderly-handoff-request-clearing-*.json")
    )
    assert len(quarantines) == 1

    if replacement:
        with pytest.raises(Exception):
            if entrypoint == "launcher":
                launcher_recover_predecessor(
                    SimpleNamespace(runtime_support=fixture["support"])
                )
            else:
                RuntimeDaemon(
                    fixture["root"], support_root=fixture["support"]
                ).start()
        assert fixture["pointer"].read_bytes() == original_raw
        assert fixture["pointer"].lstat().st_ino == alternate_inode
        assert fixture["pointer"].lstat().st_ino != original_inode
        assert not quarantines[0].exists()
    else:
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            daemon = RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
            daemon.stop()
        assert not fixture["pointer"].exists()
        assert not quarantines[0].exists()
        # A second replay observes the converged terminal state.
        recover_aborted_predecessor_resolution(fixture["support"])


@pytest.mark.parametrize("timing", ["preexisting", "concurrent"])
def test_quarantine_destination_is_atomic_no_replace(tmp_path, monkeypatch, timing):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    pointer_raw = fixture["pointer"].read_bytes()
    pointer_inode = fixture["pointer"].lstat().st_ino
    quarantine = (
        fixture["support"] / ".orderly-handoff-request-clearing-new.json"
    )
    sentinel = b'{"alternate":"quarantine"}'
    real_move = recovery_module._rename_pointer_to_quarantine
    if timing == "preexisting":
        quarantine.write_bytes(sentinel)
        quarantine.chmod(0o600)
    else:
        def create_then_move(pointer_path, quarantine_path):
            quarantine_path.write_bytes(sentinel)
            quarantine_path.chmod(0o600)
            real_move(pointer_path, quarantine_path)

        monkeypatch.setattr(
            recovery_module, "_rename_pointer_to_quarantine", create_then_move
        )
    with pytest.raises(ConflictError, match="quarantine"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    assert quarantine.read_bytes() == sentinel
    assert fixture["pointer"].read_bytes() == pointer_raw
    assert fixture["pointer"].lstat().st_ino == pointer_inode


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize(
    "cut",
    [
        "after-validation-before-fsync",
        "after-fsync-before-retirement",
        "after-retirement-before-final-fsync",
        "after-final-fsync",
    ],
)
def test_exact_quarantine_replays_every_fsync_removal_cut(
    tmp_path, monkeypatch, entrypoint, cut
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    real_fsync = recovery_module._fsync_directory
    real_atomic_rename = recovery_module._atomic_rename_noreplace
    real_remove = recovery_module._remove_exact_quarantine
    fsync_count = 0

    def cut_fsync(path):
        nonlocal fsync_count
        fsync_count += 1
        if (
            cut == "after-validation-before-fsync" and fsync_count == 1
        ) or (
            cut == "after-retirement-before-final-fsync" and fsync_count == 2
        ):
            raise OSError(f"cut {cut}")
        return real_fsync(path)

    def cut_rename(source, destination):
        if cut == "after-fsync-before-retirement" and Path(destination).name.startswith(
            ".orderly-handoff-retired-"
        ):
            raise OSError(f"cut {cut}")
        return real_atomic_rename(source, destination)

    def cut_remove(*args, **kwargs):
        result = real_remove(*args, **kwargs)
        if cut == "after-final-fsync":
            raise OSError(f"cut {cut}")
        return result

    monkeypatch.setattr(recovery_module, "_fsync_directory", cut_fsync)
    monkeypatch.setattr(recovery_module, "_atomic_rename_noreplace", cut_rename)
    monkeypatch.setattr(recovery_module, "_remove_exact_quarantine", cut_remove)
    with pytest.raises(OSError, match=f"cut {cut}"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_fsync_directory", real_fsync)
    monkeypatch.setattr(
        recovery_module, "_atomic_rename_noreplace", real_atomic_rename
    )
    monkeypatch.setattr(recovery_module, "_remove_exact_quarantine", real_remove)
    if entrypoint == "launcher":
        launcher_recover_predecessor(SimpleNamespace(runtime_support=fixture["support"]))
    else:
        daemon = RuntimeDaemon(
            fixture["root"], support_root=fixture["support"]
        ).start()
        daemon.stop()
    assert not fixture["pointer"].exists()
    assert not list(
        fixture["support"].glob(".orderly-handoff-request-clearing-*.json")
    )
    assert list(fixture["support"].glob(".orderly-handoff-retired-*.json"))
    recover_aborted_predecessor_resolution(fixture["support"])


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_swapped_quarantine_restoration_crash_preserves_public_inode(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    original_raw = fixture["pointer"].read_bytes()
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    alternate = fixture["support"] / "alternate-pointer.json"
    alternate.write_bytes(original_raw)
    alternate.chmod(0o600)
    alternate_inode = alternate.lstat().st_ino
    real_move = recovery_module._rename_pointer_to_quarantine
    real_fsync = recovery_module._fsync_directory

    def swap_then_move(pointer_path, quarantine_path):
        os.replace(alternate, pointer_path)
        real_move(pointer_path, quarantine_path)

    monkeypatch.setattr(
        recovery_module, "_rename_pointer_to_quarantine", swap_then_move
    )
    monkeypatch.setattr(
        recovery_module,
        "_fsync_directory",
        lambda _path: (_ for _ in ()).throw(OSError("crash after restoration")),
    )
    with pytest.raises(OSError, match="crash after restoration"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_rename_pointer_to_quarantine", real_move)
    monkeypatch.setattr(recovery_module, "_fsync_directory", real_fsync)
    assert fixture["pointer"].read_bytes() == original_raw
    assert fixture["pointer"].lstat().st_ino == alternate_inode


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_restoration_hardlink_checkpoint_replays_without_material_loss(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    original_raw = fixture["pointer"].read_bytes()
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    alternate = fixture["support"] / "alternate-pointer.json"
    alternate.write_bytes(original_raw)
    alternate.chmod(0o600)
    alternate_inode = alternate.lstat().st_ino
    os.replace(alternate, fixture["pointer"])
    quarantine = fixture["support"] / ".orderly-handoff-request-clearing-new.json"
    os.link(fixture["pointer"], quarantine, follow_symlinks=False)
    assert fixture["pointer"].lstat().st_ino == alternate_inode
    assert quarantine.lstat().st_ino == alternate_inode
    assert fixture["pointer"].read_bytes() == quarantine.read_bytes() == original_raw
    destructive_events = []
    real_unlink = recovery_module.os.unlink
    real_fsync = recovery_module._fsync_directory

    def observe_unlink(path, *args, **kwargs):
        destructive_events.append(("unlink", str(path)))
        return real_unlink(path, *args, **kwargs)

    def observe_fsync(path):
        destructive_events.append(("fsync", str(path)))
        return real_fsync(path)

    monkeypatch.setattr(recovery_module.os, "unlink", observe_unlink)
    monkeypatch.setattr(recovery_module, "_fsync_directory", observe_fsync)
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    assert quarantine.exists()
    assert quarantine.lstat().st_ino == alternate_inode
    assert fixture["pointer"].lstat().st_ino == alternate_inode
    assert fixture["pointer"].read_bytes() == original_raw
    assert destructive_events == []
    with pytest.raises(Exception):
        recover_aborted_predecessor_resolution(fixture["support"])
    assert destructive_events == []
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    assert fixture["pointer"].lstat().st_ino == alternate_inode
    assert quarantine.exists()
    assert quarantine.lstat().st_ino == alternate_inode
    assert destructive_events == []


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize("site", ["clearance", "dual-name"])
def test_retirement_boundary_inode_swap_preserves_every_name(
    tmp_path, monkeypatch, entrypoint, site
):
    """A same-byte inode swap at the former unlink boundary is never deleted."""

    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    original_raw = fixture["pointer"].read_bytes()
    original_inode = fixture["pointer"].lstat().st_ino
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    quarantine = fixture["support"] / ".orderly-handoff-request-clearing-new.json"
    if site == "dual-name":
        os.link(fixture["pointer"], quarantine, follow_symlinks=False)
    alternate = fixture["support"] / "boundary-replacement.json"
    alternate.write_bytes(original_raw)
    alternate.chmod(0o600)
    alternate_inode = alternate.lstat().st_ino
    real_atomic_move = recovery_module._atomic_rename_noreplace
    injected = False

    def swap_at_retirement(source_path, destination_path):
        nonlocal injected
        if (
            not injected
            and Path(destination_path).name.endswith(f"-{site}.json")
        ):
            injected = True
            os.replace(alternate, source_path)
        return real_atomic_move(source_path, destination_path)

    monkeypatch.setattr(
        recovery_module, "_atomic_rename_noreplace", swap_at_retirement
    )
    with pytest.raises(Exception) as captured:
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    provenance = []
    current = captured.value
    while current is not None:
        provenance.append(f"{type(current).__name__}:{current}")
        current = current.__cause__
    assert any("changed at retirement" in item for item in provenance)
    assert injected
    assert quarantine.exists()
    assert quarantine.read_bytes() == original_raw
    assert quarantine.lstat().st_ino == alternate_inode
    if site == "dual-name":
        assert fixture["pointer"].exists()
        assert fixture["pointer"].read_bytes() == original_raw
        assert fixture["pointer"].lstat().st_ino == original_inode
    else:
        assert not fixture["pointer"].exists()
    assert not list(fixture["support"].glob(".orderly-handoff-retired-*.json"))


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize("site", ["clearance", "dual-name"])
def test_retirement_boundary_swap_crash_replay_authenticates_retained_inode(
    tmp_path, monkeypatch, entrypoint, site
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    original_raw = fixture["pointer"].read_bytes()
    original_inode = fixture["pointer"].lstat().st_ino
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    quarantine = fixture["support"] / ".orderly-handoff-request-clearing-new.json"
    if site == "dual-name":
        os.link(fixture["pointer"], quarantine, follow_symlinks=False)
    alternate = fixture["support"] / "crash-boundary-replacement.json"
    alternate.write_bytes(original_raw)
    alternate.chmod(0o600)
    alternate_inode = alternate.lstat().st_ino
    real_atomic_move = recovery_module._atomic_rename_noreplace
    real_fsync = recovery_module._fsync_directory
    injected = False
    cut = False

    def swap_at_retirement(source_path, destination_path):
        nonlocal injected
        if (
            not injected
            and Path(destination_path).name.endswith(f"-{site}.json")
        ):
            injected = True
            os.replace(alternate, source_path)
        return real_atomic_move(source_path, destination_path)

    def crash_before_retired_validation(path):
        nonlocal cut
        if injected and not cut:
            cut = True
            raise OSError("crash after retirement rename")
        return real_fsync(path)

    monkeypatch.setattr(
        recovery_module, "_atomic_rename_noreplace", swap_at_retirement
    )
    monkeypatch.setattr(recovery_module, "_fsync_directory", crash_before_retired_validation)
    with pytest.raises(OSError, match="crash after retirement rename"):
        recover_aborted_predecessor_resolution(fixture["support"])
    monkeypatch.setattr(
        recovery_module, "_atomic_rename_noreplace", real_atomic_move
    )
    monkeypatch.setattr(recovery_module, "_fsync_directory", real_fsync)
    retired = fixture["support"] / f".orderly-handoff-retired-new-{site}.json"
    assert retired.exists()
    assert retired.lstat().st_ino == alternate_inode
    assert retired.read_bytes() == original_raw
    if site == "dual-name":
        assert fixture["pointer"].lstat().st_ino == original_inode
    else:
        assert not fixture["pointer"].exists()

    with pytest.raises(Exception) as captured:
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    provenance = []
    current = captured.value
    while current is not None:
        provenance.append(f"{type(current).__name__}:{current}")
        current = current.__cause__
    assert any(
        "retired successor request pointer custody changed" in item
        for item in provenance
    )
    assert retired.exists()
    assert retired.lstat().st_ino == alternate_inode
    assert retired.read_bytes() == original_raw
    if site == "dual-name":
        assert fixture["pointer"].lstat().st_ino == original_inode
    else:
        assert not fixture["pointer"].exists()


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_unbound_retired_evidence_fails_closed_without_mutation(
    tmp_path, entrypoint
):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    retired = support / ".orderly-handoff-retired-orphan-clearance.json"
    retired.write_text(json.dumps({"unbound": True}), encoding="utf-8")
    retired.chmod(0o600)
    before = (retired.lstat().st_ino, retired.read_bytes())
    with pytest.raises(Exception) as captured:
        if entrypoint == "launcher":
            launcher_recover_predecessor(SimpleNamespace(runtime_support=support))
        else:
            RuntimeDaemon(root, support_root=support).start()
    provenance = []
    current = captured.value
    while current is not None:
        provenance.append(f"{type(current).__name__}:{current}")
        current = current.__cause__
    assert any("not uniquely journal-bound" in item for item in provenance)
    assert (retired.lstat().st_ino, retired.read_bytes()) == before
    assert not (support / "runtime.json").exists()

@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_exact_dual_name_checkpoint_converges_idempotently(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("prepare complete journal")
        ),
    )
    with pytest.raises(OSError, match="prepare complete"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    quarantine = (
        fixture["support"] / ".orderly-handoff-request-clearing-new.json"
    )
    os.link(fixture["pointer"], quarantine, follow_symlinks=False)
    assert fixture["pointer"].lstat().st_ino == quarantine.lstat().st_ino
    custody_events = []
    real_unlink = recovery_module.os.unlink
    real_fsync = recovery_module._fsync_directory

    def observe_unlink(path, *args, **kwargs):
        if Path(path) == quarantine:
            custody_events.append(("unlink", str(path)))
        return real_unlink(path, *args, **kwargs)

    def observe_fsync(path):
        custody_events.append(("fsync", str(path)))
        return real_fsync(path)

    monkeypatch.setattr(recovery_module.os, "unlink", observe_unlink)
    monkeypatch.setattr(recovery_module, "_fsync_directory", observe_fsync)
    if entrypoint == "launcher":
        launcher_recover_predecessor(SimpleNamespace(runtime_support=fixture["support"]))
    else:
        daemon = RuntimeDaemon(
            fixture["root"], support_root=fixture["support"]
        ).start()
        daemon.stop()
    assert not fixture["pointer"].exists()
    assert not quarantine.exists()
    assert not any(event[0] == "unlink" for event in custody_events)
    assert custody_events[0] == ("fsync", str(fixture["support"]))
    retired = list(fixture["support"].glob(".orderly-handoff-retired-*.json"))
    assert len(retired) == 2
    assert all(path.lstat().st_ino == retired[0].lstat().st_ino for path in retired)
    recover_aborted_predecessor_resolution(fixture["support"])


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_quarantine_replay_never_clobbers_repopulated_public_name(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_remove = recovery_module._remove_exact_quarantine
    monkeypatch.setattr(
        recovery_module,
        "_remove_exact_quarantine",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("crash after quarantine move")
        ),
    )
    with pytest.raises(OSError, match="crash after quarantine move"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_remove_exact_quarantine", real_remove)
    quarantine = next(
        fixture["support"].glob(".orderly-handoff-request-clearing-*.json")
    )
    quarantined_identity = (quarantine.lstat().st_ino, quarantine.read_bytes())
    alternate_raw = b'{"alternate":"public"}'
    fixture["pointer"].write_bytes(alternate_raw)
    fixture["pointer"].chmod(0o600)
    public_identity = fixture["pointer"].lstat().st_ino
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    assert fixture["pointer"].read_bytes() == alternate_raw
    assert fixture["pointer"].lstat().st_ino == public_identity
    assert (quarantine.lstat().st_ino, quarantine.read_bytes()) == quarantined_identity


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize("case", ["malformed", "unbound", "multiple"])
def test_unexpected_quarantine_matrix_fails_before_startup_mutation(
    tmp_path, entrypoint, case
):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id="realm-1").close()
    names = ["one", "two"] if case == "multiple" else ["one"]
    for name in names:
        path = support / f".orderly-handoff-request-clearing-{name}.json"
        if case == "malformed":
            path.write_bytes(b"{malformed")
        else:
            path.write_text(json.dumps({"unbound": name}), encoding="utf-8")
        path.chmod(0o600)
    before = {
        path.name: (path.lstat().st_ino, path.read_bytes())
        for path in support.iterdir()
    }
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(SimpleNamespace(runtime_support=support))
        else:
            RuntimeDaemon(root, support_root=support).start()
    after = {
        path.name: (path.lstat().st_ino, path.read_bytes())
        for path in support.iterdir()
    }
    assert after == before


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_quarantine_inode_replacement_during_repeated_scan_fails_closed(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_remove = recovery_module._remove_exact_quarantine
    monkeypatch.setattr(
        recovery_module,
        "_remove_exact_quarantine",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cut after move")),
    )
    with pytest.raises(OSError, match="cut after move"):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_remove_exact_quarantine", real_remove)
    quarantine = next(
        fixture["support"].glob(".orderly-handoff-request-clearing-*.json")
    )
    original_inode = quarantine.lstat().st_ino
    real_owner_json = recovery_module._owner_json
    swapped = False
    replacement_inode = None

    def swap_after_first_read(path, label):
        nonlocal swapped, replacement_inode
        observed = real_owner_json(path, label)
        if path == quarantine and not swapped:
            swapped = True
            replacement = fixture["support"] / "replacement-quarantine.json"
            replacement.write_bytes(observed.raw)
            replacement.chmod(0o600)
            replacement_inode = replacement.lstat().st_ino
            os.replace(replacement, quarantine)
        return observed

    monkeypatch.setattr(recovery_module, "_owner_json", swap_after_first_read)
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=fixture["support"])
            )
        else:
            RuntimeDaemon(
                fixture["root"], support_root=fixture["support"]
            ).start()
    assert swapped and replacement_inode is not None
    assert quarantine.lstat().st_ino == replacement_inode
    assert quarantine.lstat().st_ino != original_inode


@pytest.mark.parametrize("kind", ["malformed", "symlink", "wrong-mode"])
def test_any_present_invalid_resolution_journal_fails_before_lock_mutation(
    tmp_path, kind
):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    journal = support / "orderly-handoff-predecessor-resolution-bad.json"
    if kind == "symlink":
        target = tmp_path / "outside.json"
        target.write_text("{}", encoding="utf-8")
        journal.symlink_to(target)
    else:
        journal.write_bytes(b"{malformed")
        journal.chmod(0o600 if kind == "malformed" else 0o644)
    before = sorted(path.name for path in support.iterdir())
    with pytest.raises(ConflictError):
        recover_aborted_predecessor_resolution(support)
    assert sorted(path.name for path in support.iterdir()) == before
    assert not (support / "bootstrap.lock").exists()
    assert not (support / "orderly-handoff-coordinator.lock").exists()


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
@pytest.mark.parametrize(
    "case",
    [
        "missing-field",
        "extra-field",
        "wrong-type",
        "wrong-digest",
        "invalid-state",
        "unreadable",
        "wrong-owner-simulated",
        "wrong-mode",
        "symlink",
        "directory",
        "fifo",
        "socket",
        "two-invalid",
        "valid-plus-invalid",
        "two-actionable-valid",
    ],
)
def test_invalid_journal_matrix_fails_before_any_startup_mutation(
    tmp_path, monkeypatch, entrypoint, case
):
    import runtime_protocol.handoff_recovery as recovery_module

    root = tmp_path / f"realm-{entrypoint}-{case}"
    if case == "socket":
        support = Path(tempfile.mkdtemp(prefix="x3-journal-", dir="/tmp"))
        support.chmod(0o700)
    else:
        support = tmp_path / f"support-{entrypoint}-{case}"
        support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id=f"realm-{entrypoint}-{case}").close()

    def write_journal(handoff_id, value, *, mode=0o600):
        path = support / (
            f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
        )
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    valid = _valid_resolution_journal(support, "case")
    nonregular_socket = None
    if case == "missing-field":
        valid.pop("cleanup_receipt_digest")
        valid["resolution_digest"] = digest(
            {key: item for key, item in valid.items() if key != "resolution_digest"}
        )
        write_journal("case", valid)
    elif case == "extra-field":
        valid["unexpected"] = True
        valid["resolution_digest"] = digest(
            {key: item for key, item in valid.items() if key != "resolution_digest"}
        )
        write_journal("case", valid)
    elif case == "wrong-type":
        valid["successor_request_pointer_byte_length"] = "10"
        valid["resolution_digest"] = digest(
            {key: item for key, item in valid.items() if key != "resolution_digest"}
        )
        write_journal("case", valid)
    elif case == "wrong-digest":
        valid["resolution_digest"] = "sha256:" + "0" * 64
        write_journal("case", valid)
    elif case == "invalid-state":
        valid["state"] = "ADOPTED"
        valid["active_reference_archived"] = False
        valid["resolution_digest"] = digest(
            {key: item for key, item in valid.items() if key != "resolution_digest"}
        )
        write_journal("case", valid)
    elif case == "unreadable":
        path = support / "orderly-handoff-predecessor-resolution-case.json"
        path.write_bytes(b"\xff\xfe\xfd")
        path.chmod(0o600)
    elif case == "wrong-owner-simulated":
        write_journal("case", valid)
    elif case == "wrong-mode":
        write_journal("case", valid, mode=0o644)
    elif case == "symlink":
        outside = tmp_path / f"outside-{entrypoint}.json"
        outside.write_text(json.dumps(valid), encoding="utf-8")
        (support / "orderly-handoff-predecessor-resolution-case.json").symlink_to(
            outside
        )
    elif case == "directory":
        (support / "orderly-handoff-predecessor-resolution-case.json").mkdir()
    elif case == "fifo":
        os.mkfifo(support / "orderly-handoff-predecessor-resolution-case.json", 0o600)
    elif case == "socket":
        nonregular_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        nonregular_socket.bind(
            str(support / "orderly-handoff-predecessor-resolution-case.json")
        )
    elif case == "two-invalid":
        for handoff_id in ("one", "two"):
            path = support / (
                f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
            )
            path.write_bytes(b"{invalid")
            path.chmod(0o600)
    elif case == "valid-plus-invalid":
        write_journal("case", valid)
        invalid = support / "orderly-handoff-predecessor-resolution-bad.json"
        invalid.write_bytes(b"{invalid")
        invalid.chmod(0o600)
    else:
        write_journal(
            "one", _valid_resolution_journal(support, "one", state="PREPARED")
        )
        write_journal(
            "two", _valid_resolution_journal(support, "two", state="PREPARED")
        )

    sentinels = {
        "catalog.json": b"catalog-sentinel",
        "discovery.json": b"discovery-sentinel",
        "owner.lock": b"owner-lock-sentinel",
        "orderly-handoff-request.json": b"pointer-sentinel",
        "orderly-handoff-adopted-owner.json": b"active-sentinel",
        "orderly-handoff-predecessor-active-sentinel.json": b"archive-sentinel",
    }
    for name, raw in sentinels.items():
        path = support / name
        path.write_bytes(raw)
        path.chmod(0o600)
    if case == "wrong-owner-simulated":
        journal = support / "orderly-handoff-predecessor-resolution-case.json"
        journal_identity = (journal.lstat().st_dev, journal.lstat().st_ino)
        real_fstat = recovery_module.os.fstat

        def wrong_journal_owner(descriptor):
            observed = real_fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != journal_identity:
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

        monkeypatch.setattr(recovery_module.os, "fstat", wrong_journal_owner)

    def snapshot():
        return {
            path.name: (
                path.lstat().st_dev,
                path.lstat().st_ino,
                path.read_bytes() if path.is_file() and not path.is_symlink() else None,
            )
            for path in support.iterdir()
        }

    before = snapshot()
    if entrypoint == "launcher":
        with pytest.raises(Exception, match="predecessor resolution replay"):
            launcher_recover_predecessor(
                SimpleNamespace(runtime_support=support)
            )
    else:
        with pytest.raises(ConflictError, match="pending audit"):
            RuntimeDaemon(root, support_root=support).start()
    assert snapshot() == before
    assert not (support / "bootstrap.lock").exists()
    assert not (support / "orderly-handoff-coordinator.lock").exists()
    if nonregular_socket is not None:
        nonregular_socket.close()
        shutil.rmtree(support)


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_same_name_journal_inode_swap_blocks_launcher_and_direct_start(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    root = tmp_path / f"realm-{entrypoint}"
    support = tmp_path / f"support-{entrypoint}"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id=f"realm-{entrypoint}").close()
    journal = support / "orderly-handoff-predecessor-resolution-case.json"
    journal.write_text(
        json.dumps(_valid_resolution_journal(support, "case")), encoding="utf-8"
    )
    journal.chmod(0o600)
    sentinel = support / "discovery.json"
    sentinel.write_bytes(b"discovery-sentinel")
    sentinel.chmod(0o600)
    sentinel_identity = (sentinel.lstat().st_ino, sentinel.read_bytes())
    original_inode = journal.lstat().st_ino
    real_owner_json = recovery_module._owner_json
    swapped = False
    replacement_inode = None

    def swapping_owner_json(path, label):
        nonlocal swapped, replacement_inode
        result = real_owner_json(path, label)
        if not swapped and path == journal:
            swapped = True
            replacement = support / "replacement-journal.json"
            replacement.write_bytes(result.raw)
            replacement.chmod(0o600)
            replacement_inode = replacement.lstat().st_ino
            os.replace(replacement, journal)
        return result

    monkeypatch.setattr(recovery_module, "_owner_json", swapping_owner_json)
    if entrypoint == "launcher":
        with pytest.raises(Exception, match="predecessor resolution replay"):
            launcher_recover_predecessor(SimpleNamespace(runtime_support=support))
    else:
        with pytest.raises(ConflictError, match="pending audit"):
            RuntimeDaemon(root, support_root=support).start()
    assert swapped
    assert replacement_inode is not None
    assert journal.lstat().st_ino == replacement_inode
    assert journal.lstat().st_ino != original_inode
    assert (sentinel.lstat().st_ino, sentinel.read_bytes()) == sentinel_identity
    assert not (support / "bootstrap.lock").exists()
    assert not (support / "orderly-handoff-coordinator.lock").exists()


@pytest.mark.parametrize("entrypoint", ["launcher", "direct"])
def test_journal_removal_during_repeated_enumeration_fails_closed(
    tmp_path, monkeypatch, entrypoint
):
    import runtime_protocol.handoff_recovery as recovery_module

    root = tmp_path / f"realm-{entrypoint}"
    support = tmp_path / f"support-{entrypoint}"
    support.mkdir(mode=0o700)
    RealmStore.initialize(root, realm_id=f"realm-{entrypoint}").close()
    journal = support / "orderly-handoff-predecessor-resolution-case.json"
    journal.write_text(
        json.dumps(_valid_resolution_journal(support, "case")), encoding="utf-8"
    )
    journal.chmod(0o600)
    real_owner_json = recovery_module._owner_json
    removed = False

    def remove_after_first_read(path, label):
        nonlocal removed
        observed = real_owner_json(path, label)
        if path == journal and not removed:
            removed = True
            journal.unlink()
        return observed

    monkeypatch.setattr(recovery_module, "_owner_json", remove_after_first_read)
    with pytest.raises(Exception):
        if entrypoint == "launcher":
            launcher_recover_predecessor(SimpleNamespace(runtime_support=support))
        else:
            RuntimeDaemon(root, support_root=support).start()
    assert removed
    assert not (support / "discovery.json").exists()
    assert not (support / "bootstrap.lock").exists()
    assert not (support / "orderly-handoff-coordinator.lock").exists()


def test_journal_added_during_enumeration_fails_closed(tmp_path, monkeypatch):
    import runtime_protocol.handoff_recovery as recovery_module

    fixture = _resolution_fixture(tmp_path)
    real_clear = recovery_module._clear_pointer
    monkeypatch.setattr(
        recovery_module,
        "_clear_pointer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("cut before pointer clear")
        ),
    )
    with pytest.raises(OSError):
        _resolve_aborted_predecessor(
            fixture["support"],
            handoff_record=fixture["successor"],
            aborted=fixture["aborted"],
        )
    monkeypatch.setattr(recovery_module, "_clear_pointer", real_clear)
    real_owner_json = recovery_module._owner_json
    inserted = False

    def racing_owner_json(path, label):
        nonlocal inserted
        result = real_owner_json(path, label)
        if (
            not inserted
            and path.name.startswith("orderly-handoff-predecessor-resolution-")
        ):
            inserted = True
            extra = (
                fixture["support"]
                / "orderly-handoff-predecessor-resolution-raced.json"
            )
            extra.write_bytes(b"{malformed")
            extra.chmod(0o600)
        return result

    monkeypatch.setattr(recovery_module, "_owner_json", racing_owner_json)
    pointer_before = fixture["pointer"].read_bytes()
    with pytest.raises(ConflictError, match="journal set changed"):
        recover_aborted_predecessor_resolution(fixture["support"])
    assert fixture["pointer"].read_bytes() == pointer_before
