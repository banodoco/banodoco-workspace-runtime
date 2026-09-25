from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sqlite3
import subprocess
import sys
import tempfile
import unittest

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
)
from banodoco_local.paths import RuntimePaths
from runtime_protocol.store import RealmStore


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
    capability_digest="caps-v1",
)


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
        self.alive.discard(kwargs["pid"])
        return self.start(realm_id="ignored", realm_root=Path(tempfile.mkdtemp()) / "realm", owner_lock=Path("/tmp/lock"), source_profile=PROFILE)

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

    def test_first_launch_writes_catalog_discovery_without_synthesizing_activation(self):
        self._configure()
        result = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "started")
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

    def test_restart_reuses_selected_realm(self):
        self._configure()
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        result = restart(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "restarted")
        self.assertEqual(result.realm_id, first.realm_id)
        self.assertEqual(self.boundary.restart_calls, 1)

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
