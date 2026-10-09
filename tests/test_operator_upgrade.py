from __future__ import annotations

from pathlib import Path
import hashlib
import json
from types import SimpleNamespace
import sqlite3

import pytest

from banodoco_local.bootstrap import BootstrapConfig, BootstrapError, SourceProfile
from banodoco_local.operator_upgrade import OperatorUpgradeError, upgrade_workspace
from banodoco_local.paths import RuntimePaths
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.store import RealmStore


class _Boundary:
    def __init__(self, paths, *, live=True):
        self.paths = paths
        self.live = live
        self.calls = []

    def is_pid_alive(self, _pid):
        return self.live

    def prepare_restart(self, **kwargs):
        self.calls.append(("prepare", kwargs))

    def stop_owner(self, **kwargs):
        self.calls.append(("stop", kwargs))

    def validate_owner(self, **_kwargs):
        return True

    def endpoint_metadata(self, **_kwargs):
        discovery = json.loads(self.paths.discovery_path.read_text())
        return {
            "runtime_instance_id": discovery["runtime_instance_id"],
            "realm_id": discovery["active_realm"],
            "status": "ok",
        }

    def health(self, **_kwargs):
        return True

    def connect(self, **_kwargs):
        return SimpleNamespace(doctor=lambda: {"ok": True, "state": "healthy"})


def _fixture(tmp_path, *, live=True, runtime_checkout=None, version=25):
    support = tmp_path / "support"
    paths = RuntimePaths.current_mac(data_root=support)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm-1"
    RealmStore.initialize(realm_root, realm_id="realm-1").close()
    if version == 25:
        connection = sqlite3.connect(realm_root / "realm.sqlite3")
        try:
            connection.execute("ALTER TABLE tasks DROP COLUMN execution_request_json")
            connection.execute("DROP TABLE execution_bindings")
            connection.execute("UPDATE runtime_schema SET version=25 WHERE id=1")
            connection.commit()
        finally:
            connection.close()
    checkout = runtime_checkout or tmp_path
    profile = SourceProfile(profile="astrid", runtime_checkout=str(checkout), source_checkout=str(checkout))
    catalog = {
        "version": 1,
        "selected_realm_id": "realm-1",
        "realms": [{"realm_id": "realm-1", "display_name": "Astrid", "data_root": str(realm_root)}],
        "source_profiles": {"astrid": profile.as_dict()},
    }
    paths.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    (paths.source_profiles_dir / "astrid.json").write_text(json.dumps(profile.as_dict()), encoding="utf-8")
    (paths.runtime_support / "credentials").mkdir(parents=True, exist_ok=True)
    (paths.runtime_support / "credentials" / "owner.token").write_text("owner-token", encoding="utf-8")
    if live:
        discovery = {
            "pid": 1234, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1234",
            "runtime_instance_id": "instance-1", "process_birth_id": "birth-1", "realm_root": str(realm_root.resolve()),
        }
        paths.discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
        paths.instance_lock_path.write_text(json.dumps({**discovery, "realm_id": "realm-1"}), encoding="utf-8")
    return paths, profile, realm_root


def test_operator_upgrade_current_realm_is_single_idempotent_workflow(tmp_path, monkeypatch):
    paths, profile, realm_root = _fixture(tmp_path)
    boundary = _Boundary(paths)
    started = []
    migration_calls = []

    def fake_start(target_paths, _boundary, _config):
        started.append(target_paths.app_support)
        discovery = {
            "pid": 1235, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1235",
            "runtime_instance_id": "instance-2", "process_birth_id": "birth-2", "realm_root": str(realm_root.resolve()),
        }
        target_paths.discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
        target_paths.instance_lock_path.write_text(json.dumps({**discovery, "realm_id": "realm-1"}), encoding="utf-8")
        return SimpleNamespace(endpoint=discovery["endpoint"], pid=1235, runtime_instance_id="instance-2")

    monkeypatch.setattr("banodoco_local.operator_upgrade._bootstrap_locked", fake_start)
    monkeypatch.setattr(
        "banodoco_local.operator_upgrade.migrate_canonical_to_current",
        lambda *args, **kwargs: (
            migration_calls.append((args, kwargs))
            or {"ok": True, "source_schema_version": 25, "target_schema_version": 26}
        ),
    )
    monkeypatch.setattr(
        "banodoco_local.operator_upgrade.migrate_historical_managed_outputs",
        lambda *args, **kwargs: pytest.fail("v25 upgrade must not run historical output migration"),
        raising=False,
    )
    result = upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert result["ok"] is True
    assert result["schema_before"] == "v25"
    assert migration_calls == [
        ((realm_root,), {"timeout_seconds": 120.0, "confirmation": "MIGRATE CANONICAL realm-1", "expected_realm_id": "realm-1"})
    ]
    assert boundary.calls[1][0] == "stop"
    assert boundary.calls[1][1]["require_health"] is False
    assert started == [paths.app_support]
    journal = json.loads((paths.runtime_support / "upgrade-journal.json").read_text())
    assert journal["state"] == "complete"
    assert [event["state"] for event in journal["history"]] == ["planned", "stopping", "stopped", "activated", "restarted", "complete"]


def test_operator_upgrade_refuses_running_task_before_signaling_owner(tmp_path):
    paths, profile, realm_root = _fixture(tmp_path)
    connection = sqlite3.connect(realm_root / "realm.sqlite3")
    try:
        timestamp = "2026-09-15T00:00:00Z"
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("project", "realm-1", "project", "Project", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("run", "project", "rendering.render", "{}", "running", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("task", "run", "rendering.render", "{}", "running", timestamp, timestamp),
        )
        connection.commit()
    finally:
        connection.close()
    boundary = _Boundary(paths)
    with pytest.raises(OperatorUpgradeError, match="work is active"):
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert not any(call[0] == "stop" for call in boundary.calls)


def test_operator_upgrade_failure_before_activation_restarts_original_and_journals(tmp_path, monkeypatch):
    paths, profile, realm_root = _fixture(tmp_path)
    boundary = _Boundary(paths)
    started = []

    def fake_start(target_paths, _boundary, _config):
        started.append(True)
        return SimpleNamespace(endpoint="http://127.0.0.1:1235", runtime_instance_id="instance-2")

    def fail_migration(*_args, **_kwargs):
        raise RuntimeError("validation failed")

    monkeypatch.setattr("banodoco_local.operator_upgrade._bootstrap_locked", fake_start)
    monkeypatch.setattr("banodoco_local.operator_upgrade.migrate_canonical_to_current", fail_migration)
    with pytest.raises(OperatorUpgradeError, match="validation failed"):
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert started == [True]
    assert (realm_root / "realm.sqlite3").is_file()
    journal = json.loads((paths.runtime_support / "upgrade-journal.json").read_text())
    assert journal["state"] == "failed"
    assert journal["activated"] is False


def test_operator_upgrade_restarts_a_real_current_runtime(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    paths, profile, _realm_root = _fixture(tmp_path, live=False, runtime_checkout=repo)
    boundary = LocalRuntimeBoundary(wait_seconds=8)
    try:
        result = upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
        assert result["ok"]
        assert result["schema_before"] == "v25"
        assert result["verification"]["health"] is True
        assert result["verification"]["integrity"]["ok"] is True
    finally:
        boundary.stop()


def test_operator_upgrade_current_v26_uses_read_only_schema_noop(tmp_path, monkeypatch):
    paths, profile, _realm_root = _fixture(tmp_path, version=26)
    boundary = _Boundary(paths)

    def fake_start(target_paths, _boundary, _config):
        discovery = {
            "pid": 1235, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1235",
            "runtime_instance_id": "instance-2", "process_birth_id": "birth-2", "realm_root": str(_realm_root.resolve()),
        }
        target_paths.discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
        target_paths.instance_lock_path.write_text(json.dumps({**discovery, "realm_id": "realm-1"}), encoding="utf-8")
        return SimpleNamespace(endpoint=discovery["endpoint"], pid=1235, runtime_instance_id="instance-2")

    monkeypatch.setattr("banodoco_local.operator_upgrade._bootstrap_locked", fake_start)
    result = upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert result["schema_before"] == "v26"
    assert result["migration"]["changed"] is False
    assert result["migration"]["steps"] == []


def test_operator_upgrade_rejects_newer_schema_before_journal_or_signal(tmp_path):
    paths, profile, realm_root = _fixture(tmp_path, version=26)
    connection = sqlite3.connect(realm_root / "realm.sqlite3")
    connection.execute("UPDATE runtime_schema SET version=27 WHERE id=1")
    connection.commit()
    connection.close()
    tracked = [realm_root / "realm.sqlite3", paths.catalog_path, paths.discovery_path, paths.instance_lock_path]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
    boundary = _Boundary(paths)
    with pytest.raises(OperatorUpgradeError, match="newer than supported"):
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
    assert after == before
    assert not (paths.runtime_support / "upgrade-journal.json").exists()
    assert not any(call[0] == "stop" for call in boundary.calls)


def test_operator_upgrade_rejects_catalog_root_with_symlink_parent_before_journal_or_signal(tmp_path):
    paths, profile, realm_root = _fixture(tmp_path, version=26)
    alias_parent = tmp_path / "realm-parent-alias"
    alias_parent.symlink_to(realm_root.parent, target_is_directory=True)
    catalog = json.loads(paths.catalog_path.read_text(encoding="utf-8"))
    catalog["realms"][0]["data_root"] = str(alias_parent / realm_root.name)
    paths.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    tracked = [realm_root / "realm.sqlite3", paths.catalog_path, paths.discovery_path, paths.instance_lock_path]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
    boundary = _Boundary(paths)

    with pytest.raises(BootstrapError, match="unsafe realm root"):
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))

    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
    assert after == before
    assert not (paths.runtime_support / "upgrade-journal.json").exists()
    assert not any(call[0] == "stop" for call in boundary.calls)
