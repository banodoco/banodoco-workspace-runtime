from __future__ import annotations

from pathlib import Path
import json
from types import SimpleNamespace
import sqlite3

import pytest

from banodoco_local.bootstrap import BootstrapConfig, SourceProfile, bootstrap
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

    def health(self, **_kwargs):
        return True

    def connect(self, **_kwargs):
        return SimpleNamespace(doctor=lambda: {"ok": True, "state": "healthy"})


def _fixture(tmp_path, *, live=True):
    support = tmp_path / "support"
    paths = RuntimePaths.current_mac(data_root=support)
    paths.ensure_support_dirs()
    realm_root = paths.realms_dir / "realm-1"
    RealmStore.initialize(realm_root, realm_id="realm-1").close()
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
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
            "runtime_instance_id": "instance-1", "process_birth_id": "birth-1",
        }
        paths.discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
        paths.instance_lock_path.write_text(json.dumps(discovery), encoding="utf-8")
    return paths, profile, realm_root


def test_operator_upgrade_current_realm_is_single_idempotent_workflow(tmp_path, monkeypatch):
    paths, profile, _realm_root = _fixture(tmp_path)
    boundary = _Boundary(paths)
    started = []

    def fake_start(target_paths, _boundary, _config):
        started.append(target_paths.app_support)
        discovery = {
            "pid": 1235, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1235",
            "runtime_instance_id": "instance-2", "process_birth_id": "birth-2",
        }
        target_paths.discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
        target_paths.instance_lock_path.write_text(json.dumps(discovery), encoding="utf-8")
        return SimpleNamespace(endpoint=discovery["endpoint"], pid=1235, runtime_instance_id="instance-2")

    monkeypatch.setattr("banodoco_local.operator_upgrade._bootstrap_locked", fake_start)
    monkeypatch.setattr(
        "banodoco_local.operator_upgrade.migrate_historical_managed_outputs",
        lambda *args, **kwargs: {"ok": True, "migrated": 0, "skipped": [], "skipped_count": 0},
    )
    result = upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert result["ok"] is True
    assert result["schema_before"] == "v25"
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
    monkeypatch.setattr("banodoco_local.operator_upgrade.migrate_historical_managed_outputs", fail_migration)
    with pytest.raises(OperatorUpgradeError, match="validation failed"):
        upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert started == [True]
    assert (realm_root / "realm.sqlite3").is_file()
    journal = json.loads((paths.runtime_support / "upgrade-journal.json").read_text())
    assert journal["state"] == "failed"
    assert journal["activated"] is False


def test_operator_upgrade_restarts_a_real_current_runtime(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    support = tmp_path / "support"
    paths = RuntimePaths.current_mac(data_root=support)
    profile = SourceProfile(profile="astrid", runtime_checkout=str(repo), source_checkout=str(repo))
    boundary = LocalRuntimeBoundary(wait_seconds=8)
    try:
        first = bootstrap(paths, boundary, BootstrapConfig(source_profile=profile))
        result = upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
        assert first.ready and result["ok"]
        assert result["schema_before"] == "v25"
        assert result["verification"]["health"] is True
        assert result["verification"]["integrity"]["ok"] is True
    finally:
        boundary.stop()
