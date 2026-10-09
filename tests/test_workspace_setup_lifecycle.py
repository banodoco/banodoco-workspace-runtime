from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
import time

import pytest

from banodoco_local import cli
from banodoco_local.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, bootstrap, doctor
from banodoco_local.paths import RuntimePaths
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from banodoco_local.workspace import configure_workspace, inspect_workspace
import banodoco_local.workspace as workspace_module
from runtime_protocol.backup import create_backup, restore_backup
from runtime_protocol.store import RealmStore


def _profile(root: Path) -> SourceProfile:
    return SourceProfile(profile="astrid", runtime_checkout=str(root), source_checkout=str(root))


def _report(realm_id: str) -> dict:
    return {
        "ok": True,
        "state": "ready",
        "checks": {"realm_identity": {"ok": True, "realm_id": realm_id, "row_count": 1}},
    }


class SelectionBoundary:
    def __init__(self):
        self.creates: list[dict] = []

    def create(self, **kwargs):
        self.creates.append(kwargs)
        RealmStore.initialize(
            kwargs["realm_root"], realm_id=kwargs["realm_id"],
            display_name=kwargs["display_name"],
        ).close()
        return {"state": "created", "realm_id": kwargs["realm_id"], "root": str(kwargs["realm_root"])}

    def inspect(self, *, realm_root):
        return RealmStore.inspect_realm(realm_root)


def test_create_and_repeat_commit_one_stable_identity_before_up(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    boundary = SelectionBoundary()
    realm_id = "3f3d09c0-8bd4-4dfa-8cd4-0e16a4f735d4"
    realm_root = tmp_path / "realm"
    config = BootstrapConfig(source_profile=_profile(tmp_path))

    first = configure_workspace(paths, boundary, config, mode="create", realm_root=realm_root, realm_id=realm_id)
    before = paths.catalog_path.read_bytes()
    second = configure_workspace(paths, boundary, config, mode="create", realm_root=realm_root, realm_id=realm_id)

    assert first["status"] == "configured_create"
    assert second["status"] == "unchanged"
    assert paths.catalog_path.read_bytes() == before
    assert len(boundary.creates) == 1
    catalog = json.loads(before)
    assert catalog["selected_realm_id"] == realm_id
    assert catalog["realms"] == [{
        "data_root": str(realm_root),
        "display_name": "Astrid Workspace",
        "readiness": "not_ready",
        "readiness_reason": "workspace_configured_runtime_not_ready",
        "realm_id": realm_id,
        "selection_source": "create",
        "source_profile": "astrid",
    }]


def test_attach_inspects_without_copy_and_rejects_wrong_conflicting_or_unsafe_identity(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    realm_root = tmp_path / "existing"
    realm_id = "f77ef51b-77e3-4fb0-aac7-2dadb70b9180"
    RealmStore.initialize(realm_root, realm_id=realm_id).close()
    before = {path.relative_to(realm_root): path.read_bytes() for path in realm_root.rglob("*") if path.is_file()}
    config = BootstrapConfig(source_profile=_profile(tmp_path))

    result = configure_workspace(paths, SelectionBoundary(), config, mode="attach", realm_root=realm_root, realm_id=realm_id)
    after = {path.relative_to(realm_root): path.read_bytes() for path in realm_root.rglob("*") if path.is_file()}
    assert result["selection_source"] == "attach"
    assert before == after
    assert not any(path.is_dir() and path.name.startswith(".existing") for path in tmp_path.iterdir())

    with pytest.raises(BootstrapError, match="identity mismatch"):
        configure_workspace(
            paths, SelectionBoundary(), config, mode="attach", realm_root=realm_root,
            realm_id="ab1b0545-b879-40fe-918e-a88b8d1cd42d",
        )
    with pytest.raises(BootstrapError, match="absolute"):
        configure_workspace(paths, SelectionBoundary(), config, mode="attach", realm_root=Path("relative"), realm_id=realm_id)
    alias = tmp_path / "alias"
    alias.symlink_to(realm_root, target_is_directory=True)
    with pytest.raises(BootstrapError, match="symlink"):
        inspect_workspace(paths, SelectionBoundary(), realm_root=alias, expected_realm_id=realm_id)


def test_attach_rejects_ambiguous_canonical_identity_without_support_writes(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    realm_root = tmp_path / "ambiguous"
    realm_id = "5ae7a430-761b-44ca-ab09-9c69a65c1c68"
    RealmStore.initialize(realm_root, realm_id=realm_id).close()
    with sqlite3.connect(realm_root / "realm.sqlite3") as connection:
        connection.execute(
            "INSERT INTO realm SELECT ?, display_name, created_at, updated_at FROM realm LIMIT 1",
            ("72c9fdf5-ae87-410c-9810-f9d2fb83ec77",),
        )

    with pytest.raises(BootstrapError, match="healthy unambiguous canonical workspace"):
        configure_workspace(
            paths,
            SelectionBoundary(),
            BootstrapConfig(source_profile=_profile(tmp_path)),
            mode="attach",
            realm_root=realm_root,
            realm_id=realm_id,
        )

    assert not paths.app_support.exists()


def test_create_commit_failure_removes_only_new_unselected_realm(tmp_path, monkeypatch):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    realm_root = tmp_path / "new-realm"
    config = BootstrapConfig(source_profile=_profile(tmp_path))

    def fail_commit(*_args, **_kwargs):
        raise OSError("injected catalog commit failure")

    monkeypatch.setattr(workspace_module, "_commit_source_profile_metadata", fail_commit)
    with pytest.raises(OSError, match="injected catalog commit failure"):
        configure_workspace(
            paths, SelectionBoundary(), config, mode="create", realm_root=realm_root,
            realm_id="ae7451f6-002a-49e3-b06e-787a9fea003e",
        )
    assert not realm_root.exists()
    assert not paths.catalog_path.exists()


def test_unconfigured_up_and_observers_do_not_create_support_state(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    with pytest.raises(BootstrapError, match="workspace is configured"):
        bootstrap(paths, SelectionBoundary(), BootstrapConfig(source_profile=_profile(tmp_path)))
    assert not paths.app_support.exists()

    missing = inspect_workspace(paths, SelectionBoundary())
    report = doctor(paths, SelectionBoundary())
    assert missing["state"] == "workspace_missing"
    assert report["healthy"] is False
    assert not paths.app_support.exists()


def test_failed_up_preserves_configured_selection_and_emits_typed_recovery(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    realm_id = "23c15370-712f-42a7-aa9b-33ddc1395322"
    config = BootstrapConfig(source_profile=_profile(tmp_path))
    configure_workspace(paths, SelectionBoundary(), config, mode="create", realm_root=tmp_path / "realm", realm_id=realm_id)
    before = paths.catalog_path.read_bytes()

    class FailingBoundary:
        def configure_source(self, _source):
            pass

        def start(self, **_kwargs):
            raise BootstrapError("occupied port or unrelated service")

        def is_pid_alive(self, _pid):
            return False

        def stop(self):
            pass

    monkeypatch.setattr(cli, "LocalRuntimeBoundary", FailingBoundary)
    assert cli.main(["up", "--data-root", str(paths.app_support), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "workspace_configured_runtime_not_ready"
    assert payload["state"] == "workspace_configured_runtime_not_ready"
    assert payload["next_action"] == "astrid-runtime up"
    assert payload["effects"] == [
        "start-stop-local-service",
        "configure-install",
        "write-relocate-change-data",
    ]
    assert payload["authorization_required"] is True
    assert paths.catalog_path.read_bytes() == before


def test_configured_but_stopped_doctor_reports_runtime_not_ready_without_mutation(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    config = BootstrapConfig(source_profile=_profile(tmp_path))
    configure_workspace(
        paths,
        SelectionBoundary(),
        config,
        mode="create",
        realm_root=tmp_path / "realm",
        realm_id="a0b4b9cf-3a7a-4c20-aabb-f109360ad7df",
    )
    before = {
        path.relative_to(paths.app_support): path.read_bytes()
        for path in paths.app_support.rglob("*")
        if path.is_file()
    }

    report = doctor(paths, SelectionBoundary())

    after = {
        path.relative_to(paths.app_support): path.read_bytes()
        for path in paths.app_support.rglob("*")
        if path.is_file()
    }
    assert report["healthy"] is False
    assert report["runtime_ready"] is False
    assert report["state"] == "workspace_configured_runtime_not_ready"
    assert before == after


def test_doctor_and_status_reject_healthy_runtime_for_another_workspace_without_writes(
    tmp_path, monkeypatch, capsys,
):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    selected_id = "7f249914-1b18-4d66-9a3c-4d151e635436"
    active_id = "58e8f8a1-a5f4-4bd7-9d00-a02c95bbab62"
    selected_root = tmp_path / "selected-workspace"
    active_root = tmp_path / "other-workspace"
    config = BootstrapConfig(source_profile=_profile(tmp_path))
    configure_workspace(
        paths, SelectionBoundary(), config, mode="create",
        realm_root=selected_root, realm_id=selected_id,
    )
    active_root.mkdir()
    catalog = json.loads(paths.catalog_path.read_text())
    catalog["realms"][0].update({
        "readiness": "ready",
        "runtime_instance_id": "instance-a",
    })
    paths.catalog_path.write_text(json.dumps(catalog))
    discovery = {
        "version": 1,
        "endpoint": "http://127.0.0.1:43100",
        "pid": 991,
        "process_birth_id": "birth-991",
        "runtime_instance_id": "instance-a",
        "active_realm": active_id,
        "realm_root": str(active_root),
    }
    owner = {
        "pid": 991,
        "process_birth_id": "birth-991",
        "runtime_instance_id": "instance-a",
        "realm_id": active_id,
        "realm_root": str(active_root),
    }
    paths.discovery_path.write_text(json.dumps(discovery))
    paths.instance_lock_path.write_text(json.dumps(owner))

    class HealthyOtherWorkspaceBoundary:
        def __init__(self):
            self.observations = []

        def is_pid_alive(self, pid):
            self.observations.append(("pid", pid))
            return True

        def validate_owner(self, **kwargs):
            self.observations.append(("owner", kwargs["instance_id"]))
            return True

        def health(self, **kwargs):
            self.observations.append(("health", kwargs["instance_id"]))
            return True

        def endpoint_metadata(self, **_kwargs):
            self.observations.append(("endpoint", active_id))
            return {
                "status": "ok",
                "runtime_instance_id": "instance-a",
                "realm_id": active_id,
                "realm_root": str(active_root),
            }

        def start(self, **_kwargs):
            raise AssertionError("doctor/status must not start a runtime")

    boundary = HealthyOtherWorkspaceBoundary()
    before = {
        path.relative_to(paths.app_support): path.read_bytes()
        for path in paths.app_support.rglob("*")
        if path.is_file()
    }

    report = doctor(paths, boundary)
    assert report["healthy"] is False
    assert report["runtime_ready"] is False
    assert report["state"] == "runtime_unavailable"
    assert "discovery_realm_mismatch" in report["issues"]
    assert "discovery_root_mismatch" in report["issues"]
    assert "owner_lock_identity_mismatch" in report["issues"]
    assert "endpoint_identity_mismatch" in report["issues"]

    monkeypatch.setattr(cli, "LocalRuntimeBoundary", lambda: boundary)
    monkeypatch.setattr(cli, "_typed_health", lambda _paths: {"status": "ok"})
    assert cli.main(["status", "--data-root", str(paths.app_support), "--json"]) == 1
    status = json.loads(capsys.readouterr().out)
    assert status["support"]["runtime_ready"] is False
    assert status["support"]["state"] == "runtime_unavailable"
    assert {name for name, _value in boundary.observations} == {"pid", "owner", "health", "endpoint"}

    after = {
        path.relative_to(paths.app_support): path.read_bytes()
        for path in paths.app_support.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_old_checkout_unavailable_fails_before_start_and_preserves_selection(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    checkout = tmp_path / "pinned-checkout"
    checkout.mkdir()
    realm_id = "b0af4214-43ed-49d6-99b6-cb219594bd82"
    config = BootstrapConfig(source_profile=_profile(checkout))
    configure_workspace(
        paths,
        SelectionBoundary(),
        config,
        mode="create",
        realm_root=tmp_path / "realm",
        realm_id=realm_id,
    )
    before = paths.catalog_path.read_bytes()
    checkout.rmdir()

    with pytest.raises(BootstrapError, match="checkout.*does not exist"):
        bootstrap(paths, LocalRuntimeBoundary(), config)

    assert paths.catalog_path.read_bytes() == before
    assert not paths.discovery_path.exists()


def test_up_success_emits_effect_and_authorization_metadata(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path)
    monkeypatch.setattr(cli, "bootstrap", lambda *_args, **_kwargs: {
        "status": "started",
        "realm_id": "65f6d650-7f4b-4a8a-bd02-8f5b5e7e34d3",
    })
    assert cli.main(["up", "--data-root", str(paths.app_support), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["effects"] == [
        "start-stop-local-service",
        "configure-install",
        "write-relocate-change-data",
    ]
    assert payload["authorization_required"] is True


def test_launcher_merge_preserves_runtime_readiness_epoch_and_instance(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    realm_id = "322c2732-f359-4745-985e-d6fb064d1c4c"
    config = BootstrapConfig(source_profile=_profile(tmp_path))
    selector = SelectionBoundary()
    configure_workspace(paths, selector, config, mode="create", realm_root=tmp_path / "realm", realm_id=realm_id)

    class Connection:
        def provision_actor(self, **_kwargs):
            return {"scope": "astrid"}

        def select_realm(self, **_kwargs):
            pass

        def handshake(self, **_kwargs):
            pass

    class StartingBoundary:
        def configure_source(self, _source):
            pass

        def start(self, **_kwargs):
            live = json.loads(paths.catalog_path.read_text())
            live["realms"][0].update({"readiness": "ready", "runtime_epoch": 9, "runtime_instance_id": "instance-live"})
            paths.catalog_path.write_text(json.dumps(live))
            return {"endpoint": "http://127.0.0.1:43100", "pid": 991, "process_birth_id": "birth-991", "runtime_instance_id": "instance-live", "coordinator_epoch": 9}

        def health(self, **kwargs):
            return kwargs["instance_id"] == "instance-live"

        def connect(self, **_kwargs):
            return Connection()

        def is_pid_alive(self, _pid):
            return False

        def stop(self):
            pass

    result = bootstrap(paths, StartingBoundary(), config)
    row = json.loads(paths.catalog_path.read_text())["realms"][0]
    assert result.ready
    assert (row["readiness"], row["runtime_epoch"], row["runtime_instance_id"]) == ("ready", 9, "instance-live")
    assert row["selection_source"] == "create"


def test_endpoint_wait_refuses_unrelated_healthy_service_instance(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary(wait_seconds=1)
    boundary.wait_seconds = 0.02
    process = type("Process", (), {"pid": 12345, "poll": lambda self: None})()
    monkeypatch.setattr(boundary, "_read_discovery", lambda _root: {
        "pid": 12345, "endpoint": "http://127.0.0.1:9999", "runtime_instance_id": "advertised",
    })
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _endpoint: {
        "protocol": "workspace.v1", "status": "ok", "runtime_instance_id": "unrelated",
    })
    monkeypatch.setattr(boundary, "_terminate", lambda _process: None)
    with pytest.raises(BootstrapError, match="bounded startup deadline"):
        boundary._wait_endpoint(tmp_path, process)


def test_disposable_backup_restore_interruption_and_recovery_rehearsal(tmp_path):
    source = tmp_path / "source-copy"
    store = RealmStore.initialize(source, realm_id="7dcfe3cf-5706-451c-af2f-442ad197829d")
    key = b"disposable-rehearsal-key-material-32-bytes-plus"
    backup = tmp_path / "backup-copy"
    try:
        receipt = create_backup(store, backup, key=key)
    finally:
        store.close()
    assert receipt["manifest"]["realm"]["id"] == "7dcfe3cf-5706-451c-af2f-442ad197829d"

    interrupted = tmp_path / "interrupted-backup-copy"
    shutil.copytree(backup, interrupted)
    (interrupted / "realm.sqlite3").write_bytes(b"interrupted")
    destination = tmp_path / "restored-copy"
    with pytest.raises(Exception):
        restore_backup(interrupted, destination, key=key)
    assert not destination.exists()

    recovered = restore_backup(backup, destination, key=key)
    assert recovered["realm_id"] == "7dcfe3cf-5706-451c-af2f-442ad197829d"
    inspection = RealmStore.inspect_realm(destination)
    assert inspection["ok"] is True
    assert inspection["checks"]["realm_identity"]["realm_id"] == "7dcfe3cf-5706-451c-af2f-442ad197829d"
