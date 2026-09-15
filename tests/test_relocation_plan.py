import json
import fcntl

import pytest

from banodoco_local import RuntimePaths
from banodoco_local.bootstrap import BootstrapConfig, BootstrapResult, SourceProfile
from banodoco_local.relocation import (
    RelocationError,
    catalog_with_relocated_root,
    plan_relocation,
    relocate,
)


def test_relocation_plan_binds_selected_owner(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    paths.ensure_support_dirs()
    current = paths.realms_dir / "realm-1"
    current.mkdir()
    paths.catalog_path.write_text(
        json.dumps({"version": 1, "realms": [{"realm_id": "realm-1", "display_name": "Realm", "data_root": str(current)}], "selected_realm_id": "realm-1", "source_profiles": {}}),
        encoding="utf-8",
    )
    paths.discovery_path.write_text(json.dumps({"pid": 1234, "active_realm": "realm-1"}), encoding="utf-8")

    plan = plan_relocation(paths, tmp_path / "candidate", tmp_path / "backup")

    assert plan["state"] == "planned"
    assert plan["execution"] == "same-volume-offline-cutover"
    assert plan["destination_support_root"] == str(tmp_path / "candidate")
    assert plan["confirmation"] == "RELOCATE realm-1"
    assert "bootstrap lock" in plan["steps"][0]


def test_relocation_plan_rejects_existing_destination(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    paths.ensure_support_dirs()
    current = paths.realms_dir / "realm-1"
    current.mkdir()
    paths.catalog_path.write_text(json.dumps({"version": 1, "realms": [{"realm_id": "realm-1", "display_name": "Realm", "data_root": str(current)}], "selected_realm_id": "realm-1", "source_profiles": {}}), encoding="utf-8")
    paths.discovery_path.write_text(json.dumps({"pid": 1234, "active_realm": "realm-1"}), encoding="utf-8")
    target = tmp_path / "candidate"
    target.mkdir()

    try:
        plan_relocation(paths, target, tmp_path / "backup")
    except RelocationError as exc:
        assert "must be new" in str(exc)
    else:
        raise AssertionError("existing destination should be rejected")


def test_catalog_root_update_preserves_all_realms_and_metadata(tmp_path):
    destination = tmp_path / "candidate"
    catalog = {
        "version": 1,
        "selected_realm_id": "realm-1",
        "source_profiles": {"astrid": {"checkout": "/workspace/Astrid"}},
        "realms": [
            {"realm_id": "realm-1", "display_name": "One", "data_root": "/old/one"},
            {"realm_id": "realm-2", "display_name": "Two", "data_root": "/old/two"},
        ],
    }

    updated = catalog_with_relocated_root(catalog, "realm-1", destination)

    assert updated["selected_realm_id"] == "realm-1"
    assert updated["source_profiles"] == catalog["source_profiles"]
    assert [row["realm_id"] for row in updated["realms"]] == ["realm-1", "realm-2"]
    assert updated["realms"][0]["data_root"] == str(destination)
    assert updated["realms"][1] == catalog["realms"][1]


def test_relocation_execution_is_side_effect_free_until_quiescence_api(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    paths.ensure_support_dirs()
    current = paths.realms_dir / "realm-1"
    current.mkdir()
    catalog = {
        "version": 1,
        "realms": [{"realm_id": "realm-1", "display_name": "Realm", "data_root": str(current)}],
        "selected_realm_id": "realm-1",
        "source_profiles": {},
    }
    paths.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    paths.discovery_path.write_text(json.dumps({"pid": 1234, "active_realm": "realm-1"}), encoding="utf-8")
    before = paths.catalog_path.read_bytes()

    try:
        relocate(
            paths,
            boundary=object(),
            config=BootstrapConfig(source_profile=SourceProfile(
                profile="astrid",
                runtime_checkout=str(tmp_path),
                source_checkout=str(tmp_path),
            )),
            client=object(),
            destination=tmp_path / "candidate",
            backup=tmp_path / "backup",
            confirmation="RELOCATE realm-1",
        )
    except RelocationError as exc:
        assert "birth-checked stop handoff" in str(exc)
    else:
        raise AssertionError("live relocation must remain gated")

    assert paths.catalog_path.read_bytes() == before
    assert not (tmp_path / "candidate").exists()
    assert not (tmp_path / "backup").exists()


class _StoppedBoundary:
    def prepare_restart(self, **_kwargs):
        return None

    def stop_owner(self, **_kwargs):
        return {"status": "stopped"}


def _config(tmp_path, runtime_environment=None):
    return BootstrapConfig(source_profile=SourceProfile(
        profile="astrid",
        runtime_checkout=str(tmp_path),
        source_checkout=str(tmp_path),
        runtime_environment=runtime_environment,
    ))


def test_relocation_moves_support_root_and_preserves_catalog_realms(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    paths.ensure_support_dirs()
    old_support = paths.app_support
    current = paths.realms_dir / "realm-1"
    other = paths.realms_dir / "realm-2"
    current.mkdir()
    other.mkdir()
    environment = old_support / "runtime-environments" / "astrid"
    environment.mkdir(parents=True)
    catalog = {
        "version": 1,
        "realms": [
            {"realm_id": "realm-1", "display_name": "One", "data_root": str(current)},
            {"realm_id": "realm-2", "display_name": "Two", "data_root": str(other)},
        ],
        "selected_realm_id": "realm-1",
        "source_profiles": {"astrid": {"profile": "astrid", "runtime_checkout": str(tmp_path), "source_checkout": str(tmp_path), "runtime_environment": str(environment), "runtime_command": []}},
    }
    paths.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    (paths.source_profiles_dir / "astrid.json").write_text(json.dumps(catalog["source_profiles"]["astrid"]), encoding="utf-8")
    paths.discovery_path.write_text(json.dumps({"pid": 1234, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1", "runtime_instance_id": "instance", "process_birth_id": "birth"}), encoding="utf-8")
    destination = tmp_path / "Astrid" / ".astrid-data"
    destination.parent.mkdir()

    def cold_start(target_paths, boundary, config):
        assert config.source_profile.runtime_environment == str(destination / "runtime-environments" / "astrid")
        with target_paths.bootstrap_lock_path.open("a+") as lock:
            with pytest.raises(BlockingIOError):
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return BootstrapResult("started", "realm-1", "One", "http://127.0.0.1:1", "actor", "astrid")

    monkeypatch.setattr("banodoco_local.relocation._bootstrap_locked", cold_start)
    result = relocate(paths, _StoppedBoundary(), _config(tmp_path, str(environment)), object(), destination=destination, backup=tmp_path / "unused-backup", confirmation="RELOCATE realm-1")

    assert result["status"] == "relocated"
    moved = json.loads((destination / "runtime" / "catalog.json").read_text())
    assert [row["realm_id"] for row in moved["realms"]] == ["realm-1", "realm-2"]
    assert all(str(destination) in row["data_root"] for row in moved["realms"])
    assert moved["source_profiles"]["astrid"]["runtime_environment"] == str(destination / "runtime-environments" / "astrid")
    assert not old_support.exists()


def test_relocation_restores_old_support_root_when_cutover_fails(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "support")
    paths.ensure_support_dirs()
    current = paths.realms_dir / "realm-1"
    current.mkdir()
    catalog = {"version": 1, "realms": [{"realm_id": "realm-1", "display_name": "Realm", "data_root": str(current)}], "selected_realm_id": "realm-1", "source_profiles": {}}
    paths.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    paths.discovery_path.write_text(json.dumps({"pid": 1234, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:1", "runtime_instance_id": "instance", "process_birth_id": "birth"}), encoding="utf-8")
    before = paths.catalog_path.read_bytes()
    destination = tmp_path / "Astrid" / ".astrid-data"
    destination.parent.mkdir()
    monkeypatch.setattr("banodoco_local.relocation._bootstrap_locked", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected cold-start failure")))

    try:
        relocate(paths, _StoppedBoundary(), _config(tmp_path), object(), destination=destination, backup=tmp_path / "unused-backup", confirmation="RELOCATE realm-1")
    except RelocationError as exc:
        assert "rolled back" in str(exc)
    else:
        raise AssertionError("failed cutover should roll back")

    assert paths.app_support.exists()
    assert not destination.exists()
    assert paths.catalog_path.read_bytes() == before
