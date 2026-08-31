from __future__ import annotations

import json
from pathlib import Path

import pytest

from banodoco_local.bootstrap import (
    BootstrapConfig,
    LEGACY_NEXT_ACTION,
    LegacyRootCollisionError,
    SourceProfile,
    _canonical_json,
    _verified_activation_manifest,
    bootstrap,
)
from banodoco_local.io import atomic_write_json
from banodoco_local.paths import RuntimePaths
from tools.astrid_migrate import MigrationConfig, RuntimeServiceAdapter, build_synthetic_fixture, migrate
from runtime_protocol.service import RuntimeService


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
)


class CountingBoundary:
    def __init__(self):
        self.starts = 0

    def start(self, **kwargs):  # pragma: no cover - invalid proofs must not call this
        self.starts += 1
        raise AssertionError("bootstrap started before activation proof verification")

    def connect(self, **kwargs):
        raise AssertionError("unexpected connection")

    def health(self, **kwargs):
        return False

    def validate_owner(self, **kwargs):
        return False

    def is_pid_alive(self, pid):
        return False


def _prepare(tmp_path: Path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    archive = tmp_path / "archive"
    destination = tmp_path / "destination"
    paths = RuntimePaths.sandbox(tmp_path / "support")
    runtime = RuntimeService(destination, realm_id="realm-proof")
    try:
        migrate(
            MigrationConfig(
                source,
                archive,
                destination,
                activation_registry_root=paths.activations_dir,
            ),
            RuntimeServiceAdapter(runtime),
        )
    finally:
        runtime.close()
    atomic_write_json(
        paths.catalog_path,
        {
            "version": 1,
            "selected_realm_id": "realm-proof",
            "realms": [{"realm_id": "realm-proof", "display_name": "Proof", "data_root": str(destination.resolve())}],
            "source_profiles": {},
        },
    )
    (paths.home / ".astrid").mkdir()
    return paths, archive, destination


def _resign(record: dict) -> None:
    unsigned = {key: value for key, value in record.items() if key != "registry_sha256"}
    record["registry_sha256"] = __import__("hashlib").sha256(_canonical_json(unsigned)).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    ["empty_digest", "destination", "archive", "report", "database", "cas", "missing_registry", "dangling_legacy"],
)
def test_legacy_collision_rejects_every_mutated_activation_before_start(tmp_path, mutation):
    paths, archive, destination = _prepare(tmp_path)
    registry = paths.activations_dir / "realm-proof.json"
    record = json.loads(registry.read_text())
    if mutation == "empty_digest":
        record["migration_report_sha256"] = ""
        _resign(record)
        registry.write_text(json.dumps(record))
    elif mutation == "destination":
        record["destination_root"] = str((tmp_path / "swapped-destination").resolve())
        _resign(record)
        registry.write_text(json.dumps(record))
    elif mutation == "archive":
        manifest = archive / "manifest.json"
        value = json.loads(manifest.read_text())
        value["source_version"] = "forged"
        manifest.write_text(json.dumps(value))
    elif mutation == "report":
        (destination / "migration-report.json").write_text("{}")
    elif mutation == "database":
        db = destination / "realm.sqlite3"
        db.write_bytes(db.read_bytes() + b"tampered")
    elif mutation == "cas":
        cas_files = tuple(path for path in (destination / "cas").rglob("*") if path.is_file())
        if cas_files:
            cas_files[0].write_bytes(cas_files[0].read_bytes() + b"tampered")
        else:  # The fixture normally has objects; retain a hostile mutation if it does not.
            (destination / "cas" / "forged").write_bytes(b"forged")
    elif mutation == "missing_registry":
        registry.unlink()
    elif mutation == "dangling_legacy":
        legacy = paths.home / ".astrid"
        legacy.rmdir()
        legacy.symlink_to(paths.home / "missing-legacy-root")
        registry.unlink()

    boundary = CountingBoundary()
    with pytest.raises(LegacyRootCollisionError) as error:
        bootstrap(paths, boundary, BootstrapConfig(source_profile=PROFILE))
    assert boundary.starts == 0
    assert LEGACY_NEXT_ACTION.format(legacy_root=paths.home / ".astrid") in str(error.value)


def test_verified_activation_allows_completed_migration_and_restart(tmp_path):
    paths, _archive, _destination = _prepare(tmp_path)
    assert _verified_activation_manifest(paths) is True
    # A valid proof waives only the historical root collision; the boundary is
    # then allowed to own the already-catalogued realm.
    class Boundary:
        def start(self, **kwargs):
            kwargs["realm_root"].mkdir(parents=True, exist_ok=True)
            return {"endpoint": "http://127.0.0.1:1", "pid": 1, "runtime_instance_id": "proof", "protocol_version": "workspace.v1", "schema_version": "workspace-schema-v1"}
        def connect(self, **kwargs):
            return object()
        def health(self, **kwargs): return True
        def validate_owner(self, **kwargs): return False
        def is_pid_alive(self, pid): return False

    result = bootstrap(paths, Boundary(), BootstrapConfig(source_profile=PROFILE))
    assert result.status == "started"


def test_verified_activation_is_required_even_for_dangling_legacy_root(tmp_path):
    paths, _archive, _destination = _prepare(tmp_path)
    legacy = paths.home / ".astrid"
    legacy.rmdir()
    legacy.symlink_to(paths.home / "missing-legacy-root")
    assert _verified_activation_manifest(paths) is True
