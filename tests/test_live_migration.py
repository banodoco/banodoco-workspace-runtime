from __future__ import annotations

import json

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import (
    MigrationConfig,
    MigrationError,
    Migrator,
    build_synthetic_fixture,
    issue_live_authorizations,
    run_live_migration,
)


def _config(source, tmp_path):
    return MigrationConfig(
        source,
        tmp_path / "archive",
        tmp_path / "destination",
        evidence_root=tmp_path / "evidence",
        capacity_margin_bytes=0,
    )


def test_b12_live_migration_freezes_migrates_rolls_back_and_reactivates(tmp_path):
    source = tmp_path / "source"
    fixture = build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active", display_name="selected realm")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        report = run_live_migration(
            config,
            active,
            authorizations,
            writer_stop=lambda: {"stopped": True, "writer_count": 0},
        )
        assert report["packet"] == "B12"
        assert report["source_freeze"]["source_manifest_sha256"] == report["migration"]["inventory"]["source_manifest_sha256"]
        assert report["source_freeze"]["source_tree_sha256"] == fixture.source_tree_sha256
        assert report["reconciliation"]["ok"] is True
        assert report["journal"]["state"] == "reactivated"
        assert [entry["to"] for entry in report["journal"]["entries"]] == ["active", "rolled_back", "reactivated"]
        assert report["identity"]["activation_epoch"] == 3
        assert report["identity"]["realm_id"] == active.realm["id"]
        assert report["final_snapshot"]["projects"]
        assert (config.archive_root.parent / "archive-live-pre-migration-backup" / "manifest.json").is_file()
        assert (config.archive_root.parent / "archive-live-destination-backup" / "manifest.json").is_file()
        assert (active.store.root / "activation-manifest.json").is_file()
        assert json.loads((config.evidence_root / "activated-destination-b12.json").read_text())["activation_epoch"] == 3
    finally:
        active.close()


def test_b12_bound_authorization_rejects_source_write_after_writer_stop(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    expected_source_manifest = Migrator(config, None).inventory()["source_manifest_sha256"]
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(
            source_manifest_sha256=expected_source_manifest,
            selected_realm_id=active.realm["id"],
        )

        def writer_stop():
            (source / "writer-race.txt").write_text("late writer\n", encoding="utf-8")
            return {"stopped": True}

        with pytest.raises(MigrationError, match="source manifest"):
            run_live_migration(config, active, authorizations, writer_stop=writer_stop)
        assert not config.destination_root.exists()
        assert not (config.evidence_root / "migration-receipt-b12.json").exists()
    finally:
        active.close()


def test_b12_requires_explicit_writer_stop_boundary(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        with pytest.raises(MigrationError, match="stopped=true"):
            run_live_migration(
                _config(source, tmp_path),
                active,
                authorizations,
                writer_stop=lambda: {"stopped": False},
            )
    finally:
        active.close()
