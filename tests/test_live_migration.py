from __future__ import annotations

import json
from dataclasses import replace

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import (
    LIVE_AUTHORIZATION_IDS,
    LiveMigration,
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


@pytest.mark.parametrize("authorization_id", LIVE_AUTHORIZATION_IDS)
def test_b12_rejects_scope_mismatch_for_each_operation(tmp_path, authorization_id):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        other_id = next(item for item in LIVE_AUTHORIZATION_IDS if item != authorization_id)
        authorizations[authorization_id] = {
            **authorizations[authorization_id],
            "scope": other_id.removeprefix("AUTH-").lower(),
        }
        migration = LiveMigration(_config(source, tmp_path), active, authorizations, writer_stop=lambda: {"stopped": True})
        with pytest.raises(MigrationError, match="scope"):
            migration._validate_authorization(authorization_id, source_manifest_sha256=None, realm_id=active.realm["id"])
    finally:
        active.close()


@pytest.mark.parametrize(
    "crash_at",
    [
        "after_active_backup",
        "after_migration",
        "after_destination_backup",
        "after_candidate_restore",
        "after_active_activation",
        "after_rollback_restore",
        "after_rollback_activation",
        "after_reactivation_restore",
        "after_reactivation_activation",
    ],
)
def test_b12_live_migration_resumes_after_each_durable_crash_seam(tmp_path, crash_at):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        with pytest.raises(MigrationError, match="injected rehearsal crash"):
            run_live_migration(
                config,
                active,
                authorizations,
                writer_stop=lambda: {"stopped": True},
                crash_at=crash_at,
            )
        resumed = run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
        assert resumed["journal"]["state"] == "reactivated"
        assert [entry["to"] for entry in resumed["journal"]["entries"]] == ["active", "rolled_back", "reactivated"]
    finally:
        active.close()


def test_b12_terminal_replay_is_bound_to_exact_request_and_final_identity(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        first = run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
        assert run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})["idempotent"] is True

        conflicting_auth = {key: dict(value) for key, value in authorizations.items()}
        conflicting_auth["AUTH-LIVE-INPUT-B12"]["nonce"] = "different-request"
        with pytest.raises(MigrationError, match="durable authorization"):
            run_live_migration(config, active, conflicting_auth, writer_stop=lambda: {"stopped": True})

        conflicting_config = replace(config, destination_root=tmp_path / "another-destination")
        with pytest.raises(MigrationError, match="realm or destination binding"):
            run_live_migration(conflicting_config, active, authorizations, writer_stop=lambda: {"stopped": True})

        (source / "late-write.txt").write_text("changed after completion\n", encoding="utf-8")
        with pytest.raises(MigrationError, match="frozen source manifest"):
            run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
        assert first["identity"]["realm_id"] == active.realm["id"]
    finally:
        active.close()


def test_b12_terminal_replay_rejects_wal_only_active_mutation(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = issue_live_authorizations(selected_realm_id=active.realm["id"])
        run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})

        # Leave the committed mutation in WAL; do not checkpoint it into the
        # main database file. Terminal replay must still see this live state.
        active.store.conn.execute("UPDATE projects SET name = ?", ("tampered-after-reactivation",))
        active.store.conn.commit()
        with pytest.raises(MigrationError, match="active final identity"):
            run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
    finally:
        active.close()


def test_b12_destination_must_not_preexist_even_empty_or_be_symlink(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    active = RuntimeService(tmp_path / "active")
    try:
        empty_destination = config_destination = tmp_path / "destination"
        empty_destination.mkdir()
        with pytest.raises(MigrationError, match="fresh"):
            run_live_migration(_config(source, tmp_path), active, issue_live_authorizations(selected_realm_id=active.realm["id"]), writer_stop=lambda: {"stopped": True})

        symlink_destination = tmp_path / "symlink-destination"
        symlink_destination.symlink_to(tmp_path / "not-created")
        symlink_config = replace(_config(source, tmp_path), destination_root=symlink_destination)
        with pytest.raises(MigrationError, match="fresh"):
            run_live_migration(symlink_config, active, issue_live_authorizations(selected_realm_id=active.realm["id"]), writer_stop=lambda: {"stopped": True})
    finally:
        active.close()
