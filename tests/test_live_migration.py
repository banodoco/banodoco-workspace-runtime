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


def _auth(config, active):
    source_manifest = Migrator(config, None).inventory()["source_manifest_sha256"]
    return issue_live_authorizations(source_manifest_sha256=source_manifest, selected_realm_id=active.realm["id"])


def test_b12_live_migration_freezes_migrates_rolls_back_and_reactivates(tmp_path):
    source = tmp_path / "source"
    fixture = build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active", display_name="selected realm")
    try:
        authorizations = _auth(config, active)
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
        authorizations = _auth(_config(source, tmp_path), active)
        with pytest.raises(MigrationError, match="stopped=true"):
            run_live_migration(
                _config(source, tmp_path),
                active,
                authorizations,
                writer_stop=lambda: {"stopped": False},
            )
    finally:
        active.close()


def test_b12_authorizations_require_realm_and_exact_source_manifest(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    active = RuntimeService(tmp_path / "active")
    try:
        with pytest.raises(ValueError, match="exact source manifest"):
            issue_live_authorizations(selected_realm_id=active.realm["id"])
        with pytest.raises(ValueError, match="selected realm"):
            issue_live_authorizations(source_manifest_sha256="a" * 64)
    finally:
        active.close()


def test_b12_writer_stop_completion_file_prevents_a_second_external_stop(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    calls = []

    def writer_stop():
        calls.append("stop")
        return {"stopped": True, "writer_count": 0}

    def fail_before_writer_effect(seam):
        if seam == "before_effect_writer-stop":
            raise MigrationError("injected rehearsal crash")

    try:
        auth = _auth(config, active)
        with pytest.raises(MigrationError, match="injected rehearsal crash"):
            run_live_migration(config, active, auth, writer_stop=writer_stop, fault_injector=fail_before_writer_effect)
        resumed = run_live_migration(config, active, auth, writer_stop=writer_stop)
        assert resumed["journal"]["state"] == "reactivated"
        assert calls == ["stop"]
    finally:
        active.close()


def test_b12_destination_parent_symlink_is_rejected_before_any_write(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    parent = tmp_path / "destination-parent"
    outside = tmp_path / "outside"
    outside.mkdir()
    parent.symlink_to(outside, target_is_directory=True)
    config = replace(_config(source, tmp_path), destination_root=parent / "destination")
    active = RuntimeService(tmp_path / "active")
    try:
        with pytest.raises(MigrationError, match="symlink"):
            run_live_migration(config, active, _auth(config, active), writer_stop=lambda: {"stopped": True})
        assert not (outside / "destination").exists()
    finally:
        active.close()


@pytest.mark.parametrize("swap_mode", ["symlink", "replacement"])
def test_b12_active_backup_parent_swap_fails_closed_before_material_write(tmp_path, swap_mode):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    archive_parent = tmp_path / "archive-parent"
    archive_parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    config = replace(_config(source, tmp_path), archive_root=archive_parent / "archive")
    active = RuntimeService(tmp_path / "active")

    def swap_parent(seam):
        if seam == "before_active_backup":
            archive_parent.rename(tmp_path / "archive-parent-real")
            if swap_mode == "symlink":
                archive_parent.symlink_to(outside, target_is_directory=True)
            else:
                archive_parent.mkdir()

    try:
        with pytest.raises(MigrationError, match="symlink|identity|material"):
            run_live_migration(config, active, _auth(config, active), writer_stop=lambda: {"stopped": True}, fault_injector=swap_parent)
        assert not (outside / "archive-live-pre-migration-backup").exists()
    finally:
        active.close()


def test_b12_reconciliation_rechecks_destination_after_migration_callback(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        auth = _auth(config, active)

        def tamper_after_migration(seam):
            if seam == "after_migration":
                import sqlite3
                connection = sqlite3.connect(config.destination_root / "realm.sqlite3")
                try:
                    connection.execute("UPDATE projects SET name='post-migration-tamper'")
                    connection.commit()
                finally:
                    connection.close()

        with pytest.raises(MigrationError, match="reconciliation"):
            run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True}, fault_injector=tamper_after_migration)
    finally:
        active.close()


def test_b12_reconciliation_does_not_repair_a_deleted_destination_on_resume(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        auth = _auth(config, active)
        with pytest.raises(MigrationError, match="injected rehearsal crash"):
            run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True}, crash_at="after_migration")
        import sqlite3
        connection = sqlite3.connect(config.destination_root / "realm.sqlite3")
        try:
            # The native destination allocates its own project identity; bind
            # the adversarial mutation to the imported source slug rather
            # than assuming the legacy source primary key is reused.
            connection.execute("DELETE FROM projects WHERE slug='demo'")
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(MigrationError, match="destination changed"):
            run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True})
        connection = sqlite3.connect(config.destination_root / "realm.sqlite3")
        try:
            assert connection.execute("SELECT count(*) FROM projects WHERE slug='demo'").fetchone()[0] == 0
        finally:
            connection.close()
    finally:
        active.close()


@pytest.mark.parametrize("authorization_id", LIVE_AUTHORIZATION_IDS)
def test_b12_rejects_scope_mismatch_for_each_operation(tmp_path, authorization_id):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = _auth(_config(source, tmp_path), active)
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
        authorizations = _auth(config, active)
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
        authorizations = _auth(config, active)
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


def test_b12_terminal_replay_survives_a_runtime_process_reopen(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = _auth(config, active)
        run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
        root = active.store.root
        display_name = active.realm["display_name"]
        realm_id = active.realm["id"]
        active.close()
        active = RuntimeService(root, display_name=display_name, realm_id=realm_id)
        replay = run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
        assert replay["idempotent"] is True
    finally:
        active.close()


def test_b12_terminal_replay_rejects_wal_only_active_mutation(tmp_path):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        authorizations = _auth(config, active)
        run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})

        # Leave the committed mutation in WAL; do not checkpoint it into the
        # main database file. Terminal replay must still see this live state.
        active.store.conn.execute("UPDATE projects SET name = ?", ("tampered-after-reactivation",))
        active.store.conn.commit()
        with pytest.raises(MigrationError, match="active final identity"):
            run_live_migration(config, active, authorizations, writer_stop=lambda: {"stopped": True})
    finally:
        active.close()


@pytest.mark.parametrize("artifact", ["cas", "activation", "backup"])
def test_b12_terminal_replay_verifies_content_and_control_artifacts(tmp_path, artifact):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = _config(source, tmp_path)
    active = RuntimeService(tmp_path / "active")
    try:
        auth = _auth(config, active)
        run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True})
        if artifact == "cas":
            digest = next(active.store.conn.execute("SELECT digest FROM objects"))[0]
            cas_path = active.store.cas_root / digest[:2] / digest[2:]
            cas_path.write_bytes(b"corrupted-cas")
        elif artifact == "activation":
            activation_path = active.store.root / "activation-manifest.json"
            activation_path.write_text("{}\n", encoding="utf-8")
        else:
            manifest = config.archive_root.parent / "archive-live-destination-backup" / "manifest.json"
            manifest.write_text(manifest.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
        with pytest.raises(MigrationError):
            run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True})
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
            config = _config(source, tmp_path)
            run_live_migration(config, active, _auth(config, active), writer_stop=lambda: {"stopped": True})

        symlink_destination = tmp_path / "symlink-destination"
        symlink_destination.symlink_to(tmp_path / "not-created")
        symlink_config = replace(_config(source, tmp_path), destination_root=symlink_destination)
        with pytest.raises(MigrationError, match="fresh"):
            run_live_migration(symlink_config, active, _auth(symlink_config, active), writer_stop=lambda: {"stopped": True})
    finally:
        active.close()
