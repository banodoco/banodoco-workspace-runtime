from __future__ import annotations

import json
from pathlib import Path

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
from tools.astrid_migrate.live import LiveMigration
from tools.astrid_migrate.operator import _parser
from tools.astrid_migrate.rehearsal import MigrationJournal


def _setup(tmp_path: Path, *, redundancy: str = "compact", margin: int | None = 0):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", evidence_root=tmp_path / "evidence", capacity_margin_bytes=margin, redundancy=redundancy)
    config.evidence_root.mkdir()
    active = RuntimeService(tmp_path / "active")
    auth = issue_live_authorizations(source_manifest_sha256=Migrator(config, None).inventory()["source_manifest_sha256"], selected_realm_id=active.realm["id"])
    return config, active, auth


def test_compact_journey_reuses_signed_destination_backup_without_restore_siblings(tmp_path):
    config, active, auth = _setup(tmp_path)
    before = json.dumps(sorted(str(path.relative_to(config.source_root)) for path in config.source_root.rglob("*")), sort_keys=True)
    try:
        report = run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True})
        assert report["journal"]["state"] == "reactivated"
        binding = report["journal"]["binding"]
        assert binding["redundancy"] == "compact"
        active_effect = next(effect for effect in report["journal"]["effects"] if effect["name"] == "active-activation")
        assert active_effect["payload"]["candidate"].endswith("archive-live-destination-backup")
        assert not (tmp_path / "archive-live-candidate").exists()
        assert not (tmp_path / "archive-live-reactivated").exists()
        assert not list(tmp_path.glob(".active.inactive-*"))
        assert before == json.dumps(sorted(str(path.relative_to(config.source_root)) for path in config.source_root.rglob("*")), sort_keys=True)
    finally:
        active.close()


def test_extreme_journey_keeps_historical_restore_trees(tmp_path):
    config, active, auth = _setup(tmp_path, redundancy="extreme")
    try:
        report = run_live_migration(config, active, auth, writer_stop=lambda: {"stopped": True})
        assert report["journal"]["binding"]["redundancy"] == "extreme"
        assert (tmp_path / "archive-live-candidate").is_dir()
        assert (tmp_path / "archive-live-reactivated").is_dir()
        assert len(list(tmp_path.glob(".active.inactive-*"))) == 3
    finally:
        active.close()


def test_capacity_split_uses_compact_margin_and_charges_activation_temp(tmp_path):
    config, active, auth = _setup(tmp_path, margin=None)
    try:
        migration = LiveMigration(config, active, auth, writer_stop=lambda: {"stopped": True})
        receipt = migration._capacity(Migrator(config, None).inventory(), config.evidence_root)
        components = receipt
        assert components["redundancy"] == "compact"
        assert components["candidate_bytes"] == 0
        assert components["reactivation_bytes"] == 0
        assert components["margin_bytes"] == int(components["source_bytes"] * 0.2)
        assert components["activation_temp_bytes"] > 0
        assert any("activation_temp" in domain["roots"] for domain in receipt["domains"])
    finally:
        active.close()


def test_legacy_prepared_journal_cannot_be_rebound_to_compact(tmp_path):
    config, active, auth = _setup(tmp_path)
    try:
        journal = MigrationJournal(config.evidence_root / "migration-journal-b12.json")
        source_manifest = next(iter(auth.values()))["source_manifest_sha256"]
        legacy = {
            "realm_id": active.realm["id"],
            "source_manifest_sha256": source_manifest,
            "source_root": str(config.source_root),
            "archive_root": str(config.archive_root),
            "destination_root": str(config.destination_root),
            "evidence_root": str(config.evidence_root),
            "authorization_nonce_sha256": {key: LiveMigration._nonce_digest(value) for key, value in auth.items()},
        }
        journal.bind(**legacy)
        migration = LiveMigration(config, active, auth, writer_stop=lambda: {"stopped": True})
        with pytest.raises(MigrationError, match="legacy B12 journal"):
            migration._bind_request(journal, realm_id=active.realm["id"], source_manifest_sha256=source_manifest, evidence_root=config.evidence_root)
    finally:
        active.close()


def test_operator_parser_defaults_compact_and_accepts_extreme():
    args = _parser().parse_args(["live-migrate", "--source-root", "s", "--active-root", "a", "--support-root", "p", "--archive-root", "c", "--destination-root", "d", "--evidence-root", "e", "--realm-id", "r", "--authorization-file", "x", "--writer-stop-receipt", "w", "--confirm", "MIGRATE LIVE ASTRID"])
    assert args.redundancy == "compact"
    extreme = _parser().parse_args(["live-migrate", "--source-root", "s", "--active-root", "a", "--support-root", "p", "--archive-root", "c", "--destination-root", "d", "--evidence-root", "e", "--realm-id", "r", "--authorization-file", "x", "--writer-stop-receipt", "w", "--confirm", "MIGRATE LIVE ASTRID", "--redundancy", "extreme"])
    assert extreme.redundancy == "extreme"
