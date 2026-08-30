from __future__ import annotations

import json
from pathlib import Path

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import MigrationConfig, RuntimeServiceAdapter, build_synthetic_fixture, run_rehearsal


def test_b10_rehearsal_preserves_evidence_and_reactivates_idempotently(tmp_path):
    source = tmp_path / "legacy-clone"
    fixture = build_synthetic_fixture(source)
    runtime_root = tmp_path / "destination"
    archive_root = tmp_path / "source-archive"
    rollback_root = tmp_path / "rollback"
    evidence_root = tmp_path / "evidence"
    runtime = RuntimeService(runtime_root, display_name="B10 disposable")
    try:
        report = run_rehearsal(
            MigrationConfig(source, archive_root, runtime_root, evidence_root=evidence_root, capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime),
            runtime=runtime,
            rollback_root=rollback_root,
        )
    finally:
        runtime.close()

    assert report["packet"] == "B10"
    assert report["source_freeze"]["source_manifest_sha256"] == report["migration"]["inventory"]["source_manifest_sha256"]
    assert report["reconciliation"]["source_tree_sha256"] == fixture.source_tree_sha256
    assert report["reconciliation"]["backup_verified"] is True
    assert report["reconciliation"]["restore_verified"] is True
    assert report["journal"]["state"] == "reactivated"
    assert report["idempotent_reactivation"] is True
    assert report["journal"]["entries"][-2]["to"] == "rolled_back"
    assert json.loads((evidence_root / "source-freeze-b10.json").read_text())["packet"] == "B10.1"
    assert json.loads((evidence_root / "capacity-receipt-b10.json").read_text())["reserved"] is True
    assert json.loads((evidence_root / "reconciliation-b10.json").read_text())["source_counts"]["projects"] == 1
    assert (archive_root / "manifest.json").is_file()
    assert (rollback_root / "activation-handoff.json").is_file()


def test_b10_journal_rejects_skipping_rollback(tmp_path):
    from tools.astrid_migrate import MigrationJournal, MigrationError

    journal = MigrationJournal(tmp_path / "journal.json")
    journal.transition("active")
    try:
        journal.transition("reactivated")
    except MigrationError as exc:
        assert "active -> reactivated" in str(exc)
    else:
        raise AssertionError("journal allowed reactivation without rollback")
