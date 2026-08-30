from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import MigrationConfig, MigrationError, RuntimeServiceAdapter, build_synthetic_fixture, run_rehearsal


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


@pytest.mark.parametrize(
    "seam",
    (
        "after_active_to_rolled_back",
        "before_rolled_back_to_reactivated",
        "after_rolled_back_to_reactivated",
    ),
)
def test_b10_restart_resumes_from_durable_journal_at_transition_seams(tmp_path, seam):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    runtime_root = tmp_path / "destination"
    archive_root = tmp_path / "source-archive"
    rollback_root = tmp_path / "rollback"
    evidence_root = tmp_path / "evidence"

    runtime = RuntimeService(runtime_root, display_name="B10 disposable")
    try:
        with pytest.raises(MigrationError, match=f"injected rehearsal crash at {seam}"):
            run_rehearsal(
                MigrationConfig(source, archive_root, runtime_root, evidence_root=evidence_root, capacity_margin_bytes=0),
                RuntimeServiceAdapter(runtime),
                runtime=runtime,
                rollback_root=rollback_root,
                crash_at=seam,
            )
    finally:
        runtime.close()

    # A restart opens the configured destination path, which is the authority
    # that the activation handoff selected.  Resume must consume the journal
    # suffix and must not replay migration or attempt rolled_back -> active.
    runtime = RuntimeService(runtime_root, display_name="B10 disposable")
    try:
        resumed = run_rehearsal(
            MigrationConfig(source, archive_root, runtime_root, evidence_root=evidence_root, capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime),
            runtime=runtime,
            rollback_root=rollback_root,
        )
        assert resumed["journal"]["state"] == "reactivated"
        assert resumed["idempotent_reactivation"] is True
        transitions = [(entry["from"], entry["to"]) for entry in resumed["journal"]["entries"]]
        assert transitions == [("prepared", "active"), ("active", "rolled_back"), ("rolled_back", "reactivated")]
    finally:
        runtime.close()
