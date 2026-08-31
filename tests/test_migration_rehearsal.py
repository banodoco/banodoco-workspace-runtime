from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import MigrationConfig, MigrationError, Migrator, RuntimeServiceAdapter, build_synthetic_fixture, run_rehearsal


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


def test_b10_rehearsal_preserves_all_source_streams_and_relationships(tmp_path):
    source = tmp_path / "legacy-clone"
    fixture = build_synthetic_fixture(source)
    runtime = RuntimeService(tmp_path / "destination")
    try:
        report = run_rehearsal(
            MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime), runtime=runtime,
        )
        truth = report["reconciliation"]["destination_truth"]["truth"]
        assert len(truth["event_streams"]) == 4
        assert {row["id"] for row in truth["event_streams"]} == {"stream-project", "stream-tl", "stream-run", "stream-task"}
        assert len(truth["event_mappings"]) == 2
        assert {(row["source_event_id"], row["source_stream_id"], row["destination_stream_id"]) for row in truth["event_mappings"]} == {
            ("event-project", "stream-project", "stream-project"),
            ("event-task", "stream-task", "stream-task"),
        }
        assert report["reconciliation"]["destination_truth"]["ok"] is True
    finally:
        runtime.close()


def test_b10_owner_data_preserves_every_row_identity_order_and_digest(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    runtime = RuntimeService(tmp_path / "destination")
    try:
        report = run_rehearsal(
            MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime), runtime=runtime,
        )
        rows = report["reconciliation"]["destination_truth"]["truth"]["owner_data"]
        assert len(rows) == 12
        assert {row["source_table"] for row in rows} == {
            "media_references", "media_relations", "reference_links", "generation_variants",
            "shot_items", "task_dependencies", "task_outputs", "execution_attempts",
            "command_receipts", "evidence_items", "runaway_transitions",
        }
        assert all(len(row["row_sha256"]) == 64 for row in rows)
        assert rows == sorted(rows, key=lambda row: (row["source_table"], row["source_ordinal"], row["source_key"]))
        relation_keys = [json.loads(row["row_json"]) for row in rows if row["source_table"] == "media_relations"]
        assert [(row["from_media_id"], row["to_media_id"], row["kind"], row["ordinal"]) for row in relation_keys] == [
            ("media-1", "media-1", "derived", 0), ("media-1", "media-1", "derived", 1),
        ]
    finally:
        runtime.close()


def test_b10_owner_data_missing_fk_fails_before_destination_write(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    db = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("UPDATE media_references SET media_id='missing-media' WHERE id='media-ref-1'")
    db.commit()
    db.close()
    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="integrity/foreign-key preflight"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                RuntimeServiceAdapter(runtime), runtime=runtime,
            )
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM migration_owner_records").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_owner_data_truncation_fails_reconciliation(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)

    class TruncatingAdapter(RuntimeServiceAdapter):
        def destination_snapshot(self):
            snapshot = super().destination_snapshot()
            snapshot["owner_data"] = snapshot["owner_data"][:-1]
            return snapshot

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="reconciliation failed"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                TruncatingAdapter(runtime), runtime=runtime,
            )
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM migration_owner_records").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_rehearsal_rejects_omitted_source_stream(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)

    class OmittingAdapter(RuntimeServiceAdapter):
        def import_event_stream(self, stream, **kwargs):
            if stream.get("id") == "stream-tl":
                return {"skipped": True}
            return super().import_event_stream(stream, **kwargs)

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="reconciliation failed"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                OmittingAdapter(runtime), runtime=runtime,
            )
        # Rehearsal cleanup removes the incomplete destination ledger; the
        # failed migration must not leave a partially imported stream graph.
        rows = runtime.store.conn.execute("SELECT source_stream_id FROM migration_event_streams").fetchall()
        assert rows == []
    finally:
        runtime.close()


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


class _RawLedgerWrapper:
    """Expose a tampered verification view beside an untouched raw authority."""

    def __init__(self, raw, *, events=None, streams=None):
        self.raw = raw
        self.visible = dict(raw)
        if events is not None:
            self.visible["events"] = events
        if streams is not None:
            self.visible["event_streams"] = streams

    def destination_verification(self):
        return self.visible

    def destination_raw_ledger(self):
        return {"events": self.raw["events"], "event_streams": self.raw["event_streams"]}


def _ledger_snapshot(events, streams):
    return {
        "projects": [], "timelines": [], "timeline_shots": [],
        "timeline_references": [], "objects": [], "generations": [],
        "runs": [], "tasks": [], "events": events, "event_streams": streams,
        "media_locations": [], "foreign_key_errors": [],
    }


def _ledger_migrator(wrapper):
    migrator = object.__new__(Migrator)
    migrator.client = wrapper
    migrator.config = SimpleNamespace(require_destination_verification=True)
    migrator._project_ids = {}
    return migrator


def _raw_ledger():
    events = [
        {"event_id": "event-1", "stream_id": "stream-1", "seq": 1, "kind": "project.created", "payload_json": "{}"},
        {"event_id": "event-2", "stream_id": "stream-2", "seq": 1, "kind": "task.admitted", "payload_json": "{\"capability\":\"render.basic\"}"},
    ]
    streams = [
        {"id": "stream-1", "stream_type": "project", "aggregate_id": "project-1", "head_seq": 1},
        {"id": "stream-2", "stream_type": "task", "aggregate_id": "task-1", "head_seq": 1},
    ]
    return _ledger_snapshot(events, streams)


def test_b10_raw_destination_verification_rejects_events_truncated_two_to_one():
    raw = _raw_ledger()
    wrapper = _RawLedgerWrapper(raw, events=raw["events"][:1])
    result = _ledger_migrator(wrapper)._destination_reconciliation({"events": raw["events"], "event_streams": raw["event_streams"]})
    assert result["ok"] is False
    assert any(error["reason"] == "destination event rows are truncated or expanded" for error in result["errors"])


def test_b10_raw_destination_verification_rejects_streams_truncated_two_to_one():
    raw = _raw_ledger()
    wrapper = _RawLedgerWrapper(raw, streams=raw["event_streams"][:1])
    result = _ledger_migrator(wrapper)._destination_reconciliation({"events": raw["events"], "event_streams": raw["event_streams"]})
    assert result["ok"] is False
    assert any(error["reason"] == "destination event stream rows are truncated or expanded" for error in result["errors"])


def test_b10_raw_destination_verification_rejects_unexpected_duplicate_event():
    raw = _raw_ledger()
    duplicate = dict(raw["events"][0], event_id="event-extra", kind="unexpected.event")
    wrapper = _RawLedgerWrapper(raw, events=[raw["events"][0], duplicate])
    result = _ledger_migrator(wrapper)._destination_reconciliation({"events": raw["events"], "event_streams": raw["event_streams"]})
    assert result["ok"] is False
    assert any(error["reason"] == "destination event ID set differs from raw ledger" for error in result["errors"])
    assert any(error["reason"] == "destination event kind set differs from raw ledger" for error in result["errors"])


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


def test_b10_strict_reconciliation_rejects_native_event_kind_loss():
    raw = _raw_ledger()
    # Both rows have native IDs, so this exercises the native branch where a
    # kind omitted entirely used to evade the old intersection-only check.
    visible = _ledger_snapshot([{"id": 1, "kind": raw["events"][0]["kind"], "payload_json": raw["events"][0]["payload_json"]}], raw["event_streams"])
    wrapper = _RawLedgerWrapper(raw, events=visible["events"], streams=visible["event_streams"])
    result = _ledger_migrator(wrapper)._destination_reconciliation({"events": raw["events"], "event_streams": raw["event_streams"]})
    assert result["ok"] is False
    assert any(error["reason"] == "destination event ledger is truncated" for error in result["errors"])


def test_b10_generation_fields_and_project_media_relationship_are_preserved(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    runtime = RuntimeService(tmp_path / "destination")
    try:
        report = run_rehearsal(MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0), RuntimeServiceAdapter(runtime), runtime=runtime)
        generation = next(row for row in report["reconciliation"]["destination_truth"]["truth"]["generations"] if row["id"] == "gen-1")
        task = report["reconciliation"]["destination_truth"]["truth"]["tasks"][0]
        assert generation["source_task_id"] == task["id"]
        assert generation["source_task_id"] != "task-1"
        assert json.loads(generation["metadata_json"])["legacy_name"] == "Opening generation"
        relationships = report["reconciliation"]["destination_truth"]["truth"]["project_objects"]
        assert len(relationships) == 1
        assert relationships[0]["relation"] == "generic"
    finally:
        runtime.close()


def test_b10_multiple_media_associations_use_primary_and_preserve_owner_rows(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    alternate = b"astrid-stage1-b10-alternate-media\n"
    (source / "media" / "alternate.bin").write_bytes(alternate)
    alternate_digest = hashlib.sha256(alternate).hexdigest()
    db = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    db.execute("UPDATE media_references SET is_primary=0 WHERE id='media-ref-1'")
    db.execute(
        "INSERT INTO media VALUES ('media-2','p-demo','generic','application/octet-stream',?,?,?,?)",
        (len(alternate), alternate_digest, "{}", "2026-01-01"),
    )
    db.execute("INSERT INTO media_locations VALUES ('loc-2','media-2','external_local','media/alternate.bin',NULL,'2026-01-01')")
    db.execute("INSERT INTO media_references VALUES ('media-ref-2','ref-1','media-2','alternate','task-1',1,1,'{}','2026-01-01')")
    db.commit()
    db.close()

    runtime = RuntimeService(tmp_path / "destination")
    try:
        report = run_rehearsal(
            MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime), runtime=runtime,
        )
        reference = report["reconciliation"]["destination_truth"]["truth"]["timeline_references"][0]
        assert reference["object_id"] == alternate_digest
        owner_rows = [
            json.loads(row["row_json"])
            for row in report["reconciliation"]["destination_truth"]["truth"]["owner_data"]
            if row["source_table"] == "media_references"
        ]
        assert [row["id"] for row in owner_rows] == ["media-ref-1", "media-ref-2"]
    finally:
        runtime.close()


def test_b10_reference_metadata_object_id_cannot_override_primary_media_association(tmp_path):
    source = tmp_path / "legacy-clone"
    fixture = build_synthetic_fixture(source)
    metadata_digest = "f" * 64
    db = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    db.execute("UPDATE project_references SET metadata_json=? WHERE id='ref-1'", (json.dumps({"object_id": metadata_digest}),))
    db.commit()
    db.close()

    runtime = RuntimeService(tmp_path / "destination")
    try:
        report = run_rehearsal(
            MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
            RuntimeServiceAdapter(runtime), runtime=runtime,
        )
        reference = report["reconciliation"]["destination_truth"]["truth"]["timeline_references"][0]
        assert reference["object_id"] == fixture.media_digest
        assert reference["object_id"] != metadata_digest
    finally:
        runtime.close()


def test_b10_explicit_zero_shot_duration_fails_closed_without_rewriting(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    db = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    db.execute("UPDATE shots SET metadata_json=? WHERE id='shot-1'", (json.dumps({"timeline_id": "tl-main", "duration_ms": 0}),))
    db.commit()
    db.close()

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="shot shot-1 has invalid timing"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                RuntimeServiceAdapter(runtime), runtime=runtime,
            )
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0
        assert not (tmp_path / "destination" / "activation-manifest.json").exists()
    finally:
        runtime.close()


@pytest.mark.parametrize(
    ("table", "column"),
    (
        ("generation_variants", "media_id"),
        ("shot_items", "media_id"),
        ("task_outputs", "media_id"),
        ("runaway_transitions", "run_id"),
    ),
)
@pytest.mark.parametrize("bad_value", [None, "missing-id", {"malformed": True}])
def test_b10_required_owner_foreign_keys_fail_closed_before_writes(tmp_path, table, column, bad_value):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    db = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    db.execute("PRAGMA foreign_keys=OFF")
    # SQLite cannot bind a mapping; the JSON object is intentionally a
    # malformed FK value rather than a string that could accidentally match.
    value = json.dumps(bad_value) if isinstance(bad_value, dict) else bad_value
    db.execute(f"UPDATE {table} SET {column}=?", (value,))
    db.commit()
    db.close()

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match=f"({table}.*foreign key|integrity/foreign-key preflight)"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                RuntimeServiceAdapter(runtime), runtime=runtime,
            )
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM migration_owner_records").fetchone()[0] == 0
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_reconciliation_rejects_tampered_generation_source_task_mapping(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)

    class TamperingAdapter(RuntimeServiceAdapter):
        def destination_snapshot(self):
            snapshot = super().destination_snapshot()
            if snapshot["generations"]:
                snapshot["generations"][0]["source_task_id"] = "evil-task"
            return snapshot

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="reconciliation failed"):
            run_rehearsal(
                MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0),
                TamperingAdapter(runtime), runtime=runtime,
            )
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_reconciliation_rejects_tampered_shot_mount(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)

    class TamperingAdapter(RuntimeServiceAdapter):
        def destination_snapshot(self):
            snapshot = super().destination_snapshot()
            if snapshot["timeline_shots"]:
                snapshot["timeline_shots"][0]["duration_ms"] += 1
            return snapshot

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="reconciliation failed"):
            run_rehearsal(MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0), TamperingAdapter(runtime), runtime=runtime)
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM timeline_shots").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_reconciliation_rejects_tampered_reference_object_identity(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)

    class TamperingAdapter(RuntimeServiceAdapter):
        def destination_snapshot(self):
            snapshot = super().destination_snapshot()
            if snapshot["timeline_references"]:
                snapshot["timeline_references"][0]["object_id"] = "0" * 64
            return snapshot

    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="reconciliation failed"):
            run_rehearsal(MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0), TamperingAdapter(runtime), runtime=runtime)
        assert runtime.store.conn.execute("SELECT COUNT(*) FROM timeline_references").fetchone()[0] == 0
    finally:
        runtime.close()


def test_b10_before_migration_mutation_rejected_against_freeze_receipt(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    runtime = RuntimeService(tmp_path / "destination")
    try:
        def mutate(seam):
            if seam == "before_migration":
                (source / ".astrid" / "preferences.json").write_text('{"selected_project":"changed"}\n')
        with pytest.raises(MigrationError, match="bound freeze receipt"):
            run_rehearsal(MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0), RuntimeServiceAdapter(runtime), runtime=runtime, fault_injector=mutate)
        assert not (tmp_path / "archive" / "manifest.json").exists()
        assert not (tmp_path / "destination" / "activation-manifest.json").exists()
    finally:
        runtime.close()


def test_b10_capacity_is_reserved_before_migration_writes(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    runtime = RuntimeService(tmp_path / "destination")
    try:
        with pytest.raises(MigrationError, match="capacity reservation"):
            run_rehearsal(MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=shutil.disk_usage(tmp_path).free + 1), RuntimeServiceAdapter(runtime), runtime=runtime)
        journal = json.loads((tmp_path / "destination" / "migration-journal.json").read_text())
        assert any(effect["name"] == "capacity_preflight_refused" for effect in journal["effects"])
        assert not (tmp_path / "destination" / "activation-manifest.json").exists()
    finally:
        runtime.close()


def test_b10_archive_manifest_binds_symlink_identity_and_retarget(tmp_path):
    source = tmp_path / "legacy-clone"
    build_synthetic_fixture(source)
    (source / "media" / "alias.bin").symlink_to("clip.bin")
    archive = tmp_path / "archive"
    first = Migrator(MigrationConfig(source, archive, tmp_path / "destination"), _FakeClientForSymlink())
    first._archive(first.inventory())
    (source / "media" / "alias.bin").unlink()
    (source / "media" / "alias.bin").symlink_to("missing.bin")
    with pytest.raises(MigrationError, match="does not match"):
        second = Migrator(MigrationConfig(source, archive, tmp_path / "destination-2"), _FakeClientForSymlink())
        second._archive(second.inventory())


def test_b10_tampered_restore_candidate_never_activates(tmp_path):
    runtime = RuntimeService(tmp_path / "destination")
    try:
        project = runtime.create_project({"name": "baseline", "slug": "baseline"})
        backup = runtime.backup(tmp_path / "backup")
        restored = runtime.restore(tmp_path / "backup", tmp_path / "candidate")
        db = sqlite3.connect(tmp_path / "candidate" / "realm.sqlite3")
        db.execute("INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at, idempotency_key) VALUES ('tampered', ?, 'tampered', 'Tampered', '{}', 1, 'now', 'now', NULL)", (project["realm_id"],))
        db.commit()
        db.close()
        adapter = RuntimeServiceAdapter(runtime)
        with pytest.raises(MigrationError, match="candidate failed verification"):
            adapter.activate_destination(tmp_path / "candidate", state="reactivated")
        assert runtime.get_project("baseline")["slug"] == "baseline"
    finally:
        runtime.close()


class _FakeClientForSymlink:
    def create_project(self, name, *, slug=None, metadata=None, idempotency_key=None, legacy_id=None):
        return {"project_id": "p"}

    def ingest_object(self, data, **kwargs):
        import hashlib
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        return {"object_id": digest, "digest": digest}

    def create_timeline(self, project_id, timeline_id, **kwargs):
        return {"timeline_id": timeline_id}

    def create_shot(self, *args, **kwargs):
        return {"shot_id": "shot-1"}

    def create_reference(self, *args, **kwargs):
        return {"reference_id": "ref-1"}

    def create_generation(self, generation, **kwargs):
        return {"generation_id": generation["id"]}
