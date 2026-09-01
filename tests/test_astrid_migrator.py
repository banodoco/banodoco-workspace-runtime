from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from tools.astrid_migrate import MigrationConfig, MigrationError, migrate


class FakeClient:
    def __init__(self):
        self.calls = []

    def create_project(self, name, *, idempotency_key):
        self.calls.append(("project", name, idempotency_key))
        return {"project_id": "neutral-project"}

    def ingest_object(self, data, *, media_type, idempotency_key, filename=None):
        self.calls.append(("media", bytes(data), media_type, idempotency_key, filename))
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        return {"object_id": digest, "digest": digest}

    def create_timeline(self, project_id, timeline_id, *, idempotency_key):
        self.calls.append(("timeline", project_id, timeline_id, idempotency_key))
        return {"timeline_id": timeline_id}

    def create_shot(self, timeline_id, shot, *, idempotency_key):
        self.calls.append(("shot", timeline_id, shot, idempotency_key))
        return shot

    def create_reference(self, timeline_id, reference, *, idempotency_key):
        self.calls.append(("reference", timeline_id, reference, idempotency_key))
        return reference

    def create_generation(self, generation, *, idempotency_key):
        self.calls.append(("generation", generation, idempotency_key))
        return generation


def _fixture(root: Path, *, unreadable: bool = False) -> bytes:
    (root / ".astrid").mkdir(parents=True)
    media = root / "media" / "clip.mp4"
    media.parent.mkdir()
    payload = b"fixture-media"
    media.write_bytes(b"wrong" if unreadable else payload)
    digest = hashlib.sha256(payload).hexdigest()
    db = sqlite3.connect(root / ".astrid" / "astrid.sqlite3")
    db.executescript("""
      PRAGMA foreign_keys=ON;
      CREATE TABLE projects (id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, settings_json TEXT, event_head_seq INTEGER, created_at TEXT, updated_at TEXT);
      CREATE TABLE timelines (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), name TEXT, document_json TEXT, asset_registry_json TEXT, created_at TEXT, updated_at TEXT);
      CREATE TABLE shots (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), name TEXT, sort_key TEXT, metadata_json TEXT, created_at TEXT, updated_at TEXT);
      CREATE TABLE project_references (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), kind TEXT, name TEXT, description TEXT, metadata_json TEXT, created_at TEXT, updated_at TEXT, archived_at TEXT);
      CREATE TABLE media (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), media_kind TEXT, mime_type TEXT, byte_size INTEGER, content_hash TEXT, metadata_json TEXT, created_at TEXT);
      CREATE TABLE media_locations (id TEXT PRIMARY KEY, media_id TEXT REFERENCES media(id), realm TEXT, locator TEXT, verified_at TEXT, created_at TEXT);
      CREATE TABLE generations (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), task_id TEXT, type TEXT, name TEXT, based_on_generation_id TEXT, parent_generation_id TEXT, child_order INTEGER, params_json TEXT, starred INTEGER, deleted_at TEXT, created_at TEXT, updated_at TEXT);
      CREATE TABLE event_streams (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), stream_type TEXT, aggregate_id TEXT, head_seq INTEGER, created_at TEXT);
      CREATE TABLE events (event_id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), project_seq INTEGER, stream_id TEXT REFERENCES event_streams(id), seq INTEGER, subject_type TEXT, subject_id TEXT, changes_json TEXT, kind TEXT, schema_version TEXT, idempotency_key TEXT, txn_id TEXT, actor_kind TEXT, payload_json TEXT, created_at TEXT);
      CREATE TABLE schema_migrations (pack TEXT, version INTEGER, name TEXT, checksum TEXT, applied_at TEXT);
    """)
    db.execute("INSERT INTO projects VALUES ('p1','demo','Demo','{}',0,'now','now')")
    db.execute("INSERT INTO timelines VALUES ('tl1','p1','Main','{}','{}','now','now')")
    db.execute("INSERT INTO shots VALUES ('s1','p1','Shot 1','001','{\"timeline_id\":\"tl1\"}','now','now')")
    db.execute("INSERT INTO project_references VALUES ('r1','p1','image','Ref','desc','{}','now','now',NULL)")
    db.execute("INSERT INTO media VALUES ('m1','p1','video','video/mp4',13,?, '{}','now')", (digest,))
    db.execute("INSERT INTO media_locations VALUES ('ml1','m1','external_local','media/clip.mp4',NULL,'now')")
    db.execute("INSERT INTO generations VALUES ('g1','p1',NULL,'image','Gen',NULL,NULL,0,'{}',0,NULL,'now','now')")
    db.commit(); db.close()
    return payload


def test_dry_run_inventory_mapping_and_external_local_ingest_preview(tmp_path):
    payload = _fixture(tmp_path)
    client = FakeClient()
    report = migrate(MigrationConfig(tmp_path, tmp_path.parent / "archive-dry", tmp_path.parent / "destination-dry", dry_run=True), client)
    assert report["dry_run"] is True
    assert report["inventory"]["row_counts"]["projects"] == 1
    assert report["mapping"] == {"projects": 1, "timelines": 1, "shots": 1, "references": 1, "generations": 1, "media": 1, "runs": 0, "tasks": 0}
    assert client.calls == []
    assert (tmp_path / "media" / "clip.mp4").read_bytes() == payload
    assert not (tmp_path.parent / "destination-dry" / "activation-manifest.json").exists()


def test_migration_archives_maps_and_atomically_activates(tmp_path):
    _fixture(tmp_path)
    client = FakeClient()
    report = migrate(MigrationConfig(tmp_path, tmp_path.parent / "archive-real", tmp_path.parent / "destination-real"), client)
    assert report["reconciliation"]["ok"] is True
    assert [call[0] for call in client.calls] == ["project", "media", "timeline", "shot", "reference", "generation"]
    assert (tmp_path.parent / "archive-real" / "manifest.json").is_file()
    activation = json.loads((tmp_path.parent / "destination-real" / "activation-manifest.json").read_text())
    assert activation["state"] == "activated"
    assert "token" not in json.dumps(activation)
    assert (tmp_path.parent / "archive-real" / "ROLLBACK.md").is_file()


def test_unreadable_media_fails_closed_without_source_mutation(tmp_path):
    _fixture(tmp_path, unreadable=True)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(MigrationError, match="content hash"):
        migrate(MigrationConfig(tmp_path, tmp_path.parent / "archive-fail", tmp_path.parent / "destination-fail"), FakeClient())
    after = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after
    assert not (tmp_path.parent / "destination-fail" / "activation-manifest.json").exists()


def test_active_writer_refuses_before_archive_or_client_calls(tmp_path):
    _fixture(tmp_path)
    with pytest.raises(MigrationError, match="writer"):
        migrate(MigrationConfig(tmp_path, tmp_path.parent / "archive-freeze", tmp_path.parent / "destination-freeze", freeze_probe=lambda: False), FakeClient())
    assert not (tmp_path.parent / "archive-freeze").exists()


def test_source_freeze_does_not_report_its_own_writer_lock_as_active(tmp_path):
    """The freeze's held descriptor must not fail its second flock probe.

    macOS treats a second descriptor opened by the same process as a
    conflicting non-blocking flock.  This lock file therefore reproduces the
    self-lock failure while asserting that external writer protection still
    allows a normal migration once this process owns the lock.
    """
    _fixture(tmp_path)
    (tmp_path / ".astrid" / "writer.lock").touch()

    report = migrate(
        MigrationConfig(
            tmp_path,
            tmp_path.parent / "archive-self-lock",
            tmp_path.parent / "destination-self-lock",
        ),
        FakeClient(),
    )

    assert report["reconciliation"]["ok"] is True


def test_managed_local_cas_locator_can_follow_an_explicitly_moved_snapshot(tmp_path):
    _fixture(tmp_path)
    digest = hashlib.sha256(b"fixture-media").hexdigest()
    cas_path = tmp_path / ".astrid" / "media" / "sha256" / digest[:2] / digest[2:4] / digest
    cas_path.parent.mkdir(parents=True)
    shutil.copy2(tmp_path / "media" / "clip.mp4", cas_path)
    connection = sqlite3.connect(tmp_path / ".astrid" / "astrid.sqlite3")
    connection.execute(
        "UPDATE media_locations SET realm='managed_local', locator=?",
        (f"/old/authority/.astrid/media/sha256/{digest[:2]}/{digest[2:4]}/{digest}",),
    )
    connection.commit()
    connection.close()

    report = migrate(
        MigrationConfig(tmp_path, tmp_path.parent / "archive-relocated", tmp_path.parent / "destination-relocated"),
        FakeClient(),
    )

    assert report["reconciliation"]["ok"] is True


def test_archive_file_map_ignores_only_appledouble_metadata(tmp_path):
    _fixture(tmp_path)
    (tmp_path / "._finder-metadata").write_bytes(b"\x00\x05\x16\x07metadata")
    (tmp_path / "._authored-file").write_bytes(b"ordinary authored bytes")

    archive = tmp_path.parent / "archive-appledouble"
    report = migrate(MigrationConfig(tmp_path, archive, tmp_path.parent / "destination-appledouble"), FakeClient())

    assert report["reconciliation"]["ok"] is True
    files = json.loads((archive / "manifest.json").read_text())["files"]
    assert "._finder-metadata" not in files
    assert files["._authored-file"]["sha256"] == hashlib.sha256(b"ordinary authored bytes").hexdigest()
