from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys

import pytest

from runtime_protocol.errors import OwnerBusyError, ValidationError
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import upgrade_realm


def _legacy_realm(root, *, register_indexes=True):
    store = RealmStore.initialize(root)
    realm_id = store.realm["id"]
    timestamp = "2026-09-15T00:00:00Z"
    store.close()
    payload = b"legacy-video"
    digest = hashlib.sha256(payload).hexdigest()
    cas = root / "cas" / "sha256" / digest[:2]
    cas.mkdir(parents=True, exist_ok=True)
    (cas / digest[2:]).write_bytes(payload)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.executescript(
            """
            DROP INDEX idx_managed_output_task;
            DROP INDEX idx_managed_output_manifest;
            DROP TABLE managed_output_lifecycle;
            DROP TABLE managed_output_associations;
            DROP TABLE runtime_schema;
            CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
            CREATE TABLE canonical_receipt_backfills(id INTEGER PRIMARY KEY, detail TEXT);
            CREATE TABLE lost_and_found(id INTEGER PRIMARY KEY, payload BLOB);
            CREATE TABLE migration_event_streams(id TEXT PRIMARY KEY, payload TEXT);
            CREATE TABLE migration_events(id TEXT PRIMARY KEY, payload TEXT);
            CREATE TABLE migration_owner_records(id TEXT PRIMARY KEY, payload TEXT);
            """
        )
        connection.executemany(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            [(version, f"2026-09-15T00:00:{version:02d}Z") for version in range(1, 24)],
        )
        connection.execute("INSERT INTO lost_and_found(id, payload) VALUES (1, ?)", (b"legacy-bytes",))
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("project-1", realm_id, "kept-project", "Kept project", "{}", 1, timestamp, timestamp, None),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_json, status, idempotency_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("run-1", "project-1", "rendering.render", "{}", "completed", None, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, attempt, lease_fence, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("task-1", "run-1", "test-capability", json.dumps({"inputs": {"output_name": "legacy.mp4"}}), "completed", 1, 1, timestamp, timestamp),
        )
        connection.execute(
            "UPDATE tasks SET attempt_id=?, result_json=? WHERE id=?",
            (
                "attempt-1",
                json.dumps({"outputs": [{"kind": "object", "name": "video", "digest": "sha256:" + digest, "media_type": "clip/visual", "size": len(payload), "ordinal": 0, "role": "result"}]}),
                "task-1",
            ),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, 1, ?, ?, 1, 1)",
            ("attempt-1", "task-1", "lease-1", "fixture", timestamp),
        )
        if register_indexes:
            connection.execute(
                "INSERT INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (digest, len(payload), "clip/visual", "video", timestamp),
            )
            connection.execute(
                "INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, ?, ?)",
                ("project-1", digest, "managed", timestamp),
            )
        connection.execute(
            "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("generation-1", "project-1", "task-1", "generation", "succeeded", "{}", 1, timestamp, timestamp),
        )
        connection.commit()
    finally:
        connection.close()
    return realm_id


def test_upgrade_archives_legacy_state_and_preserves_canonical_rows(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)

    result = upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert result["ok"] is True
    archive = tmp_path / "realm" / "realm-upgrade-backups" / result["archive"].split("/")[-1]
    manifest = json.loads((archive / "manifest.json").read_text())
    assert manifest["source_schema_version"] == 23
    assert manifest["target_schema_version"] == 24
    assert manifest["historical_managed_outputs"]["migrated"] == 1
    assert set(manifest["legacy_tables"]) >= {"schema_migrations", "lost_and_found"}
    assert (archive / "realm.sqlite3").is_file()
    archived = sqlite3.connect(archive / "realm.sqlite3")
    try:
        assert archived.execute("SELECT payload FROM lost_and_found WHERE id=1").fetchone()[0] == b"legacy-bytes"
    finally:
        archived.close()

    reopened = RealmStore(root)
    try:
        row = reopened.conn.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
        assert tuple(row) == ("astrid-runtime-sqlite-v1", 24)
        assert reopened.conn.execute("SELECT id FROM realm").fetchone()[0] == realm_id
        assert reopened.conn.execute("SELECT id FROM generations").fetchone()[0] == "generation-1"
        migrated_output = reopened.list_managed_outputs("task-1")
        assert migrated_output[0]["filename"] == "legacy.mp4"
        tables = {row[0] for row in reopened.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "schema_migrations" not in tables
        assert {"managed_output_associations", "managed_output_lifecycle"}.issubset(tables)
    finally:
        reopened.close()


def test_upgrade_refuses_unknown_shape_without_touching_source(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("CREATE TABLE unexpected_data(id INTEGER PRIMARY KEY, payload BLOB)")
        connection.execute("INSERT INTO unexpected_data(payload) VALUES (?)", (b"must-preserve",))
        connection.commit()
    finally:
        connection.close()
    before = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
        if (root / name).exists()
    }

    with pytest.raises(ValidationError, match="unknown source tables"):
        upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    after = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
        if (root / name).exists()
    }
    assert after == before


def test_upgrade_repairs_missing_historical_object_indexes(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root, register_indexes=False)
    result = upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert result["historical_managed_outputs"]["migrated"] == 1
    reopened = RealmStore(root)
    try:
        digest = reopened.conn.execute("SELECT object_digest FROM managed_output_associations").fetchone()[0]
        assert reopened.conn.execute("SELECT size FROM objects WHERE digest=?", (digest,)).fetchone()[0] == len(b"legacy-video")
        assert reopened.conn.execute(
            "SELECT relation FROM project_objects WHERE project_id='project-1' AND digest=?", (digest,)
        ).fetchone()[0] == "managed"
    finally:
        reopened.close()


def test_upgrade_is_not_repeatable_and_refuses_live_owner(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    active_names = ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")
    after = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in active_names
        if (root / name).exists()
    }
    with pytest.raises(ValidationError, match="schema_migrations"):
        upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    assert {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in active_names
        if (root / name).exists()
    } == after

    lock = (root / "owner.lock").open("a+")
    try:
        import fcntl
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(OwnerBusyError):
            upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def test_upgrade_archives_wal_before_activation(tmp_path):
    root = tmp_path / "realm"
    realm_id = _legacy_realm(root)
    # Simulate an interrupted owner: a normal final connection.close() may
    # checkpoint and delete the WAL, depending on the SQLite build.
    subprocess.run(
        [sys.executable, "-c", """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode=WAL")
connection.execute("PRAGMA wal_autocheckpoint=0")
connection.execute("UPDATE realm SET display_name=?", ("WAL realm",))
connection.commit()
os._exit(0)
""", str(root / "realm.sqlite3")],
        check=True,
    )
    assert (root / "realm.sqlite3-wal").is_file()

    result = upgrade_realm(root, timeout_seconds=30, confirmation=f"UPGRADE {realm_id}")
    archive = root / "realm-upgrade-backups" / result["archive"].split("/")[-1]
    manifest = json.loads((archive / "manifest.json").read_text())
    assert "realm.sqlite3-wal" in manifest["components"]
    assert (archive / "realm.sqlite3-wal").is_file()
    assert not any((root / f"realm.sqlite3{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))
    reopened = RealmStore(root)
    try:
        assert reopened.realm["display_name"] == "WAL realm"
    finally:
        reopened.close()
