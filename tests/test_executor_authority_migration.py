from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from runtime_protocol.store import RealmStore


def _make_schema18_realm(root: Path) -> None:
    """Build the last transitional schema without booting a current store."""
    db = root / "realm.sqlite3"
    conn = sqlite3.connect(db)
    migrations = Path(__file__).parents[1] / "runtime_protocol" / "migrations"
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    for version in range(1, 19):
        script = next(migrations.glob(f"{version:03d}_*.sql")).read_text()
        conn.executescript(script)
        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))", (version,))
    conn.execute("INSERT INTO realm(id, display_name, created_at, updated_at) VALUES ('realm', 'Legacy', '2026-01-01', '2026-01-01')")
    conn.execute("INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) VALUES ('project', 'realm', 'legacy', 'Legacy', '{}', '2026-01-01', '2026-01-01')")
    conn.execute("INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) VALUES ('run', 'project', 'render.basic', '{}', 'queued', '2026-01-01', '2026-01-01')")
    conn.execute("INSERT INTO tasks(id, run_id, capability, spec_json, status, worker_id, created_at, updated_at) VALUES ('task', 'run', 'render.basic', '{}', 'queued', 'legacy-executor', '2026-01-01', '2026-01-01')")
    conn.execute("INSERT INTO workers(id, capabilities_json, max_concurrency, resource_keys_json, created_at, last_seen_at, readiness, readiness_reason, runtime_epoch) VALUES ('legacy-executor', ?, 2, ?, '2026-01-01', '2026-01-02', 'not_ready', 'warming', 7)", (json.dumps(['render.basic']), json.dumps(['gpu'])))
    conn.execute("INSERT INTO reservations(task_id, resource_key, lease_token, created_at, released_at, worker_id, fence, lease_expires_at, runtime_epoch) VALUES ('task', 'gpu', 'lease', '2026-01-01', NULL, 'legacy-executor', 1, NULL, 7)")
    conn.commit()
    conn.close()


def test_schema18_worker_state_migrates_to_one_executor_authority(tmp_path):
    root = tmp_path / "realm"
    root.mkdir()
    _make_schema18_realm(root)
    store = RealmStore(root)
    try:
        assert store.conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 19
        assert store.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workers'").fetchone() is None
        executor = store.conn.execute("SELECT * FROM executors WHERE id='legacy-executor'").fetchone()
        assert executor["max_concurrency"] == 2
        assert executor["resource_keys_json"] == '["gpu"]'
        assert executor["readiness"] == "not_ready"
        assert executor["last_seen_at"] == "2026-01-02"
        assert store.conn.execute("SELECT executor_id FROM tasks WHERE id='task'").fetchone()[0] == "legacy-executor"
        assert store.conn.execute("SELECT executor_id FROM reservations WHERE task_id='task'").fetchone()[0] == "legacy-executor"
    finally:
        store.close()


def test_schema19_authority_migration_is_safe_to_retry_after_structural_upgrade(tmp_path):
    root = tmp_path / "realm"
    first = RealmStore(root)
    try:
        assert first.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workers'").fetchone() is None
    finally:
        first.close()

    # Simulate a crash after the schema-19 DDL committed but before its
    # migration marker was recorded.  Older receipt fixtures exercise this
    # same shape by rewinding the marker while retaining the live schema.
    conn = sqlite3.connect(root / "realm.sqlite3")
    conn.execute("DELETE FROM schema_migrations WHERE version=19")
    conn.commit()
    conn.close()

    retried = RealmStore(root)
    try:
        assert retried.conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 19
        assert retried.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workers'").fetchone() is None
        assert "readiness" in {row[1] for row in retried.conn.execute("PRAGMA table_info(executors)")}
        assert "executor_id" in {row[1] for row in retried.conn.execute("PRAGMA table_info(tasks)")}
        assert "executor_id" in {row[1] for row in retried.conn.execute("PRAGMA table_info(reservations)")}
    finally:
        retried.close()
