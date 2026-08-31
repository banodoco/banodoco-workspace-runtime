from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from runtime_protocol.service import RuntimeService


def _digest(capability: str) -> str:
    return "sha256:" + hashlib.sha256(capability.encode()).hexdigest()


def _make_pre016(root):
    service = RuntimeService(root)
    project = service.create_project({"name": "Historical", "slug": "historical"}, idempotency_key="project")
    service.select_project("actor", project["id"], idempotency_key="select")
    service.create_task({
        "capability_id": "render.basic", "capability_digest": _digest("render.basic"),
        "input_object_ids": [], "project": project["id"], "idempotency_key": "task", "spec": {},
    })
    service.store.conn.execute(
        "UPDATE command_idempotency SET txn_id=NULL, primary_stream_id=NULL, resulting_stream_seq=NULL, "
        "first_project_seq=NULL, last_project_seq=NULL, event_ids_json=NULL"
    )
    service.store.conn.execute("DELETE FROM canonical_receipt_backfills")
    service.store.conn.execute("DELETE FROM schema_migrations WHERE version=17")
    service.close()


def test_pre016_receipts_backfill_once_and_replay_after_restart(tmp_path):
    root = tmp_path / "realm"
    _make_pre016(root)

    first = RuntimeService(root)
    rows = first.store.conn.execute(
        "SELECT command_kind, aggregate_id, idempotency_key FROM command_idempotency ORDER BY created_at"
    ).fetchall()
    receipts = {
        row["command_kind"]: first.committed_receipt(
            row["command_kind"], row["aggregate_id"], row["idempotency_key"],
            project_id=(first.store._legacy_receipt_project(
                row["command_kind"], row["aggregate_id"],
                json.loads(first.store.conn.execute(
                    "SELECT result_json FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                    (row["command_kind"], row["aggregate_id"], row["idempotency_key"]),
                ).fetchone()[0])
            ) or "unscoped"),
        ) for row in rows
    }
    task_receipt = receipts["task.create"]
    event_id = task_receipt["event_ids"][0]
    assert first.store.conn.execute("SELECT 1 FROM events WHERE id=?", (int(event_id),)).fetchone()
    assert task_receipt["project_seq"] == [3, 3]
    assert all(receipt is not None for receipt in receipts.values())
    first.close()

    second = RuntimeService(root)
    replay_rows = second.store.conn.execute(
        "SELECT command_kind, aggregate_id, idempotency_key FROM command_idempotency ORDER BY created_at"
    ).fetchall()
    assert second.store.conn.execute("SELECT COUNT(*) FROM canonical_receipt_backfills").fetchone()[0] == 1
    for row in replay_rows:
        assert second.store.conn.execute(
            "SELECT txn_id, first_project_seq, event_ids_json FROM command_idempotency "
            "WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
            (row["command_kind"], row["aggregate_id"], row["idempotency_key"]),
        ).fetchone()[0]
    second.close()


def test_receipt_backfill_failure_rolls_back_and_can_retry(tmp_path):
    root = tmp_path / "realm"
    _make_pre016(root)
    db = root / "realm.sqlite3"
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE command_idempotency SET result_json=? WHERE command_kind='task.create'",
        ("not-json",),
    )
    conn.commit()
    conn.close()
    with pytest.raises(json.JSONDecodeError):
        RuntimeService(root)
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 16
    assert conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE txn_id IS NOT NULL").fetchone()[0] == 0
    conn.execute(
        "UPDATE command_idempotency SET result_json=? WHERE command_kind='task.create'",
        (json.dumps({"run": {"id": "missing"}, "task": {}}),),
    )
    conn.commit()
    conn.close()
    repaired = RuntimeService(root)
    assert repaired.store.conn.execute("SELECT COUNT(*) FROM canonical_receipt_backfills").fetchone()[0] == 1
    repaired.close()
