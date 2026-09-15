from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.store import RealmStore
from runtime_protocol.upgrade import migrate_historical_managed_outputs


def _historical_realm(root):
    store = RealmStore.initialize(root, realm_id="realm-history")
    store.close()
    payload = b"historical-video-bytes"
    digest = hashlib.sha256(payload).hexdigest()
    cas = root / "cas" / "sha256" / digest[:2]
    cas.mkdir(parents=True, exist_ok=True)
    (cas / digest[2:]).write_bytes(payload)
    connection = sqlite3.connect(root / "realm.sqlite3")
    timestamp = "2026-09-15T00:00:00Z"
    try:
        connection.execute(
            "INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            ("project-history", "realm-history", "history", "History", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("run-history", "project-history", "rendering.render", "{}", "completed", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (digest, len(payload), "clip/visual", "video", timestamp),
        )
        connection.execute(
            "INSERT INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, ?, ?)",
            ("project-history", digest, "managed", timestamp),
        )
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, attempt, lease_fence, attempt_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, ?)",
            (
                "task-history", "run-history", "rendering.render",
                json.dumps({"spec": {"inputs": {"output_name": "historical.mp4"}}}),
                "completed", "attempt-history", timestamp, timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, 1, ?, ?, 1, 1)",
            ("attempt-history", "task-history", "lease-history", "fixture", timestamp),
        )
        connection.execute(
            "UPDATE tasks SET result_json=? WHERE id=?",
            (json.dumps({"outputs": [{"kind": "object", "name": "video", "digest": "sha256:" + digest, "media_type": "clip/visual", "size": len(payload), "ordinal": 0, "role": "result"}]}), "task-history"),
        )
        connection.commit()
    finally:
        connection.close()
    return digest


def test_historical_output_migration_materializes_verified_association(tmp_path):
    root = tmp_path / "realm"
    digest = _historical_realm(root)
    confirmation = "MIGRATE MANAGED OUTPUTS realm-history"

    result = migrate_historical_managed_outputs(
        root, project_id="project-history", task_id="task-history", confirmation=confirmation
    )
    assert result["migrated"] == 1
    assert result["skipped_count"] == 0
    store = RealmStore(root)
    try:
        outputs = store.list_managed_outputs("task-history")
        assert len(outputs) == 1
        assert outputs[0]["object_id"] == "sha256:" + digest
        assert outputs[0]["filename"] == "historical.mp4"
        assert outputs[0]["media_type"] == "clip/visual"
    finally:
        store.close()

    repeated = migrate_historical_managed_outputs(
        root, project_id="project-history", task_id="task-history", confirmation=confirmation
    )
    assert repeated["migrated"] == 0
    assert repeated["skipped_count"] == 1


def test_historical_output_migration_rejects_unrelated_attempt(tmp_path):
    root = tmp_path / "realm"
    _historical_realm(root)
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        timestamp = "2026-09-15T00:00:00Z"
        connection.execute(
            "INSERT INTO tasks(id, run_id, capability, spec_json, status, attempt, lease_fence, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)",
            ("task-other", "run-history", "rendering.render", "{}", "completed", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, 1, ?, ?, 1, 1)",
            ("attempt-other", "task-other", "lease-other", "fixture", timestamp),
        )
        connection.execute("UPDATE tasks SET attempt_id=? WHERE id=?", ("attempt-other", "task-history"))
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValidationError, match="unrelated attempt"):
        migrate_historical_managed_outputs(
            root, task_id="task-history", confirmation="MIGRATE MANAGED OUTPUTS realm-history"
        )
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        assert connection.execute("SELECT COUNT(*) FROM managed_output_associations").fetchone()[0] == 0
    finally:
        connection.close()
