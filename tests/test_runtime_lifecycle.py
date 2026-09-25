from __future__ import annotations

import sqlite3

import pytest

from runtime_protocol.errors import ConflictError, RealmAdmissionError
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence
from runtime_protocol.store import RealmStore


def _realm(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root, realm_id="realm-lifecycle").close()
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO projects(id, realm_id, slug, name, metadata_json, created_at, updated_at) "
        "VALUES ('project', 'realm-lifecycle', 'project', 'Project', '{}', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO runs(id, project_id, capability, spec_json, status, created_at, updated_at) "
        "VALUES ('run', 'project', 'test', '{}', 'running', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO tasks(id, run_id, capability, spec_json, status, created_at, updated_at) "
        "VALUES ('task', 'run', 'test', '{}', 'queued', ?, ?)",
        (timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    return root


@pytest.mark.parametrize(
    "lease_expires_at, expected_expired",
    [
        ("2000-01-01T00:00:00Z", True),
        ("not-a-time", None),
    ],
)
def test_unsettled_attempt_blocks_even_when_expired_or_uncertain(
    tmp_path, lease_expires_at, expected_expired
):
    root = _realm(tmp_path)
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) "
        "VALUES ('attempt', 'task', 'lease', 1, 'executor', ?, 0, 1)",
        (lease_expires_at,),
    )
    connection.commit()
    connection.close()

    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["unreconciled_attempts"][0]["lease_expired"] is expected_expired
    with pytest.raises(ConflictError, match="active or unreconciled"):
        with interruption_fence(root):
            pass


@pytest.mark.parametrize("binding_status", ["claimed", "stale"])
def test_claimed_or_stale_execution_binding_blocks_interruption(tmp_path, binding_status):
    root = _realm(tmp_path)
    timestamp = "2026-09-24T00:00:00Z"
    connection = sqlite3.connect(root / "realm.sqlite3")
    connection.execute(
        "INSERT INTO execution_bindings("
        "binding_id, task_id, run_id, session_id, runtime_epoch, capability_id, "
        "target_kind, resolved_target_json, status, created_at, updated_at"
        ") VALUES ('binding', 'task', 'run', 'session', 1, 'test', 'local', '{}', ?, ?, ?)",
        (binding_status, timestamp, timestamp),
    )
    connection.commit()
    connection.close()
    report = inspect_interruption_state(root)
    assert report["safe"] is False
    assert report["claimed_or_stale_bindings"][0]["status"] == binding_status


def test_interruption_fence_serializes_with_admission_and_claim_writes(tmp_path):
    root = _realm(tmp_path)
    database = root / "realm.sqlite3"
    with interruption_fence(root, timeout_seconds=0.05) as report:
        assert report["safe"] is True
        contender = sqlite3.connect(database, timeout=0.01)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            contender.close()

    contender = sqlite3.connect(database, timeout=0.05)
    try:
        contender.execute("BEGIN IMMEDIATE")
        contender.rollback()
    finally:
        contender.close()


def test_interruption_observation_rejects_symlink_realm_alias(tmp_path):
    root = _realm(tmp_path)
    alias = tmp_path / "realm-alias"
    alias.symlink_to(root, target_is_directory=True)
    before = (root / "realm.sqlite3").read_bytes()
    with pytest.raises(RealmAdmissionError, match="symlink"):
        inspect_interruption_state(alias)
    assert (root / "realm.sqlite3").read_bytes() == before
