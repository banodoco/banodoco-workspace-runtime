from __future__ import annotations

import hashlib

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon


@pytest.fixture()
def daemon(tmp_path):
    value = RuntimeDaemon(tmp_path / "realm").start()
    try:
        yield value
    finally:
        value.stop()


def _seed(client):
    project = client.create_project("text-bindings", idempotency_key="project")
    client.create_project_shot(project.project_id, {"shot_id": "opening", "name": "Opening"}, idempotency_key="shot")
    return project


def test_set_is_deterministic_project_scoped_and_replays(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client)
    first = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "héllo", "expected_head": 0}, idempotency_key="set")
    replay = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "héllo", "expected_head": 0}, idempotency_key="set")
    assert replay == first
    assert first["binding_id"]
    assert first["head"] == 1
    assert first["byte_size"] == len("héllo".encode())
    assert first.receipt["command_kind"] == "shot.text_binding.set"
    assert client.list_project_shot_text_bindings(project.project_id, shot_id="opening")[0][0]["binding_id"] == first["binding_id"]
    with pytest.raises(ApiError):
        client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "changed", "expected_head": 0}, idempotency_key="set")


def test_set_rebind_and_event_order(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client)
    first = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": "one", "expected_head": 0}, idempotency_key="one")
    second = client.set_project_shot_text_binding(project.project_id, {"binding_id": first["binding_id"], "text": "two", "expected_head": 1}, idempotency_key="two")
    rebound = client.rebind_project_shot_text_binding(project.project_id, first["binding_id"], media_id=first["media_id"], expected_head=2, idempotency_key="rebind")
    assert second["head"] == 2 and rebound["head"] == 3
    rows = daemon.service.store.conn.execute("SELECT seq, kind FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq", (first["binding_id"],)).fetchall()
    assert [tuple(row) for row in rows] == [(1, "shot.text_binding.created"), (2, "shot.text_binding.rebound"), (3, "shot.text_binding.rebound")]


def test_invalid_utf8_and_size_are_zero_write(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client)
    before = daemon.service.store.conn.execute("SELECT COUNT(*) FROM shot_text_bindings").fetchone()[0]
    with pytest.raises(ApiError):
        client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": "x" * 1_048_577, "expected_head": 0}, idempotency_key="large")
    with pytest.raises(Exception):
        daemon.service.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": b"\xff", "expected_head": 0}, idempotency_key="invalid")
    after = daemon.service.store.conn.execute("SELECT COUNT(*) FROM shot_text_bindings").fetchone()[0]
    assert after == before


def test_identity_digest_is_sha256(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client)
    value = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "voiceover_script", "text": "voice", "expected_head": 0}, idempotency_key="voice")
    assert value["content_hash"] == "sha256:" + hashlib.sha256(b"voice").hexdigest()
