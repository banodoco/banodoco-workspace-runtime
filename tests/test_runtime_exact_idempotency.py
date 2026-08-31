from __future__ import annotations

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon


def test_executor_registration_requires_key_and_replays_exactly_after_restart(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    daemon = RuntimeDaemon(root, support_root=support).start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        executor = {
            "executor_id": "exact-executor",
            "max_concurrency": 2,
            "resource_keys": ["gpu"],
            "capabilities": ["render.basic"],
            "protocol": "workspace.v1",
        }
        with pytest.raises(RuntimeError) as missing:
            api.request("POST", "/v1/executors", executor)
        assert missing.value.status == 400
        first = api.request("POST", "/v1/executors", executor, headers={"Idempotency-Key": "executor-exact"})
        assert first["executor_id"] == "exact-executor"
    finally:
        daemon.stop()

    restarted = RuntimeDaemon(root, support_root=support).start()
    try:
        api = Api(restarted.endpoint, restarted.token)
        assert api.request("POST", "/v1/executors", executor, headers={"Idempotency-Key": "executor-exact"}) == first
        with pytest.raises(RuntimeError) as changed:
            api.request("POST", "/v1/executors", {**executor, "max_concurrency": 3}, headers={"Idempotency-Key": "executor-exact"})
        assert changed.value.status == 409
        assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM executors WHERE id=?", ("exact-executor",)).fetchone()[0] == 1
    finally:
        restarted.stop()


def test_timeline_shot_and_reference_creation_are_keyed_durable_and_non_overwriting(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    daemon = RuntimeDaemon(root, support_root=support).start()
    project_id = None
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Exact Timeline", idempotency_key="exact-project")
        project_id = project.project_id
        client.create_timeline(project_id, "exact-timeline", idempotency_key="exact-timeline")
        shot = {"shot_id": "exact-shot", "start_ms": 0, "duration_ms": 100, "reference_ids": []}
        reference = {"reference_id": "exact-reference", "object_id": "object-digest", "role": "source"}
        with pytest.raises(ApiError) as missing_shot:
            client._request("POST", "/v1/timelines/exact-timeline/shots", body=b'{"shot_id":"exact-shot","start_ms":0,"duration_ms":100,"reference_ids":[]}', headers={"Content-Type": "application/json"})
        assert missing_shot.value.status == 400
        first_shot = client.create_shot("exact-timeline", shot, idempotency_key="exact-shot-key")
        first_reference = client.create_reference("exact-timeline", reference, idempotency_key="exact-reference-key")
    finally:
        daemon.stop()

    restarted = RuntimeDaemon(root, support_root=support).start()
    try:
        client = WorkspaceClient(restarted.endpoint, restarted.token)
        assert client.create_shot("exact-timeline", shot, idempotency_key="exact-shot-key") == first_shot
        assert client.create_reference("exact-timeline", reference, idempotency_key="exact-reference-key") == first_reference
        with pytest.raises(ApiError) as changed_shot:
            client.create_shot("exact-timeline", {**shot, "duration_ms": 101}, idempotency_key="exact-shot-key")
        assert changed_shot.value.status == 409
        with pytest.raises(ApiError) as changed_reference:
            client.create_reference("exact-timeline", {**reference, "role": "target"}, idempotency_key="exact-reference-key")
        assert changed_reference.value.status == 409
        with pytest.raises(ApiError) as overwrite_shot:
            client.create_shot("exact-timeline", {**shot, "duration_ms": 200}, idempotency_key="different-shot-key")
        assert overwrite_shot.value.status == 409
        with pytest.raises(ApiError) as overwrite_reference:
            client.create_reference("exact-timeline", {**reference, "role": "target"}, idempotency_key="different-reference-key")
        assert overwrite_reference.value.status == 409
        assert restarted.service.store.conn.execute("SELECT duration_ms FROM timeline_shots WHERE id='exact-shot'").fetchone()[0] == 100
        assert restarted.service.store.conn.execute("SELECT role FROM timeline_references WHERE id='exact-reference'").fetchone()[0] == "source"
    finally:
        restarted.stop()
