from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient


TASK = {"task_id": "t", "run_id": "r", "state": "queued", "version": 1, "capability_id": "render.basic", "capability_digest": "sha256:" + "b" * 64, "idempotency_key": "i", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "attempt_id": None}


def test_control_plane_methods_preserve_fences_cursors_and_idempotency() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/tasks" and method == "POST":
            admission = json.loads(body)
            assert admission["capability_digest"] == "sha256:" + "b" * 64
            assert admission["input_object_ids"] == ["obj"]
            return 201, {}, json.dumps(TASK).encode()
        if path.endswith("/cancel"):
            assert headers["Idempotency-Key"] == "cancel-1"
            assert json.loads(body) == {"expected_version": 1}
            return 200, {}, json.dumps({**TASK, "state": "cancel_requested", "version": 2}).encode()
        if path == "/v1/events?limit=10&cursor=c0&aggregate_id=t":
            event = {"event_id": "e", "sequence": 3, "cursor": "c1", "event_type": "task.cancel_requested", "aggregate_type": "task", "aggregate_id": "t", "payload": {}, "occurred_at": "2026-01-01T00:00:00Z"}
            return 200, {}, json.dumps({"items": [event], "next_cursor": "c1"}).encode()
        if path == "/v1/executors":
            return 201, {}, json.dumps({"executor_id": "x", "max_concurrency": 1, "resource_keys": ["cpu"], "capabilities": [], "protocol": "workspace.v1"}).encode()
        if path == "/v1/capabilities":
            return 200, {}, json.dumps({"items": [{"capability_id": "render.basic", "definition_digest": "sha256:" + "b" * 64, "status": "ready", "required_resource_keys": ["cpu"], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}]}).encode()
        if path.endswith("/settle"):
            value = json.loads(body)
            assert value["lease_id"] == "l" and value["fence"] == 4
            return 200, {}, json.dumps({**TASK, "state": "succeeded", "version": 2}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", transport=transport)
    task = client.admit_task(capability_id="render.basic", capability_digest="sha256:" + "b" * 64, input_object_ids=["obj"], idempotency_key="task-1")
    assert task.task_id == "t"
    cancelled = client.cancel_task("t", idempotency_key="cancel-1", expected_version=1)
    assert cancelled.state == "cancel_requested"
    events, cursor = client.list_events(cursor="c0", limit=10, aggregate_id="t")
    assert events[0].sequence == 3 and cursor == "c1"
    executor = client.register_executor({"executor_id": "x", "max_concurrency": 1, "resource_keys": ["cpu"], "capabilities": [], "protocol": "workspace.v1"}, idempotency_key="exec-1")
    assert executor.executor_id == "x"
    assert client.list_capabilities()[0].status == "ready"
    assert client.settle_attempt("a", {"attempt_id": "a", "lease_id": "l", "fence": 4, "outputs": [], "effect": None}, idempotency_key="settle-1").state == "succeeded"
    assert any(call[2].get("Idempotency-Key") == "task-1" for call in calls)
