from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient


TASK = {"task_id": "t", "run_id": "r", "state": "queued", "version": 1, "capability_id": "render.basic", "capability_digest": "sha256:" + "b" * 64, "idempotency_key": "i", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "attempt_id": None, "runtime_epoch": 1}


def mutation_response(data, command_kind: str, idempotency_key: str) -> bytes:
    receipt = {"receipt_id": f"{command_kind}-receipt", "command_kind": command_kind, "idempotency_key": idempotency_key, "request_hash": "sha256:" + "a" * 64, "project_id": "runtime-realm", "project_seq": [1, 1], "event_ids": [], "result": {}, "created_at": "2026-01-01T00:00:00Z"}
    return json.dumps({"data": data, "receipt": receipt}).encode()


def test_control_plane_methods_preserve_fences_cursors_and_idempotency() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/tasks" and method == "POST":
            admission = json.loads(body)
            assert admission["capability_digest"] == "sha256:" + "b" * 64
            assert admission["input_object_ids"] == ["obj"]
            assert admission["storage_estimate"] == {"scratch_bytes": 300, "output_bytes": 40}
            return 201, {}, json.dumps({"data": TASK, "receipt": {"receipt_id": "runtime-command-1", "command_kind": "task.create", "idempotency_key": "task-1", "request_hash": "sha256:" + "a" * 64, "project_id": "runtime-realm", "project_seq": [1, 1], "event_ids": [], "result": {}, "created_at": "2026-01-01T00:00:00Z"}}).encode()
        if path.endswith("/cancel"):
            assert headers["Idempotency-Key"] == "cancel-1"
            assert json.loads(body) == {"expected_version": 1}
            return 200, {}, mutation_response({**TASK, "state": "cancel_requested", "version": 2}, "task.cancel", headers["Idempotency-Key"])
        if path == "/v1/events?limit=10&cursor=c0&aggregate_id=t":
            event = {"event_id": "e", "sequence": 3, "cursor": "c1", "event_type": "task.cancel_requested", "aggregate_type": "task", "aggregate_id": "t", "payload": {}, "occurred_at": "2026-01-01T00:00:00Z"}
            return 200, {}, json.dumps({"items": [event], "next_cursor": "c1"}).encode()
        if path == "/v1/executors":
            return 201, {}, json.dumps({"executor_id": "x", "max_concurrency": 1, "resource_keys": ["cpu"], "capabilities": [], "protocol": "workspace.v1"}).encode()
        if path == "/v1/capabilities" and method == "POST":
            value = json.loads(body)
            assert value["capability_id"] == "render.new"
            return 201, {}, json.dumps({"capability_id": "render.new", "definition_digest": value["definition_digest"], "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 0}).encode()
        if path == "/v1/capabilities":
            return 200, {}, json.dumps({"items": [{"capability_id": "render.basic", "definition_digest": "sha256:" + "b" * 64, "status": "ready", "required_resource_keys": ["cpu"], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}], "next_cursor": None}).encode()
        if path.endswith("/settle"):
            value = json.loads(body)
            assert value["lease_id"] == "l" and value["fence"] == 4
            return 200, {}, mutation_response({**TASK, "state": "succeeded", "version": 2}, "attempt.settle", headers["Idempotency-Key"])
        if path.endswith("/fail"):
            value = json.loads(body)
            assert value["lease_id"] == "l" and value["fence"] == 4
            return 200, {}, mutation_response({**TASK, "state": "failed", "version": 2}, "attempt.fail", headers["Idempotency-Key"])
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", transport=transport)
    task = client.admit_task(capability_id="render.basic", capability_digest="sha256:" + "b" * 64, input_object_ids=["obj"], idempotency_key="task-1", storage_estimate={"scratch_bytes": 300, "output_bytes": 40})
    assert task.task_id == "t"
    cancelled = client.cancel_task("t", idempotency_key="cancel-1", expected_version=1)
    assert cancelled.state == "cancel_requested"
    events, cursor = client.list_events(cursor="c0", limit=10, aggregate_id="t")
    assert events[0].sequence == 3 and cursor == "c1"
    executor = client.register_executor({"executor_id": "x", "max_concurrency": 1, "resource_keys": ["cpu"], "capabilities": [], "protocol": "workspace.v1"}, idempotency_key="exec-1")
    assert executor.executor_id == "x"
    capabilities, capability_cursor = client.list_capabilities()
    assert capabilities[0].status == "ready" and capability_cursor is None
    capability = client.register_capability("render.new", "sha256:" + "c" * 64, idempotency_key="cap-1")
    assert capability.capability_id == "render.new"
    assert client.settle_attempt("a", {"attempt_id": "a", "lease_id": "l", "fence": 4, "outputs": [], "effect": None}, idempotency_key="settle-1").state == "succeeded"
    assert client.fail_attempt("a", lease_id="l", fence=4, error={"code": "worker_error"}, runtime_epoch=1, idempotency_key="fail-1").state == "failed"
    assert any(call[2].get("Idempotency-Key") == "task-1" for call in calls)
