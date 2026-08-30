from __future__ import annotations

import hashlib

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.daemon import RuntimeDaemon
from http_helpers import Api
from runtime_protocol.service import RuntimeService


def _digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def _task(service: RuntimeService, key: str):
    return service.create_task({
        "capability_id": "render.gpu",
        "capability_digest": _digest("render.gpu-v1"),
        "input_object_ids": [],
        "spec": {},
        "idempotency_key": key,
    })


def test_named_resource_reservation_blocks_and_releases_with_attempt_lease(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({
            "capability_id": "render.gpu",
            "definition_digest": _digest("render.gpu-v1"),
            "required_resource_keys": ["gpu"],
        })
        service.register_worker({"worker_id": "gpu-worker", "capabilities": ["render.gpu"], "resource_keys": ["gpu"], "max_concurrency": 1})
        first = _task(service, "first")["task"]["id"]
        second = _task(service, "second")["task"]["id"]
        claimed = service.claim(first, {"worker_id": "gpu-worker", "lease_token": "lease-first"})
        assert claimed["task"]["status"] == "running"
        blocked = service.claim(second, {"worker_id": "gpu-worker", "lease_token": "lease-second"})
        assert blocked["task"]["status"] == "queued"
        assert blocked["task"]["waiting_reason"] == "waiting_for_worker"
        assert blocked["task"]["blocked_reason"] == "waiting_for_worker"
        service.settle(first, {"lease_token": "lease-first", "fence": 1, "result": {"ok": True}})
        reservation = service.store.conn.execute("SELECT released_at FROM reservations WHERE task_id=? AND resource_key='gpu'", (first,)).fetchone()
        assert reservation["released_at"] is not None
        released = service.claim(second, {"worker_id": "gpu-worker", "lease_token": "lease-second"})
        assert released["task"]["status"] == "running"
        assert released["task"]["lease_fence"] == 1
    finally:
        service.close()


def test_missing_named_resource_has_exact_resource_waiting_reason(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        service.register_worker({"worker_id": "cpu-worker", "capabilities": ["render.gpu"], "resource_keys": ["cpu"]})
        task_id = _task(service, "missing-gpu")["task"]["id"]
        result = service.claim(task_id, {"worker_id": "cpu-worker", "lease_token": "lease"})
        assert result["task"]["status"] == "queued"
        assert result["task"]["waiting_reason"] == "waiting_for_gpu"
    finally:
        service.close()


def test_unavailable_capability_never_claims_even_when_worker_is_ready(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "status": "unavailable", "unavailable_reason": "model_missing"})
        service.register_worker({"worker_id": "worker", "capabilities": ["render.gpu"], "resource_keys": []})
        task_id = _task(service, "capability-unavailable")["task"]["id"]
        result = service.claim(task_id, {"worker_id": "worker", "lease_token": "lease"})
        assert result["task"]["status"] == "queued"
        assert result["task"]["waiting_reason"] == "capability_unavailable"
    finally:
        service.close()


def test_worker_readiness_and_heartbeat_control_admission(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        service.register_worker({"worker_id": "worker", "capabilities": ["render.gpu"], "resource_keys": ["gpu"], "readiness": "not_ready", "readiness_reason": "warming_up"})
        task_id = _task(service, "readiness")["task"]["id"]
        blocked = service.claim(task_id, {"worker_id": "worker", "lease_token": "lease"})
        assert blocked["task"]["waiting_reason"] == "waiting_for_worker"
        ready = service.worker_heartbeat("worker", {"ready": True})
        assert ready["readiness"] == "ready"
        claimed = service.claim(task_id, {"worker_id": "worker", "lease_token": "lease"})
        before = claimed["task"]["lease_expires_at"]
        renewed = service.heartbeat(task_id, {"lease_token": "lease", "fence": claimed["task"]["lease_fence"], "lease_seconds": 120})
        assert renewed["task"]["lease_expires_at"] > before
        with pytest.raises(LeaseError):
            service.heartbeat(task_id, {"lease_token": "lease", "fence": 99})
    finally:
        service.close()


def test_executor_registration_uses_same_worker_capacity_contract(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        registered = service.register_executor({"executor_id": "executor", "max_concurrency": 2, "resource_keys": ["cpu"], "capabilities": ["render.basic"], "protocol": "workspace.v1"})
        assert registered["max_concurrency"] == 2
        worker = service.store.conn.execute("SELECT max_concurrency, resource_keys_json FROM workers WHERE id='executor'").fetchone()
        assert worker["max_concurrency"] == 2
        assert worker["resource_keys_json"] == '["cpu"]'
    finally:
        service.close()


def test_http_executor_claim_heartbeat_and_release_surface(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        owner.request("POST", "/v1/capabilities", {"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"), "required_resource_keys": ["gpu"]})
        owner.request("POST", "/v1/executors", {"executor_id": "executor", "max_concurrency": 1, "resource_keys": ["gpu"], "capabilities": ["render.gpu"], "protocol": "workspace.v1"})
        headers = {"Idempotency-Key": "task-http-1"}
        first = owner.request("POST", "/v1/tasks", {"capability": "render.gpu", "spec": {"input_object_ids": []}}, headers=headers)
        second = owner.request("POST", "/v1/tasks", {"capability": "render.gpu", "spec": {"input_object_ids": []}}, headers={**headers, "Idempotency-Key": "task-http-2"})
        worker = Api(daemon.endpoint, daemon.worker_token)
        first_attempt = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"]}, headers={"Idempotency-Key": "claim-http-1"})
        assert first_attempt["fence"] == 1
        blocked = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"]}, headers={"Idempotency-Key": "claim-http-2"})
        assert blocked["waiting_reason"] == "waiting_for_worker"
        renewed = worker.request("POST", f"/v1/attempts/{first_attempt['attempt_id']}/heartbeat", {"lease_id": first_attempt["lease_id"], "fence": first_attempt["fence"], "lease_seconds": 60}, headers={"Idempotency-Key": "heartbeat-http-1"})
        assert renewed["fence"] == first_attempt["fence"] and renewed["lease_expires_at"] > first_attempt["lease_expires_at"]
    finally:
        daemon.stop()
