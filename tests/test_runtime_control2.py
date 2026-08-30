from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from runtime_protocol.backup import verify_backup
from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
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
        task_body = {"capability_id": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "input_object_ids": []}
        first = owner.request("POST", "/v1/tasks", task_body, headers=headers)
        second = owner.request("POST", "/v1/tasks", task_body, headers={**headers, "Idempotency-Key": "task-http-2"})
        worker = Api(daemon.endpoint, daemon.worker_token)
        first_attempt = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"]}, headers={"Idempotency-Key": "claim-http-1"})
        assert first_attempt["fence"] == 1
        blocked = worker.request("POST", "/v1/tasks/claim", {"executor_id": "executor", "capability_ids": ["render.gpu"]}, headers={"Idempotency-Key": "claim-http-2"})
        assert blocked["waiting_reason"] == "waiting_for_worker"
        renewed = worker.request("POST", f"/v1/attempts/{first_attempt['attempt_id']}/heartbeat", {"lease_id": first_attempt["lease_id"], "fence": first_attempt["fence"], "lease_seconds": 60}, headers={"Idempotency-Key": "heartbeat-http-1"})
        assert renewed["fence"] == first_attempt["fence"] and renewed["lease_expires_at"] > first_attempt["lease_expires_at"]
    finally:
        daemon.stop()


def test_backup_restore_and_structured_export_verify_cas_and_sqlite(tmp_path):
    service = RuntimeService(tmp_path / "realm", display_name="Backup Realm")
    try:
        project = service.create_project({"slug": "demo", "name": "Demo", "metadata": {"kind": "test"}})
        ingested = service.ingest(project["id"], b"backup-payload", media_type="text/plain", original_name="payload.txt")
        exported = service.export_structured()
        assert exported["realm"]["display_name"] == "Backup Realm"
        assert exported["projects"][0]["metadata"] == {"kind": "test"}
        assert exported["objects"][0]["digest"] == ingested["digest"]
        assert "owner.lock" not in json.dumps(exported)

        backup = tmp_path / "backup"
        result = service.backup(backup)
        assert result["manifest"]["realm_id"] == service.realm["id"]
        assert (backup / "cas-manifest.json").is_file()
        verify_backup(backup)

        restored = service.restore(backup, tmp_path / "restored")
        assert restored["verification"]["realm_id"] == service.realm["id"]
        handoff = json.loads((tmp_path / "restored" / "activation-handoff.json").read_text())
        assert handoff["state"] == "prepared"
        with pytest.raises(ConflictError):
            service.restore(backup, tmp_path / "restored")
    finally:
        service.close()


def test_http_admin_export_backup_and_restore_routes(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        exported = owner.request("GET", "/v1/export")
        assert exported["realm"]["id"] == daemon.service.realm["id"]
        backup = tmp_path / "http-backup"
        created = owner.request("POST", "/v1/backup", {"destination": str(backup)})
        assert created["manifest"]["realm_id"] == daemon.service.realm["id"]
        restored = owner.request("POST", "/v1/restore", {"backup": str(backup), "destination": str(tmp_path / "http-restored")})
        assert restored["activation_handoff"].endswith("activation-handoff.json")
    finally:
        daemon.stop()


def test_retry_is_state_guarded_and_records_transition(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1")})
        service.register_worker({"worker_id": "worker", "capabilities": ["render.gpu"]})
        cancelled = _task(service, "retry-cancelled")["task"]["id"]
        service.cancel(cancelled)
        retried = service.retry_task(cancelled, {"expected_version": 1})
        assert retried["state"] == "queued"
        events = service.events(service.task(cancelled)["run"]["id"])
        assert events[-1]["kind"] == "task.retried"

        running = _task(service, "retry-running")["task"]["id"]
        service.claim(running, {"worker_id": "worker", "lease_token": "running-lease"})
        with pytest.raises(ConflictError):
            service.retry_task(running)
    finally:
        service.close()


def test_settlement_effect_rejects_undeclared_stale_and_duplicate(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "effect", "name": "Effect"})
        service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1")})
        service.register_worker({"worker_id": "worker", "capabilities": ["render.gpu"]})
        undeclared = _task(service, "effect-undeclared")["task"]["id"]
        service.claim(undeclared, {"worker_id": "worker", "lease_token": "u"})
        with pytest.raises(ValidationError):
            service.settle(undeclared, {"lease_token": "u", "fence": 1, "result": {}, "effect": {"kind": "project.update", "target": project["id"], "expected_version": 1}})
        service.cancel(undeclared)

        stale_effect = {"kind": "project.update", "target": project["id"], "expected_version": 2}
        stale = service.create_task({"capability": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "settlement_effect": stale_effect, "idempotency_key": "effect-stale"})["task"]["id"]
        service.claim(stale, {"worker_id": "worker", "lease_token": "s"})
        with pytest.raises(ConflictError):
            service.settle(stale, {"lease_token": "s", "fence": 1, "result": {}, "effect": stale_effect})
        service.cancel(stale)

        valid_effect = {"kind": "project.update", "target": project["id"], "expected_version": 1}
        duplicate = service.create_task({"capability": "render.gpu", "capability_digest": _digest("render.gpu-v1"), "settlement_effect": valid_effect, "idempotency_key": "effect-duplicate"})["task"]["id"]
        service.claim(duplicate, {"worker_id": "worker", "lease_token": "d"})
        service.settle(duplicate, {"lease_token": "d", "fence": 1, "result": {}, "effect": valid_effect})
        with pytest.raises(LeaseError):
            service.settle(duplicate, {"lease_token": "d", "fence": 1, "result": {}, "effect": valid_effect})
    finally:
        service.close()


def test_storage_admission_sets_exact_waiting_reason(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.large", "definition_digest": _digest("render.large-v1"), "estimated_output_bytes": 1024})
        monkeypatch.setattr("runtime_protocol.store.shutil.disk_usage", lambda _path: SimpleNamespace(free=1))
        task = service.create_task({"capability": "render.large", "capability_digest": _digest("render.large-v1"), "idempotency_key": "disk-full"})
        assert task["task"]["waiting_reason"] == "insufficient_storage"
        service.register_worker({"worker_id": "worker", "capabilities": ["render.large"]})
        claimed = service.claim(task["task"]["id"], {"worker_id": "worker", "lease_token": "disk-lease"})
        assert claimed["task"]["waiting_reason"] == "insufficient_storage"
    finally:
        service.close()
