from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def test_two_worker_credentials_cannot_cross_claim_or_mutate_attempt(tmp_path: Path) -> None:
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        capability = "render.security"
        definition = _digest(b"render-security-v1")
        owner.request("POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": definition})
        for executor_id in ("worker-a", "worker-b"):
            owner.request(
                "POST", "/v1/executors",
                {"executor_id": executor_id, "capabilities": [{"capability_id": capability, "definition_digest": definition, "status": "ready", "required_resource_keys": []}]},
                headers={"Idempotency-Key": executor_id},
            )
        token_a, _ = daemon.credentials.provision("worker-a", ["handshake", "worker:execute", "tasks:read"])
        token_b, _ = daemon.credentials.provision("worker-b", ["handshake", "worker:execute", "tasks:read"])
        worker_a, worker_b = Api(daemon.endpoint, token_a), Api(daemon.endpoint, token_b)
        owner.request("POST", "/v1/tasks", {"capability_id": capability, "capability_digest": definition, "input_object_ids": []}, headers={"Idempotency-Key": "security-task"})
        epoch = owner.health()["runtime_epoch"]

        with pytest.raises(RuntimeError) as wrong_claim:
            worker_b.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "wrong-claim"})
        assert wrong_claim.value.status == 401

        attempt = worker_a.request("POST", "/v1/tasks/claim", {"executor_id": "worker-a", "capability_ids": [capability], "runtime_epoch": epoch}, headers={"Idempotency-Key": "right-claim"})
        for action, body in (
            ("heartbeat", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch}),
            ("checkpoint", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "nonce": "forged", "authorization": "forged", "state": {}}),
            ("fail", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "error": {"code": "forged"}}),
            ("settle", {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": []}),
        ):
            with pytest.raises(RuntimeError) as wrong_action:
                worker_b.request("POST", f"/v1/attempts/{attempt['attempt_id']}/{action}", body, headers={"Idempotency-Key": f"wrong-{action}"})
            assert wrong_action.value.status == 401
    finally:
        daemon.stop()


def test_settlement_stages_all_outputs_before_fenced_publication(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path / "realm")
    try:
        definition = _digest(b"render-settlement-v1")
        service.register_capability({"capability_id": "render.settlement", "definition_digest": definition})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.settlement"]})
        project = service.create_project({"slug": "settlement", "name": "Settlement"})
        task = service.create_task({"capability_id": "render.settlement", "capability_digest": definition, "project": project["id"], "idempotency_key": "settlement-task"})
        attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.settlement"], "runtime_epoch": service.health()["runtime_epoch"]})
        payload = b"first-output"
        valid = {"digest": _digest(payload), "data_base64": base64.b64encode(payload).decode("ascii"), "size": len(payload), "media_type": "application/octet-stream", "kind": "object", "name": "first"}
        with pytest.raises(ValidationError):
            service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid, {"digest": "malformed"}]})
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert list((service.store.cas_root).glob("*/*")) == []

        service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [valid]})
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)).fetchone()[0] == 1
        assert service.task(task["task"]["id"])["task"]["status"] == "completed"
    finally:
        service.close()
