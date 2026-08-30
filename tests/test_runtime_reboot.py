from __future__ import annotations

import hashlib
import json

import pytest

from runtime_protocol.errors import LeaseError, ValidationError
from runtime_protocol.service import RuntimeService


def _digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def test_reboot_requeues_durable_task_and_fences_old_process(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root)
    first.register_worker({"worker_id": "worker", "capabilities": ["render.basic"]})
    admitted = first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "reboot-task"})
    task_id = admitted["task"]["id"]
    claimed = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
    assert claimed["task_id"] == task_id
    old_lease = {key: claimed[key] for key in ("attempt_id", "lease_id", "fence")}
    old_epoch = first.health()["runtime_epoch"]
    old_realm = first.realm["id"]
    first.close()

    second = RuntimeService(root)
    try:
        assert second.realm["id"] == old_realm
        assert second.health()["runtime_epoch"] == old_epoch + 1
        lifecycle = second.runtime_lifecycle()
        assert lifecycle["recovered_task_count"] == 1
        recovered = second.task(task_id)
        assert recovered["task"]["status"] == "queued"
        assert recovered["task"]["waiting_reason"] == "runtime_recovery"
        assert recovered["task"]["id"] == task_id

        with pytest.raises(LeaseError):
            second.settle_attempt(old_lease["attempt_id"], {"lease_id": old_lease["lease_id"], "fence": old_lease["fence"], "outputs": []})

        resumed = second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
        assert resumed["task_id"] == task_id
        assert resumed["fence"] == old_lease["fence"] + 1
        settled = second.settle_attempt(resumed["attempt_id"], {"lease_id": resumed["lease_id"], "fence": resumed["fence"], "outputs": [{"digest": _digest("reboot-output"), "data_base64": "cmVib290LW91dHB1dA=="}]})
        assert settled["state"] == "succeeded"
        assert second.task(task_id)["task"]["status"] == "completed"
        events = second.events(admitted["run"]["id"])
        assert [event["kind"] for event in events][-3:] == ["task.runtime_recovered", "task.claimed", "task.completed"]
    finally:
        second.close()


def test_reboot_recovery_is_atomic_with_settlement_effects(tmp_path):
    root = tmp_path / "realm"
    first = RuntimeService(root)
    project = first.create_project({"slug": "effect", "name": "Before"})
    effect = {"kind": "project.update", "target": project["id"], "expected_version": 1, "payload": {"name": "After"}}
    admitted = first.create_task({"capability_id": "render.basic", "project": project["id"], "spec": {}, "expected_effect": effect, "idempotency_key": "effect-reboot"})
    first.register_worker({"worker_id": "worker", "capabilities": ["render.basic"]})
    attempt = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
    first.close()

    second = RuntimeService(root)
    try:
        resumed = second.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
        assert resumed["task_id"] == admitted["task"]["id"]
        body = {"lease_id": resumed["lease_id"], "fence": resumed["fence"], "outputs": [], "effect": effect}
        second.settle_attempt(resumed["attempt_id"], body)
        assert second.get_project(project["id"])["name"] == "After"
        with pytest.raises(LeaseError):
            second.settle_attempt(resumed["attempt_id"], body)
        assert second.get_project(project["id"])["version"] == 2
        assert attempt["fence"] < resumed["fence"]
    finally:
        second.close()


def test_stale_settlement_rejects_before_cas_or_object_mutation(tmp_path):
    root = tmp_path / "realm"
    service = RuntimeService(root)
    service.register_worker({"worker_id": "worker", "capabilities": ["render.basic"]})
    admitted = service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "stale-cas"})
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
    stale_epoch = attempt["runtime_epoch"]
    digest = _digest("stale-output").removeprefix("sha256:")
    service.store.conn.execute("UPDATE runtime_lifecycle SET runtime_epoch=runtime_epoch+1 WHERE id=1")
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": stale_epoch, "outputs": [{"digest": "sha256:" + digest, "data_base64": "c3RhbGUtb3V0cHV0"}]})
    assert not service.cas.path_for(digest).exists()
    assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
    assert service.task(admitted["task"]["id"])["task"]["status"] == "running"
    service.close()


def test_checkpoint_reboot_resume_is_nonce_bound_and_test_injected(tmp_path):
    root = tmp_path / "realm"
    invoked = []

    def injected_executor(command, checkpoint):
        invoked.append((command, checkpoint))
        return {"test_injected": True}

    first = RuntimeService(root, reboot_executor=injected_executor)
    first.register_worker({"worker_id": "worker", "capabilities": ["render.basic"]})
    first.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "checkpoint"})
    attempt = first.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"]})
    nonce = first.prepare_reboot({"attempt_id": attempt["attempt_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"]})["nonce"]
    checkpoint = first.checkpoint_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "nonce": nonce, "authorization": nonce, "state": {"step": 1}})
    assert json.loads((root / "checkpoints" / (checkpoint["checkpoint_id"] + ".json")).read_text())["step"] == 1
    with pytest.raises(ValidationError):
        first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": "wrong"})
    receipt = first.request_reboot({"checkpoint_id": checkpoint["checkpoint_id"], "nonce": nonce, "authorization": nonce})
    assert receipt["type"] == "runtime.recovery.receipt"
    assert invoked == [("reboot", {"step": 1})]
    first.close()
