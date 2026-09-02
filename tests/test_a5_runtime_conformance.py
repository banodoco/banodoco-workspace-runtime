from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.service import RuntimeService


CAPABILITY = "render.synthetic.cpu"
EXECUTOR = "fake-cpu-a5"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _service(root, *, max_concurrency=1) -> RuntimeService:
    service = RuntimeService(root)
    service.register_capability(
        {
            "capability_id": CAPABILITY,
            "definition_digest": _digest(CAPABILITY.encode()),
            "required_resource_keys": [],
        }
    )
    epoch = service.health()["runtime_epoch"]
    service.register_executor(
        {
            "executor_id": EXECUTOR,
            "max_concurrency": max_concurrency,
            "resource_keys": ["cpu"],
            "capabilities": [CAPABILITY],
            "protocol": "workspace.v1",
            "runtime_epoch": epoch,
        },
        idempotency_key=f"a5-executor-register-{epoch}",
    )
    return service


def _task(service: RuntimeService, project_id: str, key: str):
    return service.create_task(
        {
            "capability_id": CAPABILITY,
            "capability_digest": _digest(CAPABILITY.encode()),
            "input_object_ids": [],
            "spec": {"synthetic": True, "scenario": key},
            "project": project_id,
            "idempotency_key": key,
        }
    )


def _claim(service: RuntimeService, key: str):
    return service.claim_next(
        {
            "executor_id": EXECUTOR,
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=key,
    )


def _settle(service: RuntimeService, attempt: dict, key: str, outputs=None):
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": [] if outputs is None else outputs,
        },
        idempotency_key=key,
    )


def _project(service: RuntimeService, name: str):
    return service.create_project({"slug": name, "name": name, "metadata": {}})["id"]


def test_a5_crash_reclaim_fences_old_attempt_and_publishes_new_output(tmp_path):
    """A runtime crash requeues work; the old epoch can never publish."""
    service = _service(tmp_path / "realm")
    project_id = _project(service, "a5-crash-reclaim")
    task = _task(service, project_id, "a5-crash-task")
    old_attempt = _claim(service, "a5-crash-claim-1")
    old_epoch = old_attempt["runtime_epoch"]
    service.close()

    recovered = _service(tmp_path / "realm")
    try:
        assert recovered.health()["runtime_epoch"] == old_epoch + 1
        recovered_task = recovered.task(task["task"]["id"])
        assert recovered_task["task"]["status"] == "queued"
        assert recovered_task["task"]["waiting_reason"] == "runtime_recovery"
        payload = b"a5-crash-reclaimed-output"
        output = {
            "name": "reclaimed.bin",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
        }
        with pytest.raises(LeaseError):
            _settle(recovered, old_attempt, "a5-crash-stale-settle", [output])
        new_attempt = _claim(recovered, "a5-crash-claim-2")
        assert new_attempt["fence"] > old_attempt["fence"]
        result = _settle(recovered, new_attempt, "a5-crash-settle", [output])
        assert result["data"]["state"] == "succeeded"
        digest = _digest(payload).removeprefix("sha256:")
        assert recovered.cas.read(digest) == payload
        assert recovered.store.conn.execute("SELECT COUNT(*) FROM objects WHERE digest=?", (digest,)).fetchone()[0] == 1
        event_kinds = [event["kind"] for event in recovered.events(task["run"]["id"])]
        assert "task.runtime_recovered" in event_kinds
        assert event_kinds[-1] == "task.completed"
    finally:
        recovered.close()


def test_a5_expired_attempt_is_reclaimed_and_stale_fence_is_rejected(tmp_path):
    """Lease expiry fences a worker before a replacement claim can settle."""
    service = _service(tmp_path / "realm")
    try:
        project_id = _project(service, "a5-stale-attempt")
        task = _task(service, project_id, "a5-stale-task")
        old_attempt = _claim(service, "a5-stale-claim-1")
        expired = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at=? WHERE id=?",
            (expired, task["task"]["id"]),
        )
        new_attempt = _claim(service, "a5-stale-claim-2")
        assert new_attempt["attempt_id"] != old_attempt["attempt_id"]
        assert new_attempt["fence"] > old_attempt["fence"]
        with pytest.raises(LeaseError):
            _settle(service, old_attempt, "a5-stale-old-settle", [])
        _settle(service, new_attempt, "a5-stale-new-settle", [])
        event_kinds = [event["kind"] for event in service.events(task["run"]["id"])]
        assert "task.lease_expired" in event_kinds
        assert event_kinds[-1] == "task.completed"
    finally:
        service.close()


def test_a5_duplicate_publish_is_single_writer_and_idempotent(tmp_path):
    """Concurrent fake workers may publish one digest, but CAS has one object."""
    service = _service(tmp_path / "realm", max_concurrency=2)
    try:
        project_id = _project(service, "a5-duplicate-publish")
        first = _task(service, project_id, "a5-duplicate-task-1")
        second = _task(service, project_id, "a5-duplicate-task-2")
        first_attempt = _claim(service, "a5-duplicate-claim-1")
        second_attempt = _claim(service, "a5-duplicate-claim-2")
        payload = b"one-content-addressed-output"
        output = {
            "name": "shared.bin",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
        }
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda value: _settle(service, value[0], value[1], [output]),
                    ((first_attempt, "a5-duplicate-settle-1"), (second_attempt, "a5-duplicate-settle-2")),
                )
            )
        assert all(result["data"]["state"] == "succeeded" for result in results)
        digest = _digest(payload).removeprefix("sha256:")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects WHERE digest=?", (digest,)).fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone()[0] == 1
        assert service.cas.read(digest) == payload
        for task in (first, second):
            event_kinds = [event["kind"] for event in service.events(task["run"]["id"])]
            assert event_kinds[-1] == "task.completed"

        replay = _settle(service, first_attempt, "a5-duplicate-settle-1", [output])
        assert replay == results[0]
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects WHERE digest=?", (digest,)).fetchone()[0] == 1
    finally:
        service.close()


def test_a5_large_synthetic_output_is_hashed_staged_and_promoted(tmp_path):
    """A multi-megabyte CPU-generated output remains hash-verified in CAS."""
    service = _service(tmp_path / "realm")
    try:
        project_id = _project(service, "a5-large-output")
        task = _task(service, project_id, "a5-large-task")
        attempt = _claim(service, "a5-large-claim")
        payload = bytes(index % 251 for index in range(4 * 1024 * 1024))
        output = {
            "name": "large-synthetic.bin",
            "digest": _digest(payload),
            "media_type": "application/octet-stream",
            "size": len(payload),
            "data_base64": base64.b64encode(payload).decode("ascii"),
        }
        settled = _settle(service, attempt, "a5-large-settle", [output])
        assert settled["data"]["state"] == "succeeded"
        digest = _digest(payload).removeprefix("sha256:")
        row = service.store.conn.execute("SELECT size, media_type FROM objects WHERE digest=?", (digest,)).fetchone()
        assert dict(row) == {"size": len(payload), "media_type": "application/octet-stream"}
        assert service.cas.read(digest) == payload
        assert not any(service.store.staging_root.rglob("*.stage"))
        assert service.task(task["task"]["id"])["task"]["status"] == "completed"
    finally:
        service.close()
