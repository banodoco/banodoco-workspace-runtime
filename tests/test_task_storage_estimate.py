from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _register_render(service: RuntimeService, *, scratch_bytes: int, output_bytes: int) -> None:
    digest = _digest("render.storage-v1")
    service.register_capability({
        "capability_id": "render.storage",
        "definition_digest": digest,
        "estimated_scratch_bytes": scratch_bytes,
        "estimated_output_bytes": output_bytes,
    })
    service.register_executor({
        "executor_id": "render-worker",
        "capabilities": [{
            "capability_id": "render.storage",
            "definition_digest": digest,
            "status": "ready",
            "required_resource_keys": [],
            "estimated_scratch_bytes": scratch_bytes,
            "estimated_output_bytes": output_bytes,
        }],
        "resource_keys": [],
    }, idempotency_key="register-render-worker")


def _admission(*, key: str, storage_estimate=None):
    body = {
        "capability_id": "render.storage",
        "capability_digest": _digest("render.storage-v1"),
        "input_object_ids": [],
        "idempotency_key": key,
    }
    if storage_estimate is not None:
        body["storage_estimate"] = storage_estimate
    return body


def _claim(service: RuntimeService, key: str):
    return service.claim_next({
        "executor_id": "render-worker",
        "capability_ids": ["render.storage"],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key=key)


def test_task_estimate_overrides_capability_fallback_at_admission_and_claim(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        _register_render(service, scratch_bytes=800, output_bytes=200)
        free = {"bytes": 500}
        monkeypatch.setattr(
            "runtime_protocol.store.shutil.disk_usage",
            lambda _path: SimpleNamespace(free=free["bytes"]),
        )

        estimate = {"scratch_bytes": 250, "output_bytes": 150}
        admitted = service.create_task(
            _admission(key="task-specific", storage_estimate=estimate),
            enforce_readiness=True,
        )
        assert admitted["task"].get("waiting_reason") is None
        task = service._task_resource(admitted)
        assert task["storage_estimate"] == estimate
        assert task["spec"]["storage_estimate"] == estimate

        # Claim preflight reads the admitted task snapshot, not the mutable
        # capability-wide fallback and not a new worker-side estimate.
        free["bytes"] = 399
        waiting = _claim(service, "claim-too-small")
        assert waiting["waiting_reason"] == "insufficient_storage"
        assert waiting["task"]["storage_estimate"] == estimate

        free["bytes"] = 400
        claimed = _claim(service, "claim-exact-fit")
        assert claimed["task_id"] == task["task_id"]
        assert claimed["storage_estimate"] == estimate
        assert claimed["spec"]["storage_estimate"] == estimate
    finally:
        service.close()


def test_missing_task_estimate_uses_capability_fallback(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        _register_render(service, scratch_bytes=400, output_bytes=200)
        monkeypatch.setattr(
            "runtime_protocol.store.shutil.disk_usage",
            lambda _path: SimpleNamespace(free=599),
        )
        admitted = service.create_task(_admission(key="fallback"))
        assert admitted["task"]["waiting_reason"] == "insufficient_storage"
        assert "storage_estimate" not in admitted["task"]["spec"]
        preflight = service.store.storage_preflight("render.storage")
        assert preflight == {
            "ok": False,
            "required_bytes": 600,
            "available_bytes": 599,
            "scratch_bytes": 400,
            "output_bytes": 200,
            "estimate_source": "capability",
            "reason": "insufficient_storage",
        }
    finally:
        service.close()


def test_task_storage_failure_is_not_mislabeled_as_capability_unavailable(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    try:
        _register_render(service, scratch_bytes=1, output_bytes=1)
        monkeypatch.setattr(
            "runtime_protocol.store.shutil.disk_usage",
            lambda _path: SimpleNamespace(free=99),
        )
        admitted = service.create_task(
            _admission(
                key="insufficient-task-storage",
                storage_estimate={"scratch_bytes": 80, "output_bytes": 20},
            ),
            enforce_readiness=True,
        )
        assert admitted["task"]["waiting_reason"] == "insufficient_storage"
    finally:
        service.close()


@pytest.mark.parametrize("estimate", [
    {},
    {"scratch_bytes": 1},
    {"scratch_bytes": 1, "output_bytes": 2, "extra": 3},
    {"scratch_bytes": True, "output_bytes": 2},
    {"scratch_bytes": 1.5, "output_bytes": 2},
    {"scratch_bytes": -1, "output_bytes": 2},
    {"scratch_bytes": (1 << 53), "output_bytes": 0},
    {"scratch_bytes": (1 << 53) - 1, "output_bytes": 1},
    [1, 2],
])
def test_storage_estimate_is_strictly_validated_before_admission(tmp_path, estimate):
    service = RuntimeService(tmp_path / "realm")
    try:
        with pytest.raises(ValidationError):
            service.create_task(_admission(key="invalid", storage_estimate=estimate))
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
    finally:
        service.close()


def test_explicit_null_storage_estimate_is_rejected(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        body = _admission(key="null-estimate")
        body["storage_estimate"] = None
        with pytest.raises(ValidationError, match="must be an object"):
            service.create_task(body)
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    finally:
        service.close()


def test_storage_estimate_is_bound_to_admission_idempotency(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        first = service.create_task(_admission(
            key="stable-estimate",
            storage_estimate={"scratch_bytes": 100, "output_bytes": 20},
        ))
        replay = service.create_task(_admission(
            key="stable-estimate",
            storage_estimate={"scratch_bytes": 100, "output_bytes": 20},
        ))
        assert replay == first
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1

        with pytest.raises(ConflictError, match="idempotency key"):
            service.create_task(_admission(
                key="stable-estimate",
                storage_estimate={"scratch_bytes": 101, "output_bytes": 20},
            ))
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    finally:
        service.close()
