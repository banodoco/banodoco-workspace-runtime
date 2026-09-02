from __future__ import annotations

import json

import pytest

from runtime_protocol.errors import LeaseError, ValidationError
from runtime_protocol.service import RuntimeService


@pytest.fixture
def service(tmp_path):
    value = RuntimeService(tmp_path / "realm")
    try:
        yield value
    finally:
        value.close()


def test_empty_claim_replays_committed_null(service):
    service.register_executor({"executor_id": "worker", "capabilities": []})
    body = {
        "executor_id": "worker",
        "capability_ids": [],
        "runtime_epoch": service.health()["runtime_epoch"],
    }

    first = service.claim_next(body, idempotency_key="empty-claim")
    second = service.claim_next(body, idempotency_key="empty-claim")

    assert first is None
    assert second is None
    receipt = service.store.conn.execute(
        "SELECT result_json FROM command_idempotency "
        "WHERE command_kind='task.claim' AND aggregate_id='claim' "
        "AND idempotency_key='empty-claim'"
    ).fetchone()
    assert json.loads(receipt["result_json"]) is None


@pytest.mark.parametrize(
    "invoke",
    [
        lambda runtime: runtime.register_executor(
            {"executor_id": "worker", "unknown": True}
        ),
        lambda runtime: runtime.claim_next(
            {
                "executor_id": "worker",
                "capability_ids": [],
                "runtime_epoch": 1,
                "unknown": True,
            },
            idempotency_key="wire-claim",
        ),
        lambda runtime: runtime.prepare_reboot(
            {
                "attempt_id": "missing",
                "lease_id": "lease",
                "fence": 1,
                "runtime_epoch": 1,
                "unknown": True,
            }
        ),
        lambda runtime: runtime.checkpoint_attempt(
            "missing",
            {
                "lease_id": "lease",
                "fence": 1,
                "nonce": "nonce",
                "authorization": "nonce",
                "runtime_epoch": 1,
                "unknown": True,
            },
        ),
        lambda runtime: runtime.settle_attempt(
            "missing",
            {
                "lease_id": "lease",
                "fence": 1,
                "runtime_epoch": 1,
                "outputs": [],
                "unknown": True,
            },
            idempotency_key="wire-settle",
        ),
        lambda runtime: runtime.heartbeat_attempt(
            "missing",
            {"lease_id": "lease", "fence": 1, "runtime_epoch": 1, "unknown": True},
            idempotency_key="wire-heartbeat",
        ),
        lambda runtime: runtime.fail_attempt(
            "missing",
            {"lease_id": "lease", "fence": 1, "runtime_epoch": 1, "unknown": True},
            idempotency_key="wire-fail",
        ),
        lambda runtime: runtime.request_reboot(
            {"nonce": "nonce", "authorization": "nonce", "runtime_epoch": 1, "unknown": True}
        ),
        lambda runtime: runtime.resume_attempt(
            {"nonce": "nonce", "authorization": "nonce", "runtime_epoch": 1, "unknown": True}
        ),
    ],
)
def test_worker_mutations_validate_wire_before_lookup(service, invoke):
    with pytest.raises(ValidationError):
        invoke(service)


def test_fence_zero_and_stale_lease_are_lease_errors(service):
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]})
    service.create_task(
        {
            "capability_id": "render.basic",
            "spec": {},
            "idempotency_key": "lease-guard-task",
        }
    )
    epoch = service.health()["runtime_epoch"]
    attempt = service.claim_next(
        {
            "executor_id": "worker",
            "capability_ids": ["render.basic"],
            "runtime_epoch": epoch,
        },
        idempotency_key="lease-guard-claim",
    )

    def settle(body, key):
        return service.settle_attempt(attempt["attempt_id"], body, idempotency_key=key)

    def heartbeat(body, key):
        return service.heartbeat_attempt(attempt["attempt_id"], body, idempotency_key=key)

    def fail(body, key):
        return service.fail_attempt(attempt["attempt_id"], body, idempotency_key=key)

    operations = (settle, heartbeat, fail)

    bodies = (
        {"outputs": []},
        {},
        {"error": {"code": "worker_failed"}},
    )
    for index, (operation, extra) in enumerate(zip(operations, bodies)):
        with pytest.raises(LeaseError):
            operation(
                {
                    "lease_id": attempt["lease_id"],
                    "fence": 0,
                    "runtime_epoch": epoch,
                    **extra,
                },
                f"fence-zero-{index}",
            )

    for index, (operation, extra) in enumerate(zip(operations, bodies)):
        with pytest.raises(LeaseError):
            operation(
                {
                    "lease_id": "stale-lease",
                    "fence": attempt["fence"],
                    "runtime_epoch": epoch,
                    **extra,
                },
                f"stale-lease-{index}",
            )

    service.store.conn.execute(
        "UPDATE runtime_lifecycle SET runtime_epoch=runtime_epoch+1 WHERE id=1"
    )
    with pytest.raises(LeaseError):
        service.heartbeat_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": epoch,
            },
            idempotency_key="stale-epoch",
        )

    task = service.task(attempt["task_id"])
    assert task["task"]["status"] == "running"
