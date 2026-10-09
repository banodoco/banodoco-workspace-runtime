from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "vibecomfy.run"
EXECUTOR = "astrid-pack-host"
DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()
SELECTED = {
    "selected": {
        "target": {
            "kind": "runpod",
            "pod_id": "pod-bound",
            "provider_account_ref": "runpod-default",
        },
        "profile": "pip_embedded",
    }
}
ACTUAL = {
    "actual": {
        "target": {
            "kind": "runpod",
            "pod_id": "pod-bound",
            "provider_account_ref": "runpod-default",
        },
        "profile": "pip_embedded",
    }
}
TRUSTED = {
    **ACTUAL,
    "verification": {
        "method": "credential_claim",
        "evidence_digest": "sha256:" + hashlib.sha256(b"pod-bound-credential").hexdigest(),
        "verified": True,
    },
}


def _service(root):
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def _identity(binding=TRUSTED):
    value = {"actor": EXECUTOR, "scopes": ["worker:register", "worker:execute"]}
    if binding is not None:
        value["execution_binding"] = binding
    return value


def _register(
    service, *, actual=ACTUAL, trusted=TRUSTED, key="register", resource_key=None
):
    resource_keys = [resource_key] if resource_key else []
    body = {
        "executor_id": EXECUTOR,
        "resource_keys": resource_keys,
        "capabilities": [{
            "capability_id": CAPABILITY,
            "definition_digest": DIGEST,
            "status": "ready",
            "required_resource_keys": resource_keys,
            "estimated_scratch_bytes": 0,
            "estimated_output_bytes": 16,
        }],
        "runtime_epoch": service.health()["runtime_epoch"],
    }
    if actual is not None:
        body["execution_binding"] = actual
    return service.register_executor(
        body, idempotency_key=key, identity=_identity(trusted)
    )


def _admit(service, key):
    return service.create_task({
        "capability_id": CAPABILITY,
        "capability_digest": DIGEST,
        "input_object_ids": [],
        "spec": {"scenario": key},
        "idempotency_key": key,
        "execution_binding": SELECTED,
    })


def _claim(service, key):
    return service.claim_next(
        {
            "executor_id": EXECUTOR,
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=key,
        identity=_identity(),
    )


def test_binding_match_dispatches_and_missing_unverified_or_wrong_profile_do_not(tmp_path):
    matching = _service(tmp_path / "matching")
    try:
        _register(matching)
        task = _admit(matching, "matching")
        attempt = _claim(matching, "matching-claim")
        assert attempt["task_id"] == task["task"]["id"]
        assert attempt["execution_binding"] == {**SELECTED, **TRUSTED}
    finally:
        matching.close()

    missing = _service(tmp_path / "missing")
    try:
        _register(missing, actual=None, trusted=None)
        task = _admit(missing, "missing")
        waiting = _claim(missing, "missing-claim")
        assert waiting["waiting_reason"] == "execution_binding_missing"
        assert waiting["task"]["attempt_id"] is None
        assert missing.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
        assert waiting["task"]["task_id"] == task["task"]["id"]
    finally:
        missing.close()

    unverified = _service(tmp_path / "unverified")
    try:
        _register(unverified, trusted=None)
        _admit(unverified, "unverified")
        waiting = _claim(unverified, "unverified-claim")
        assert waiting["waiting_reason"] == "execution_binding_unverified"
        assert unverified.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    finally:
        unverified.close()

    wrong_profile = _service(tmp_path / "wrong-profile")
    try:
        wrong_actual = {
            "actual": {**ACTUAL["actual"], "profile": "checkout_server"}
        }
        wrong_trusted = {
            **wrong_actual,
            "verification": TRUSTED["verification"],
        }
        _register(wrong_profile, actual=wrong_actual, trusted=wrong_trusted)
        _admit(wrong_profile, "wrong-profile")
        waiting = _claim(wrong_profile, "wrong-profile-claim")
        assert waiting["waiting_reason"] == "execution_binding_mismatch"
        assert wrong_profile.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    finally:
        wrong_profile.close()


def test_restart_preserves_remote_uncertainty_and_authorized_resume_binding_and_output(tmp_path):
    root = tmp_path / "realm"
    first = _service(root)
    first.reboot_executor = lambda *_args, **_kwargs: {"reboot": "observed"}
    _register(first)
    admitted = _admit(first, "remote-recovery")
    attempt = _claim(first, "remote-claim")
    epoch = attempt["runtime_epoch"]
    prepared = first.prepare_reboot(
        {
            "attempt_id": attempt["attempt_id"],
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "runtime_epoch": epoch,
        },
        identity=_identity(),
    )
    checkpoint = first.checkpoint_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": epoch,
            "state": {"provider_operation_id": "provider-op-1", "phase": "running"},
        },
        identity=_identity(),
    )
    first.request_reboot(
        {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": epoch,
        },
        identity=_identity(),
    )
    first.close()

    second = RuntimeService(root, reboot_executor=lambda *_: {"reboot": "observed"})
    try:
        recovered = second._task_resource(second.task(admitted["task"]["id"]))
        assert recovered["state"] == "queued"
        assert recovered["waiting_reason"] == "provider_state_unknown"
        assert recovered["attempt_id"] == attempt["attempt_id"]
        assert recovered["execution_binding"] == {**SELECTED, **TRUSTED}

        _register(second, key="register-after-restart")
        before_attempts = second.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        blocked = _claim(second, "blind-redispatch")
        assert blocked["waiting_reason"] == "provider_state_unknown"
        assert second.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == before_attempts

        resumed = second.resume_attempt(
            {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "runtime_epoch": second.health()["runtime_epoch"],
            },
            identity=_identity(),
        )["attempt"]
        assert resumed["attempt_id"] != attempt["attempt_id"]
        assert resumed["execution_binding"] == {**SELECTED, **TRUSTED}

        output = b"verified resumed output"
        settled = second.settle_attempt(
            resumed["attempt_id"],
            {
                "lease_id": resumed["lease_id"],
                "fence": resumed["fence"],
                "runtime_epoch": resumed["runtime_epoch"],
                "outputs": [{
                    "name": "result.bin",
                    "digest": "sha256:" + hashlib.sha256(output).hexdigest(),
                    "media_type": "application/octet-stream",
                    "size": len(output),
                    "data_base64": base64.b64encode(output).decode(),
                }],
            },
            idempotency_key="resume-settle",
            identity=_identity(),
        )
        assert settled["data"]["state"] == "succeeded"
        assert settled["data"]["execution_binding"] == {**SELECTED, **TRUSTED}
        outputs = second.managed_outputs(admitted["task"]["id"])
        assert outputs[0]["attempt_id"] == resumed["attempt_id"]
        assert outputs[0]["digest"] == "sha256:" + hashlib.sha256(output).hexdigest()
    finally:
        second.close()


def test_run_cancel_preserves_unknown_provider_attempt_and_blocks_blind_retry(tmp_path):
    root = tmp_path / "cancel-uncertain-realm"
    first = _service(root)
    first.reboot_executor = lambda *_args, **_kwargs: {"reboot": "observed"}
    _register(first, resource_key="runpod-pod")
    admitted = _admit(first, "cancel-uncertain")
    old_attempt = _claim(first, "cancel-uncertain-claim")
    old_epoch = old_attempt["runtime_epoch"]
    prepared = first.prepare_reboot(
        {
            "attempt_id": old_attempt["attempt_id"],
            "lease_id": old_attempt["lease_id"],
            "fence": old_attempt["fence"],
            "runtime_epoch": old_epoch,
        },
        identity=_identity(),
    )
    checkpoint = first.checkpoint_attempt(
        old_attempt["attempt_id"],
        {
            "lease_id": old_attempt["lease_id"],
            "fence": old_attempt["fence"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": old_epoch,
            "state": {"provider_operation_id": "provider-op-cancel", "phase": "running"},
        },
        identity=_identity(),
    )
    first.request_reboot(
        {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": old_epoch,
        },
        identity=_identity(),
    )
    first.close()

    second = RuntimeService(root, reboot_executor=lambda *_: {"reboot": "observed"})
    try:
        task_id = admitted["task"]["id"]
        _register(second, key="register-after-cancel-restart", resource_key="runpod-pod")
        recovered = second._task_resource(second.task(task_id))
        assert recovered["state"] == "queued"
        assert recovered["waiting_reason"] == "provider_state_unknown"
        assert recovered["attempt_id"] == old_attempt["attempt_id"]
        assert recovered["execution_binding"] == {**SELECTED, **TRUSTED}

        attempts_before = second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0]
        task_before = second.store.conn.execute(
            "SELECT attempt, attempt_id, lease_fence FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        reservation_before = second.store.conn.execute(
            "SELECT lease_token, fence, released_at FROM reservations "
            "WHERE task_id=? AND resource_key='runpod-pod'",
            (task_id,),
        ).fetchone()
        assert attempts_before == 1
        assert task_before["attempt"] == 1
        assert task_before["attempt_id"] == old_attempt["attempt_id"]
        assert task_before["lease_fence"] == old_attempt["fence"]
        assert reservation_before["released_at"] is None

        blocked_before_cancel = _claim(second, "blind-paid-claim-before-cancel")
        assert blocked_before_cancel["waiting_reason"] == "provider_state_unknown"
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before

        cancelled = second.cancel_task_canonical(
            task_id, {}, idempotency_key="cancel-unknown-provider"
        )["data"]
        assert cancelled["state"] == "cancel_requested"
        assert cancelled["waiting_reason"] == "provider_state_unknown"
        assert cancelled["attempt_id"] == old_attempt["attempt_id"]
        assert cancelled["execution_binding"] == {**SELECTED, **TRUSTED}

        task_after_cancel = second.store.conn.execute(
            "SELECT attempt, attempt_id, lease_fence FROM tasks WHERE id=?", (task_id,)
        ).fetchone()
        reservation_after_cancel = second.store.conn.execute(
            "SELECT lease_token, fence, released_at FROM reservations "
            "WHERE task_id=? AND resource_key='runpod-pod'",
            (task_id,),
        ).fetchone()
        assert tuple(task_after_cancel) == tuple(task_before)
        assert tuple(reservation_after_cancel) == tuple(reservation_before)
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before
        old_attempt_row = second.store.conn.execute(
            "SELECT settled, execution_binding_json FROM attempts WHERE id=?",
            (old_attempt["attempt_id"],),
        ).fetchone()
        assert old_attempt_row["settled"] == 0
        assert old_attempt_row["execution_binding_json"] is not None

        cancellation_event = second.events(admitted["run"]["id"])[-1]
        assert cancellation_event["kind"] == "task.cancel_requested"
        assert cancellation_event["payload"]["remote_stop_confirmed"] is False
        assert cancellation_event["payload"]["billing_stop_confirmed"] is False

        with pytest.raises(LeaseError):
            second.settle_attempt(
                old_attempt["attempt_id"],
                {
                    "lease_id": old_attempt["lease_id"],
                    "fence": old_attempt["fence"],
                    "runtime_epoch": second.health()["runtime_epoch"],
                    "outputs": [],
                },
                idempotency_key="stale-old-attempt-settle",
                identity=_identity(),
            )
        with pytest.raises(ConflictError, match="authorized checkpoint resume"):
            second.retry_task(task_id, {}, idempotency_key="blind-paid-retry")
        assert _claim(second, "blind-paid-claim-after-cancel") is None
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before

        run_cancelled = second.cancel_run(
            admitted["run"]["id"], {}, idempotency_key="cancel-uncertain-run"
        )
        assert run_cancelled["status"] == "cancelled"

        task_after_run_cancel = second._task_resource(second.task(task_id))
        assert task_after_run_cancel["state"] == "cancel_requested"
        assert task_after_run_cancel["waiting_reason"] == "provider_state_unknown"
        assert task_after_run_cancel["attempt_id"] == old_attempt["attempt_id"]
        assert task_after_run_cancel["execution_binding"] == {**SELECTED, **TRUSTED}
        assert tuple(second.store.conn.execute(
            "SELECT attempt, attempt_id, lease_fence FROM tasks WHERE id=?", (task_id,)
        ).fetchone()) == tuple(task_before)
        assert tuple(second.store.conn.execute(
            "SELECT lease_token, fence, released_at FROM reservations "
            "WHERE task_id=? AND resource_key='runpod-pod'",
            (task_id,),
        ).fetchone()) == tuple(reservation_before)
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before
        assert tuple(second.store.conn.execute(
            "SELECT settled, execution_binding_json FROM attempts WHERE id=?",
            (old_attempt["attempt_id"],),
        ).fetchone()) == tuple(old_attempt_row)

        run_cancel_events = second.events(admitted["run"]["id"])[-2:]
        assert run_cancel_events[0]["kind"] == "task.cancel_requested"
        assert run_cancel_events[0]["payload"]["reason"] == "run.cancelled"
        assert run_cancel_events[0]["payload"]["remote_stop_confirmed"] is False
        assert run_cancel_events[0]["payload"]["billing_stop_confirmed"] is False
        assert run_cancel_events[1]["kind"] == "run.cancelled"
        assert run_cancel_events[1]["payload"]["task_ids"] == []
        assert run_cancel_events[1]["payload"]["cancel_requested_task_ids"] == [task_id]

        with pytest.raises(ConflictError, match="authorized checkpoint resume"):
            second.retry_task(task_id, {}, idempotency_key="blind-paid-retry-after-run-cancel")
        assert _claim(second, "blind-paid-claim-after-run-cancel") is None
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before

        resumed = second.resume_attempt(
            {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "runtime_epoch": second.health()["runtime_epoch"],
            },
            identity=_identity(),
        )["attempt"]
        assert resumed["attempt_id"] != old_attempt["attempt_id"]
        assert resumed["fence"] > old_attempt["fence"]
        assert resumed["execution_binding"] == {**SELECTED, **TRUSTED}
        assert second.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == attempts_before + 1
        assert second.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (old_attempt["attempt_id"],)
        ).fetchone()[0] == 0
    finally:
        second.close()


def test_new_attempt_never_inherits_prior_attempt_progress(tmp_path):
    service = _service(tmp_path / "progress")
    try:
        service.register_executor({"executor_id": EXECUTOR, "capabilities": [CAPABILITY]})
        task = service.create_task({
            "capability_id": CAPABILITY,
            "spec": {},
            "idempotency_key": "progress-attempts",
        })
        first = service.claim_next({
            "executor_id": EXECUTOR,
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        }, idempotency_key="progress-claim-1")
        service.heartbeat_attempt(
            first["attempt_id"],
            {
                "lease_id": first["lease_id"],
                "fence": first["fence"],
                "runtime_epoch": first["runtime_epoch"],
                "progress": {"phase": "render", "percent": 75},
            },
            idempotency_key="progress-heartbeat-1",
        )
        task_id = task["task"]["id"]
        assert service._task_resource(service.store.get_task(task_id))["progress"]["percent"] == 75

        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, task_id)
        )
        second = service.claim_next({
            "executor_id": EXECUTOR,
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        }, idempotency_key="progress-claim-2")
        assert second["attempt_id"] != first["attempt_id"]
        assert "progress" not in service._task_resource(service.store.get_task(task_id))

        service.heartbeat_attempt(
            second["attempt_id"],
            {
                "lease_id": second["lease_id"],
                "fence": second["fence"],
                "runtime_epoch": second["runtime_epoch"],
                "progress": {"phase": "restart", "percent": 5},
            },
            idempotency_key="progress-heartbeat-2",
        )
        assert service._task_resource(service.store.get_task(task_id))["progress"] == {
            "phase": "restart", "percent": 5,
        }
    finally:
        service.close()
