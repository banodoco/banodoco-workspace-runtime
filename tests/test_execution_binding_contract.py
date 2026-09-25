from __future__ import annotations

import hashlib
import json

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, NotFoundError, ValidationError
from runtime_protocol.lifecycle import assert_interruption_safe, inspect_interruption_state
from runtime_protocol.service import TARGETED_EXECUTION_BINDING_CAPABILITY, RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "test.targeted"
CAPABILITY_DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()


def _service(root, *, resource_keys=None):
    resource_keys = list(resource_keys or [])
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_capability(
        {
            "capability_id": CAPABILITY,
            "definition_digest": CAPABILITY_DIGEST,
            "required_resource_keys": resource_keys,
        }
    )
    service.register_executor(
        {
            "executor_id": "executor-a",
            "capabilities": [CAPABILITY],
            "max_concurrency": 2,
            "resource_keys": resource_keys,
        },
        idempotency_key="executor-a-register",
    )
    return service


def _request(target: dict) -> dict:
    return {
        "schema_version": 1,
        "target": target,
        "inputs": [],
    }


def _admit(service: RuntimeService, key: str, target: dict, **extra):
    body = {
        "capability_id": CAPABILITY,
        "capability_digest": CAPABILITY_DIGEST,
        "input_object_ids": [],
        "spec": {"params": {"source": "immutable"}},
        "execution_request": _request(target),
        "idempotency_key": key,
    }
    body.update(extra)
    return service.create_task(body, enforce_readiness=True)


def _identity(target: dict, *, incarnation="executor-a/incarnation-1"):
    return {
        "actor": "executor-a",
        "scopes": ["worker:execute"],
        "execution_binding": {
            "actual": target,
            "verification": {
                "method": "credential_claim",
                "evidence_digest": "sha256:" + hashlib.sha256(
                    canonical_target_bytes(target)
                ).hexdigest(),
                "verified": True,
            },
            "executor_incarnation": incarnation,
        },
    }


def canonical_target_bytes(target: dict) -> bytes:
    import json
    return json.dumps(target, sort_keys=True, separators=(",", ":")).encode()


def _claim(
    service: RuntimeService, key: str, target: dict | None, *,
    identity_target: dict | None | object = ...,
    incarnation="executor-a/incarnation-1",
):
    body = {
        "executor_id": "executor-a",
        "capability_ids": [CAPABILITY],
        "runtime_epoch": service.health()["runtime_epoch"],
    }
    if target is not None:
        body["target"] = target
    if identity_target is ...:
        identity_target = target
    identity = (
        _identity(identity_target, incarnation=incarnation)
        if isinstance(identity_target, dict) else None
    )
    return service.claim_next(body, idempotency_key=key, identity=identity)


def test_targeted_admission_persists_runtime_binding_atomically(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {
            "kind": "runpod",
            "pod_id": "pod-h3",
            "provider_account_ref": "account-a",
            "profile_revision": "profile-r7",
            "profile_digest": "sha256:" + "a" * 64,
            "release_digest": "sha256:" + "b" * 64,
            "storage": {"network_volume_id": "volume-1"},
            "mounts": [{"source": "volume-1", "target": "/workspace", "read_only": True}],
        }
        admitted = _admit(service, "targeted-atomic", target)
        binding = admitted["execution_binding"]
        assert binding["status"] == "prepared"
        assert binding["task_id"] == admitted["task"]["id"]
        assert binding["run_id"] == admitted["run"]["id"]
        assert binding["target_kind"] == "runpod"
        assert binding["provider_account_ref"] == "account-a"
        assert binding["pod_id"] == "pod-h3"
        assert binding["profile_revision"] == "profile-r7"
        assert binding["storage"] == {"network_volume_id": "volume-1"}
        assert binding["resolved_target"] == target
        row = service.store.conn.execute(
            "SELECT execution_bindings.status, binding_id, execution_request_json, tasks.spec_json "
            "FROM execution_bindings JOIN tasks ON tasks.id=execution_bindings.task_id WHERE tasks.id=?",
            (admitted["task"]["id"],),
        ).fetchone()
        assert row["status"] == "prepared"
        assert row["binding_id"] == binding["binding_id"]
        assert row["execution_request_json"] is not None
        stored_spec = json.loads(row["spec_json"])
        assert "execution_request" not in stored_spec
        assert "execution_request" not in stored_spec["spec"]
        public = service.task(admitted["task"]["id"])
        assert public["task"]["execution_request"] == _request(target)
        assert "execution_request" not in public["task"]["spec"]
        assert "execution_request" not in service.run(admitted["run"]["id"])["spec"]
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM execution_bindings WHERE task_id=?",
            (admitted["task"]["id"],),
        ).fetchone()[0] == 1
    finally:
        service.close()


def test_caller_binding_and_opaque_execution_request_are_rejected_before_queue(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        base = {
            "capability_id": CAPABILITY,
            "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [],
            "idempotency_key": "rejected",
            "spec": {},
        }
        with pytest.raises(ValidationError, match="caller-supplied"):
            service.create_task(
                {
                    **base,
                    "execution_request": _request(
                        {"kind": "machine", "id": "machine-a"}
                    )
                    | {"execution_binding": {"binding_id": "forged"}},
                }
            )
        with pytest.raises(ValidationError, match="first-class"):
            service.create_task(
                {
                    **base,
                    "execution_request": None,
                    "spec": {
                        "execution_request": _request(
                            {"kind": "machine", "id": "machine-a"}
                        )
                    },
                }
            )
        with pytest.raises(ValidationError, match="first-class"):
            service.create_task(
                {
                    **base,
                    "idempotency_key": "rejected-nested-request",
                    "spec": {"spec": {"execution_request": _request({"kind": "machine", "id": "machine-a"})}},
                }
            )
        with pytest.raises(ValidationError, match="caller-supplied"):
            service.create_task(
                {
                    **base,
                    "idempotency_key": "rejected-spec-binding",
                    "spec": {"execution_binding": {"task_id": "forged"}},
                }
            )
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM execution_bindings"
        ).fetchone()[0] == 0
    finally:
        service.close()


def test_exact_target_claim_matches_and_queue_wide_claim_cannot_steal_targeted_work(
    tmp_path,
):
    service = _service(tmp_path / "realm")
    try:
        target_a = {"kind": "machine", "id": "machine-a"}
        target_b = {
            "kind": "runpod",
            "pod_id": "pod-b",
            "provider_account_ref": "account-b",
        }
        first = _admit(service, "target-a", target_a)
        second = _admit(service, "target-b", target_b)

        assert _claim(service, "queue-wide", None) is None
        assert service.task(first["task"]["id"])["task"]["status"] == "queued"

        assert _claim(service, "wrong-target", {"kind": "machine", "id": "machine-other"}) is None
        claimed_a = _claim(service, "claim-a", {"kind": "machine", "id": "machine-a"})
        assert claimed_a["task_id"] == first["task"]["id"]
        assert claimed_a["run_id"] == first["run"]["id"]
        assert claimed_a["lease_expires_at"]
        assert claimed_a["execution_binding"]["status"] == "claimed"
        assert claimed_a["execution_binding"]["target_id"] == "machine-a"
        assert claimed_a["execution_binding"]["actual_target"] == target_a
        assert claimed_a["execution_binding"]["verification"]["verified"] is True
        assert claimed_a["execution_binding"]["executor_incarnation"] == "executor-a/incarnation-1"

        claimed_b = _claim(service, "claim-b", target_b)
        assert claimed_b["task_id"] == second["task"]["id"]
        assert claimed_b["execution_binding"]["provider_account_ref"] == "account-b"
        assert claimed_b["execution_binding"]["pod_id"] == "pod-b"
    finally:
        service.close()


def test_duplicate_admission_replays_the_same_runtime_binding(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        first = _admit(service, "duplicate", {"kind": "profile", "profile_alias": "h3"})
        replay = _admit(service, "duplicate", {"kind": "profile", "id": "h3"})
        assert replay["task"]["id"] == first["task"]["id"]
        assert replay["execution_binding"]["binding_id"] == first["execution_binding"]["binding_id"]
        assert replay["execution_binding"]["resolved_target"] == {
            "kind": "profile",
            "id": "h3",
        }
        with pytest.raises(ConflictError, match="different input"):
            _admit(service, "duplicate", {"kind": "profile", "id": "other"})
    finally:
        service.close()


def test_inventoried_legacy_nested_request_is_read_only_compatibility(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {"kind": "machine", "id": "machine-legacy"}
        admitted = _admit(service, "legacy-request", target)
        task_id = admitted["task"]["id"]
        run_id = admitted["run"]["id"]
        legacy_request = _request(target)
        for table, identifier in (("tasks", task_id), ("runs", run_id)):
            row = service.store.conn.execute(
                f"SELECT spec_json FROM {table} WHERE id=?", (identifier,)
            ).fetchone()
            spec = json.loads(row["spec_json"])
            spec["execution_request"] = legacy_request
            statement = f"UPDATE {table} SET spec_json=?"
            if table == "tasks":
                statement += ", execution_request_json=NULL"
            service.store.conn.execute(
                statement + " WHERE id=?",
                (json.dumps(spec, sort_keys=True, separators=(",", ":")), identifier),
            )
        service.store.conn.execute(
            "DELETE FROM command_idempotency WHERE command_kind='task.create' "
            "AND aggregate_id='unscoped' AND idempotency_key=?",
            ("legacy-request",),
        )
        service.store.conn.commit()

        public = service.task(task_id)
        assert public["task"]["execution_request"] == legacy_request
        assert "execution_request" not in public["task"]["spec"]
        replay = _admit(service, "legacy-request", target)
        assert replay["task"]["id"] == task_id
        assert replay["task"]["execution_request"] == legacy_request
        with pytest.raises(ConflictError, match="different input"):
            _admit(service, "legacy-request", {"kind": "machine", "id": "other-machine"})
    finally:
        service.close()


def test_missing_mismatched_and_forged_actual_placement_cannot_claim(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {
            "kind": "runpod", "pod_id": "pod-bound",
            "provider_account_ref": "account-bound",
        }
        admitted = _admit(service, "placement-guards", target)

        missing = _claim(
            service, "placement-missing", target, identity_target=None,
        )
        assert missing["waiting_reason"] == "execution_binding_missing"
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0

        mismatch = _claim(
            service, "placement-mismatch", target,
            identity_target={
                "kind": "runpod", "pod_id": "pod-forged",
                "provider_account_ref": "account-bound",
            },
        )
        assert mismatch["waiting_reason"] == "execution_binding_mismatch"
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0

        unverified = _identity(target)
        unverified["execution_binding"]["verification"]["verified"] = False
        with pytest.raises(AuthorizationError, match="invalid execution placement"):
            service.claim_next(
                {
                    "executor_id": "executor-a", "capability_ids": [CAPABILITY],
                    "runtime_epoch": service.health()["runtime_epoch"],
                    "target": target,
                },
                idempotency_key="unverified-placement", identity=unverified,
            )

        with pytest.raises(ValidationError, match="unsupported fields"):
            service.claim_next(
                {
                    "executor_id": "executor-a", "capability_ids": [CAPABILITY],
                    "runtime_epoch": service.health()["runtime_epoch"],
                    "target": target,
                    "execution_binding": _identity(target)["execution_binding"],
                },
                idempotency_key="forged-body-binding",
                identity=_identity(target),
            )

        claimed = _claim(service, "placement-valid", target)
        assert claimed["task_id"] == admitted["task"]["id"]
        assert claimed["execution_binding"]["actual_target"] == target
    finally:
        service.close()


def test_attempt_mutations_reject_wrong_executor_incarnation(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {"kind": "machine", "id": "machine-a"}
        _admit(service, "incarnation", target)
        claim = _claim(service, "incarnation-claim", target)
        with pytest.raises(AuthorizationError, match="fenced execution binding"):
            service.heartbeat_attempt(
                claim["attempt_id"],
                {
                    "lease_id": claim["lease_id"], "fence": claim["fence"],
                    "runtime_epoch": claim["runtime_epoch"],
                },
                idempotency_key="wrong-incarnation-heartbeat",
                identity=_identity(target, incarnation="executor-a/incarnation-2"),
            )
        assert service.heartbeat_attempt(
            claim["attempt_id"],
            {
                "lease_id": claim["lease_id"], "fence": claim["fence"],
                "runtime_epoch": claim["runtime_epoch"],
            },
            idempotency_key="right-incarnation-heartbeat",
            identity=_identity(target),
        )["data"]["attempt_id"] == claim["attempt_id"]
        settlement = {
            "lease_id": claim["lease_id"], "fence": claim["fence"],
            "runtime_epoch": claim["runtime_epoch"], "outputs": [],
        }
        settled = service.settle_attempt(
            claim["attempt_id"], settlement,
            idempotency_key="incarnation-settle", identity=_identity(target),
        )
        assert settled["data"]["state"] == "succeeded"
        assert settled["data"]["execution_binding"]["status"] == "released"
        assert service.settle_attempt(
            claim["attempt_id"], settlement,
            idempotency_key="incarnation-settle", identity=_identity(target),
        ) == settled
        with pytest.raises(ConflictError, match="different input"):
            service.settle_attempt(
                claim["attempt_id"], settlement | {"result": {"different": True}},
                idempotency_key="incarnation-settle", identity=_identity(target),
            )
    finally:
        service.close()


def test_unknown_external_state_cancellation_retains_attempt_and_blocks_retry(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {
            "kind": "runpod", "pod_id": "pod-cancel",
            "provider_account_ref": "account-cancel",
        }
        admitted = _admit(service, "cancel-unknown", target)
        claim = _claim(service, "cancel-unknown-claim", target)
        cancelled = service.cancel_task_canonical(
            admitted["task"]["id"], {}, idempotency_key="cancel-unknown-request",
        )["data"]
        assert cancelled["state"] == "cancel_requested"
        assert cancelled["waiting_reason"] == "provider_state_unknown"
        assert cancelled["attempt_id"] == claim["attempt_id"]
        assert cancelled["execution_binding"]["status"] == "stale"
        assert service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (claim["attempt_id"],)
        ).fetchone()[0] == 0
        with pytest.raises(ConflictError, match="authorized checkpoint resume"):
            service.retry_task(
                admitted["task"]["id"], {}, idempotency_key="blind-retry",
            )
        event = service.events(admitted["run"]["id"])[-1]
        assert event["kind"] == "task.cancel_requested"
        assert event["payload"]["remote_stop_confirmed"] is False
        assert event["payload"]["billing_stop_confirmed"] is False
    finally:
        service.close()


def test_expired_bound_lease_enters_unknown_state_without_blind_retry(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        target = {
            "kind": "runpod", "pod_id": "pod-expired",
            "provider_account_ref": "account-expired",
        }
        admitted = _admit(service, "expired-bound", target)
        claim = _claim(service, "expired-bound-claim", target)
        service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
            (admitted["task"]["id"],),
        )
        service.store._reap_expired_leases()
        retained = service.task(admitted["task"]["id"])
        assert retained["task"]["status"] == "running"
        assert retained["task"]["waiting_reason"] == "provider_state_unknown"
        assert retained["task"]["attempt_id"] == claim["attempt_id"]
        assert retained["execution_binding"]["status"] == "claimed"
        assert service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (claim["attempt_id"],)
        ).fetchone()[0] == 0
        assert _claim(service, "expired-blind-claim", target) is None
    finally:
        service.close()


def test_ordered_input_object_mirror_and_duplicates_remain_runtime_enforced(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        first = "sha256:" + "1" * 64
        second = "sha256:" + "2" * 64
        request = _request({"kind": "machine", "id": "machine-a"})
        request["inputs"] = [
            {"name": "first", "object_id": first, "filename": "first.bin"},
            {"name": "second", "object_id": second, "filename": "second.bin"},
        ]
        with pytest.raises(ValidationError, match="exactly mirror"):
            _admit(service, "mirror-order", request["target"], input_object_ids=[second, first], execution_request=request)
        duplicate = dict(request)
        duplicate["inputs"] = [request["inputs"][0], request["inputs"][0]]
        with pytest.raises(ValidationError, match="duplicate"):
            _admit(service, "mirror-duplicate", duplicate["target"], execution_request=duplicate)
    finally:
        service.close()


def test_restart_retains_prior_attempt_and_requires_authorized_recovery(tmp_path):
    root = tmp_path / "realm"
    service = _service(root)
    target = {
        "kind": "runpod", "pod_id": "pod-restart",
        "provider_account_ref": "account-restart",
    }
    first = _admit(service, "restart", target)
    waiting = _admit(service, "restart-waiting", target)
    old = _claim(service, "restart-claim-old", target)
    old_epoch = old["runtime_epoch"]
    prepared = service.prepare_reboot(
        {
            "attempt_id": old["attempt_id"], "lease_id": old["lease_id"],
            "fence": old["fence"], "runtime_epoch": old_epoch,
        },
        identity=_identity(target),
    )
    checkpoint = service.checkpoint_attempt(
        old["attempt_id"],
        {
            "lease_id": old["lease_id"], "fence": old["fence"],
            "runtime_epoch": old_epoch, "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "state": {"provider_operation_id": "provider-op-restart"},
        },
        identity=_identity(target),
    )
    service.close()

    replacement = RuntimeService(root)
    try:
        new_epoch = replacement.health()["runtime_epoch"]
        assert new_epoch > old_epoch
        replacement.register_executor(
            {
                "executor_id": "executor-a",
                "capabilities": [CAPABILITY],
                "runtime_epoch": new_epoch,
            },
            idempotency_key="executor-a-register-restart",
        )
        stored = replacement.task(first["task"]["id"])
        assert stored["execution_binding"]["binding_id"] == old["execution_binding"]["binding_id"]
        assert stored["execution_binding"]["status"] == "stale"
        assert stored["execution_binding"]["runtime_epoch"] == old_epoch
        assert stored["task"]["waiting_reason"] == "provider_state_unknown"
        assert stored["task"]["attempt_id"] == old["attempt_id"]
        waiting_stored = replacement.task(waiting["task"]["id"])
        assert waiting_stored["execution_binding"]["status"] == "prepared"
        assert waiting_stored["execution_binding"]["runtime_epoch"] == new_epoch
        assert waiting_stored["execution_binding"]["session_id"] != waiting["execution_binding"]["session_id"]
        blocked = _claim(
            replacement,
            "restart-claim-new",
            target,
        )
        assert blocked["waiting_reason"] == "provider_state_unknown"
        blocked_lifecycle = inspect_interruption_state(root)
        assert blocked_lifecycle["safe"] is False
        assert blocked_lifecycle["unreconciled_attempts"]
        with pytest.raises(ConflictError, match="active or unreconciled"):
            assert_interruption_safe(root)
        assert replacement.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (first["task"]["id"],)
        ).fetchone()[0] == 1
        with pytest.raises((LeaseError, NotFoundError, ConflictError)):
            replacement.settle_attempt(
                old["attempt_id"],
                {
                    "lease_id": old["lease_id"],
                    "fence": old["fence"],
                    "runtime_epoch": old_epoch,
                    "outputs": [],
                },
                idempotency_key="stale-settle",
                identity=_identity(target),
            )
        resumed = replacement.resume_attempt(
            {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "nonce": prepared["nonce"], "authorization": prepared["nonce"],
                "runtime_epoch": new_epoch,
            },
            identity=_identity(target),
        )["attempt"]
        assert resumed["attempt_id"] != old["attempt_id"]
        assert resumed["fence"] > old["fence"]
        assert resumed["execution_binding"]["status"] == "claimed"
        assert replacement.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (old["attempt_id"],)
        ).fetchone()[0] == 0
        bound_events = [
            event for event in replacement.events(first["run"]["id"])
            if event["kind"] == "task.execution_bound"
        ]
        assert [event["payload"]["attempt_id"] for event in bound_events] == [
            old["attempt_id"], resumed["attempt_id"],
        ]
    finally:
        replacement.close()


def test_restart_reconciles_runtime_owned_attempt_before_successor_claim(tmp_path):
    root = tmp_path / "realm"
    service = _service(root)
    try:
        admitted = service.create_task(
            {
                "capability_id": CAPABILITY,
                "capability_digest": CAPABILITY_DIGEST,
                "input_object_ids": [],
                "spec": {"params": {"source": "runtime-owned"}},
                "idempotency_key": "runtime-owned-recovery",
            },
            enforce_readiness=True,
        )
        old = service.claim_next(
            {
                "executor_id": "executor-a",
                "capability_ids": [CAPABILITY],
                "runtime_epoch": service.health()["runtime_epoch"],
            },
            idempotency_key="runtime-owned-old-claim",
        )
        assert old["task_id"] == admitted["task"]["id"]
        with pytest.raises(ConflictError, match="active or unreconciled"):
            assert_interruption_safe(root)
    finally:
        service.close()

    replacement = RuntimeService(root)
    try:
        new_epoch = replacement.health()["runtime_epoch"]
        replacement.register_executor(
            {
                "executor_id": "executor-a",
                "capabilities": [CAPABILITY],
                "runtime_epoch": new_epoch,
            },
            idempotency_key="executor-a-register-runtime-owned-restart",
        )
        old_row = replacement.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (old["attempt_id"],)
        ).fetchone()
        assert old_row["settled"] == 1
        recovered_events = [
            event for event in replacement.events(admitted["run"]["id"])
            if event["kind"] == "task.runtime_recovered"
        ]
        assert recovered_events[-1]["payload"]["attempt_id"] == old["attempt_id"]
        assert recovered_events[-1]["payload"]["recovery_disposition"] == "runtime_owned_attempt_reconciled"
        assert replacement.task(admitted["task"]["id"])["task"]["status"] == "queued"

        successor = replacement.claim_next(
            {
                "executor_id": "executor-a",
                "capability_ids": [CAPABILITY],
                "runtime_epoch": new_epoch,
            },
            idempotency_key="runtime-owned-successor-claim",
        )
        assert successor["attempt_id"] != old["attempt_id"]
        settled = replacement.settle_attempt(
            successor["attempt_id"],
            {
                "lease_id": successor["lease_id"],
                "fence": successor["fence"],
                "runtime_epoch": new_epoch,
                "outputs": [],
            },
            idempotency_key="runtime-owned-successor-settle",
        )
        assert settled["data"]["state"] == "succeeded"
        with pytest.raises(LeaseError):
            replacement.settle_attempt(
                old["attempt_id"],
                {
                    "lease_id": old["lease_id"],
                    "fence": old["fence"],
                    "runtime_epoch": old["runtime_epoch"],
                    "outputs": [],
                },
                idempotency_key="runtime-owned-stale-settle",
            )
        assert inspect_interruption_state(root)["safe"] is True
        assert assert_interruption_safe(root)["safe"] is True
        assert replacement.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (successor["attempt_id"],)
        ).fetchone()[0] == 1
    finally:
        replacement.close()


def _assert_external_uncertainty_survives_restart(
    service, admitted, claim, target, *, run_status, expect_recovery_event=True
):
    stored = service.task(admitted["task"]["id"])
    assert stored["task"]["status"] == "cancel_requested"
    assert stored["task"]["waiting_reason"] == "provider_state_unknown"
    assert stored["task"]["attempt_id"] == claim["attempt_id"]
    assert stored["run"]["status"] == run_status

    binding = stored["execution_binding"]
    assert binding["status"] == "stale"
    assert binding["attempt_id"] == claim["attempt_id"]
    assert binding["lease_id"] == claim["lease_id"]
    assert binding["fence"] == claim["fence"]
    assert binding["actual_target"] == target
    assert binding["verification"]["verified"] is True
    assert binding["executor_incarnation"] == claim["execution_binding"]["executor_incarnation"]

    attempt = service.store.conn.execute(
        "SELECT settled, lease_id, fence, executor_id, runtime_epoch "
        "FROM attempts WHERE id=?",
        (claim["attempt_id"],),
    ).fetchone()
    assert dict(attempt) == {
        "settled": 0,
        "lease_id": claim["lease_id"],
        "fence": claim["fence"],
        "executor_id": "executor-a",
        "runtime_epoch": claim["runtime_epoch"],
    }

    reservation = service.store.conn.execute(
        "SELECT released_at, lease_token, fence, executor_id "
        "FROM reservations WHERE task_id=?",
        (admitted["task"]["id"],),
    ).fetchone()
    assert reservation["released_at"] is None
    assert reservation["lease_token"] == claim["lease_id"]
    assert reservation["fence"] == claim["fence"]
    assert reservation["executor_id"] == "executor-a"

    with pytest.raises((ConflictError, LeaseError, NotFoundError)):
        service.settle_attempt(
            claim["attempt_id"],
            {
                "lease_id": claim["lease_id"],
                "fence": claim["fence"],
                "runtime_epoch": claim["runtime_epoch"],
                "outputs": [],
            },
            idempotency_key=f"stale-settle-{service.health()['runtime_epoch']}",
            identity=_identity(target),
        )

    if expect_recovery_event:
        recovered_events = [
            event for event in service.events(admitted["run"]["id"])
            if event["kind"] == "task.runtime_recovered"
        ]
        assert recovered_events
        assert recovered_events[-1]["payload"]["recovery"] == "provider_state_unknown"
        assert all(
            event["payload"].get("recovery_disposition")
            != "runtime_owned_attempt_reconciled"
            for event in recovered_events
        )

    assert _claim(
        service, f"blind-claim-{service.health()['runtime_epoch']}", target
    ) is None
    with pytest.raises(ConflictError, match="authorized checkpoint resume"):
        service.retry_task(
            admitted["task"]["id"], {},
            idempotency_key=f"blind-retry-{service.health()['runtime_epoch']}",
        )
    blocked_lifecycle = inspect_interruption_state(service.store.root)
    assert blocked_lifecycle["safe"] is False
    assert blocked_lifecycle["unreconciled_attempts"]
    assert blocked_lifecycle["claimed_or_stale_bindings"]
    assert blocked_lifecycle["unreleased_reservations"]
    with pytest.raises(ConflictError, match="active or unreconciled"):
        assert_interruption_safe(service.store.root)


def test_task_cancellation_unknown_external_state_survives_repeated_restarts(tmp_path):
    root = tmp_path / "realm"
    target = {
        "kind": "runpod", "pod_id": "pod-task-restart",
        "provider_account_ref": "account-task-restart",
    }
    service = _service(root, resource_keys=["gpu"])
    admitted = _admit(service, "cancel-restart", target)
    claim = _claim(service, "cancel-restart-claim", target)
    cancelled = service.cancel_task_canonical(
        admitted["task"]["id"], {}, idempotency_key="cancel-restart-request",
    )["data"]
    assert cancelled["state"] == "cancel_requested"
    assert cancelled["waiting_reason"] == "provider_state_unknown"
    assert cancelled["execution_binding"]["status"] == "stale"
    _assert_external_uncertainty_survives_restart(
        service, admitted, claim, target, run_status="running",
        expect_recovery_event=False,
    )
    service.close()

    for restart in (1, 2):
        replacement = RuntimeService(root)
        try:
            epoch = replacement.health()["runtime_epoch"]
            replacement.register_executor(
                {
                    "executor_id": "executor-a",
                    "capabilities": [CAPABILITY],
                    "max_concurrency": 2,
                    "resource_keys": ["gpu"],
                    "runtime_epoch": epoch,
                },
                idempotency_key=f"executor-a-task-restart-{restart}",
            )
            _assert_external_uncertainty_survives_restart(
                replacement, admitted, claim, target, run_status="queued"
            )
        finally:
            replacement.close()


def test_run_cancellation_unknown_external_state_survives_repeated_restarts(tmp_path):
    root = tmp_path / "realm"
    target = {
        "kind": "runpod", "pod_id": "pod-run-restart",
        "provider_account_ref": "account-run-restart",
    }
    service = _service(root, resource_keys=["gpu"])
    admitted = _admit(service, "run-cancel-restart", target)
    claim = _claim(service, "run-cancel-restart-claim", target)
    cancelled = service.cancel_run(
        admitted["run"]["id"], {}, idempotency_key="run-cancel-restart-request",
    )
    assert cancelled["status"] == "cancelled"
    _assert_external_uncertainty_survives_restart(
        service, admitted, claim, target, run_status="cancelled",
        expect_recovery_event=False,
    )
    service.close()

    for restart in (1, 2):
        replacement = RuntimeService(root)
        try:
            epoch = replacement.health()["runtime_epoch"]
            replacement.register_executor(
                {
                    "executor_id": "executor-a",
                    "capabilities": [CAPABILITY],
                    "max_concurrency": 2,
                    "resource_keys": ["gpu"],
                    "runtime_epoch": epoch,
                },
                idempotency_key=f"executor-a-run-restart-{restart}",
            )
            _assert_external_uncertainty_survives_restart(
                replacement, admitted, claim, target, run_status="cancelled"
            )
        finally:
            replacement.close()


def test_cancelled_external_attempt_uses_authorized_checkpoint_resume_after_restart(tmp_path):
    root = tmp_path / "realm"
    target = {
        "kind": "runpod", "pod_id": "pod-cancel-resume",
        "provider_account_ref": "account-cancel-resume",
    }
    service = _service(root)
    admitted = _admit(service, "cancel-resume", target)
    old = _claim(service, "cancel-resume-claim", target)
    epoch = service.health()["runtime_epoch"]
    prepared = service.prepare_reboot(
        {
            "attempt_id": old["attempt_id"], "lease_id": old["lease_id"],
            "fence": old["fence"], "runtime_epoch": epoch,
        },
        identity=_identity(target),
    )
    checkpoint = service.checkpoint_attempt(
        old["attempt_id"],
        {
            "lease_id": old["lease_id"], "fence": old["fence"],
            "runtime_epoch": epoch, "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "state": {"provider_operation_id": "provider-op-cancel-resume"},
        },
        identity=_identity(target),
    )
    cancelled = service.cancel_task_canonical(
        admitted["task"]["id"], {}, idempotency_key="cancel-resume-request",
    )["data"]
    assert cancelled["state"] == "cancel_requested"
    assert cancelled["execution_binding"]["status"] == "stale"
    service.close()

    replacement = RuntimeService(root)
    try:
        new_epoch = replacement.health()["runtime_epoch"]
        replacement.register_executor(
            {
                "executor_id": "executor-a",
                "capabilities": [CAPABILITY],
                "max_concurrency": 2,
                "runtime_epoch": new_epoch,
            },
            idempotency_key="executor-a-cancel-resume-restart",
        )
        preserved = replacement.task(admitted["task"]["id"])
        assert preserved["task"]["status"] == "cancel_requested"
        assert preserved["task"]["waiting_reason"] == "provider_state_unknown"
        assert preserved["execution_binding"]["status"] == "stale"
        resumed = replacement.resume_attempt(
            {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "runtime_epoch": new_epoch,
            },
            identity=_identity(target),
        )["attempt"]
        assert resumed["attempt_id"] != old["attempt_id"]
        assert resumed["execution_binding"]["status"] == "claimed"
        assert replacement.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (old["attempt_id"],)
        ).fetchone()[0] == 0
        settled = replacement.settle_attempt(
            resumed["attempt_id"],
            {
                "lease_id": resumed["lease_id"], "fence": resumed["fence"],
                "runtime_epoch": new_epoch, "outputs": [],
            },
            idempotency_key="cancel-resume-successor-settle",
            identity=_identity(target),
        )
        assert settled["data"]["state"] == "succeeded"
        with pytest.raises(LeaseError):
            replacement.settle_attempt(
                old["attempt_id"],
                {
                    "lease_id": old["lease_id"], "fence": old["fence"],
                    "runtime_epoch": old["runtime_epoch"], "outputs": [],
                },
                idempotency_key="cancel-resume-old-settle",
                identity=_identity(target),
            )
    finally:
        replacement.close()


def test_runtime_exposes_binding_capability_without_provider_side_effects(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        handshake = service.handshake(
            {
                "authenticated_actor": "astrid-test",
                "authenticated_scopes": ["tasks:read", "tasks:write"],
                "requested_scopes": ["tasks:read", "tasks:write"],
            }
        )
        assert TARGETED_EXECUTION_BINDING_CAPABILITY in handshake["capabilities"]
    finally:
        service.close()
