from __future__ import annotations

import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


PARENT = "test.placement.parent"
CHILD = "test.placement.child"
PARENT_DIGEST = "sha256:" + hashlib.sha256(PARENT.encode()).hexdigest()
CHILD_DIGEST = "sha256:" + hashlib.sha256(CHILD.encode()).hexdigest()
OLD = {"kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a"}
NEW = {"kind": "runpod", "pod_id": "pod-new", "provider_account_ref": "account-a"}
QUALIFICATION_DIGEST = "sha256:" + "a" * 64
OWNER = {"actor": "owner", "scopes": ["admin", "tasks:write"]}


def _service(root):
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    for capability, digest in ((PARENT, PARENT_DIGEST), (CHILD, CHILD_DIGEST)):
        service.register_capability(
            {"capability_id": capability, "definition_digest": digest}
        )
    service.register_executor(
        {
            "executor_id": "executor-a",
            "capabilities": [PARENT, CHILD],
            "max_concurrency": 2,
        },
        idempotency_key="executor-a-register",
    )
    return service


def _request(target):
    return {"schema_version": 1, "target": target, "inputs": []}


def _identity(target, *, digest=QUALIFICATION_DIGEST, incarnation="executor-a/new"):
    return {
        "actor": "executor-a",
        "scopes": ["worker:execute"],
        "execution_binding": {
            "actual": target,
            "verification": {
                "method": "credential_claim",
                "evidence_digest": digest,
                "verified": True,
            },
            "executor_incarnation": incarnation,
        },
    }


def _claim(service, key, target, identity):
    return service.claim_next(
        {
            "executor_id": "executor-a",
            "capability_ids": [PARENT, CHILD],
            "runtime_epoch": service.health()["runtime_epoch"],
            "target": target,
        },
        idempotency_key=key,
        identity=identity,
    )


def _admit_parent(service, key="parent", *, child_delegation=False):
    body = {
        "capability_id": PARENT,
        "capability_digest": PARENT_DIGEST,
        "input_object_ids": [],
        "spec": {"params": {"identity": "immutable"}},
        "execution_request": _request(OLD),
        "idempotency_key": key,
    }
    if child_delegation:
        body["child_delegation"] = {
            "capabilities": [
                {"capability_id": CHILD, "capability_digest": CHILD_DIGEST}
            ],
            "targets": [OLD],
            "input_object_ids": [],
        }
    return service.create_task(body, enforce_readiness=True)


def _fail(service, claim, identity):
    return service.fail_attempt(
        claim["attempt_id"],
        {
            "lease_id": claim["lease_id"],
            "fence": claim["fence"],
            "runtime_epoch": claim["runtime_epoch"],
            "error": {"code": "old_pod_failed"},
        },
        idempotency_key="fail-" + claim["attempt_id"],
        identity=identity,
    )


def _recovery_body(service, task_id, *, replacement=NEW, observed_at=None):
    task = service.task(task_id)["task"]
    current = service.store.effective_execution_target(task_id)
    recovery = service.store.placement_recovery(task_id)
    return {
        "schema_version": 1,
        "expected_task_version": int(task["attempt"] or 0) + 1,
        "expected_placement_version": int(recovery["placement_version"]) if recovery else 0,
        "expected_original_target": OLD,
        "expected_current_target": current,
        "replacement_target": replacement,
        "reason": "the exact provider pod was deleted after a terminal attempt",
        "loss_evidence": {
            "source": "runpod_lifecycle.status",
            "status": "absent",
            "target": current,
            "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
            "evidence_digest": "sha256:" + "b" * 64,
            "no_active_work": True,
        },
        "qualification": {
            "target": replacement,
            "verified": True,
            "evidence_digest": QUALIFICATION_DIGEST,
            "executor_incarnation": "executor-a/new",
        },
    }


def _terminal_parent(service, *, child_delegation=False):
    admitted = _admit_parent(service, child_delegation=child_delegation)
    old_identity = _identity(
        OLD, digest="sha256:" + "c" * 64, incarnation="executor-a/old"
    )
    claim = _claim(service, "claim-old", OLD, old_identity)
    _fail(service, claim, old_identity)
    return admitted, claim, old_identity


def test_owner_recovery_preserves_admission_and_replay_then_claims_with_higher_fence(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted, old_claim, _old_identity = _terminal_parent(service)
        task_id = admitted["task"]["id"]
        before = service.task(task_id)
        body = _recovery_body(service, task_id)

        recovered = service.recover_task_placement(
            task_id, body, idempotency_key="recover-one", identity=OWNER
        )
        replay = service.recover_task_placement(
            task_id, body, idempotency_key="recover-one", identity=OWNER
        )
        assert replay == recovered
        decision = recovered["data"]["placement_recovery"]
        assert decision["placement_version"] == 1
        assert decision["original_target"] == OLD
        assert decision["replacement_target"] == NEW
        assert decision["superseded_binding"]["attempt_id"] == old_claim["attempt_id"]
        assert decision["decision_digest"].startswith("sha256:")

        after = service.task(task_id)
        assert after["task"]["id"] == before["task"]["id"]
        assert after["run"]["id"] == before["run"]["id"]
        assert after["task"]["spec"] == before["task"]["spec"]
        assert after["task"]["execution_request"] == before["task"]["execution_request"]
        assert after["execution_binding"]["original_target"] == OLD
        assert after["execution_binding"]["effective_target"] == NEW
        assert after["execution_binding"]["resolved_target"] == NEW
        assert service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (old_claim["attempt_id"],)
        ).fetchone()[0] == 1

        version = service._task_resource(after)["version"]
        service.retry_task(
            task_id, {"expected_version": version}, idempotency_key="retry-recovered"
        )
        wrong = _claim(
            service,
            "claim-wrong-qualification",
            NEW,
            _identity(NEW, digest="sha256:" + "d" * 64),
        )
        assert wrong["waiting_reason"] == "execution_qualification_mismatch"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
        ).fetchone()[0] == 1

        successor = _claim(service, "claim-new", NEW, _identity(NEW))
        assert successor["task_id"] == task_id
        assert successor["run_id"] == admitted["run"]["id"]
        assert successor["fence"] > old_claim["fence"]
        assert successor["execution_binding"]["resolved_target"] == NEW
        assert successor["execution_request"]["target"] == OLD
        successor_binding = copy.deepcopy(service.store.execution_binding(task_id))
        successor_fence = successor["fence"]
        old_heartbeat = {
            "lease_id": old_claim["lease_id"],
            "fence": old_claim["fence"],
            "runtime_epoch": old_claim["runtime_epoch"],
        }
        with pytest.raises(AuthorizationError, match="fenced execution binding"):
            service.heartbeat_attempt(
                old_claim["attempt_id"],
                old_heartbeat,
                idempotency_key="old-heartbeat",
                identity=_identity(OLD, digest="sha256:" + "c" * 64, incarnation="executor-a/old"),
            )
        with pytest.raises(LeaseError):
            service.heartbeat_attempt(
                old_claim["attempt_id"],
                old_heartbeat,
                idempotency_key="settled-old-heartbeat",
                identity=_identity(NEW),
            )
        assert service.heartbeat_attempt(
            successor["attempt_id"],
            {
                "lease_id": successor["lease_id"],
                "fence": successor_fence,
                "runtime_epoch": successor["runtime_epoch"],
            },
            idempotency_key="successor-heartbeat",
            identity=_identity(NEW),
        )["data"]["attempt_id"] == successor["attempt_id"]
        assert service.store.execution_binding(task_id) == successor_binding
        assert service.store.conn.execute(
            "SELECT fence FROM attempts WHERE id=?", (successor["attempt_id"],)
        ).fetchone()[0] == successor_fence
    finally:
        service.close()


def test_recovery_rejects_missing_authority_wrong_account_stale_and_unknown_work(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        active = _admit_parent(service, "active")
        _claim(
            service,
            "active-claim",
            OLD,
            _identity(OLD, digest="sha256:" + "c" * 64, incarnation="executor-a/old"),
        )
        with pytest.raises(ConflictError, match="terminal"):
            service.recover_task_placement(
                active["task"]["id"],
                _recovery_body(service, active["task"]["id"]),
                idempotency_key="active-recovery",
                identity=OWNER,
            )

        admitted, _claim_old, _identity_old = _terminal_parent(service)
        task_id = admitted["task"]["id"]
        body = _recovery_body(service, task_id)
        with pytest.raises(AuthorizationError, match="owner authority"):
            service.recover_task_placement(
                task_id, body, idempotency_key="no-owner", identity=None
            )
        wrong_account = copy.deepcopy(body)
        wrong_account["replacement_target"] = {
            "kind": "runpod", "pod_id": "pod-other", "provider_account_ref": "account-b"
        }
        wrong_account["qualification"]["target"] = wrong_account["replacement_target"]
        with pytest.raises(AuthorizationError, match="different provider account"):
            service.recover_task_placement(
                task_id, wrong_account, idempotency_key="wrong-account", identity=OWNER
            )
        stale = _recovery_body(
            service,
            task_id,
            observed_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        )
        with pytest.raises(ConflictError, match="stale"):
            service.recover_task_placement(
                task_id, stale, idempotency_key="stale-loss", identity=OWNER
            )
        missing = copy.deepcopy(body)
        missing["loss_evidence"]["no_active_work"] = False
        with pytest.raises(ConflictError, match="unknown active work"):
            service.recover_task_placement(
                task_id, missing, idempotency_key="unknown-loss", identity=OWNER
            )
    finally:
        service.close()


def test_concurrent_recovery_binds_exactly_one_replacement(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted, _old_claim, _old_identity = _terminal_parent(service)
        task_id = admitted["task"]["id"]
        first = _recovery_body(service, task_id)
        other_target = {
            "kind": "runpod", "pod_id": "pod-other", "provider_account_ref": "account-a"
        }
        second = _recovery_body(service, task_id, replacement=other_target)

        def invoke(key, body):
            try:
                result = service.recover_task_placement(
                    task_id, body, idempotency_key=key, identity=OWNER
                )
                return ("ok", result["data"]["placement_recovery"]["replacement_target"])
            except ConflictError as exc:
                return ("conflict", str(exc))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: invoke(*args), (("race-a", first), ("race-b", second))))
        assert [state for state, _ in results].count("ok") == 1
        assert [state for state, _ in results].count("conflict") == 1
        latest = service.store.placement_recovery(task_id)
        assert latest["placement_version"] == 1
        assert service.store.execution_binding(task_id)["resolved_target"] == latest["replacement_target"]
    finally:
        service.close()


def test_recovery_fences_old_children_and_propagates_effective_target(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        admitted = _admit_parent(service, child_delegation=True)
        task_id = admitted["task"]["id"]
        old_identity = _identity(
            OLD, digest="sha256:" + "c" * 64, incarnation="executor-a/old"
        )
        parent_claim = _claim(service, "parent-old-claim", OLD, old_identity)
        old_authority = service.issue_child_authority(
            parent_claim["attempt_id"],
            {
                "lease_id": parent_claim["lease_id"],
                "fence": parent_claim["fence"],
                "runtime_epoch": parent_claim["runtime_epoch"],
            },
            identity=old_identity,
        )["authority"]
        old_child = service.admit_delegated_child(
            {
                "authority": old_authority,
                "task": {
                    "capability_id": CHILD,
                    "capability_digest": CHILD_DIGEST,
                    "input_object_ids": [],
                    "spec": {"params": {"child": "old"}},
                    "execution_request": _request(OLD),
                },
            },
            idempotency_key="old-child",
            identity=old_identity,
        )
        _fail(service, parent_claim, old_identity)
        service.recover_task_placement(
            task_id,
            _recovery_body(service, task_id),
            idempotency_key="recover-parent",
            identity=OWNER,
        )
        fenced_child = service.task(old_child["task"]["id"])
        assert fenced_child["task"]["status"] == "cancelled"
        assert fenced_child["task"]["waiting_reason"] == "parent_placement_recovered"
        with pytest.raises((LeaseError, AuthorizationError)):
            service.admit_delegated_child(
                {
                    "authority": old_authority,
                    "task": {
                        "capability_id": CHILD,
                        "capability_digest": CHILD_DIGEST,
                        "input_object_ids": [],
                        "spec": {},
                        "execution_request": _request(OLD),
                    },
                },
                idempotency_key="stale-child",
                identity=old_identity,
            )

        version = service._task_resource(service.task(task_id))["version"]
        service.retry_task(
            task_id, {"expected_version": version}, idempotency_key="retry-parent"
        )
        new_identity = _identity(NEW)
        successor = _claim(service, "parent-new-claim", NEW, new_identity)
        new_authority = service.issue_child_authority(
            successor["attempt_id"],
            {
                "lease_id": successor["lease_id"],
                "fence": successor["fence"],
                "runtime_epoch": successor["runtime_epoch"],
            },
            identity=new_identity,
        )["authority"]
        new_child = service.admit_delegated_child(
            {
                "authority": new_authority,
                "task": {
                    "capability_id": CHILD,
                    "capability_digest": CHILD_DIGEST,
                    "input_object_ids": [],
                    "spec": {"params": {"child": "new"}},
                    # The caller may retain the immutable declared target;
                    # Runtime projects the parent's authorized effective one.
                    "execution_request": _request(OLD),
                },
            },
            idempotency_key="new-child",
            identity=new_identity,
        )
        assert new_child["task"]["execution_request"]["target"] == NEW
        lineage = new_child["task"]["spec"]["delegated_parent"]
        assert lineage["parent_effective_target"] == NEW
        assert new_child["execution_binding"]["resolved_target"] == NEW
    finally:
        service.close()
