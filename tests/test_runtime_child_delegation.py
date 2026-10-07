"""D18 deterministic fixtures; every realm/CAS here is pytest-owned temporary data."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, ValidationError
from runtime_protocol import service as service_module
from runtime_protocol.service import CHILD_LIMITS, CHILD_LIMIT_CEILINGS, OBJECT_MAX_BYTES, RuntimeService
from runtime_protocol.store import RealmStore


PARENT = "test.d18.parent"
CHILD = "test.d18.child"
OTHER = "test.d18.other"
TARGET = {"kind": "machine", "id": "fixture-machine"}


def digest(data):
    return "sha256:" + hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


IDENTITY = {"actor": "worker", "scopes": ["worker:execute"], "execution_binding": {
    "actual": TARGET, "executor_incarnation": "worker/fixture",
    "verification": {"method": "credential_claim", "verified": True, "evidence_digest": digest("placement")},
}}


@pytest.fixture
def runtime(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    for cap in (PARENT, CHILD, OTHER):
        service.register_capability({"capability_id": cap, "definition_digest": digest(cap)})
    service.register_executor({"executor_id": "worker", "capabilities": [PARENT, CHILD, OTHER], "max_concurrency": 64}, idempotency_key="register")
    project = service.create_project({"slug": "d18", "name": "D18 fixture"})["id"]
    try:
        yield service, project
    finally:
        service.close()


def claim(service, cap, key):
    body = {"executor_id": "worker", "capability_ids": [cap], "runtime_epoch": service.health()["runtime_epoch"]}
    row = service.store.conn.execute("SELECT id FROM tasks WHERE capability=? AND status='queued' ORDER BY rowid LIMIT 1", (cap,)).fetchone()
    if row is not None:
        target = service.store.effective_execution_target(row["id"])
        if target is not None:
            body["target"] = target
    return service.claim_next(body, idempotency_key=key, identity=IDENTITY)


def lease(attempt):
    return {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}


def parent(runtime, *, limits=None, targeted=False, key="parent"):
    service, project = runtime
    policy = {"capabilities": [{"capability_id": cap, "capability_digest": digest(cap)} for cap in (CHILD, OTHER)], "targets": [{"kind": "default"}, TARGET], "input_object_ids": []}
    if limits is not None:
        policy["limits"] = limits
    body = {"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT), "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": key}
    if targeted:
        body["execution_request"] = {"schema_version": 1, "target": TARGET, "inputs": []}
    service.create_task(body, enforce_readiness=True)
    return claim(service, PARENT, "claim-" + key)


def upload(service, attempt, data=b"new-parent-frame", name="frame"):
    descriptor = {"name": name, "output_port": name, "filename": name + ".bin", "object_id": digest(data), "size": len(data), "media_type": "application/octet-stream"}
    binding = {"project_id": attempt["project_id"], "run_id": attempt["run_id"], "task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"], "executor_id": "worker", **lease(attempt), "output_key": name, "output_port": name, "filename": descriptor["filename"], "digest": digest(data), "size": len(data), "media_type": descriptor["media_type"]}
    service.ingest_object(data, original_name=descriptor["filename"], idempotency_key=service._generic_output_idempotency_key(binding), identity=IDENTITY, upload_binding=binding)
    return descriptor


def authority(service, attempt, *, refs=None, key="child", cap=CHILD):
    body = lease(attempt)
    if refs is not None:
        body.update(child={"child_id": key, "capability_id": cap, "capability_digest": digest(cap)}, derived_inputs=refs)
    return service.issue_child_authority(attempt["attempt_id"], body, identity=IDENTITY)


def admit(service, receipt, *, refs=None, key="child", cap=CHILD, params=None):
    task = {"capability_id": cap, "capability_digest": digest(cap), "input_object_ids": [], "spec": {"params": params or {"query": "fixture://video"}}}
    if refs is not None:
        task["input_object_ids"] = [ref["object_id"] for ref in refs]
        task["execution_request"] = {"schema_version": 1, "target": {"kind": "default"}, "inputs": [{"name": ref["name"], "object_id": ref["object_id"], "filename": ref["filename"], "digest": ref["object_id"]} for ref in refs]}
    return service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key=key, identity=IDENTITY)


def settle(service, attempt, key, outputs=None):
    return service.settle_attempt(attempt["attempt_id"], {**lease(attempt), "outputs": outputs or []}, idempotency_key=key, identity=IDENTITY)


def test_live_derived_registration_exact_admission_and_verified_success(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    assert authority(service, attempt, refs=[ref]) == receipt
    child = admit(service, receipt, refs=[ref])
    assert admit(service, receipt, refs=[ref]) == child
    assert child["task"]["spec"]["delegated_inputs"][0]["association_id"] == receipt["derived_inputs"][0]["association_id"]
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "early-parent")
    child_attempt = claim(service, CHILD, "claim-child")
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "running-parent")
    payload = b"verified-child-result"
    settle(service, child_attempt, "settle-child", [{"name": "result", "digest": digest(payload), "data_base64": base64.b64encode(payload).decode()}])
    settle(service, attempt, "settle-parent")
    assert service.task(attempt["task_id"])["task"]["status"] == "completed"
    assert len(service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])) == 1
    with pytest.raises(LeaseError):
        admit(service, receipt, refs=[ref], key="after-parent")


def test_scalar_no_object_call_progress_and_same_target(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    assert child["task"]["execution_request"]["target"] == TARGET
    child_attempt = claim(service, CHILD, "claim-scalar")
    progress = service.heartbeat_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "progress": {"percent": 50}}, idempotency_key="scalar-progress", identity=IDENTITY)
    assert progress["data"]["task_id"] == child["task"]["id"]
    settle(service, child_attempt, "scalar-success")
    settle(service, attempt, "scalar-parent-success")


@pytest.mark.parametrize("field", ["fence", "runtime_epoch", "lease_id"])
def test_stale_attempt_registration_rejected(runtime, field):
    service, _ = runtime
    attempt = parent(runtime)
    body = {**lease(attempt), "child": {"child_id": "child", "capability_id": CHILD, "capability_digest": digest(CHILD)}, "derived_inputs": [upload(service, attempt)]}
    body[field] = "foreign" if field == "lease_id" else body[field] + 1
    with pytest.raises((LeaseError, ConflictError)):
        service.issue_child_authority(attempt["attempt_id"], body, identity=IDENTITY)
    assert not service.managed_outputs(attempt["task_id"])


def test_foreign_worker_project_and_unregistered_object_rejected(runtime):
    service, project = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    foreign = copy.deepcopy(IDENTITY)
    foreign["actor"] = "foreign-worker"
    with pytest.raises(AuthorizationError):
        service.issue_child_authority(attempt["attempt_id"], lease(attempt), identity=foreign)
    receipt = authority(service, attempt, refs=[ref])
    with pytest.raises(AuthorizationError):
        service.admit_delegated_child({"authority": receipt["authority"], "task": {"capability_id": CHILD, "capability_digest": digest(CHILD)}}, idempotency_key="child", identity=foreign)
    service.store.conn.execute("UPDATE runs SET project_id=NULL WHERE id=?", (attempt["run_id"],))
    with pytest.raises(AuthorizationError):
        admit(service, receipt, refs=[ref])
    service.store.conn.execute("UPDATE runs SET project_id=? WHERE id=?", (project, attempt["run_id"]))
    raw = b"unbound-upload"
    service.ingest_object(raw, original_name="raw.bin", idempotency_key="unbound")
    with pytest.raises(AuthorizationError, match="authenticated upload receipt"):
        authority(service, attempt, refs=[{"name": "raw", "output_port": "raw", "filename": "raw.bin", "object_id": digest(raw), "size": len(raw), "media_type": "application/octet-stream"}])
    with pytest.raises(AuthorizationError):
        admit(service, authority(service, attempt), refs=[ref])


@pytest.mark.parametrize("change", ["capability", "digest", "child_id", "filename", "bytes", "association", "metadata", "project_association", "registry"])
def test_wrong_child_receipt_or_changed_object_rejected(runtime, change):
    service, project = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    if change == "bytes":
        service.cas.path_for(ref["object_id"][7:]).write_bytes(b"corrupt-object!!")
    elif change == "association":
        service.store.conn.execute("UPDATE managed_output_associations SET role='output' WHERE association_id=?", (receipt["derived_inputs"][0]["association_id"],))
    elif change == "metadata":
        service.store.conn.execute("UPDATE objects SET media_type='image/png' WHERE digest=?", (ref["object_id"][7:],))
    elif change == "project_association":
        service.store.conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?", (project, ref["object_id"][7:]))
    elif change == "registry":
        spec = json.loads(service.store.conn.execute("SELECT spec_json FROM tasks WHERE id=?", (attempt["task_id"],)).fetchone()[0])
        spec["derived_input_registry"] = {}
        service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), attempt["task_id"]))
    elif change == "filename":
        ref["filename"] = "changed.bin"
    elif change == "digest":
        payload = service._decode_child_authority(receipt["authority"])
        payload["child"]["capability_digest"] = digest("wrong")
        # Unsigned mutation cannot turn a predicted identity into authority.
        encoded, signature = receipt["authority"].split(".")
        receipt["authority"] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "." + signature
    with pytest.raises((AuthorizationError, ConflictError)):
        admit(service, receipt, refs=[ref], cap=OTHER if change == "capability" else CHILD, key="replayed-other-id" if change == "child_id" else "child")


def test_replay_cannot_change_child_and_limits_are_atomic(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 1, "max_derived_objects": 1, "max_derived_bytes": 20, "max_child_inputs": 1})
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    admit(service, receipt, refs=[ref])
    with pytest.raises(ConflictError):
        admit(service, receipt, refs=[ref], params={"changed": True})
    with pytest.raises(ValidationError, match="child count"):
        admit(service, authority(service, attempt), key="second")
    second = upload(service, attempt, b"second", "second")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[second], key="second")
    with pytest.raises(ValidationError, match="child input count"):
        authority(service, attempt, refs=[ref, second], key="second")
    assert len(service.managed_outputs(attempt["task_id"])) == 1


def test_derived_byte_budget_rejects_before_registration(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_bytes": 3})
    ref = upload(service, attempt, b"four")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[ref])
    assert not service.managed_outputs(attempt["task_id"])


@pytest.mark.parametrize("end", ["cancel", "failure", "lease", "authority", "epoch"])
def test_parent_end_contains_queued_and_running_children_and_fences_admission(runtime, end):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    running = admit(service, receipt, key="running")
    child_attempt = claim(service, CHILD, "claim-running")
    queued = admit(service, receipt, key="queued")
    if end == "cancel":
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="cancel-parent")
    elif end == "failure":
        service.fail_attempt(attempt["attempt_id"], {**lease(attempt), "error": {"code": "fixture_failure"}}, idempotency_key="fail-parent", identity=IDENTITY)
    elif end == "lease":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, attempt["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
        with service.store._transaction():
            service.store._reap_expired_leases()
    elif end == "authority":
        # Deterministic fixture for the existing owner revocation endpoint.
        service.store._append_event(attempt["run_id"], attempt["task_id"], "task.remote_activation_qualified", {"activation_id": "fixture-activation"})
        service.revoke_remote_activation(attempt["task_id"], "fixture-activation", identity={"actor": "owner", "scopes": ["admin"]})
    else:
        service.store.begin_runtime_session("fixture-next-boot")
    for child in (running, queued):
        assert service.task(child["task"]["id"])["task"]["status"] == "cancelled"
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        admit(service, receipt, key="late")
    with pytest.raises(LeaseError):
        settle(service, child_attempt, "late-child-settle")


def test_external_descendant_termination_stays_unknown(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    claim(service, CHILD, "claim-external")
    service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="cancel-external-parent")
    child_value = service.task(child["task"]["id"])["task"]
    assert child_value["status"] == "cancel_requested"
    assert child_value["waiting_reason"] == "provider_state_unknown"
    events = service.events(child["run"]["id"])
    cancellation = next(e for e in events if e["kind"] == "task.cancel_requested")
    assert cancellation["payload"]["remote_stop_confirmed"] is False
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child_value["id"]))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child_value["attempt_id"]))
    with service.store._transaction():
        service.store._reap_expired_leases()
    assert service.task(child_value["id"])["task"]["status"] == "cancel_requested"
    service.store.begin_runtime_session("external-next-boot")
    assert service.task(child_value["id"])["task"]["status"] == "cancel_requested"
    assert service.task(child_value["id"])["task"]["waiting_reason"] == "provider_state_unknown"
    assert not service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (child_value["attempt_id"],)).fetchone()[0]


@pytest.mark.parametrize("corruption", ["bytes", "lifecycle", "association", "failed_child"])
def test_parent_success_requires_managed_verified_child_outputs(runtime, corruption):
    service, _ = runtime
    attempt = parent(runtime)
    child = admit(service, authority(service, attempt))
    child_attempt = claim(service, CHILD, "claim-child")
    if corruption == "failed_child":
        service.fail_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "error": {"code": "failed"}}, idempotency_key="fail-child", identity=IDENTITY)
    else:
        payload = b"child-output"
        settle(service, child_attempt, "child-success", [{"digest": digest(payload), "data_base64": base64.b64encode(payload).decode()}])
        association = service.managed_outputs(child["task"]["id"])[0]
        if corruption == "bytes":
            service.cas.path_for(digest(payload)[7:]).write_bytes(b"bad-output!!")
        elif corruption == "lifecycle":
            service.store.conn.execute("UPDATE managed_output_lifecycle SET state='reclaimed' WHERE association_id=?", (association["association_id"],))
        else:
            service.store.conn.execute("DELETE FROM managed_output_lifecycle WHERE association_id=?", (association["association_id"],))
    with pytest.raises(ConflictError):
        settle(service, attempt, "parent-success")
    assert service.task(attempt["task_id"])["task"]["status"] == "running"


def test_bounded_parallel_admission_and_same_key_replay(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 2})
    receipt = authority(service, attempt)
    def one(key):
        try:
            return admit(service, receipt, key=key)["task"]["id"]
        except ValidationError:
            return "limit"
    with ThreadPoolExecutor(max_workers=3) as pool:
        values = list(pool.map(one, ["first", "second", "third"]))
    assert values.count("limit") == 1
    assert len(service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])) == 2


def test_policy_limits_cannot_expand_runtime_ceiling(runtime):
    for key, ceiling in CHILD_LIMIT_CEILINGS.items():
        with pytest.raises(ValidationError):
            parent(runtime, limits={key: ceiling + 1}, key=key)


@pytest.mark.parametrize("key,ceiling", list(CHILD_LIMIT_CEILINGS.items()))
def test_every_limit_ceiling_is_accepted_and_next_integer_rejected(key, ceiling):
    base = {"capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}], "targets": [{"kind": "default"}], "input_object_ids": []}
    for value in (ceiling - 1, ceiling):
        policy = RuntimeService._child_policy({**base, "limits": {key: value}})
        assert policy["limits"][key] == value
        assert set(policy["limits"]) == set(CHILD_LIMITS)
    for value in (ceiling + 1, 0, -1, True, 1.5, "1"):
        with pytest.raises(ValidationError):
            RuntimeService._child_policy({**base, "limits": {key: value}})


def test_effective_defaults_are_frozen_at_admission(runtime, monkeypatch):
    service, _ = runtime
    attempt = parent(runtime)
    stored = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"]
    assert stored == CHILD_LIMITS
    monkeypatch.setattr(service_module, "CHILD_LIMITS", {key: 1 for key in CHILD_LIMITS})
    receipt = authority(service, attempt)
    admit(service, receipt, key="first")
    admit(service, receipt, key="second")
    assert service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"] == stored


def test_explicit_expanded_envelope_and_lifetime_active_accounting(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 500, "max_active_children": 1, "max_derived_objects": 512, "max_derived_bytes": 1024 ** 3})
    policy = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"]
    assert policy["max_children"] == 500
    assert policy["max_derived_bytes"] == 1024 ** 3
    receipt = authority(service, attempt)
    first = admit(service, receipt, key="first")
    assert admit(service, receipt, key="first") == first
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"]) == {"lifetime": 1, "active": 1, "replay": False}
    with pytest.raises(ValidationError, match="active child"):
        admit(service, receipt, key="second")
    first_attempt = claim(service, CHILD, "claim-first")
    settle(service, first_attempt, "first-done")
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 0
    admit(service, receipt, key="second")
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["lifetime"] == 2
    with pytest.raises(ValidationError, match="active child"):
        service.retry_task(first["task"]["id"], {}, idempotency_key="retry-first")


@pytest.mark.parametrize("state", ["queued", "running", "cancel_requested", "provider_state_unknown"])
def test_all_outstanding_child_states_hold_active_capacity(runtime, state):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 3, "max_active_children": 1}, targeted=state in {"cancel_requested", "provider_state_unknown"})
    receipt = authority(service, attempt)
    child = admit(service, receipt, key="first")
    child_attempt = None
    if state != "queued":
        child_attempt = claim(service, CHILD, "claim-first")
    if state == "cancel_requested":
        service.cancel_task_canonical(child["task"]["id"], {}, idempotency_key="cancel-first")
    if state == "provider_state_unknown":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child_attempt["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child_attempt["attempt_id"]))
        with service.store._transaction():
            service.store._reap_expired_leases()
        assert service.task(child_attempt["task_id"])["task"]["waiting_reason"] == "provider_state_unknown"
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 1
    assert admit(service, receipt, key="first")["task"]["id"] == child["task"]["id"]
    with pytest.raises(ValidationError, match="active child"):
        admit(service, receipt, key="second")


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_terminal_release_preserves_lifetime_and_retry_reuses_identity(runtime, terminal):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 1, "max_active_children": 1})
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    if terminal == "cancelled":
        service.cancel_task_canonical(child["task"]["id"], {}, idempotency_key="cancel-child")
    else:
        child_attempt = claim(service, CHILD, "claim-child")
        if terminal == "completed":
            settle(service, child_attempt, "done-child")
        else:
            service.fail_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "error": {"code": "fixture"}}, idempotency_key="failed-child", identity=IDENTITY)
    accounting = service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])
    assert accounting["lifetime"] == 1 and accounting["active"] == 0
    with pytest.raises(ValidationError, match="parent child count"):
        admit(service, receipt, key="new-child")
    service.retry_task(child["task"]["id"], {}, idempotency_key="retry-child")
    accounting = service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])
    assert accounting["lifetime"] == 1 and accounting["active"] == 1


def test_distinct_object_union_and_scaled_exact_byte_boundary(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_objects": 2, "max_derived_bytes": 5})
    first = upload(service, attempt, b"12", "first")
    second = upload(service, attempt, b"345", "second")
    one = authority(service, attempt, refs=[first], key="one")
    assert authority(service, attempt, refs=[first], key="one") == one
    authority(service, attempt, refs=[first, second], key="two")
    registry = service.task(attempt["task_id"])["task"]["spec"]["derived_input_registry"]
    assert len(registry) == 2 and sum(ref["size"] for ref in registry.values()) == 5
    third = upload(service, attempt, b"6", "third")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[third], key="three")
    assert service.task(attempt["task_id"])["task"]["spec"]["derived_input_registry"] == registry


def test_scaled_byte_overage_with_object_capacity_remaining(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_objects": 3, "max_derived_bytes": 5})
    first = upload(service, attempt, b"12345", "first")
    authority(service, attempt, refs=[first])
    second = upload(service, attempt, b"6", "second")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[second], key="second")
    assert len(service.managed_outputs(attempt["task_id"])) == 1


def test_per_child_derived_bytes_and_individual_object_boundary(runtime, monkeypatch):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_child_bytes": 4, "max_derived_bytes": 10})
    first = upload(service, attempt, b"12", "first")
    second = upload(service, attempt, b"345", "second")
    authority(service, attempt, refs=[first], key="first")
    authority(service, attempt, refs=[second], key="second")
    with pytest.raises(ValidationError, match="child input byte"):
        authority(service, attempt, refs=[first, second], key="both")
    too_big = {**first, "size": OBJECT_MAX_BYTES + 1}
    with pytest.raises(ValidationError, match="identity or size"):
        authority(service, attempt, refs=[too_big], key="oversized")
    # Scale the already-established 64 MiB per-object gate to real tiny bytes.
    monkeypatch.setattr(service_module, "OBJECT_MAX_BYTES", 4)
    boundary = upload(service, attempt, b"1234", "boundary")
    assert boundary["size"] == 4
    authority(service, attempt, refs=[boundary], key="exact-child-byte-boundary")
    with pytest.raises(ValidationError):
        upload(service, attempt, b"12345", "over-boundary")


def test_direct_wrong_capability_digest_and_scalar_omitted_objects(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    task = {"capability_id": CHILD, "capability_digest": digest("wrong"), "spec": {"params": {"query": "fixture://video"}}}
    with pytest.raises(AuthorizationError, match="capability"):
        service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key="child", identity=IDENTITY)
    task["capability_digest"] = digest(CHILD)
    child = service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key="child", identity=IDENTITY)
    assert child["task"]["spec"]["input_object_ids"] == []


def test_four_by_four_runtime_fanout_has_33_overlapping_required_children(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    refs = [upload(service, attempt, f"frame-{index}".encode(), f"frame-{index}") for index in range(17)]
    accepted = []
    for index in range(33):
        cap = CHILD if index < 17 else OTHER
        key = "fanout-" + str(index)
        ref = refs[index if index < 17 else index - 16]
        accepted.append(admit(service, authority(service, attempt, refs=[ref], key=key, cap=cap), refs=[ref], key=key, cap=cap))
    attempts = [claim(service, CHILD if index < 17 else OTHER, "claim-fanout-" + str(index)) for index in range(33)]
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 33
    assert all(value["task"]["execution_request"]["target"] == TARGET for value in accepted)
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "fanout-early")
    service.heartbeat_attempt(attempts[0]["attempt_id"], {**lease(attempts[0]), "progress": {"percent": 50}}, idempotency_key="fanout-progress", identity=IDENTITY)
    for index, child_attempt in enumerate(attempts):
        settle(service, child_attempt, "fanout-done-" + str(index))
    settle(service, attempt, "fanout-parent-done")


def test_maximum_child_and_registry_accounting_has_bounded_admission_overhead(runtime, capsys):
    service, _ = runtime
    attempt = parent(runtime, limits=CHILD_LIMIT_CEILINGS)
    ref = upload(service, attempt, b"x", "selected")
    receipt = authority(service, attempt, refs=[ref], key="selected-child")
    parent_row = service.store.conn.execute("SELECT * FROM tasks WHERE id=?", (attempt["task_id"],)).fetchone()
    spec = json.loads(parent_row["spec_json"])
    # Populate bounded metadata in the temporary fixture, without allocating GiB
    # or treating synthetic references as authenticated objects. Only `ref` is used.
    for index in range(1023):
        object_id = digest("metadata-" + str(index))
        spec["derived_input_registry"][object_id] = {**ref, "object_id": object_id, "parent_attempt_id": attempt["attempt_id"], "association_id": "fixture-association-" + str(index)}
    service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), attempt["task_id"]))
    selected = admit(service, receipt, refs=[ref], key="selected-child")
    selected_row = service.store.conn.execute("SELECT * FROM tasks WHERE id=?", (selected["task"]["id"],)).fetchone()
    run_row = service.store.conn.execute("SELECT * FROM runs WHERE id=?", (selected_row["run_id"],)).fetchone()
    task_columns = list(selected_row.keys())
    run_columns = list(run_row.keys())
    with service.store._transaction():
        for index in range(4095):
            task = dict(selected_row)
            run = dict(run_row)
            run["id"] = "metadata-run-" + str(index)
            run["idempotency_key"] = "metadata-child-" + str(index)
            task.update(id="metadata-task-" + str(index), run_id=run["id"], status="queued" if index < 63 else "completed", result_json='{"outputs": []}')
            service.store.conn.execute(f"INSERT INTO runs({','.join(run_columns)}) VALUES ({','.join('?' for _ in run_columns)})", [run[key] for key in run_columns])
            service.store.conn.execute(f"INSERT INTO tasks({','.join(task_columns)}) VALUES ({','.join('?' for _ in task_columns)})", [task[key] for key in task_columns])
            if index == 62:
                assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 64
                with pytest.raises(ValidationError, match="active child"):
                    admit(service, authority(service, attempt), key="over-active")
    started = time.perf_counter()
    for _ in range(10):
        assert admit(service, receipt, refs=[ref], key="selected-child")["task"]["id"] == selected["task"]["id"]
    elapsed = time.perf_counter() - started
    assert elapsed < 5, f"10 exact admissions at bounded maximum took {elapsed:.3f}s"
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["lifetime"] == 4096
    with pytest.raises(ValidationError, match="parent child count"):
        admit(service, authority(service, attempt), key="over-lifetime")
    extra = upload(service, attempt, b"extra", "extra")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[extra], key="over-registry")
    with capsys.disabled():
        print(f"D18_OVERHEAD children=4096 registry=1024 replays=10 elapsed_seconds={elapsed:.6f}")


def test_parent_success_racing_child_admission_has_one_fenced_outcome(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    barrier = threading.Barrier(2)
    def admit_child():
        barrier.wait()
        try:
            admit(service, receipt)
            return "accepted"
        except LeaseError:
            return "fenced"
    def settle_parent():
        barrier.wait()
        try:
            settle(service, attempt, "race-success")
            return "completed"
        except ConflictError:
            return "child-active"
    with ThreadPoolExecutor(max_workers=2) as pool:
        child_future = pool.submit(admit_child)
        parent_future = pool.submit(settle_parent)
        outcome = (child_future.result(), parent_future.result())
    assert outcome in {("accepted", "child-active"), ("fenced", "completed")}
    if outcome[0] == "accepted":
        assert service.task(attempt["task_id"])["task"]["status"] == "running"
    else:
        assert not service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])


def test_parent_cancellation_racing_admission_contains_any_accepted_child(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    barrier = threading.Barrier(2)
    def admit_child():
        barrier.wait()
        try:
            return admit(service, receipt)["task"]["id"]
        except LeaseError:
            return None
    def cancel_parent():
        barrier.wait()
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="race-cancel")
    with ThreadPoolExecutor(max_workers=2) as pool:
        child_future = pool.submit(admit_child)
        parent_future = pool.submit(cancel_parent)
        child_id = child_future.result()
        parent_future.result()
    assert service.task(attempt["task_id"])["task"]["status"] == "cancelled"
    if child_id is not None:
        assert service.task(child_id)["task"]["status"] == "cancelled"
    with pytest.raises(LeaseError):
        admit(service, receipt, key="late-race")


def test_external_parent_run_cancellation_contains_delegated_children(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    claim(service, CHILD, "claim-run-child")
    service.cancel_run(attempt["run_id"], {}, idempotency_key="parent-run-cancel")
    assert service.task(attempt["task_id"])["task"]["status"] == "cancel_requested"
    assert service.task(child["task"]["id"])["task"]["status"] == "cancel_requested"
    with pytest.raises(LeaseError):
        admit(service, receipt, key="after-run-cancel")

# B01/D18/M04: producing-child snapshots use the actual Human Review ID,
# with deterministic local capability bytes and two independent worker actors.
HUMAN_REVIEW = "editorial.human_review"
REVIEWER_IDENTITY = {**copy.deepcopy(IDENTITY), "actor": "reviewer"}


def snapshot_parent(runtime, *, permitted=True, limits=None):
    service, project = runtime
    service.register_capability({"capability_id": HUMAN_REVIEW, "definition_digest": digest(HUMAN_REVIEW)})
    service.register_executor({"executor_id": "reviewer", "capabilities": [HUMAN_REVIEW], "max_concurrency": 4}, idempotency_key="register-reviewer")
    policy = {"capabilities": [{"capability_id": HUMAN_REVIEW, "capability_digest": digest(HUMAN_REVIEW)}],
              "targets": [{"kind": "default"}], "input_object_ids": []}
    if permitted:
        policy["recoverable_outputs"] = [{**policy["capabilities"][0], "output_ports": ["state_result"]}]
    if limits is not None:
        policy["limits"] = limits
    service.create_task({"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
        "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": "snapshot-parent"}, enforce_readiness=True)
    return claim(service, PARENT, "claim-snapshot-parent")


def snapshot_child(service, parent_attempt, key="review"):
    task = admit(service, authority(service, parent_attempt), cap=HUMAN_REVIEW, key=key)
    attempt = service.claim_next({"executor_id": "reviewer", "capability_ids": [HUMAN_REVIEW],
        "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-" + key, identity=REVIEWER_IDENTITY)
    assert attempt["task_id"] == task["task"]["id"]
    return attempt


def snapshot_upload(service, attempt, data=b'{"draft":1}', *, name="draft", port="state_result"):
    output = {"name": name, "output_port": port, "filename": name + ".json", "object_id": digest(data),
              "size": len(data), "media_type": "application/json"}
    binding = {"project_id": attempt["project_id"], "run_id": attempt["run_id"], "task_id": attempt["task_id"],
        "attempt_id": attempt["attempt_id"], "executor_id": "reviewer", **lease(attempt), "output_key": name,
        "output_port": port, "filename": output["filename"], "digest": output["object_id"], "size": len(data),
        "media_type": output["media_type"]}
    service.ingest_object(data, media_type=output["media_type"], original_name=output["filename"],
        idempotency_key=service._generic_output_idempotency_key(binding), identity=REVIEWER_IDENTITY, upload_binding=binding)
    return output


def publish_snapshot(service, attempt, output, revision=1, key="save-1", **kwargs):
    return service.publish_recoverable_snapshot(attempt["attempt_id"], {**lease(attempt), "revision": revision, "output": output},
        idempotency_key=key, identity=kwargs.get("identity", REVIEWER_IDENTITY))


def test_snapshot_grant_omission_denies_and_admission_freezes_defaults(runtime, monkeypatch):
    service, _ = runtime
    p = snapshot_parent(runtime, permitted=False)
    child = snapshot_child(service, p)
    assert "delegated_recoverable_outputs" not in child["spec"]
    with pytest.raises(AuthorizationError, match="grant"):
        publish_snapshot(service, child, snapshot_upload(service, child))


def test_snapshot_grant_is_parent_bound_and_runtime_owned(runtime, monkeypatch):
    service, _ = runtime
    p = snapshot_parent(runtime)
    policy = service.task(p["task_id"])["task"]["spec"]["child_delegation"]
    for grant in ([{**policy["recoverable_outputs"][0], "output_ports": ["*"]}],
                  [policy["recoverable_outputs"][0]] * 2,
                  [{**policy["recoverable_outputs"][0], "capability_id": CHILD}],
                  [{**policy["recoverable_outputs"][0], "capability_digest": digest("wrong")}],
                  [{**policy["recoverable_outputs"][0], "limits": {}}]):
        with pytest.raises(ValidationError):
            service._child_policy({**policy, "recoverable_outputs": grant})
    receipt = authority(service, p)
    for spec in ({"delegated_recoverable_outputs": {}}, {"delegated_parent": {}}):
        with pytest.raises(ValidationError, match="Runtime admission"):
            service.admit_delegated_child(
                {"authority": receipt["authority"], "task": {"capability_id": HUMAN_REVIEW,
                    "capability_digest": digest(HUMAN_REVIEW), "spec": spec}}, idempotency_key="forge", identity=IDENTITY)
    child = snapshot_child(service, p)
    frozen = child["spec"]["delegated_recoverable_outputs"]
    assert frozen["capability_id"] == HUMAN_REVIEW and frozen["output_ports"] == ["state_result"]
    assert frozen["policy_digest"] == child["spec"]["delegated_parent"]["policy_digest"]
    assert frozen["parent_attempt_id"] == p["attempt_id"]
    assert frozen["limits"] == {k: CHILD_LIMITS[k] for k in ("max_recoverable_snapshots", "max_recoverable_bytes", "max_snapshot_bytes")}
    monkeypatch.setitem(CHILD_LIMITS, "max_snapshot_bytes", 1)
    publish_snapshot(service, child, snapshot_upload(service, child))


@pytest.mark.parametrize("limit", ["max_recoverable_snapshots", "max_recoverable_bytes", "max_snapshot_bytes"])
def test_snapshot_policy_hard_ceilings_inclusive(runtime, limit):
    service, _ = runtime
    p = snapshot_parent(runtime)
    policy = service.task(p["task_id"])["task"]["spec"]["child_delegation"]
    assert service._child_policy({**policy, "limits": {limit: CHILD_LIMIT_CEILINGS[limit]}})["limits"][limit] == CHILD_LIMIT_CEILINGS[limit]
    for bad in (0, True, CHILD_LIMIT_CEILINGS[limit] + 1):
        with pytest.raises(ValidationError, match="finite Runtime"):
            service._child_policy({**policy, "limits": {limit: bad}})


def test_snapshot_own_worker_replay_revision_conflict_and_settlement_separation(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    saved = publish_snapshot(service, child, output)
    assert saved["data"]["role"] == "recoverable_snapshot"
    assert saved["data"]["provenance"]["executor_id"] == "reviewer"
    assert p["spec"].get("delegated_parent") is None
    assert publish_snapshot(service, child, output) == saved
    assert publish_snapshot(service, child, output, key="lost-response-new-key") == saved
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, output, revision=2, key="lost-response-new-key")
    assert len(service.managed_outputs(child["task_id"])) == 1
    changed = snapshot_upload(service, child, b'{"draft":2}')
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, changed)
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, changed, key="changed-revision")
    publish_snapshot(service, child, changed, revision=3, key="save-3")
    with pytest.raises(ConflictError, match="stale"):
        publish_snapshot(service, child, output, revision=2, key="save-2")
    assert service.task(child["task_id"])["task"]["status"] == "running"
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, p, "draft-is-not-success")
    with pytest.raises(ValidationError, match="Runtime-reserved"):
        service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"digest": output["object_id"], "role": "recoverable_snapshot"}]}, idempotency_key="forge-role", identity=REVIEWER_IDENTITY)
    final_data = b'{"submitted":true}'
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"name": "state_result", "output_port": "state_result",
        "digest": digest(final_data), "data_base64": base64.b64encode(final_data).decode()}]}, idempotency_key="review-submit", identity=REVIEWER_IDENTITY)
    task = service.task(child["task_id"])["task"]
    assert len(task["result"]["outputs"]) == 1
    assert task["result"]["outputs"][0]["digest"] == digest(final_data)
    assert len(service.managed_outputs(child["task_id"])) == 3
    settle(service, p, "parent-with-final")
    assert service.task(p["task_id"])["task"]["status"] == "completed"


@pytest.mark.parametrize("change", ["identity", "no_identity", "fence", "lease_id", "runtime_epoch", "attempt", "no_receipt",
    "foreign_receipt", "digest", "unprefixed_digest", "size", "media_type", "filename", "object_metadata", "project", "port", "capability", "grant", "parent_policy", "corrupt", "missing", "malformed"])
def test_snapshot_authentication_upload_and_custody_rejections(runtime, change):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    body = {**lease(child), "revision": 1, "output": output}
    attempt_id = child["attempt_id"]
    identity = REVIEWER_IDENTITY
    if change in ("identity", "no_identity"):
        identity = IDENTITY if change == "identity" else None
    elif change in ("fence", "lease_id", "runtime_epoch"):
        body[change] = "foreign" if change == "lease_id" else body[change] + 1
    elif change == "attempt":
        attempt_id = p["attempt_id"]
    elif change == "no_receipt":
        service.store.conn.execute("DELETE FROM command_idempotency WHERE command_kind='object.ingest'")
    elif change == "foreign_receipt":
        sibling = snapshot_child(service, p, key="sibling")
        body["output"] = snapshot_upload(service, sibling, b"foreign")
    elif change == "digest":
        output["object_id"] = digest("unuploaded")
    elif change == "unprefixed_digest":
        output["object_id"] = output["object_id"][7:]
    elif change == "filename":
        output["filename"] = "wrong.json"
    elif change == "object_metadata":
        service.store.conn.execute("UPDATE objects SET media_type='image/png' WHERE digest=?", (output["object_id"][7:],))
    elif change in ("size", "media_type", "port"):
        output["size" if change == "size" else "media_type" if change == "media_type" else "output_port"] = len(b'{"draft":1}') + 1 if change == "size" else "image/png" if change == "media_type" else "other"
    elif change == "project":
        service.store.conn.execute("UPDATE runs SET project_id=NULL WHERE id=?", (child["run_id"],))
    elif change in ("capability", "grant"):
        spec = json.loads(service.store.conn.execute("SELECT spec_json FROM tasks WHERE id=?", (child["task_id"],)).fetchone()[0])
        if change == "capability":
            spec["capability_digest"] = digest("changed")
        else:
            spec["delegated_recoverable_outputs"]["output_ports"] = ["other"]
        service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), child["task_id"]))
    elif change == "parent_policy":
        spec = json.loads(service.store.conn.execute("SELECT spec_json FROM tasks WHERE id=?", (p["task_id"],)).fetchone()[0])
        spec["child_delegation"]["limits"]["max_snapshot_bytes"] = 2
        service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), p["task_id"]))
    elif change in ("corrupt", "missing"):
        path = service.cas.path_for(output["object_id"][7:])
        path.write_bytes(b"corrupt!!!") if change == "corrupt" else path.unlink()
    elif change == "malformed":
        output["unexpected"] = True
    with pytest.raises((AuthorizationError, LeaseError, ConflictError, ValidationError)):
        service.publish_recoverable_snapshot(attempt_id, body, idempotency_key="bad-save", identity=identity)
    assert not service.managed_outputs(child["task_id"])
    assert not service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='attempt.recoverable_snapshot.publish'").fetchone()


@pytest.mark.parametrize("bound", ["count", "aggregate_bytes", "object_bytes"])
def test_snapshot_quota_inclusive_edges_and_replay_no_double_charge(runtime, bound):
    service, _ = runtime
    limits = {"max_recoverable_snapshots": 2 if bound == "count" else 10,
              "max_recoverable_bytes": 4 if bound == "aggregate_bytes" else 100,
              "max_snapshot_bytes": 2 if bound == "object_bytes" else 100}
    p = snapshot_parent(runtime, limits=limits)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child, b"12")
    saved = publish_snapshot(service, child, output)
    assert publish_snapshot(service, child, output) == saved
    publish_snapshot(service, child, output, revision=2, key="save-2")
    extra = snapshot_upload(service, child, b"123" if bound == "object_bytes" else b"1", name="extra")
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, child, extra, revision=3, key="overflow")
    assert len(service.managed_outputs(child["task_id"])) == 2
    assert len(service.store.recoverable_snapshots(parent_attempt_id=p["attempt_id"])) == 2


def test_snapshot_quota_shared_by_children_and_cancel_does_not_refund(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    saved = publish_snapshot(service, child, snapshot_upload(service, child))
    service.cancel_task_canonical(child["task_id"], {}, idempotency_key="cancel-review")
    sibling = snapshot_child(service, p, "retry-child")
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, sibling, snapshot_upload(service, sibling), key="sibling-save")
    assert service.managed_output(saved["data"]["association_id"]) == saved["data"]
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, p, "cancelled-draft-is-not-success")


@pytest.mark.parametrize("closure", ["child_cancel", "parent_cancel", "child_lease", "parent_lease", "restart"])
def test_snapshot_closure_preserves_acknowledged_receipt_and_exact_bytes(runtime, closure):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    data = b'{"partial":"acknowledged"}'
    output = snapshot_upload(service, child, data)
    saved = publish_snapshot(service, child, output)
    # Upload a proposed later revision while live; closure must still deny it.
    later = snapshot_upload(service, child, b'{"partial":"unacknowledged"}', name="later")
    if closure.endswith("cancel"):
        closing = child if closure.startswith("child") else p
        service.cancel_task_canonical(closing["task_id"], {}, idempotency_key="close")
    elif closure.endswith("lease"):
        closing = child if closure.startswith("child") else p
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with service.store._mutex, service.store._transaction():
            service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, closing["task_id"]))
            service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, closing["attempt_id"]))
            service.store._reap_expired_leases()
    else:
        root = service.store.root
        service.close()
        service = RuntimeService(root)
    try:
        assert publish_snapshot(service, child, output) == saved
        assert publish_snapshot(service, child, output, key="recover-receipt") == saved
        with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
            publish_snapshot(service, child, later, revision=2, key="after-close")
        items = service.managed_output_page(child["task_id"])["items"]
        assert [a["association_id"] for a in items] == [saved["data"]["association_id"]]
        recovered = service.managed_output(saved["data"]["association_id"])
        row, raw = service.object(recovered["object_id"])
        assert raw == data and digest(raw) == recovered["object_id"] and row["size"] == len(data)
        assert recovered["lifecycle"]["state"] == "available"
        assert service.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (child["project_id"], output["object_id"][7:])).fetchone()
        assert service.task(child["task_id"])["task"]["status"] != "completed"
    finally:
        if closure == "restart":
            service.close()


@pytest.mark.parametrize("closure", ["child_cancel", "parent_cancel", "child_lease", "parent_lease"])
@pytest.mark.parametrize("order", ["publish_first", "close_first", "concurrent"])
def test_snapshot_publication_and_authority_closure_serialize(runtime, closure, order):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    barrier = threading.Barrier(2) if order == "concurrent" else None
    def publish():
        if barrier:
            barrier.wait()
        try:
            return publish_snapshot(service, child, output)
        except (LeaseError, AuthorizationError, ConflictError):
            return None
    def close():
        if barrier:
            barrier.wait()
        closing = child if closure.startswith("child") else p
        if closure.endswith("cancel"):
            service.cancel_task_canonical(closing["task_id"], {}, idempotency_key="race-close")
        else:
            with service.store._mutex, service.store._transaction():
                expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, closing["task_id"]))
                service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, closing["attempt_id"]))
                service.store._reap_expired_leases()
    if order == "concurrent":
        with ThreadPoolExecutor(max_workers=2) as pool:
            published = pool.submit(publish)
            closed = pool.submit(close)
            saved = published.result()
            closed.result()
    elif order == "publish_first":
        saved = publish()
        assert saved is not None
        close()
    else:
        close()
        saved = publish()
        assert saved is None
    items = service.managed_outputs(child["task_id"])
    assert len(items) == int(saved is not None)
    if saved is not None:
        assert publish_snapshot(service, child, output) == saved
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        publish_snapshot(service, child, output, revision=2, key="closed-revision")


def test_snapshot_transaction_failure_rolls_back_custody_event_quota_and_receipt(runtime, monkeypatch):
    service, project = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    before = service.events(child["run_id"])
    original = service._command_record
    def fail_commit(kind, *args, **kwargs):
        if kind == "attempt.recoverable_snapshot.publish":
            raise ConflictError("injected receipt failure")
        return original(kind, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(service, "_command_record", fail_commit)
        with pytest.raises(ConflictError, match="injected"):
            publish_snapshot(service, child, output)
    assert service.managed_outputs(child["task_id"]) == []
    assert service.store.recoverable_snapshots(parent_attempt_id=p["attempt_id"]) == []
    assert service.events(child["run_id"]) == before
    assert not service.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project, output["object_id"][7:])).fetchone()
    assert not service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='attempt.recoverable_snapshot.publish'").fetchone()
    publish_snapshot(service, child, output)


def test_snapshot_cannot_replace_missing_final_managed_association(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    saved = publish_snapshot(service, child, output)
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"name": output["name"],
        "filename": output["filename"], "output_port": "state_result", "digest": output["object_id"],
        "size": output["size"], "media_type": output["media_type"]}]}, idempotency_key="final-same-bytes", identity=REVIEWER_IDENTITY)
    service.store.conn.execute("DELETE FROM managed_output_lifecycle WHERE association_id IN (SELECT association_id FROM managed_output_associations WHERE task_id=? AND role!='recoverable_snapshot')", (child["task_id"],))
    service.store.conn.execute("DELETE FROM managed_output_associations WHERE task_id=? AND role!='recoverable_snapshot'", (child["task_id"],))
    assert service.managed_outputs(child["task_id"])[0]["association_id"] == saved["data"]["association_id"]
    with pytest.raises(ConflictError, match="verified durable"):
        settle(service, p, "snapshots-cannot-cover-final")


def test_snapshot_same_task_retry_shares_parent_quota(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    publish_snapshot(service, child, snapshot_upload(service, child))
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with service.store._mutex, service.store._transaction():
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child["attempt_id"]))
        service.store._reap_expired_leases()
    retry = service.claim_next({"executor_id": "reviewer", "capability_ids": [HUMAN_REVIEW],
        "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-review-retry", identity=REVIEWER_IDENTITY)
    assert retry["task_id"] == child["task_id"] and retry["attempt_id"] != child["attempt_id"]
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, retry, snapshot_upload(service, retry), key="attempt-retry-save")


def test_snapshot_restart_fresh_authorized_generated_reads_return_exact_bytes(runtime, tmp_path):
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    from runtime_protocol.auth import CredentialStore
    from runtime_protocol.server import RuntimeHandler
    sys.path.insert(0, str(Path(__file__).parents[1] / "packages/python"))
    from banodoco_workspace_client import WorkspaceClient

    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    payload = b'{"last_acknowledged":true}'
    saved = publish_snapshot(service, child, snapshot_upload(service, child, payload))
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        credentials = CredentialStore(tmp_path / "fresh-reader-credentials")
        token, _ = credentials.provision("fresh-reader", ["tasks:read", "objects:read"])
        no_scopes, _ = credentials.provision("unauthorized-reader", [])
        def transport(method, path, headers, body):
            handler = object.__new__(RuntimeHandler)
            handler.server = SimpleNamespace(runtime=restarted, credentials=credentials)
            handler.command = method
            handler.path = path
            handler.headers = headers
            handler._send = lambda status, value=None, *, headers=None, body=None: (
                status, headers or {}, body if body is not None else json.dumps(value).encode())
            return handler._route()
        reader = WorkspaceClient("http://runtime", token, transport=transport)
        items, cursor = reader.list_managed_outputs(child["task_id"])
        assert cursor is None and len(items) == 1
        recovered = reader.get_managed_output(saved["data"]["association_id"])
        assert items[0].association_id == recovered.association_id
        raw = reader.get_object(recovered.object_id)
        assert raw.data == payload and digest(raw.data) == recovered.object_id
        assert recovered.size == len(payload) and recovered.role == "recoverable_snapshot"
        forbidden = WorkspaceClient("http://runtime", no_scopes, transport=transport)
        for read in (lambda: forbidden.list_managed_outputs(child["task_id"]),
                     lambda: forbidden.get_managed_output(recovered.association_id),
                     lambda: forbidden.get_object(recovered.object_id)):
            with pytest.raises(AuthorizationError):
                read()
    finally:
        restarted.close()


def test_snapshot_is_not_a_settled_stage_output_even_after_submit(runtime):
    service, project = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    saved = publish_snapshot(service, child, snapshot_upload(service, child))
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": []}, idempotency_key="review-done", identity=REVIEWER_IDENTITY)
    declared = [{"name": "state", "producer_stage": "review", "output_port": "state_result"}]
    supplied = [{"name": "state", "producer_task_id": child["task_id"], "association_id": saved["data"]["association_id"], "output_port": "state_result"}]
    siblings = {"review": {"id": child["task_id"], "attempt_id": child["attempt_id"], "status": "completed"}}
    with pytest.raises(AuthorizationError, match="declared live lineage"):
        service._resolve_delegated_stage_inputs(declared, supplied, siblings=siblings, project=project,
            lineage=child["spec"]["delegated_parent"])


# B01/M21: discovery selects one historical tuple; execution authority remains D18.
def discovery_parent_body(runtime):
    service, project = runtime
    selected = parent(runtime, key="discovery-selected")
    settle(service, selected, "discovery-selected-success")
    grant = {"project_id": project, "run_id": selected["run_id"], "task_id": selected["task_id"],
             "attempt_id": selected["attempt_id"], "capability_id": PARENT, "capability_digest": digest(PARENT),
             "limits": dict(service_module.DISCOVERY_GRANT_CEILINGS)}
    policy = {"capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}],
              "targets": [{"kind": "default"}], "input_object_ids": [], "discovery_grant": grant}
    return {"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
            "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": "discovery-parent"}


def test_discovery_grant_persists_exact_historical_tuple_and_preserves_receipts(runtime):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    expected = copy.deepcopy(body["child_delegation"]["discovery_grant"])
    service.create_task(body, enforce_readiness=True)
    attempt = claim(service, PARENT, "claim-discovery-parent")
    persisted = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]
    assert persisted["discovery_grant"] == expected
    assert persisted["limits"] == CHILD_LIMITS
    assert attempt["spec"]["child_delegation"]["discovery_grant"] == expected
    assert expected["attempt_id"] != attempt["attempt_id"]
    assert service._decode_child_authority(authority(service, attempt)["authority"])["policy_digest"] == digest(
        service_module.canonical_json(persisted)).removeprefix("sha256:")
    raw = b"discovery-unbound"
    service.ingest_object(raw, original_name="raw.bin", idempotency_key="discovery-unbound")
    unbound = {"name": "raw", "output_port": "raw", "filename": "raw.bin", "object_id": digest(raw),
               "size": len(raw), "media_type": "application/octet-stream"}
    with pytest.raises(AuthorizationError, match="authenticated upload receipt"):
        authority(service, attempt, refs=[unbound])
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    child = admit(service, receipt, refs=[ref])
    assert child["task"]["spec"]["delegated_inputs"][0]["association_id"] == receipt["derived_inputs"][0]["association_id"]
    assert "child_delegation" not in child["task"]["spec"]


@pytest.mark.parametrize("field", ["project_id", "run_id", "task_id", "attempt_id", "capability_id", "capability_digest"])
def test_discovery_grant_rejects_parent_or_selected_tuple_mismatch(runtime, field):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    body["child_delegation"]["discovery_grant"][field] = digest("foreign") if field == "capability_digest" else "foreign"
    with pytest.raises(AuthorizationError, match="discovery grant"):
        service.create_task(body, enforce_readiness=True)


@pytest.mark.parametrize("bad", [None, [], {}, {"authority": "caller-forged"}])
def test_discovery_grant_rejects_malformed_object(runtime, bad):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    body["child_delegation"]["discovery_grant"] = bad
    with pytest.raises(ValidationError, match="discovery_grant"):
        service.create_task(body)


@pytest.mark.parametrize("field", ["project_id", "run_id", "task_id", "attempt_id", "capability_id", "capability_digest", "limits"])
def test_discovery_grant_rejects_missing_required_fields(runtime, field):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    del body["child_delegation"]["discovery_grant"][field]
    with pytest.raises(ValidationError, match="discovery_grant"):
        service.create_task(body)


@pytest.mark.parametrize("field", list(service_module.DISCOVERY_GRANT_CEILINGS))
@pytest.mark.parametrize("bad", [None, True, 0, -1, 1.5, "1", "missing", "excessive"])
def test_discovery_grant_requires_every_finite_budget(runtime, field, bad):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    bounds = body["child_delegation"]["discovery_grant"]["limits"]
    if bad == "missing":
        del bounds[field]
    else:
        bounds[field] = service_module.DISCOVERY_GRANT_CEILINGS[field] + 1 if bad == "excessive" else bad
    with pytest.raises(ValidationError, match="finite prototype bound"):
        service.create_task(body)


@pytest.mark.parametrize("change", ["wildcard", "empty_identity", "list_identity", "bare_digest", "extra_grant", "extra_limit", "empty_limits", "forged_parent_attempt", "spec", "body"])
def test_discovery_grant_rejects_wildcard_unknown_and_caller_authority(runtime, change):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    grant = body["child_delegation"]["discovery_grant"]
    if change == "wildcard":
        grant["run_id"] = "*"
    elif change == "empty_identity":
        grant["run_id"] = ""
    elif change == "list_identity":
        grant["task_id"] = [grant["task_id"]]
    elif change == "bare_digest":
        grant["capability_digest"] = digest(PARENT)[7:]
    elif change == "extra_grant":
        grant["authority"] = "caller-forged"
    elif change == "extra_limit":
        grant["limits"]["extra"] = 1
    elif change == "empty_limits":
        grant["limits"] = {}
    elif change == "forged_parent_attempt":
        grant["parent_attempt_id"] = "caller-forged"
    else:
        (body["spec"] if change == "spec" else body)["discovery_grant"] = grant
    with pytest.raises(ValidationError):
        service.create_task(body)


@pytest.mark.parametrize("change", ["grant", "policy", "signature", "redelegation"])
def test_discovery_grant_policy_is_signed_and_cannot_redelegate(runtime, change):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    service.create_task(body)
    attempt = claim(service, PARENT, "claim-discovery-parent")
    receipt = authority(service, attempt)
    if change in {"grant", "policy"}:
        spec = json.loads(service.store.conn.execute("SELECT spec_json FROM tasks WHERE id=?", (attempt["task_id"],)).fetchone()[0])
        if change == "grant":
            spec["child_delegation"]["discovery_grant"]["limits"]["max_discovery_rows"] -= 1
        else:
            spec["child_delegation"]["limits"]["max_children"] -= 1
        service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), attempt["task_id"]))
    elif change == "signature":
        payload = service._decode_child_authority(receipt["authority"])
        payload["policy_digest"] = digest("caller-forged")
        _, signature = receipt["authority"].split(".")
        receipt["authority"] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "." + signature
    else:
        with pytest.raises(ValidationError, match="cannot delegate further"):
            service.create_task(body, _delegated_lineage={"parent_attempt_id": attempt["attempt_id"]})
        child = admit(service, receipt)
        child_attempt = claim(service, CHILD, "claim-discovery-child")
        spec = json.loads(service.store.conn.execute("SELECT spec_json FROM tasks WHERE id=?", (child["task"]["id"],)).fetchone()[0])
        spec["child_delegation"] = body["child_delegation"]
        service.store.conn.execute("UPDATE tasks SET spec_json=? WHERE id=?", (json.dumps(spec), child["task"]["id"]))
        with pytest.raises(AuthorizationError, match="cannot delegate further"):
            authority(service, child_attempt)
        return
    with pytest.raises(AuthorizationError):
        admit(service, receipt)


@pytest.mark.parametrize("end", ["cancel", "expired", "epoch", "fence", "recovered"])
def test_discovery_grant_uses_live_parent_lifecycle(runtime, monkeypatch, end):
    service, _ = runtime
    service.create_task(discovery_parent_body(runtime))
    attempt = claim(service, PARENT, "claim-discovery-parent")
    receipt = authority(service, attempt)
    if end == "cancel":
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="discovery-cancel")
    elif end == "expired":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
    elif end == "epoch":
        service.store.begin_runtime_session("discovery-next-boot")
    elif end == "fence":
        service.store.conn.execute("UPDATE tasks SET lease_fence=lease_fence+1 WHERE id=?", (attempt["task_id"],))
    else:
        monkeypatch.setattr(service.store, "placement_recovery", lambda task_id: {
            "placement_version": 1, "replacement_target": dict(TARGET),
        })
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        admit(service, receipt)
