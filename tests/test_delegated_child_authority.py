from __future__ import annotations

import hashlib
import base64

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon, WORKER_SCOPES
from runtime_protocol.store import RealmStore


PARENT = "test.delegating-parent"
CHILD = "test.delegated-child"
TARGET = {"kind": "runpod", "pod_id": "pod-child", "provider_account_ref": "test-account"}


def _digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def actors(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        owner, worker = Api(daemon.endpoint, daemon.token), Api(daemon.endpoint, daemon.worker_token)
        assert "tasks:write" not in WORKER_SCOPES and "projects:write" not in WORKER_SCOPES
        for capability in (PARENT, CHILD):
            owner.request("POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": _digest(capability)})
        owner.register_executor("astrid-pack-host", [PARENT, CHILD])
        project = owner.create_project("delegation", "Delegation")
        allowed_input = owner.ingest(project["project_id"], b"allowed-child-input", idempotency_key="delegation-input")["data"]["digest"]
        parent = owner.request("POST", "/v1/tasks", {
            "capability_id": PARENT, "capability_digest": _digest(PARENT),
            "project": project["project_id"], "input_object_ids": [], "spec": {},
            "child_delegation": {
                "capabilities": [{"capability_id": CHILD, "capability_digest": _digest(CHILD)}],
                "targets": [{"kind": "default"}, TARGET], "input_object_ids": [allowed_input],
            },
        }, headers={"Idempotency-Key": "delegating-parent"})["data"]
        claim = worker.request("POST", "/v1/tasks/claim", {
            "executor_id": "astrid-pack-host", "capability_ids": [PARENT],
            "runtime_epoch": owner.health()["runtime_epoch"],
        }, headers={"Idempotency-Key": "delegating-parent-claim"})
        yield daemon, owner, worker, parent, claim
    finally:
        daemon.stop()


def _authority(worker, claim):
    return worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/child-authority", {
        "lease_id": claim["lease_id"], "fence": claim["fence"],
        "runtime_epoch": claim["runtime_epoch"],
    })["authority"]


def _admit(worker, authority, key="child-1", **changes):
    task = {"capability_id": CHILD, "capability_digest": _digest(CHILD), "input_object_ids": [], "spec": {"prompt": "hello"}}
    task.update(changes)
    return worker.request("POST", "/v1/delegated-tasks", {"authority": authority, "task": task}, headers={"Idempotency-Key": key})["data"]


def test_worker_admits_only_policy_bound_child_with_durable_lineage(actors):
    daemon, owner, worker, parent, claim = actors
    authority = _authority(worker, claim)
    child = _admit(worker, authority)
    assert child["project_id"] == parent["project_id"]
    assert child["spec"]["delegated_parent"] == {
        "parent_task_id": parent["task_id"], "parent_attempt_id": claim["attempt_id"],
        "parent_lease_id": claim["lease_id"], "parent_fence": claim["fence"],
        "runtime_epoch": claim["runtime_epoch"], "executor_id": "astrid-pack-host",
        "parent_placement": None,
        "project_id": parent["project_id"],
    }
    assert _admit(worker, authority) == child
    assert owner.task(child["task_id"])["spec"]["delegated_parent"] == child["spec"]["delegated_parent"]
    assert daemon.credentials.load(daemon.worker_token)["scopes"] == sorted(WORKER_SCOPES)


def test_allowed_target_is_frozen_in_child_execution_binding(actors):
    _daemon, _owner, worker, _parent, claim = actors
    child = _admit(worker, _authority(worker, claim), execution_request={"schema_version": 1, "target": TARGET, "inputs": []})
    assert child["execution_request"]["target"] == TARGET
    assert child["execution_binding"]["resolved_target"] == TARGET


def test_allowed_project_input_is_admitted(actors):
    _daemon, _owner, worker, _parent, claim = actors
    allowed_input = claim["spec"]["child_delegation"]["input_object_ids"][0]
    child = _admit(worker, _authority(worker, claim), input_object_ids=[allowed_input])
    assert child["input_object_ids"] == [allowed_input]


@pytest.mark.parametrize("changes", [
    {"capability_id": PARENT, "capability_digest": _digest(PARENT)},
    {"input_object_ids": ["sha256:" + "a" * 64]},
    {"execution_request": {"schema_version": 1, "target": {"kind": "profile", "id": "other"}, "inputs": []}},
    {"settlement_effect": {"effect_type": "project.update"}},
    {"child_delegation": {"capabilities": [], "targets": [], "input_object_ids": []}},
    {"spec": {"runtime_dependencies": {}}},
])
def test_child_cannot_exceed_parent_policy(actors, changes):
    _daemon, _owner, worker, _parent, claim = actors
    with pytest.raises(RuntimeError) as rejected:
        _admit(worker, _authority(worker, claim), **changes)
    assert rejected.value.status in {400, 401, 422}


def test_tampering_and_parent_settlement_fence_child_admission(actors):
    _daemon, _owner, worker, _parent, claim = actors
    token = _authority(worker, claim)
    with pytest.raises(RuntimeError) as tampered:
        _admit(worker, token[:-1] + ("0" if token[-1] != "0" else "1"))
    assert tampered.value.status == 401
    worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/settle", {
        "lease_id": claim["lease_id"], "fence": claim["fence"],
        "runtime_epoch": claim["runtime_epoch"], "outputs": [],
    }, headers={"Idempotency-Key": "parent-settle"})
    with pytest.raises(RuntimeError) as stale:
        _admit(worker, token)
    assert stale.value.status == 409


def test_expired_lease_fences_authority_even_before_claim_reaping(actors):
    daemon, _owner, worker, _parent, claim = actors
    token = _authority(worker, claim)
    daemon.service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (claim["attempt_id"],))
    with pytest.raises(RuntimeError) as stale:
        _admit(worker, token)
    assert stale.value.status == 409


def test_heartbeat_requires_authority_refresh_and_other_worker_cannot_use_it(actors):
    daemon, _owner, worker, _parent, claim = actors
    token = _authority(worker, claim)
    foreign_token, _ = daemon.credentials.provision("other-worker", list(WORKER_SCOPES))
    with pytest.raises(RuntimeError) as foreign:
        _admit(Api(daemon.endpoint, foreign_token), token)
    assert foreign.value.status == 401
    worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/heartbeat", {
        "lease_id": claim["lease_id"], "fence": claim["fence"],
        "runtime_epoch": claim["runtime_epoch"], "lease_seconds": 120,
    }, headers={"Idempotency-Key": "delegation-heartbeat"})
    with pytest.raises(RuntimeError) as old:
        _admit(worker, token)
    assert old.value.status == 401
    assert _admit(worker, _authority(worker, claim))["task_id"]


def test_new_runtime_session_rejects_prior_authority(actors):
    daemon, _owner, worker, _parent, claim = actors
    token = _authority(worker, claim)
    root, support = daemon.root, daemon.support_root
    daemon.stop()
    successor = RuntimeDaemon(root, support_root=support, production_worker_credentials=True).start()
    try:
        with pytest.raises(RuntimeError) as old:
            _admit(Api(successor.endpoint, successor.worker_token), token)
        assert old.value.status == 401
    finally:
        successor.stop()


def test_worker_cannot_issue_authority_without_declared_policy(actors):
    _daemon, owner, worker, _parent, claim = actors
    ordinary = owner.create_task(PARENT, {}, idempotency_key="ordinary-parent")
    worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/settle", {
        "lease_id": claim["lease_id"], "fence": claim["fence"], "runtime_epoch": claim["runtime_epoch"], "outputs": [],
    }, headers={"Idempotency-Key": "finish-delegating-parent"})
    next_claim = worker.request("POST", "/v1/tasks/claim", {
        "executor_id": "astrid-pack-host", "capability_ids": [PARENT], "runtime_epoch": owner.health()["runtime_epoch"],
    }, headers={"Idempotency-Key": "ordinary-parent-claim"})
    assert next_claim["task_id"] == ordinary["task_id"]
    with pytest.raises(RuntimeError) as rejected:
        _authority(worker, next_claim)
    assert rejected.value.status == 401


@pytest.fixture
def staged(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        owner, worker = Api(daemon.endpoint, daemon.token), Api(daemon.endpoint, daemon.worker_token)
        for capability in (PARENT, CHILD):
            owner.request("POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": _digest(capability)})
        owner.register_executor("astrid-pack-host", [PARENT, CHILD], max_concurrency=4)
        project = owner.create_project("staged-delegation", "Staged Delegation")
        root_input = owner.ingest(project["project_id"], b"root", idempotency_key="staged-root")["data"]["digest"]
        effect = {
            "effect_type": "generation.publish_v1", "target_id": project["project_id"],
            "payload": {"version": 1, "modality": "video", "generation_type": "h3_verified",
                        "metadata": {"prompt": "bounded"}, "partial_success_policy": "reject",
                        "groups": [{"group_key": "main", "selectors": [{"selector": "verified", "ordinal": 0,
                                    "variant_key": "original", "output_port": "verified"}]}]},
        }
        stages = [
            {"name": "render", "capability_id": CHILD, "capability_digest": _digest(CHILD), "target": {"kind": "default"},
             "inputs": [{"name": "source", "root_object_id": root_input}]},
            {"name": "verify", "capability_id": CHILD, "capability_digest": _digest(CHILD), "target": {"kind": "default"},
             "inputs": [{"name": "source", "root_object_id": root_input},
                        {"name": "rendered", "producer_stage": "render", "output_port": "rendered"}]},
            {"name": "publish", "capability_id": CHILD, "capability_digest": _digest(CHILD), "target": {"kind": "default"},
             "inputs": [{"name": "verified", "producer_stage": "verify", "output_port": "verified"}]},
        ]
        parent = owner.request("POST", "/v1/tasks", {
            "capability_id": PARENT, "capability_digest": _digest(PARENT), "project": project["project_id"],
            "input_object_ids": [], "spec": {},
            "child_delegation": {"capabilities": [{"capability_id": CHILD, "capability_digest": _digest(CHILD)}],
                                 "targets": [{"kind": "default"}, TARGET], "input_object_ids": [root_input],
                                 "stages": stages,
                                 "final_publication": {"stage": "publish", "verify_stage": "verify", "verify_output_port": "verified", "effect": effect}},
        }, headers={"Idempotency-Key": "staged-parent"})["data"]
        claim = worker.request("POST", "/v1/tasks/claim", {
            "executor_id": "astrid-pack-host", "capability_ids": [PARENT], "runtime_epoch": owner.health()["runtime_epoch"],
        }, headers={"Idempotency-Key": "staged-parent-claim"})
        yield daemon, owner, worker, parent, claim, _authority(worker, claim), effect, root_input
    finally:
        daemon.stop()


def _stage(worker, authority, name, refs, *, key=None, **extra):
    task = {"stage": name, "capability_id": CHILD, "capability_digest": _digest(CHILD),
            "input_refs": refs, "spec": {"stage": name}}
    task.update(extra)
    return worker.request("POST", "/v1/delegated-tasks", {"authority": authority, "task": task},
                          headers={"Idempotency-Key": key or f"stage-{name}"})["data"]


def _claim_child(worker, epoch, key):
    return worker.request("POST", "/v1/tasks/claim", {
        "executor_id": "astrid-pack-host", "capability_ids": [CHILD], "runtime_epoch": epoch,
    }, headers={"Idempotency-Key": key})


def _settle_output(worker, claim, payload, port, key, *, effect=None, durability="durable"):
    output = {"name": port, "kind": "object", "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
              "media_type": "application/octet-stream", "size": len(payload),
              "data_base64": base64.b64encode(payload).decode(), "output_port": port,
              "group_key": "main", "variant_key": "original", "ordinal": 0,
              "durability": durability}
    body = {"lease_id": claim["lease_id"], "fence": claim["fence"], "runtime_epoch": claim["runtime_epoch"],
            "outputs": [output]}
    if effect is not None:
        body["effect"] = effect
    return worker.request("POST", f"/v1/attempts/{claim['attempt_id']}/settle", body,
                          headers={"Idempotency-Key": key})


def _output_ref(owner, child, name, port):
    association = owner.request("GET", f"/v1/tasks/{child['task_id']}/managed-outputs")["items"][0]
    return {"name": name, "producer_task_id": child["task_id"],
            "association_id": association["association_id"], "output_port": port}, association


def _verify_refs(root_input, rendered_ref):
    return [{"name": "source", "root_object_id": root_input}, rendered_ref]


def test_three_stages_resolve_ordered_managed_outputs_and_publish_verified_bytes(staged):
    _daemon, owner, worker, parent, parent_claim, authority, effect, root_input = staged
    render = _stage(worker, authority, "render", [{"name": "source", "root_object_id": root_input}])
    assert _stage(worker, authority, "render", [{"name": "source", "root_object_id": root_input}]) == render
    assert render["input_object_ids"] == [root_input]
    render_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-render")
    _settle_output(worker, render_claim, b"rendered", "rendered", "settle-render")
    render_ref, render_assoc = _output_ref(owner, render, "rendered", "rendered")
    verify = _stage(worker, authority, "verify", _verify_refs(root_input, render_ref))
    assert verify["input_object_ids"] == [root_input, render_assoc["object_id"]]
    assert verify["spec"]["delegated_inputs"][1]["association_id"] == render_assoc["association_id"]
    verify_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-verify")
    _settle_output(worker, verify_claim, b"verified", "verified", "settle-verify")
    verify_ref, verify_assoc = _output_ref(owner, verify, "verified", "verified")
    publish = _stage(worker, authority, "publish", [verify_ref])
    assert publish["input_object_ids"] == [verify_assoc["object_id"]]
    assert publish["spec"]["verified_publication_source"]["association_id"] == verify_assoc["association_id"]
    publish_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-publish")
    result = _settle_output(worker, publish_claim, b"verified", "verified", "settle-publish", effect=effect)
    assert result["data"]["state"] == "succeeded"
    assert owner.task(publish["task_id"])["state"] == "succeeded"
    assert parent["project_id"] == publish["project_id"]


def test_staged_targeted_request_receives_runtime_resolved_input_mirror(staged):
    _daemon, owner, worker, parent, claim, _authority_token, _effect, root_input = staged
    owner.request("POST", "/v1/tasks", {
        "capability_id": PARENT, "capability_digest": _digest(PARENT), "project": parent["project_id"],
        "input_object_ids": [], "spec": {},
        "child_delegation": {
            "capabilities": [{"capability_id": CHILD, "capability_digest": _digest(CHILD)}],
            "targets": [TARGET], "input_object_ids": [root_input],
            "stages": [{"name": "gpu", "capability_id": CHILD, "capability_digest": _digest(CHILD),
                        "target": TARGET, "inputs": [{"name": "source", "root_object_id": root_input}]}],
        },
    }, headers={"Idempotency-Key": "targeted-staged-parent"})
    second_claim = worker.request("POST", "/v1/tasks/claim", {
        "executor_id": "astrid-pack-host", "capability_ids": [PARENT], "runtime_epoch": claim["runtime_epoch"],
    }, headers={"Idempotency-Key": "targeted-staged-parent-claim"})
    child = _stage(worker, _authority(worker, second_claim), "gpu", [{"name": "source", "root_object_id": root_input}],
                   execution_request={"schema_version": 1, "target": TARGET})
    assert child["input_object_ids"] == [root_input]
    assert child["execution_request"]["inputs"] == [{"name": "source", "object_id": root_input}]
    assert child["execution_binding"]["resolved_target"] == TARGET


def test_staged_rejects_bare_unsettled_foreign_stale_and_wrong_target(staged):
    daemon, owner, worker, parent, parent_claim, authority, _effect, root_input = staged
    render = _stage(worker, authority, "render", [{"name": "source", "root_object_id": root_input}])
    with pytest.raises(RuntimeError) as bare:
        _stage(worker, authority, "verify", [], key="bare", input_object_ids=[root_input])
    assert bare.value.status == 422
    with pytest.raises(RuntimeError) as unsettled:
        _stage(worker, authority, "verify", _verify_refs(root_input, {"name": "rendered", "producer_task_id": render["task_id"],
                                               "association_id": "missing", "output_port": "rendered"}), key="unsettled")
    assert unsettled.value.status == 409
    render_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-render-negative")
    _settle_output(worker, render_claim, b"rendered", "rendered", "settle-render-negative")
    render_ref, _association = _output_ref(owner, render, "rendered", "rendered")
    foreign_task = owner.create_task(CHILD, {}, project=parent["project_id"], idempotency_key="foreign-producer")
    foreign_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-foreign-producer")
    _settle_output(worker, foreign_claim, b"foreign", "rendered", "settle-foreign-producer")
    foreign_ref, _ = _output_ref(owner, foreign_task, "rendered", "rendered")
    with pytest.raises(RuntimeError) as foreign_association:
        _stage(worker, authority, "verify", _verify_refs(root_input, {**render_ref, "association_id": foreign_ref["association_id"]}), key="foreign-association")
    assert foreign_association.value.status == 401
    with pytest.raises(RuntimeError) as foreign:
        _stage(worker, authority, "verify", _verify_refs(root_input, {**render_ref, "producer_task_id": "foreign-task"}), key="foreign")
    assert foreign.value.status == 409
    with pytest.raises(RuntimeError) as wrong_port:
        _stage(worker, authority, "verify", _verify_refs(root_input, {**render_ref, "output_port": "other"}), key="wrong-port")
    assert wrong_port.value.status == 401
    with pytest.raises(RuntimeError) as wrong_order:
        _stage(worker, authority, "verify", list(reversed(_verify_refs(root_input, render_ref))), key="wrong-order")
    assert wrong_order.value.status == 422
    with pytest.raises(RuntimeError) as wrong_target:
        _stage(worker, authority, "verify", _verify_refs(root_input, render_ref), key="wrong-target",
               execution_request={"schema_version": 1, "target": TARGET})
    assert wrong_target.value.status == 401
    daemon.service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (parent_claim["attempt_id"],))
    with pytest.raises(RuntimeError) as stale:
        _stage(worker, authority, "verify", _verify_refs(root_input, render_ref), key="stale")
    assert stale.value.status == 409


def test_temporary_producer_output_and_broad_mutation_are_rejected(staged):
    _daemon, owner, worker, parent, parent_claim, authority, _effect, root_input = staged
    with pytest.raises(RuntimeError) as broad:
        worker.create_task(CHILD, {}, project=parent["project_id"], idempotency_key="worker-broad-task")
    assert broad.value.status == 401
    with pytest.raises(RuntimeError) as project_write:
        worker.create_project("worker-project", "Forbidden")
    assert project_write.value.status == 401
    render = _stage(worker, authority, "render", [{"name": "source", "root_object_id": root_input}])
    render_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-temporary-render")
    _settle_output(worker, render_claim, b"temporary", "rendered", "settle-temporary-render", durability="temporary")
    ref, _ = _output_ref(owner, render, "rendered", "rendered")
    with pytest.raises(RuntimeError) as temporary:
        _stage(worker, authority, "verify", _verify_refs(root_input, ref))
    assert temporary.value.status == 401


def test_intermediate_effect_and_unverified_final_output_are_rejected(staged):
    _daemon, owner, worker, _parent, parent_claim, authority, effect, root_input = staged
    render = _stage(worker, authority, "render", [{"name": "source", "root_object_id": root_input}])
    render_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-render-effect")
    with pytest.raises(RuntimeError) as intermediate:
        _settle_output(worker, render_claim, b"rendered", "rendered", "illegal-intermediate-effect", effect=effect)
    assert intermediate.value.status == 422
    _settle_output(worker, render_claim, b"rendered", "rendered", "settle-render-effect")
    render_ref, _ = _output_ref(owner, render, "rendered", "rendered")
    verify = _stage(worker, authority, "verify", _verify_refs(root_input, render_ref))
    verify_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-verify-effect")
    _settle_output(worker, verify_claim, b"verified", "verified", "settle-verify-effect")
    verify_ref, _ = _output_ref(owner, verify, "verified", "verified")
    with pytest.raises(RuntimeError) as supplied_effect:
        _stage(worker, authority, "publish", [verify_ref], key="worker-supplied-effect", settlement_effect=effect)
    assert supplied_effect.value.status == 422
    publish = _stage(worker, authority, "publish", [verify_ref])
    assert publish["spec"]["verified_publication_source"]
    publish_claim = _claim_child(worker, parent_claim["runtime_epoch"], "claim-publish-effect")
    with pytest.raises(RuntimeError) as forged:
        _settle_output(worker, publish_claim, b"forged", "verified", "forged-final", effect=effect)
    assert forged.value.status == 401
    with pytest.raises(RuntimeError) as missing:
        _settle_output(worker, publish_claim, b"verified", "verified", "missing-final-effect")
    assert missing.value.status == 422
