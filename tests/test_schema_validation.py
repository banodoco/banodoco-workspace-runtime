from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import pytest
import yaml

ROOT = Path(__file__).parents[1]


def _execution_wire_validators() -> tuple[Draft202012Validator, Draft202012Validator]:
    task = json.loads((ROOT / "contract/schemas/task.json").read_text())
    worker = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in (task, worker)
    )
    claim = Draft202012Validator(
        {"$id": worker["$id"], "definitions": worker["definitions"],
         **worker["definitions"]["AttemptFence"]},
        registry=registry,
    )
    document = yaml.safe_load((ROOT / "contract/openapi/workspace-v1.yaml").read_text())
    admission = Draft202012Validator(
        {"$id": "https://banodoco.dev/workspace/v1/workspace-v1.yaml",
         **document["components"]["schemas"]["AdmitTask"]},
        registry=registry,
    )
    return admission, claim


@pytest.mark.parametrize("target", [
    {"kind": "machine", "id": "machine-a"},
    {"kind": "runpod", "pod_id": "pod-a", "provider_account_ref": "account-a"},
])
def test_execution_wire_schemas_accept_runtime_admission_and_claim(tmp_path, target) -> None:
    from test_execution_binding_contract import CAPABILITY, CAPABILITY_DIGEST, _admit, _claim, _request, _service

    admission, claim = _execution_wire_validators()
    body = {"capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [], "execution_request": _request(target), "spec": {}}
    assert not list(admission.iter_errors(body))
    service = _service(tmp_path / "realm")
    try:
        admitted = _admit(service, "schema-admission", target)
        result = _claim(service, "schema-claim", target)
        assert result["execution_request"] == body["execution_request"]
        assert result["execution_binding"]["binding_id"] == admitted["execution_binding"]["binding_id"]
        assert result["execution_binding"]["status"] == "claimed"
        assert result["execution_binding"]["effective_target"] == target
        assert result["execution_binding"]["original_target"] == target
        assert result["execution_binding"]["placement_version"] == 0
        assert result["execution_binding"]["recovery_decision_digest"] is None
        assert "placement_recovery" not in result["execution_binding"]
        errors = list(claim.iter_errors(result))
        assert not errors, "\n".join(error.message for error in errors)
    finally:
        service.close()


def test_execution_wire_schemas_accept_real_recovered_binding_and_claim(tmp_path) -> None:
    from test_placement_recovery import NEW, OLD, OWNER, _claim, _identity, _recovery_body, _service, _terminal_parent

    _, claim = _execution_wire_validators()
    task = json.loads((ROOT / "contract/schemas/task.json").read_text())
    binding_validator = Draft202012Validator(
        {"$ref": task["$id"] + "#/definitions/ExecutionBinding"},
        registry=Registry().with_resource(task["$id"], Resource.from_contents(task)),
    )
    service = _service(tmp_path / "realm")
    try:
        admitted, old_claim, _ = _terminal_parent(service)
        assert not list(claim.iter_errors(old_claim))
        task_id = admitted["task"]["id"]
        recovered = service.recover_task_placement(
            task_id, _recovery_body(service, task_id), idempotency_key="schema-recovery", identity=OWNER,
        )
        decision = recovered["data"]["placement_recovery"]
        public = service.task(task_id)
        binding = public["execution_binding"]
        assert binding["status"] == "prepared"
        assert binding["original_target"] == OLD
        assert binding["effective_target"] == NEW
        assert binding["placement_version"] == 1
        assert binding["recovery_decision_digest"] == decision["decision_digest"]
        assert binding["placement_recovery"] == decision
        errors = list(binding_validator.iter_errors(binding))
        assert not errors, "\n".join(error.message for error in errors)
        service.retry_task(
            task_id, {"expected_version": service._task_resource(public)["version"]}, idempotency_key="schema-retry",
        )
        successor = _claim(service, "schema-recovered-claim", NEW, _identity(NEW))
        assert successor["execution_request"]["target"] == OLD
        assert successor["execution_binding"]["original_target"] == OLD
        assert successor["execution_binding"]["effective_target"] == NEW
        assert successor["execution_binding"]["placement_recovery"] == decision
        errors = list(claim.iter_errors(successor))
        assert not errors, "\n".join(error.message for error in errors)
    finally:
        service.close()


def test_execution_wire_schemas_preserve_closed_envelopes_and_untargeted_shapes() -> None:
    admission, claim = _execution_wire_validators()
    worker = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    properties = worker["definitions"]["AttemptFence"]["properties"]
    assert properties["execution_request"] == {"$ref": "task.json#/definitions/ExecutionRequest"}
    assert properties["execution_binding"] == {"$ref": "task.json#/definitions/ExecutionBinding"}
    assert admission.schema["properties"]["execution_request"]["$ref"] == "./schemas/task.json#/definitions/ExecutionRequest"
    assert "execution_binding" not in admission.schema["properties"]
    assert admission.schema["required"] == ["capability_id", "capability_digest", "input_object_ids"]
    assert claim.schema["required"] == ["attempt_id", "task_id", "run_id", "project_id", "lease_id",
                                         "fence", "lease_expires_at", "runtime_epoch", "input_object_ids"]
    body = {"capability_id": "test.targeted", "capability_digest": "sha256:" + "a" * 64, "input_object_ids": []}
    fence = {"attempt_id": "attempt", "task_id": "task", "run_id": "run", "project_id": None,
             "lease_id": "lease", "fence": 1, "lease_expires_at": "2026-10-06T12:00:00Z",
             "runtime_epoch": 1, "input_object_ids": [], "spec": {}}
    assert not list(admission.iter_errors(body))
    assert not list(claim.iter_errors(fence))
    assert list(admission.iter_errors({**body, "execution_binding": {"binding_id": "forged"}}))
    assert list(admission.iter_errors({**body, "unexpected": True}))
    assert list(claim.iter_errors({**fence, "unexpected": True}))
    task = json.loads((ROOT / "contract/schemas/task.json").read_text())
    binding = task["definitions"]["ExecutionBinding"]
    assert binding["additionalProperties"] is False
    assert binding["required"] == ["binding_id", "task_id", "run_id", "session_id", "runtime_epoch",
                                   "capability_id", "target_kind", "resolved_target", "status"]
    for key in ("effective_target", "original_target", "placement_version", "recovery_decision_digest", "placement_recovery"):
        assert key not in binding["required"]
    for key in claim.schema["required"]:
        assert list(claim.iter_errors({name: value for name, value in fence.items() if name != key}))


def test_execution_wire_schemas_reject_malformed_requests_and_bindings() -> None:
    admission, claim = _execution_wire_validators()
    body = {"capability_id": "test.targeted", "capability_digest": "sha256:" + "a" * 64, "input_object_ids": []}
    fence = {"attempt_id": "attempt", "task_id": "task", "run_id": "run", "project_id": None,
             "lease_id": "lease", "fence": 1, "lease_expires_at": "2026-10-06T12:00:00Z",
             "runtime_epoch": 1, "input_object_ids": []}
    request = {"schema_version": 1, "target": {"kind": "machine", "id": "machine-a"}, "inputs": []}
    binding = {"binding_id": "binding", "task_id": "task", "run_id": "run", "session_id": "session",
               "runtime_epoch": 1, "capability_id": "test.targeted", "target_kind": "machine",
               "resolved_target": request["target"], "status": "claimed", "attempt_id": "attempt",
               "lease_id": "lease", "fence": 1, "executor_id": "executor-a", "actual_target": request["target"],
               "executor_incarnation": "executor-a/1", "verification": {"method": "credential_claim",
                   "evidence_digest": "sha256:" + "b" * 64, "verified": True}}
    assert not list(claim.iter_errors({**fence, "execution_request": request, "execution_binding": binding}))
    # Each optional claim field remains independently optional.
    assert not list(claim.iter_errors({**fence, "execution_request": request}))
    assert not list(claim.iter_errors({**fence, "execution_binding": binding}))
    initial = {**binding, "effective_target": request["target"], "original_target": request["target"],
               "placement_version": 0, "recovery_decision_digest": None}
    recovered = {**initial, "placement_version": 1, "recovery_decision_digest": "sha256:" + "c" * 64,
                 "placement_recovery": {"schema_version": 1, "runtime_owned_extension": {"retained": True}}}
    assert not list(claim.iter_errors({**fence, "execution_binding": initial}))
    assert not list(claim.iter_errors({**fence, "execution_binding": recovered}))
    for field in ("effective_target", "original_target"):
        for malformed in (None, [], {}, {"kind": "unknown"}):
            assert list(claim.iter_errors({**fence, "execution_binding": {**initial, field: malformed}}))
    for malformed in (-1, True, 1.5, "1", None):
        assert list(claim.iter_errors({**fence, "execution_binding": {**initial, "placement_version": malformed}}))
    for malformed in ("sha256:abc", "sha256:" + "C" * 64, "c" * 64, 1, False, {}, []):
        assert list(claim.iter_errors({**fence, "execution_binding": {**initial, "recovery_decision_digest": malformed}}))
    for malformed in (None, [], "decision", True):
        assert list(claim.iter_errors({**fence, "execution_binding": {**recovered, "placement_recovery": malformed}}))
    for malformed in (None, [], {}, {"target": {}}, {"target": {"kind": "unknown"}},
                      {**request, "schema_version": True}, {**request, "inputs": {}}, {**request, "workflow": []}):
        assert list(admission.iter_errors({**body, "execution_request": malformed}))
        assert list(claim.iter_errors({**fence, "execution_request": malformed}))
    for malformed in (None, [], {}, {**binding, "binding_id": ""}, {**binding, "runtime_epoch": 0},
                      {**binding, "status": "unknown"}, {**binding, "unexpected": True},
                      {**binding, "verification": {**binding["verification"], "verified": False}},
                      {**binding, "resolved_target": {"kind": "unknown"}},
                      {**binding, "executor_incarnation": ""}):
        assert list(claim.iter_errors({**fence, "execution_request": request, "execution_binding": malformed}))
    for key in ("binding_id", "task_id", "run_id", "session_id", "runtime_epoch", "capability_id",
                "target_kind", "resolved_target", "status", "actual_target", "verification", "executor_incarnation"):
        malformed = {name: value for name, value in binding.items() if name != key}
        assert list(claim.iter_errors({**fence, "execution_binding": malformed}))


def validate(schema_name: str, fixture_name: str, *, definition: str | None = None) -> None:
    schema = json.loads((ROOT / "contract/schemas" / schema_name).read_text())
    if definition:
        schema = {"$schema": schema["$schema"], "definitions": schema["definitions"], **schema["definitions"][definition]}
    instance = json.loads((ROOT / "conformance/fixtures" / fixture_name).read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def test_core_fixtures_validate_against_closed_schemas() -> None:
    validate("handshake-response.json", "handshake.json")
    validate("project.json", "project.json")
    validate("managed-object.json", "managed-object.json")
    validate("task.json", "task.json")
    validate("event.json", "event.json")
    validate("worker.json", "settlement.json", definition="Settlement")


def test_health_schema_has_exact_closed_runtime_identity_contract() -> None:
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
    fields = ["status", "protocol", "schema_digest", "runtime_epoch", "runtime_session_id", "runtime_instance_id"]
    assert schema["additionalProperties"] is False
    assert list(schema["required"]) == fields
    assert list(schema["properties"]) == fields

    value = {
        "status": "ok",
        "protocol": "workspace.v1",
        "schema_digest": "sha256:" + "a" * 64,
        "runtime_epoch": 1,
        "runtime_session_id": "runtime-session-1",
        "runtime_instance_id": "runtime-instance-1",
    }
    assert not list(Draft202012Validator(schema).iter_errors(value))
    assert list(Draft202012Validator(schema).iter_errors({**value, "extra": True}))
    assert list(Draft202012Validator(schema).iter_errors({key: item for key, item in value.items() if key != "runtime_instance_id"}))


def test_closed_schemas_reject_unknown_fields() -> None:
    schema = json.loads((ROOT / "contract/schemas/project.json").read_text())
    instance = json.loads((ROOT / "conformance/fixtures/project.json").read_text())
    instance["product_private_field"] = True
    assert list(Draft202012Validator(schema).iter_errors(instance))


def test_settlement_schema_allows_bounded_inline_output_bytes() -> None:
    instance = json.loads((ROOT / "conformance/fixtures/settlement.json").read_text())
    payload = b"abcd"
    output = instance["outputs"][0]
    output["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    output["data_base64"] = base64.b64encode(payload).decode("ascii")
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    settlement = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Settlement"],
    }
    errors = list(Draft202012Validator(settlement).iter_errors(instance))
    assert not errors, "\n".join(error.message for error in errors)


def test_worker_schema_declares_continuation_waits_and_output_primary_contract() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    claim_waiting = schema["definitions"]["ClaimWaiting"]["properties"]["waiting_reason"]
    assert {"waiting_for_dependencies", "dependency_failed", "dependency_cancelled"} <= set(claim_waiting["enum"])
    output = schema["definitions"]["Output"]["properties"]
    assert output["is_primary"] == {"type": "boolean"}
    assert output["role"]["maxLength"] == 255


def test_child_authority_request_accepts_exact_d18_descriptors_and_rejects_drift() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    request_schema = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["ChildAuthorityRequest"],
    }
    base = {"lease_id": "lease-1", "fence": 2, "runtime_epoch": 7}
    assert not list(Draft202012Validator(request_schema).iter_errors(base))

    exact = {
        **base,
        "child": {
            "child_id": "child-1",
            "capability_id": "render.child",
            "capability_digest": "sha256:" + "a" * 64,
        },
        "derived_inputs": [{
            "name": "source-frame",
            "output_port": "frame",
            "filename": "source-frame.bin",
            "object_id": "sha256:" + "b" * 64,
            "size": 4096,
            "media_type": "application/octet-stream",
        }],
    }
    assert not list(Draft202012Validator(request_schema).iter_errors(exact))

    extra_child = json.loads(json.dumps(exact))
    extra_child["child"]["unexpected"] = True
    assert list(Draft202012Validator(request_schema).iter_errors(extra_child))

    malformed_input = json.loads(json.dumps(exact))
    malformed_input["derived_inputs"][0]["filename"] = "nested/source-frame.bin"
    assert list(Draft202012Validator(request_schema).iter_errors(malformed_input))

    extra_input = json.loads(json.dumps(exact))
    extra_input["derived_inputs"][0]["digest"] = extra_input["derived_inputs"][0]["object_id"]
    assert list(Draft202012Validator(request_schema).iter_errors(extra_input))


def test_worker_schema_declares_thumbnail_auxiliary_and_attach_effect() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    output_schema = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Output"],
    }
    source = "sha256:" + "a" * 64
    thumbnail = {
        "name": "thumbnail.jpg",
        "kind": "object",
        "digest": "sha256:" + "b" * 64,
        "media_type": "image/jpeg",
        "size": 4,
        "output_port": "thumbnail",
        "role": "thumbnail",
        "durability": "durable",
        "provenance": {
            "thumbnail": {"source_object_ids": [source], "recipe_version": 1}
        },
    }
    assert not list(Draft202012Validator(output_schema).iter_errors(thumbnail))
    wrong_mime = {**thumbnail, "media_type": "image/png"}
    assert list(Draft202012Validator(output_schema).iter_errors(wrong_mime))
    forged_primary = {**thumbnail, "is_primary": False}
    assert list(Draft202012Validator(output_schema).iter_errors(forged_primary))

    effect_schema = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Effect"],
    }
    effect = {
        "effect_type": "generation.thumbnail.attach",
        "target_id": "generation-1",
        "expected_version": 1,
        "payload": {
            "source_object_id": source,
            "output_name": "thumbnail.jpg",
            "output_ordinal": 0,
            "recipe_version": 1,
        },
    }
    assert not list(Draft202012Validator(effect_schema).iter_errors(effect))


def test_generation_schema_reserves_direct_thumbnail_descriptor() -> None:
    schema = json.loads((ROOT / "contract/schemas/generation.json").read_text())
    generation = {
        "generation_id": "generation-1",
        "project_id": "project-1",
        "source_task_id": "task-1",
        "type": "video",
        "status": "completed",
        "metadata": {
            "shot_id": "shot-1",
            "thumbnail": {
                "object_id": "sha256:" + "b" * 64,
                "source_object_id": "sha256:" + "a" * 64,
                "recipe_version": 1,
            },
        },
        "version": 1,
        "created_at": "2026-09-22T00:00:00Z",
        "updated_at": "2026-09-22T00:00:00Z",
    }
    assert not list(Draft202012Validator(schema).iter_errors(generation))
    generation["metadata"]["thumbnail"]["selection"] = {
        "kind": "source_frame", "source_time_seconds": 12.345678,
    }
    assert not list(Draft202012Validator(schema).iter_errors(generation))
    generation["metadata"]["thumbnail"]["selection"]["source_time_seconds"] = 12.3456789
    assert list(Draft202012Validator(schema).iter_errors(generation))
    generation["metadata"]["thumbnail"]["selection"] = {"kind": "source_frame"}
    assert list(Draft202012Validator(schema).iter_errors(generation))
    generation["metadata"]["thumbnail"].pop("selection")
    generation["metadata"]["thumbnail"]["recipe_version"] = 2
    assert list(Draft202012Validator(schema).iter_errors(generation))


def test_recoverable_snapshot_and_parent_policy_closed_schemas() -> None:
    from runtime_protocol.service import CHILD_LIMITS, CHILD_LIMIT_CEILINGS
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    def validator(definition):
        return Draft202012Validator({"definitions": schema["definitions"], **schema["definitions"][definition]})
    cap = {"capability_id": "editorial.human_review", "capability_digest": "sha256:" + "a" * 64}
    grant = {**cap, "output_ports": ["state_result"]}
    policy = {"capabilities": [cap], "targets": [{"kind": "default"}], "input_object_ids": [],
              "recoverable_outputs": [grant], "limits": CHILD_LIMITS}
    assert not list(validator("ChildDelegationPolicy").iter_errors(policy))
    for bad in ([grant, grant], [{**grant, "output_ports": ["*"]}], [{**grant, "capability_digest": "unpinned"}],
                [{**grant, "capability_id": "other"}], [{**grant, "derived_grant": {}}]):
        assert list(validator("ChildDelegationPolicy").iter_errors({**policy, "recoverable_outputs": bad}))
    props = schema["definitions"]["ChildDelegationPolicy"]["properties"]["limits"]["properties"]
    for key, default in CHILD_LIMITS.items():
        assert props[key]["default"] == default
        assert props[key]["maximum"] == CHILD_LIMIT_CEILINGS[key]
        assert not list(validator("ChildDelegationPolicy").iter_errors({**policy, "limits": {key: CHILD_LIMIT_CEILINGS[key]}}))
        assert list(validator("ChildDelegationPolicy").iter_errors({**policy, "limits": {key: CHILD_LIMIT_CEILINGS[key] + 1}}))
    body = {"lease_id": "lease-1", "fence": 1, "runtime_epoch": 1, "revision": 1,
            "output": {"name": "draft", "output_port": "state_result", "filename": "draft.json",
                       "object_id": "sha256:" + "b" * 64, "size": 4, "media_type": "application/json"}}
    assert not list(validator("RecoverableSnapshotRequest").iter_errors(body))
    for change in ({"revision": 0}, {"revision": True}, {"revision": 9007199254740992}, {"extra": True},
                   {"output": {**body["output"], "upload_receipt": "caller-forged"}}):
        assert list(validator("RecoverableSnapshotRequest").iter_errors({**body, **change}))


def test_discovery_grant_closed_schema_and_source_budget_parity() -> None:
    from runtime_protocol.service import DISCOVERY_GRANT_CEILINGS, RuntimeService
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    validator = Draft202012Validator({"definitions": schema["definitions"],
                                      **schema["definitions"]["ChildDelegationPolicy"]})
    grant = {"project_id": "project", "run_id": "run", "task_id": "task", "attempt_id": "attempt",
             "capability_id": "iteration.assemble", "capability_digest": "sha256:" + "a" * 64,
             "limits": dict(DISCOVERY_GRANT_CEILINGS)}
    policy = {"capabilities": [{"capability_id": "rendering.render", "capability_digest": "sha256:" + "b" * 64}],
              "targets": [{"kind": "default"}], "input_object_ids": [], "discovery_grant": grant}
    assert not list(validator.iter_errors(policy))
    assert RuntimeService._child_policy(policy)["discovery_grant"] == grant
    properties = schema["definitions"]["DiscoveryGrant"]["properties"]["limits"]["properties"]
    for key, ceiling in DISCOVERY_GRANT_CEILINGS.items():
        assert properties[key]["maximum"] == ceiling
        assert "default" not in properties[key]
        for valid in (1, ceiling):
            candidate = {**policy, "discovery_grant": {**grant, "limits": {**grant["limits"], key: valid}}}
            assert not list(validator.iter_errors(candidate))
            assert RuntimeService._child_policy(candidate)["discovery_grant"]["limits"][key] == valid
        for invalid in (None, True, 0, -1, 1.5, "1", ceiling + 1):
            candidate = {**policy, "discovery_grant": {**grant, "limits": {**grant["limits"], key: invalid}}}
            assert list(validator.iter_errors(candidate))
        missing = {name: value for name, value in grant["limits"].items() if name != key}
        assert list(validator.iter_errors({**policy, "discovery_grant": {**grant, "limits": missing}}))
    for key in grant:
        missing = {name: value for name, value in grant.items() if name != key}
        assert list(validator.iter_errors({**policy, "discovery_grant": missing}))
    for bad in (None, [], {}, {**grant, "authority": "caller-forged"},
                {**grant, "parent_attempt_id": "forged"}, {**grant, "run_id": "*"},
                {**grant, "run_id": ""}, {**grant, "task_id": ["task"]},
                {**grant, "capability_digest": "a" * 64}, {**grant, "capability_digest": "unpinned"},
                {**grant, "limits": {}}, {**grant, "limits": {**grant["limits"], "extra": 1}}):
        assert list(validator.iter_errors({**policy, "discovery_grant": bad}))
