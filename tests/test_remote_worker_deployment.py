from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from runtime_protocol.local_worker import LocalWorkerProfile
from runtime_protocol.remote_worker_deployment import (
    AdmissionIdentity,
    ArtifactReference,
    CapabilityIdentity,
    DeploymentReference,
    DeploymentReferenceError,
    deployment_binding_from_task,
    project_launch,
)
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _profile(tmp_path: Path) -> LocalWorkerProfile:
    data_root = tmp_path / "data"
    return LocalWorkerProfile(
        profile_id="astrid",
        workspace_uuid="workspace-1",
        realm_root=data_root / "realm",
        support_root=data_root / "runtime",
        machine_id="machine-1",
        worker_executable=tmp_path / "worker-python",
        host_executable=tmp_path / "host-python",
        engine_executable=tmp_path / "engine-python",
        engine_listener_executable=tmp_path / "listener-python",
        engine_endpoint="http://127.0.0.1:8188",
        worker_artifact_digest=_digest("1"),
        host_artifact_digest=_digest("2"),
        engine_artifact_digest=_digest("3"),
        engine_listener_artifact_digest=_digest("4"),
        session_config_digest=_digest("5"),
        profile_revision="profile-r1",
        profile_digest=_digest("6"),
        release_digest=_digest("7"),
    )


def _reference(tmp_path: Path) -> DeploymentReference:
    source = tmp_path / "source"
    (source / "astrid" / "packs").mkdir(parents=True)
    return DeploymentReference.from_local_worker_profile(
        _profile(tmp_path),
        deployment_id="deployment-1",
        revision="r1",
        task_id="task-1",
        run_id="run-1",
        target_ref="runpod:pod-1",
        runtime_endpoint="http://127.0.0.1:59683/",
        runtime_instance_id="runtime-1",
        runtime_epoch=4,
        runtime_schema_digest=_digest("8"),
        model_root=tmp_path / "models",
        session_ref="session-1",
        output_root=tmp_path / "outputs",
        credential_ref="file:/tmp/astrid-pack-host.token",
        boot_manifest_path=tmp_path / "data" / "runtime" / "boot-manifest.json",
        boot_manifest_hash=_digest("9"),
        readiness_profile_path=tmp_path / "data" / "runtime" / "readiness.json",
        readiness_profile_hash=_digest("a"),
        source_checkout=source,
        source_checkout_digest="b" * 64,
        pack_roots=(source / "astrid" / "packs",),
        source_inventory_identity="inventory-1",
        execution_target={
            "kind": "runpod",
            "pod_id": "pod-1",
            "provider_account_ref": "runpod",
        },
        admission_identity=AdmissionIdentity(
            task_id="task-1",
            run_id="run-1",
            project_id="project-1",
            idempotency_key="admission-1",
            admission_digest=_digest("b"),
            spec_digest=_digest("c"),
            request_digest=_digest("d"),
        ),
        capability_identity=CapabilityIdentity("h3_av.transform", _digest("e")),
        original_target={
            "kind": "runpod",
            "pod_id": "pod-1",
            "provider_account_ref": "runpod",
        },
        effective_target={
            "kind": "runpod",
            "pod_id": "pod-1",
            "provider_account_ref": "runpod",
        },
    )


def test_projection_is_deterministic_and_secret_free(tmp_path: Path) -> None:
    reference = _reference(tmp_path)
    first = project_launch(reference)
    second = project_launch(reference)

    assert first == second
    assert first.argv[:4] == (
        str(tmp_path / "host-python"),
        "-m",
        "astrid.core.execution.generic_host",
        "run",
    )
    env = dict(first.env_items)
    assert env["ASTRID_TASK_ID"] == "task-1"
    assert env["ASTRID_VIBECOMFY_MODELS_ROOT"] == str(tmp_path / "models")
    assert env["ASTRID_SESSION_CONFIG_DIGEST"] == _digest("5")
    assert env["ASTRID_CREDENTIAL_REF"] == "file:/tmp/astrid-pack-host.token"
    assert first.argv[first.argv.index("--credential-file") + 1] == "/tmp/astrid-pack-host.token"
    assert first.argv[first.argv.index("--source-checkout-digest") + 1] == "b" * 64
    assert first.argv.count("--pack-root") == 1
    assert env["ASTRID_EXECUTION_TARGET_JSON"] == (
        '{"kind":"runpod","pod_id":"pod-1","provider_account_ref":"runpod"}'
    )
    assert "rpa_live_secret" not in env.values()
    assert "sk-live-secret" not in env.values()
    assert tuple(sorted(first.env_items)) == first.env_items


def test_projection_rejects_conflicting_target(tmp_path: Path) -> None:
    with pytest.raises(DeploymentReferenceError, match="effective_target_ref"):
        DeploymentReference(
            **{
                **_reference(tmp_path).__dict__,
                "effective_target_ref": "runpod:other-pod",
            }
        )


def test_projection_rejects_incomplete_or_unsorted_closure(tmp_path: Path) -> None:
    reference = _reference(tmp_path)
    with pytest.raises(DeploymentReferenceError, match="dependency_closure"):
        DeploymentReference(
            **{
                **reference.__dict__,
                "dependency_closure": (),
            }
        )

    worker = next(item for item in reference.dependency_closure if item.name == "worker")
    with pytest.raises(DeploymentReferenceError, match="sorted"):
        DeploymentReference(
            **{
                **reference.__dict__,
                "dependency_closure": (worker, reference.executable),
            }
        )


def test_projection_rejects_literal_credential_and_missing_executable(tmp_path: Path) -> None:
    reference = _reference(tmp_path)
    with pytest.raises(DeploymentReferenceError, match="credential_ref"):
        DeploymentReference(**{**reference.__dict__, "credential_ref": "rpa_live_secret"})

    dependency = tuple(item for item in reference.dependency_closure if item.name != reference.executable.name)
    with pytest.raises(DeploymentReferenceError, match="executable must appear"):
        DeploymentReference(**{**reference.__dict__, "dependency_closure": dependency})


def test_artifact_reference_rejects_relative_path() -> None:
    with pytest.raises(DeploymentReferenceError, match="absolute"):
        ArtifactReference("host", Path("host-python"), _digest("1"))


def _task_projection(*, recovered: bool = False) -> dict:
    original = {"kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a"}
    effective = {"kind": "runpod", "pod_id": "pod-new", "provider_account_ref": "account-a"} if recovered else original
    request = {
        "schema_version": 1,
        "target": original,
        "inputs": [{"name": "source", "object_id": _digest("1")}],
    }
    task = {
        "id": "task-1",
        "run_id": "run-1",
        "project_id": "project-1",
        "idempotency_key": "admission-1",
        "capability": "h3_av.transform",
        "capability_digest": _digest("2"),
        "input_object_ids": [_digest("1")],
        "spec": {"schema_version": 1, "input_object_ids": [_digest("1")], "spec": {"prompt": "same"}},
        "execution_request": request,
        "execution_binding": {
            "original_target": original,
            "effective_target": effective,
            "resolved_target": effective,
            "placement_version": 1 if recovered else 0,
        },
    }
    if recovered:
        decision = {
            "schema_version": 1,
            "placement_version": 1,
            "task_id": "task-1",
            "run_id": "run-1",
            "task_version": 2,
            "original_target": original,
            "previous_effective_target": original,
            "replacement_target": effective,
            "reason": "provider pod absent",
        }
        decision["decision_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        task["execution_binding"]["placement_recovery"] = decision
    return task


def test_runtime_binding_preserves_initial_and_authorized_replacement_placement() -> None:
    from runtime_protocol.remote_worker_deployment import deployment_binding_from_task

    initial = deployment_binding_from_task(_task_projection())
    assert initial.placement.original_target["pod_id"] == "pod-old"
    assert initial.placement.effective_target == initial.placement.original_target
    assert initial.placement.placement_version == 0
    assert initial.input_bindings[0].name == "source"
    assert initial.input_bindings[0].digest == _digest("1")

    replacement = deployment_binding_from_task(_task_projection(recovered=True))
    assert replacement.placement.original_target["pod_id"] == "pod-old"
    assert replacement.placement.effective_target["pod_id"] == "pod-new"
    assert replacement.placement.placement_version == 1
    assert replacement.placement.recovery_decision_digest.startswith("sha256:")
    assert replacement.admission_identity.admission_digest == initial.admission_identity.admission_digest


def test_explicit_request_inputs_reject_duplicate_object_ids() -> None:
    task = _task_projection()
    duplicate = _digest("1")
    task["input_object_ids"] = [duplicate, duplicate]
    task["spec"]["input_object_ids"] = [duplicate, duplicate]
    task["execution_request"]["inputs"] = [
        {"name": "first", "object_id": duplicate},
        {"name": "second", "object_id": duplicate},
    ]
    with pytest.raises(DeploymentReferenceError, match="duplicate object IDs"):
        deployment_binding_from_task(task)


def _missing_capability_digest(task: dict) -> None:
    task.pop("capability_digest")


def _foreign_recovery(task: dict) -> None:
    task["run_id"] = "foreign-run"


def _stale_recovery(task: dict) -> None:
    task["execution_binding"]["placement_recovery"]["decision_digest"] = _digest("f")


def _target_drift(task: dict) -> None:
    task["execution_binding"]["effective_target"] = {"kind": "runpod", "pod_id": "drift", "provider_account_ref": "account-a"}


def _input_drift(task: dict) -> None:
    task["input_object_ids"] = [_digest("3")]


@pytest.mark.parametrize(
    "mutation, message",
    [
        (_missing_capability_digest, "capability_digest"),
        (_foreign_recovery, "foreign"),
        (_stale_recovery, "stale or foreign"),
        (_target_drift, "drifted"),
        (_input_drift, "conflicting identity values"),
    ],
)
def test_runtime_binding_rejects_missing_foreign_stale_and_drifted_contract(mutation, message) -> None:
    from runtime_protocol.remote_worker_deployment import DeploymentReferenceError, deployment_binding_from_task

    task = _task_projection(recovered=True)
    mutation(task)
    with pytest.raises(DeploymentReferenceError, match=message):
        deployment_binding_from_task(task)


@pytest.fixture
def admitted_omitted_input_task(tmp_path: Path):
    """Use the public admission path and its actual task readback envelope."""
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "binding-test", "name": "Binding test"})
        bundle = service.ingest(
            project["id"], b"bundle", original_name="bundle.zip", idempotency_key="bundle-input",
        )["data"]["digest"]
        request = service.ingest(
            project["id"], b"request", original_name="request.json", idempotency_key="request-input",
        )["data"]["digest"]
        ids = {"input_bundle": bundle, "request": request}
        admitted = service.create_task({
            "capability_id": "h3_av.transform",
            "capability_digest": _digest("2"),
            "project": project["id"],
            "input_object_ids": [bundle, request],
            "spec": {
                "inputs": {
                    "request": {"object_id": request, "digest": request, "filename": "request.json"},
                    "input_bundle": {"object_id": bundle, "digest": bundle, "filename": "bundle.zip"},
                },
                "input_digests": [
                    {"name": "input_bundle", "digest": bundle},
                    {"name": "request", "digest": request},
                ],
            },
            "execution_request": {"schema_version": 1, "target": {
                "kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a",
            }},
            "idempotency_key": "omitted-request-inputs",
        })
        task = service._task_resource(service.store.get_task(admitted["task"]["id"]))
        yield service, task, ids
    finally:
        service.close()


def test_omitted_request_inputs_resolve_from_public_admitted_spec(admitted_omitted_input_task) -> None:
    _, task, ids = admitted_omitted_input_task
    before = deepcopy(task)
    assert "inputs" not in task["execution_request"]
    assert task["spec"]["spec"]["inputs"]["input_bundle"]["object_id"] == ids["input_bundle"]

    binding = deployment_binding_from_task(task)

    assert [(row.name, row.object_id, row.digest) for row in binding.input_bindings] == [
        (name, ids[name], ids[name]) for name in ("input_bundle", "request")
    ]
    assert task == before


def test_explicit_empty_request_inputs_still_reject_two_admitted_ids(admitted_omitted_input_task) -> None:
    _, task, _ = admitted_omitted_input_task
    task["execution_request"]["inputs"] = []
    with pytest.raises(DeploymentReferenceError, match="does not mirror"):
        deployment_binding_from_task(task)


@pytest.mark.parametrize("mutation, message", [
    (lambda task, ids: task["spec"]["spec"]["inputs"]["request"].update(digest=ids["input_bundle"]), "conflicting digest"),
    (lambda task, ids: task["spec"]["spec"]["input_digests"][0].update(digest=ids["request"]), "input_digests conflicts"),
    (lambda task, ids: (
        task["spec"]["spec"]["inputs"].pop("request"),
        task["spec"]["spec"]["input_digests"].pop(),
    ), "do not match input_object_ids"),
    (lambda task, ids: task["spec"]["spec"]["inputs"].update(
        second_bundle={"object_id": ids["input_bundle"], "digest": ids["input_bundle"]}
    ), "ambiguous input descriptors"),
])
def test_omitted_request_inputs_reject_conflicting_missing_or_ambiguous_descriptors(
    admitted_omitted_input_task, mutation, message,
) -> None:
    _, task, ids = admitted_omitted_input_task
    mutation(task, ids)
    with pytest.raises(DeploymentReferenceError, match=message):
        deployment_binding_from_task(task)


def test_omitted_request_inputs_accept_unambiguous_direct_spec_projection(admitted_omitted_input_task) -> None:
    _, task, ids = admitted_omitted_input_task
    task["spec"]["inputs"] = task["spec"]["spec"].pop("inputs")
    task["spec"]["input_digests"] = task["spec"]["spec"].pop("input_digests")
    binding = deployment_binding_from_task(task)
    assert [(row.name, row.object_id) for row in binding.input_bindings] == [
        (name, ids[name]) for name in ("input_bundle", "request")
    ]


def test_omitted_request_inputs_reject_conflicting_direct_and_enveloped_descriptors(admitted_omitted_input_task) -> None:
    _, task, ids = admitted_omitted_input_task
    task["spec"]["inputs"] = {"input_bundle": ids["request"], "request": ids["input_bundle"]}
    with pytest.raises(DeploymentReferenceError, match="ambiguous input descriptors"):
        deployment_binding_from_task(task)


def test_omitted_request_inputs_accept_public_zero_input_task(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        admitted = service.create_task({
            "capability_id": "h3_av.transform", "capability_digest": _digest("2"),
            "input_object_ids": [], "spec": {"inputs": {"prompt": "hello"}},
            "execution_request": {"schema_version": 1, "target": {
                "kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a",
            }},
            "idempotency_key": "zero-inputs",
        })
        task = service._task_resource(service.store.get_task(admitted["task"]["id"]))
        assert deployment_binding_from_task(task).input_bindings == ()
    finally:
        service.close()
