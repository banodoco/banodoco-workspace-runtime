from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime_protocol.local_worker import LocalWorkerProfile
from runtime_protocol.remote_worker_deployment import (
    AdmissionIdentity,
    ArtifactReference,
    CapabilityIdentity,
    DeploymentReference,
    DeploymentReferenceError,
    project_launch,
)


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
