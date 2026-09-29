from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.remote_worker_activation import QualifiedRemoteWorkerLauncher, _digest
from runtime_protocol.remote_worker_deployment import ArtifactReference, DeploymentReference, deployment_binding_from_task
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "h3_av.transform"
CAPABILITY_DIGEST = "sha256:" + hashlib.sha256(CAPABILITY.encode()).hexdigest()
OLD = {"kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-a"}
NEW = {"kind": "runpod", "pod_id": "pod-new", "provider_account_ref": "account-a"}
OWNER = {"actor": "owner", "scopes": ["admin"]}


def _service(tmp_path: Path, *, child_delegation: bool = False):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST})
    service.register_executor(
        {"executor_id": "host", "capabilities": [CAPABILITY], "max_concurrency": 2},
        idempotency_key="host-register",
    )
    project = service.create_project(
        {"slug": "remote-activation", "name": "Remote activation"},
        idempotency_key="remote-activation-project",
    )
    source = service.ingest(
        project["id"],
        b"remote-worker-activation-input",
        media_type="application/octet-stream",
        original_name="source.bin",
        idempotency_key="remote-activation-input",
    )
    input_digest = source["data"]["digest"]
    admission = {
        "capability_id": CAPABILITY,
        "capability_digest": CAPABILITY_DIGEST,
        "project": project["id"],
        "input_object_ids": [input_digest],
        "spec": {"inputs": {"source": input_digest}},
        "execution_request": {
            "schema_version": 1,
            "target": OLD,
            "inputs": [{"name": "source", "object_id": input_digest}],
        },
        "idempotency_key": "same-canonical-admission",
    }
    if child_delegation:
        admission["child_delegation"] = {
            "capabilities": [{"capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST}],
            "targets": [OLD],
            "input_object_ids": [],
        }
    admitted = service.create_task(admission, enforce_readiness=True)
    task_id = admitted["task"]["id"]
    return service, task_id


def _reference(tmp_path: Path, service: RuntimeService, task_id: str) -> DeploymentReference:
    task = service._task_resource(service.store.get_task(task_id))
    binding = deployment_binding_from_task(task)
    executable = ArtifactReference("python", tmp_path / "python", "sha256:" + "2" * 64)
    target = binding.placement.effective_target
    return DeploymentReference(
        deployment_id="deployment-1", revision="revision-1",
        task_id=task_id, run_id=binding.admission_identity.run_id,
        target_ref="runpod:" + binding.placement.original_target["pod_id"],
        effective_target_ref="runpod:" + target["pod_id"],
        executable=executable, dependency_closure=(executable,),
        source_closure_digest="sha256:" + "3" * 64,
        data_root=tmp_path / "data", support_root=tmp_path / "data" / "runtime",
        runtime_endpoint="http://127.0.0.1:59683",
        runtime_instance_id="instance-1", runtime_epoch=service.health()["runtime_epoch"],
        runtime_schema_digest="sha256:" + "4" * 64,
        model_root=tmp_path / "models", capacity=2, session_ref="session-1",
        session_config_digest="sha256:" + "5" * 64,
        output_root=tmp_path / "outputs", credential_ref=str(tmp_path / "credentials" / "host.token"),
        executor_id="host", boot_manifest_path=tmp_path / "data" / "runtime" / "boot.json",
        boot_manifest_hash="sha256:" + "6" * 64,
        readiness_profile_path=tmp_path / "data" / "runtime" / "ready.json",
        readiness_profile_hash="sha256:" + "7" * 64,
        admission_identity=binding.admission_identity,
        capability_identity=binding.capability_identity,
        input_bindings=binding.input_bindings,
        original_target=binding.placement.original_target,
        effective_target=target,
        placement_version=binding.placement.placement_version,
        recovery_decision_digest=binding.placement.recovery_decision_digest,
        execution_target=target,
    )


def _observation(ref: DeploymentReference, service: RuntimeService):
    return {
        "target": dict(ref.effective_target),
        "provider_identity": {"account_ref": ref.effective_target["provider_account_ref"], "pod_id": ref.effective_target["pod_id"]},
        "process": {"pid": 12345, "birth_id": "birth-1", "pgid": 12345, "sid": 12345},
        "child": {"attached": True, "birth_id": "child-birth-1", "lanes": ["orchestration", "executor"]},
        "runtime_instance_id": ref.runtime_instance_id,
        "runtime_epoch": ref.runtime_epoch,
        "runtime_session_id": service.runtime_session_id,
        "source_closure_digest": ref.source_closure_digest,
        "dependency_closure_digest": _digest([
            {"name": item.name, "path": str(item.path), "digest": item.digest}
            for item in ref.dependency_closure
        ]),
        "model_root": str(ref.model_root), "session_ref": ref.session_ref,
        "data_root": str(ref.data_root), "support_root": str(ref.support_root),
        "capacity": 2, "model_inventory_digest": "sha256:" + "8" * 64,
        "session_config_digest": ref.session_config_digest,
    }


class Preparer:
    def __init__(self):
        self.calls = []
        self.bad_ack = False

    def prepare(self, launch):
        self.calls.append("prepare")
        return object()

    def acknowledge(self, handle, grant):
        self.calls.append("private_ack")
        return {"activation_id": "wrong" if self.bad_ack else grant["activation_id"],
                "executor_incarnation": grant["executor_incarnation"],
                "evidence_digest": grant["evidence_digest"]}

    def abort(self, handle):
        self.calls.append("abort")


class Inspector:
    def __init__(self, observation):
        self.current = observation
        self.calls = 0

    def observe(self, handle):
        self.calls += 1
        return copy.deepcopy(self.current)


def _fixture(tmp_path):
    service, task_id = _service(tmp_path)
    reference = _reference(tmp_path, service, task_id)
    credentials = CredentialStore(tmp_path / "credentials")
    preparer = Preparer()
    inspector = Inspector(_observation(reference, service))
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service, credentials=credentials, preparer=preparer, inspector=inspector,
    )
    return service, task_id, reference, credentials, preparer, inspector, launcher


def _claim(service, target, identity, key):
    return service.claim_next({
        "executor_id": "host", "capability_ids": [CAPABILITY],
        "runtime_epoch": service.health()["runtime_epoch"], "target": target,
    }, idempotency_key=key, identity=identity)


def _identity(credentials):
    return credentials.load(credentials.path_for("host").read_text().strip())


def _expired_identity(service, credentials, task_id):
    expired = copy.deepcopy(_identity(credentials)["qualified_activation"])
    expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    service.store.conn.execute(
        "UPDATE events SET payload_json=? WHERE task_id=? AND kind='task.remote_activation_qualified'",
        (json.dumps(expired, sort_keys=True, separators=(",", ":")), str(task_id)),
    )
    identity = _identity(credentials)
    identity["qualified_activation"] = expired
    return identity


def test_parked_host_remains_unclaimable_until_private_ack_and_owner_activation(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        missing = _claim(service, OLD, {"actor": "host", "scopes": ["worker:execute"]}, "missing")
        assert missing["waiting_reason"] in {"execution_binding_missing", "remote_activation_missing"}
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        assert preparer.calls == ["prepare", "private_ack"]
        assert inspector.calls == 4
        assert credentials.actor_metadata("host")["qualified_activation"] == qualification
        launcher.assert_fresh(task, ref, parked, qualification)
        claimed = _claim(service, OLD, _identity(credentials), "qualified-claim")
        assert claimed["task_id"] == task_id
        assert claimed["execution_binding"]["executor_incarnation"] == parked.executor_incarnation
        assert claimed["execution_binding"]["actual_target"] == OLD
    finally:
        service.close()


@pytest.mark.parametrize("field,bad", [
    ("process", {"pid": 12345, "birth_id": "changed", "pgid": 12345, "sid": 12345}),
    ("model_root", "/wrong/models"),
    ("session_ref", "other-session"),
    ("data_root", "/wrong/data"),
    ("capacity", 1),
])
def test_changed_observation_blocks_activation_before_credential(tmp_path, field, bad):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        inspector.current[field] = bad
        with pytest.raises(ConflictError):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert "private_ack" not in preparer.calls
    finally:
        service.close()


def test_private_ack_failure_revokes_disabled_credential_and_leaves_task_queued(tmp_path):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        preparer.bad_ack = True
        with pytest.raises(ConflictError, match="acknowledgement"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert service.task(task_id)["task"]["status"] == "queued"
    finally:
        service.close()


def test_revocation_expiry_and_replay_fail_closed(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        claimed = _claim(service, OLD, identity, "one-claim")
        assert claimed["task_id"] == task_id
        service.revoke_remote_activation(task_id, qualification["activation_id"], identity=OWNER)
        with pytest.raises(AuthorizationError, match="activation"):
            _claim(service, OLD, identity, "one-claim")
        with pytest.raises(AuthorizationError, match="activation"):
            service._assert_attempt_identity({"task_id": task_id, "executor_id": "host"}, identity)
    finally:
        service.close()


def test_expired_qualification_allows_replay_of_bound_claim_but_not_new_claim(tmp_path):
    service, task_id = _service(tmp_path)
    try:
        task = service._task_resource(service.store.get_task(task_id))
        second = service.create_task({
            "capability_id": CAPABILITY,
            "capability_digest": CAPABILITY_DIGEST,
            "project": task["project_id"],
            "input_object_ids": task["input_object_ids"],
            "spec": {"inputs": {"source": task["input_object_ids"][0]}},
            "execution_request": task["execution_request"],
            "idempotency_key": "second-canonical-admission",
        }, enforce_readiness=True)
        # The first task's activation is the only qualified generation. The
        # second queued task must not inherit it merely because the worker and
        # target are otherwise identical.
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(_reference(tmp_path, service, task_id), service)),
        )
        reference = _reference(tmp_path, service, task_id)
        parked_host = launcher.park(reference, target=OLD)
        qualification = launcher.activate(task, reference, parked_host)
        identity = _identity(credentials)
        first = _claim(service, OLD, identity, "bound-claim")
        assert first["task_id"] == task_id
        expired_identity = _expired_identity(service, credentials, task_id)
        replay = _claim(service, OLD, expired_identity, "bound-claim")
        assert replay["attempt_id"] == first["attempt_id"]
        new_claim = _claim(service, OLD, expired_identity, "new-claim-after-expiry")
        assert new_claim["task"]["task_id"] == second["task"]["id"]
        assert new_claim["waiting_reason"] == "remote_activation_missing"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE task_id=?", (second["task"]["id"],)
        ).fetchone()[0] == 0
        assert qualification["activation_id"] == expired_identity["qualified_activation"]["activation_id"]
    finally:
        service.close()


@pytest.mark.parametrize("operation", ["heartbeat", "settle", "fail"])
def test_expired_qualification_remains_authoritative_for_bound_attempt(tmp_path, operation):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        claim = _claim(service, OLD, identity, f"expired-{operation}-claim")
        identity = _expired_identity(service, credentials, task_id)
        lease = {
            "lease_id": claim["lease_id"], "fence": claim["fence"],
            "runtime_epoch": claim["runtime_epoch"],
        }
        if operation == "heartbeat":
            result = service.heartbeat_attempt(
                claim["attempt_id"], {**lease, "progress": {"phase": "still-running"}},
                idempotency_key="expired-heartbeat", identity=identity,
            )
            assert result["data"]["attempt_id"] == claim["attempt_id"]
        elif operation == "settle":
            result = service.settle_attempt(
                claim["attempt_id"], {**lease, "outputs": []},
                idempotency_key="expired-settle", identity=identity,
            )
            assert result["data"]["task_id"] == task_id
        else:
            result = service.fail_attempt(
                claim["attempt_id"], {**lease, "error": {"code": "expired-proof-test"}},
                idempotency_key="expired-fail", identity=identity,
            )
            assert result["data"]["task_id"] == task_id
    finally:
        service.close()


def test_qualified_credential_is_scoped_to_authorized_child_lineage(tmp_path):
    service, task_id = _service(tmp_path, child_delegation=True)
    try:
        ref = _reference(tmp_path, service, task_id)
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(ref, service)),
        )
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        parent = _claim(service, OLD, identity, "qualified-parent")
        authority = service.issue_child_authority(
            parent["attempt_id"], {
                "lease_id": parent["lease_id"], "fence": parent["fence"],
                "runtime_epoch": parent["runtime_epoch"],
            }, identity=identity,
        )["authority"]
        child = service.admit_delegated_child({
            "authority": authority,
            "task": {
                "capability_id": CAPABILITY,
                "capability_digest": CAPABILITY_DIGEST,
                "input_object_ids": [],
                "spec": {"params": {"child": "authorized"}},
                "execution_request": {"schema_version": 1, "target": OLD, "inputs": []},
            },
        }, idempotency_key="authorized-child", identity=identity)
        claimed_child = _claim(service, OLD, identity, "authorized-child-claim")
        assert claimed_child["task_id"] == child["task"]["id"]
        replayed_child = _claim(service, OLD, identity, "authorized-child-claim")
        assert replayed_child["attempt_id"] == claimed_child["attempt_id"]
        heartbeat = service.heartbeat_attempt(
            claimed_child["attempt_id"], {
                "lease_id": claimed_child["lease_id"],
                "fence": claimed_child["fence"],
                "runtime_epoch": claimed_child["runtime_epoch"],
            }, idempotency_key="authorized-child-heartbeat", identity=identity,
        )
        assert heartbeat["data"]["attempt_id"] == claimed_child["attempt_id"]
        service.revoke_remote_activation(
            task_id, identity["qualified_activation"]["activation_id"], identity=OWNER,
        )
        with pytest.raises(AuthorizationError, match="remote activation"):
            service.heartbeat_attempt(
                claimed_child["attempt_id"], {
                    "lease_id": claimed_child["lease_id"],
                    "fence": claimed_child["fence"],
                    "runtime_epoch": claimed_child["runtime_epoch"],
                }, idempotency_key="revoked-child-heartbeat", identity=identity,
            )

        foreign = copy.deepcopy(identity)
        foreign["qualified_activation"]["authorized_child_lineage"]["parent_task_id"] = "foreign-parent"
        with pytest.raises(AuthorizationError, match="remote activation"):
            service._assert_attempt_identity(
                {"task_id": child["task"]["id"], "executor_id": "host"}, foreign,
            )
    finally:
        service.close()


def test_revoked_activation_generation_is_tombstoned_and_replacement_needs_new_generation(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        qualification = launcher.activate(task, ref, parked)
        service.revoke_remote_activation(task_id, qualification["activation_id"], identity=OWNER)
        with pytest.raises(ConflictError, match="permanently revoked"):
            service.record_remote_activation(task_id, qualification, identity=OWNER)
        replacement = copy.deepcopy(qualification)
        replacement["activation_id"] = "replacement-generation"
        assert service.record_remote_activation(task_id, replacement, identity=OWNER) == replacement
    finally:
        service.close()


def test_recovered_placement_requires_matching_new_qualification(tmp_path):
    service, task_id, ref, credentials, _preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        original_binding = deployment_binding_from_task(task)
        old_activation = launcher.activate(task, ref, parked)
        old_identity = _identity(credentials)
        claimed = _claim(service, OLD, old_identity, "old-claim")
        service.fail_attempt(claimed["attempt_id"], {
            "lease_id": claimed["lease_id"], "fence": claimed["fence"],
            "runtime_epoch": claimed["runtime_epoch"], "error": {"code": "old-pod-lost"},
        }, idempotency_key="old-fail", identity=old_identity)
        new_ref = replace(ref, effective_target=NEW, execution_target=NEW,
                          effective_target_ref="runpod:pod-new")
        new_inspector = Inspector(_observation(new_ref, service))
        new_launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(), inspector=new_inspector,
        )
        new_parked = new_launcher.park(new_ref, target=NEW)
        before = service._task_resource(service.store.get_task(task_id))
        recovery = service.recover_task_placement(task_id, {
            "schema_version": 1, "expected_task_version": before["version"],
            "expected_placement_version": 0, "expected_original_target": OLD,
            "expected_current_target": OLD, "replacement_target": NEW,
            "reason": "old exact pod absent", "loss_evidence": {
                "source": "independent-provider", "status": "absent", "target": OLD,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "evidence_digest": "sha256:" + "9" * 64, "no_active_work": True,
            }, "qualification": new_parked.recovery_qualification(),
        }, idempotency_key="recover-once", identity=OWNER)
        assert recovery["data"]["placement_recovery"]["placement_version"] == 1
        assert service._latest_remote_activation(task_id) is None
        fresh = service._task_resource(service.store.get_task(task_id))
        recovered_ref = _reference(tmp_path, service, task_id)
        new_activation = new_launcher.activate(fresh, recovered_ref, new_parked)
        assert new_activation["binding_digest"] != old_activation["binding_digest"]
        assert fresh["run_id"] == task["run_id"]
        assert fresh["input_object_ids"] == task["input_object_ids"]
        assert fresh["execution_request"] == task["execution_request"]
        recovered_binding = deployment_binding_from_task(fresh)
        assert recovered_binding.admission_identity == original_binding.admission_identity
        assert recovered_binding.capability_identity == original_binding.capability_identity
        assert recovered_binding.input_bindings == original_binding.input_bindings
    finally:
        service.close()
