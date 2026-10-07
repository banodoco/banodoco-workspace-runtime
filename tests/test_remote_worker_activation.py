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
MACHINE = {"kind": "machine", "id": "machine-a"}
OWNER = {"actor": "owner", "scopes": ["admin"]}


def _service(tmp_path: Path, *, child_delegation: bool = False, target=OLD):
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
            "target": target,
            "inputs": [{"name": "source", "object_id": input_digest}],
        },
        "idempotency_key": "same-canonical-admission",
    }
    if child_delegation:
        admission["child_delegation"] = {
            "capabilities": [{"capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST}],
            "targets": [target],
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
        target_ref=target["kind"] + ":" + binding.placement.original_target.get("pod_id", binding.placement.original_target.get("id", "")),
        effective_target_ref=target["kind"] + ":" + target.get("pod_id", target.get("id", "")),
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
    value = {
        "target": dict(ref.effective_target),
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
    if ref.effective_target["kind"] == "runpod":
        value["provider_identity"] = {"account_ref": ref.effective_target["provider_account_ref"],
                                      "pod_id": ref.effective_target["pod_id"]}
    else:
        value.pop("child")
        value["machine_identity"] = {"id": ref.effective_target["id"], "uid": 501}
        value["process"].update(uid=501, executable=str(ref.executable.path), artifact_digest=ref.executable.digest)
    return value


class Preparer:
    def __init__(self):
        self.calls = []
        self.bad_ack = False

    def prepare(self, launch):
        self.calls.append("prepare")
        return object()

    def acknowledge(self, handle, grant, *, accept):
        accept(dict(grant), {"pid": 12345, "birth_id": "birth-1"})
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
        assert inspector.calls == 5
        assert credentials.actor_metadata("host")["qualified_activation"] == qualification
        launcher.assert_fresh(task, ref, parked, qualification)
        claimed = _claim(service, OLD, _identity(credentials), "qualified-claim")
        assert claimed["task_id"] == task_id
        assert claimed["execution_binding"]["executor_incarnation"] == parked.executor_incarnation
        assert claimed["execution_binding"]["actual_target"] == OLD
    finally:
        service.close()


@pytest.mark.parametrize("failure", [None, "grant", "process", "missing", "duplicate", "lost_reply", "cleanup"])
def test_acceptance_callback_commits_before_ack_and_keeps_credential_disabled(tmp_path, failure):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        deliveries = []

        def acknowledge(handle, grant, *, accept):
            deliveries.append(handle)
            token = Path(grant["credential_file"]).read_text().strip()
            assert service._latest_remote_activation(task_id) is None
            with pytest.raises(AuthorizationError):
                credentials.require(token, "worker:execute")
            received = dict(grant)
            process = {"pid": 12345, "birth_id": "birth-1"}
            if failure == "grant":
                received["activation_id"] = "foreign"
            if failure == "process":
                process["birth_id"] = "foreign"
            if failure != "missing":
                accept(received, process)
                assert [kind for kind, _ in service._remote_activation_history(task_id)] == [
                    "task.remote_activation_qualified", "task.remote_activation_accepted",
                ]
                with pytest.raises(AuthorizationError):
                    credentials.require(token, "worker:execute")
            if failure == "duplicate":
                accept(received, process)
            if failure == "lost_reply":
                raise EOFError("final reply lost after resident commit")
            if failure == "cleanup":
                raise ConflictError("bad final acknowledgement")
            return {key: grant[key] for key in ("activation_id", "executor_incarnation", "evidence_digest")}

        preparer.acknowledge = acknowledge
        if failure == "cleanup":
            def abort(_handle):
                raise OSError("cleanup uncertain")
            preparer.abort = abort
        task = service._task_resource(service.store.get_task(task_id))
        if failure in {None, "lost_reply"}:
            launcher.activate(task, ref, parked)
            assert launcher.activation_state == "active"
            assert credentials.require(credentials.path_for("host").read_text().strip(), "worker:execute")
        else:
            with pytest.raises(ConflictError):
                launcher.activate(task, ref, parked)
            assert credentials.actor_metadata("host") is None
            assert service._latest_remote_activation(task_id) is None
            assert launcher.activation_state == ("unknown" if failure == "cleanup" else "inactive")
        assert deliveries == [parked.handle]
    finally:
        service.close()


@pytest.mark.parametrize("target,field,change", [
    (OLD, "provider_identity", {"account_ref": "account-a", "pod_id": "foreign-pod"}),
    (OLD, "child", {"attached": False}),
    (MACHINE, "machine_identity", {"id": "foreign-machine", "uid": 501}),
    (MACHINE, "machine_identity", {"id": "machine-a", "uid": 502}),
])
def test_placement_witness_cannot_substitute_provider_machine_or_child(tmp_path, target, field, change):
    service, task_id = _service(tmp_path, target=target)
    try:
        ref = _reference(tmp_path, service, task_id)
        observation = _observation(ref, service)
        observation[field] = change
        with pytest.raises(ConflictError):
            QualifiedRemoteWorkerLauncher._validate_observation(observation, target)
    finally:
        service.close()


def test_readiness_failure_revokes_enabled_worker_before_claim(tmp_path):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def not_ready(_handle):
            preparer.calls.append("await_ready")
            raise ConflictError("required H3 capability is unavailable")

        preparer.await_ready = not_ready
        with pytest.raises(ConflictError, match="required H3 capability"):
            launcher.activate(service._task_resource(service.store.get_task(task_id)), ref, parked)
        assert preparer.calls[-2:] == ["await_ready", "abort"]
        assert credentials.actor_metadata("host") is None
        waiting = _claim(service, OLD, {"actor": "host", "scopes": ["worker:execute"]}, "after-failed-ready")
        assert waiting["waiting_reason"] in {"execution_binding_missing", "remote_activation_missing"}
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


@pytest.mark.parametrize("target", [OLD, MACHINE])
@pytest.mark.parametrize("finish", [False, True])
def test_qualified_credential_is_scoped_to_authorized_child_lineage(tmp_path, target, finish):
    service, task_id = _service(tmp_path, child_delegation=True, target=target)
    try:
        ref = _reference(tmp_path, service, task_id)
        credentials = CredentialStore(tmp_path / "credentials")
        launcher = QualifiedRemoteWorkerLauncher(
            runtime=service, credentials=credentials, preparer=Preparer(),
            inspector=Inspector(_observation(ref, service)),
        )
        parked = launcher.park(ref, target=target)
        task = service._task_resource(service.store.get_task(task_id))
        launcher.activate(task, ref, parked)
        identity = _identity(credentials)
        parent = _claim(service, target, identity, "qualified-parent")
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
                "execution_request": {"schema_version": 1, "target": target, "inputs": []},
            },
        }, idempotency_key="authorized-child", identity=identity)
        claimed_child = _claim(service, target, identity, "authorized-child-claim")
        assert claimed_child["task_id"] == child["task"]["id"]
        replayed_child = _claim(service, target, identity, "authorized-child-claim")
        assert replayed_child["attempt_id"] == claimed_child["attempt_id"]
        heartbeat = service.heartbeat_attempt(
            claimed_child["attempt_id"], {
                "lease_id": claimed_child["lease_id"],
                "fence": claimed_child["fence"],
                "runtime_epoch": claimed_child["runtime_epoch"],
            }, idempotency_key="authorized-child-heartbeat", identity=identity,
        )
        assert heartbeat["data"]["attempt_id"] == claimed_child["attempt_id"]
        # Two actual resident attempts make progress while the parent's lease
        # remains live. Machine evidence carries no invented remote child.
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE executor_id='host' AND settled=0"
        ).fetchone()[0] == 2
        parent_lease = {key: parent[key] for key in ("lease_id", "fence", "runtime_epoch")}
        progress = service.heartbeat_attempt(
            parent["attempt_id"], {**parent_lease, "progress": {"phase": "child-running"}},
            idempotency_key="parent-with-live-child", identity=identity,
        )
        assert progress["data"]["attempt_id"] == parent["attempt_id"]
        if finish:
            child_lease = {key: claimed_child[key] for key in ("lease_id", "fence", "runtime_epoch")}
            service.settle_attempt(
                claimed_child["attempt_id"], {**child_lease, "outputs": []},
                idempotency_key="child-progress-completed", identity=identity,
            )
            service.heartbeat_attempt(
                parent["attempt_id"], {**parent_lease, "progress": {"phase": "child-completed"}},
                idempotency_key="parent-after-child-completed", identity=identity,
            )
            service.settle_attempt(
                parent["attempt_id"], {**parent_lease, "outputs": []},
                idempotency_key="parent-progress-completed", identity=identity,
            )
            assert service.task(child["task"]["id"])["task"]["status"] == "completed"
            assert service.task(task_id)["task"]["status"] == "completed"
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
        with pytest.raises(ConflictError, match="queued task or exact recovered"):
            service.assert_remote_activation_admissible(task_id, old_activation)
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
        candidate = {**old_activation, "binding_digest": recovered_ref.deployment_binding.digest(),
                     "effective_target": NEW, "evidence_digest": new_parked.evidence_digest,
                     "executor_incarnation": new_parked.executor_incarnation,
                     "authorized_child_lineage": {**old_activation["authorized_child_lineage"],
                                                  "effective_target": NEW, "placement_version": 1}}
        service.assert_remote_activation_admissible(task_id, candidate)
        for field, bad in (("binding_digest", old_activation["binding_digest"]),
                           ("effective_target", OLD), ("evidence_digest", "sha256:" + "0" * 64),
                           ("executor_incarnation", "foreign"),
                           ("authorized_child_lineage", {**candidate["authorized_child_lineage"], "placement_version": 0})):
            with pytest.raises(ConflictError):
                service.assert_remote_activation_admissible(task_id, {**candidate, field: bad})
        service.store.conn.execute("UPDATE attempts SET settled=0 WHERE id=?", (claimed["attempt_id"],))
        with pytest.raises(ConflictError, match="unknown active work"):
            service.assert_remote_activation_admissible(task_id, candidate)
        service.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (claimed["attempt_id"],))
        service.store.conn.execute(
            "INSERT INTO reservations(task_id,resource_key,lease_token,created_at,released_at,executor_id,fence,lease_expires_at,runtime_epoch) "
            "VALUES (?, 'recovery-test', ?, ?, NULL, 'host', ?, ?, ?)",
            (task_id, claimed["lease_id"], datetime.now(timezone.utc).isoformat(), claimed["fence"],
             datetime.now(timezone.utc).isoformat(), claimed["runtime_epoch"]),
        )
        with pytest.raises(ConflictError, match="active reservation"):
            service.assert_remote_activation_admissible(task_id, candidate)
        service.store.conn.execute("DELETE FROM reservations WHERE task_id=? AND resource_key='recovery-test'", (task_id,))
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
