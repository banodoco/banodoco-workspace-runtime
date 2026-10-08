from __future__ import annotations

import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.remote_worker_deployment import deployment_binding_from_task
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api


def _qualification(service, task_id):
    task = service._task_resource(service.store.get_task(task_id))
    binding = deployment_binding_from_task(task)
    target = binding.placement.effective_target
    digest = "sha256:" + "a" * 64
    return {
        "activation_id": "activation-1",
        "task_id": task_id,
        "run_id": binding.admission_identity.run_id,
        "credential_actor": "remote-executor",
        "binding_digest": binding.digest(),
        "deployment_digest": digest,
        "evidence_digest": digest,
        "effective_target": target,
        "executor_incarnation": "remote-incarnation-1",
        "runtime_session_id": service.runtime_session_id,
        "runtime_epoch": service.store._current_runtime_epoch(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "observation_digest": digest,
        "authorized_child_lineage": {
            "parent_task_id": task_id,
            "parent_run_id": binding.admission_identity.run_id,
            "max_depth": 1,
            "placement_version": binding.placement.placement_version,
            "effective_target": target,
        },
    }


def test_remote_activation_rpc_uses_daemon_owner_and_resident_service(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        assert daemon.httpd.runtime is service
        capability = "remote.activation.http"
        capability_digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        target = {"kind": "runpod", "pod_id": "pod-1", "provider_account_ref": "account-1"}
        service.register_capability({"capability_id": capability, "definition_digest": capability_digest})
        service.register_executor(
            {"executor_id": "remote-executor", "capabilities": [capability]},
            idempotency_key="remote-executor-register",
        )
        admitted = service.create_task({
            "capability_id": capability,
            "capability_digest": capability_digest,
            "input_object_ids": [],
            "spec": {},
            "execution_request": {"schema_version": 1, "target": target},
            "idempotency_key": "remote-activation-admit",
        }, enforce_readiness=True)
        task_id = admitted["task"]["id"]
        qualification = _qualification(service, task_id)
        route = f"/v1/tasks/{task_id}/remote-activation"

        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        anonymous = Api(daemon.endpoint, None)
        worker_token, _ = daemon.credentials.provision("remote-worker-test", ["tasks:write"])
        worker = Api(daemon.endpoint, worker_token)
        other_admin_token, _ = daemon.credentials.provision("other-admin", ["admin"])
        other_admin = Api(daemon.endpoint, other_admin_token)

        for caller in (anonymous, worker, other_admin):
            with pytest.raises(RuntimeError) as error:
                caller.request("POST", route, qualification)
            assert error.value.status == 401
        assert service._latest_remote_activation(task_id) is None

        with pytest.raises(RuntimeError) as error:
            Api(daemon.endpoint, daemon.token).request(
                "POST", route, {**qualification, "actor": "owner", "scopes": ["admin"]}
            )
        assert error.value.status == 422
        assert service._latest_remote_activation(task_id) is None

        assert owner.record_remote_activation(task_id, qualification) == qualification
        assert owner.record_remote_activation(task_id, qualification) == qualification
        assert service._latest_remote_activation(task_id) == qualification
        assert daemon.service is service

        revoke_route = route + "/revoke"
        for caller in (anonymous, worker, other_admin):
            with pytest.raises(RuntimeError) as error:
                caller.request("POST", revoke_route, {"activation_id": qualification["activation_id"]})
            assert error.value.status == 401
        with pytest.raises(RuntimeError) as error:
            Api(daemon.endpoint, daemon.token).request(
                "POST", revoke_route,
                {"activation_id": qualification["activation_id"], "actor": "owner"},
            )
        assert error.value.status == 400
        assert service._latest_remote_activation(task_id) == qualification

        assert owner.revoke_remote_activation(task_id, qualification["activation_id"]) is None
        assert service._latest_remote_activation(task_id) is None
        with pytest.raises(RuntimeError) as error:
            Api(daemon.endpoint, daemon.token).request(
                "POST", revoke_route, {"activation_id": qualification["activation_id"]}
            )
        assert error.value.status == 409
    finally:
        daemon.stop()


@pytest.mark.parametrize("target", [
    {"kind": "runpod", "pod_id": "pod-1", "provider_account_ref": "account-1"},
    {"kind": "machine", "id": "machine-1"},
])
def test_resident_remote_credential_is_disabled_until_recorded_activation(tmp_path, target):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        service = daemon.service
        capability = "remote.activation.credential"
        digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        service.register_capability({"capability_id": capability, "definition_digest": digest})
        task_id = service.create_task({
            "capability_id": capability, "capability_digest": digest,
            "input_object_ids": [], "spec": {},
            "execution_request": {"schema_version": 1, "target": target},
            "idempotency_key": "credential-admission",
        }, enforce_readiness=True)["task"]["id"]
        qualification = _qualification(service, task_id)
        qualification["credential_actor"] = "astrid-pack-host"
        placement = {
            "actual": target,
            "verification": {"method": "credential_claim", "verified": True,
                             "evidence_digest": qualification["evidence_digest"]},
            "executor_incarnation": qualification["executor_incarnation"],
        }
        route = f"/v1/tasks/{task_id}/remote-credential"
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        other_admin_token, _ = daemon.credentials.provision("other-admin", ["admin"])
        with pytest.raises(RuntimeError) as error:
            Api(daemon.endpoint, other_admin_token).request(
                "POST", route, {"action": "provision", "qualification": qualification, "placement": placement}
            )
        assert error.value.status == 401
        with pytest.raises(RuntimeError):
            owner.control_remote_credential(task_id, {
                "action": "provision", "qualification": {**qualification, "binding_digest": "sha256:" + "0" * 64},
                "placement": placement,
            })
        result = owner.control_remote_credential(task_id, {
            "action": "provision", "qualification": qualification, "placement": placement,
        })
        assert result["credential_actor"] == "astrid-pack-host"
        assert daemon.credentials.actor_metadata("astrid-pack-host")["qualified_activation"] == qualification
        with pytest.raises(RuntimeError):
            owner.control_remote_credential(task_id, {"action": "enable", "activation_id": qualification["activation_id"]})
        with pytest.raises(Exception):
            daemon.credentials.require(daemon.credentials.path_for("astrid-pack-host").read_text().strip(), "worker:execute")
        owner.record_remote_activation(task_id, qualification)
        owner.record_remote_activation(task_id, qualification)
        assert [kind for kind, _ in service._remote_activation_history(task_id)] == [
            "task.remote_activation_qualified", "task.remote_activation_accepted",
        ]
        token = daemon.credentials.path_for("astrid-pack-host").read_text().strip()
        with pytest.raises(Exception):
            daemon.credentials.require(token, "worker:execute")
        with pytest.raises(RuntimeError):
            owner.control_remote_credential(task_id, {
                "action": "provision", "qualification": qualification, "placement": placement,
            })
        assert daemon.credentials.path_for("astrid-pack-host").read_text().strip() == token
        assert owner.control_remote_credential(task_id, {"action": "enable", "activation_id": qualification["activation_id"]}) == {"enabled": True}
        assert owner.control_remote_credential(task_id, {"action": "verify", "activation_id": qualification["activation_id"]}) == {"fresh": True}
        assert owner.control_remote_credential(task_id, {"action": "revoke", "activation_id": qualification["activation_id"]}) == {"revoked": True}
        assert service._latest_remote_activation(task_id) is None
        assert daemon.credentials.actor_metadata("astrid-pack-host") is None
        assert owner.control_remote_credential(task_id, {"action": "revoke", "activation_id": qualification["activation_id"]}) == {"revoked": True}
    finally:
        daemon.stop()


def test_unaccepted_resident_generation_revoke_is_replayable_and_tombstoned(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        service = daemon.service
        capability = "machine.unaccepted"
        digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        target = {"kind": "machine", "id": "machine-1"}
        service.register_capability({"capability_id": capability, "definition_digest": digest})
        task_id = service.create_task({
            "capability_id": capability, "capability_digest": digest, "input_object_ids": [], "spec": {},
            "execution_request": {"schema_version": 1, "target": target}, "idempotency_key": "unaccepted",
        }, enforce_readiness=True)["task"]["id"]
        qualification = _qualification(service, task_id)
        qualification["credential_actor"] = "astrid-pack-host"
        placement = {"actual": target, "executor_incarnation": qualification["executor_incarnation"],
                     "verification": {"method": "credential_claim", "verified": True,
                                      "evidence_digest": qualification["evidence_digest"]}}
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        owner.control_remote_credential(task_id, {
            "action": "provision", "qualification": qualification, "placement": placement,
        })
        control = {"action": "revoke", "activation_id": qualification["activation_id"]}
        assert owner.control_remote_credential(task_id, control) == {"revoked": True}
        assert owner.control_remote_credential(task_id, control) == {"revoked": True}
        with pytest.raises(RuntimeError):
            owner.record_remote_activation(task_id, qualification)
        assert daemon.credentials.actor_metadata("astrid-pack-host") is None
        assert service._latest_remote_activation(task_id) is None
    finally:
        daemon.stop()


def test_resident_recovered_terminal_activation_requires_exact_replacement_receipt(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        service = daemon.service
        capability = "remote.recovered.credential"
        digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        old = {"kind": "runpod", "pod_id": "pod-old", "provider_account_ref": "account-1"}
        new = {**old, "pod_id": "pod-new"}
        service.register_capability({"capability_id": capability, "definition_digest": digest})
        service.register_executor({"executor_id": "astrid-pack-host", "capabilities": [capability], "max_concurrency": 2},
                                  idempotency_key="recovered-executor")
        task_id = service.create_task({
            "capability_id": capability, "capability_digest": digest, "input_object_ids": [], "spec": {},
            "execution_request": {"schema_version": 1, "target": old}, "idempotency_key": "recovered-admission",
        }, enforce_readiness=True)["task"]["id"]
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        qualification = _qualification(service, task_id)
        qualification["credential_actor"] = "astrid-pack-host"

        def placement(proof):
            return {"actual": proof["effective_target"], "executor_incarnation": proof["executor_incarnation"],
                    "verification": {"method": "credential_claim", "verified": True,
                                     "evidence_digest": proof["evidence_digest"]}}

        owner.control_remote_credential(task_id, {
            "action": "provision", "qualification": qualification, "placement": placement(qualification),
        })
        owner.record_remote_activation(task_id, qualification)
        owner.control_remote_credential(task_id, {"action": "enable", "activation_id": qualification["activation_id"]})
        identity = daemon.credentials.load(daemon.worker_credential_path.read_text().strip())
        claim = service.claim_next({"executor_id": "astrid-pack-host", "capability_ids": [capability],
                                    "runtime_epoch": service.health()["runtime_epoch"], "target": old},
                                   idempotency_key="recovered-old-claim", identity=identity)
        service.fail_attempt(claim["attempt_id"], {
            **{key: claim[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "error": {"code": "old-pod-lost"},
        }, idempotency_key="recovered-old-fail", identity=identity)
        before = service._task_resource(service.store.get_task(task_id))
        evidence = "sha256:" + "b" * 64
        service.recover_task_placement(task_id, {
            "schema_version": 1, "expected_task_version": before["version"], "expected_placement_version": 0,
            "expected_original_target": old, "expected_current_target": old, "replacement_target": new,
            "reason": "old exact pod absent", "loss_evidence": {
                "source": "independent-provider", "status": "absent", "target": old,
                "observed_at": datetime.now(timezone.utc).isoformat(), "evidence_digest": evidence, "no_active_work": True,
            }, "qualification": {"target": new, "verified": True, "evidence_digest": evidence,
                                  "executor_incarnation": "replacement-host"},
        }, idempotency_key="resident-recovery", identity={"actor": "owner", "scopes": ["admin"]})
        recovered = _qualification(service, task_id)
        recovered.update(activation_id="activation-2", credential_actor="astrid-pack-host",
                         evidence_digest=evidence, executor_incarnation="replacement-host")
        with pytest.raises(RuntimeError):
            owner.control_remote_credential(task_id, {
                "action": "provision", "qualification": {**recovered, "executor_incarnation": "foreign"},
                "placement": placement(recovered),
            })
        owner.control_remote_credential(task_id, {
            "action": "provision", "qualification": recovered, "placement": placement(recovered),
        })
        owner.record_remote_activation(task_id, recovered)
        assert owner.control_remote_credential(task_id, {"action": "enable", "activation_id": "activation-2"}) == {"enabled": True}
        assert service.task(task_id)["task"]["status"] == "failed"  # Activation does not retry/admit.
    finally:
        daemon.stop()
