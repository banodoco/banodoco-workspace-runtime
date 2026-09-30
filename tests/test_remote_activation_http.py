from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.remote_worker_deployment import deployment_binding_from_task
from runtime_protocol.store import RealmStore
from tests.http_helpers import Api
from tests.test_remote_worker_activation import (
    CAPABILITY, CAPABILITY_DIGEST, OLD, OWNER, Inspector, Preparer, _observation, _reference,
)
from runtime_protocol.remote_worker_activation import QualifiedRemoteWorkerLauncher
from runtime_protocol.errors import AuthorizationError, ConflictError


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


@pytest.mark.parametrize("lost_action", ["ack", "provision", "enable", "readiness"])
def test_resident_acceptance_recovery_and_authenticated_enablement(tmp_path, lost_action):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        service = daemon.service
        service.register_capability({"capability_id": CAPABILITY, "definition_digest": CAPABILITY_DIGEST})
        task_id = service.create_task({
            "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [], "spec": {}, "idempotency_key": "resident-acceptance",
            "execution_request": {"schema_version": 1, "target": OLD},
        }, enforce_readiness=True)["task"]["id"]
        ref = replace(_reference(tmp_path, service, task_id), executor_id="astrid-pack-host",
                      runtime_endpoint=daemon.endpoint, runtime_instance_id=daemon.instance_id,
                      credential_ref=str(daemon.worker_credential_path))
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        actions = []

        def control(task, body):
            result = owner.control_remote_credential(task, body)
            actions.append(body["action"])
            if body["action"] == lost_action:
                raise EOFError("resident credential reply deliberately lost")
            return result

        preparer = Preparer()
        deliveries = []

        def accepted_but_reply_lost(handle, grant, *, accept):
            deliveries.append(handle)
            token = daemon.worker_credential_path.read_text().strip()
            worker = Api(daemon.endpoint, token)
            # Public health is positive for this explicitly disabled bearer.
            assert worker.health()["status"] == "ok"
            with pytest.raises(RuntimeError) as rejected:
                worker.request("POST", "/v1/handshake", {"requested_scopes": ["worker:execute"]})
            assert rejected.value.status == 401
            accept(grant, {"pid": 12345, "birth_id": "birth-1"})
            assert service._latest_remote_activation(task_id) is None
            raise EOFError("private acceptance reply deliberately lost")

        preparer.acknowledge = accepted_but_reply_lost
        launcher = QualifiedRemoteWorkerLauncher(runtime=service, credentials=None, credential_control=control,
                                                 preparer=preparer, inspector=Inspector(_observation(ref, service)))
        if lost_action == "readiness":
            preparer.await_ready = lambda handle: (_ for _ in ()).throw(ConflictError("capability readiness failed"))
        parked = launcher.park(ref, target=OLD)
        task = service._task_resource(service.store.get_task(task_id))
        if lost_action == "ack":
            result = launcher.activate(task, ref, parked)
            assert launcher.activation_state == "active"
            assert deliveries == [parked.handle]
            token = daemon.worker_credential_path.read_text().strip()
            assert Api(daemon.endpoint, token).request(
                "POST", "/v1/handshake", {"requested_scopes": ["worker:execute"]},
            )["actor_id"] == "astrid-pack-host"
            assert service._latest_remote_activation(task_id) == result
            assert actions == ["provision", "enable"]
            assert service.doctor()["ok"]
        else:
            with pytest.raises((EOFError, ConflictError)):
                launcher.activate(task, ref, parked)
            assert launcher.activation_state == "inactive"
            assert "revoke" in actions
            assert service._latest_remote_activation(task_id) is None
            assert daemon.credentials.actor_metadata("astrid-pack-host") is None
            assert preparer.calls[-1] == "abort"
            with pytest.raises(AuthorizationError):
                daemon.credentials.load("never-enabled-or-already-revoked")
    finally:
        daemon.stop()


def test_resident_remote_credential_is_disabled_until_recorded_activation(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        service = daemon.service
        capability = "remote.activation.credential"
        digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        target = {"kind": "runpod", "pod_id": "pod-1", "provider_account_ref": "account-1"}
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
        assert owner.control_remote_credential(task_id, {"action": "enable", "activation_id": qualification["activation_id"]}) == {"enabled": True}
        assert owner.control_remote_credential(task_id, {"action": "verify", "activation_id": qualification["activation_id"]}) == {"fresh": True}
        assert owner.control_remote_credential(task_id, {"action": "revoke", "activation_id": qualification["activation_id"]}) == {"revoked": True}
        assert service._latest_remote_activation(task_id) is None
        assert daemon.credentials.actor_metadata("astrid-pack-host") is None
        assert owner.control_remote_credential(task_id, {"action": "revoke", "activation_id": qualification["activation_id"]}) == {"revoked": True}
    finally:
        daemon.stop()
