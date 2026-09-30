"""Owner acceptance ordering and recovery, independent of public health."""

import copy
import json
import os
import sqlite3
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.auth import CredentialStore
from runtime_protocol.remote_worker_deployment import deployment_binding_from_task
from runtime_protocol.remote_worker_activation import QualifiedRemoteWorkerLauncher
from tests.test_remote_worker_activation import (
    OLD, OWNER, Inspector, Preparer, _claim, _fixture, _identity, _observation, _reference, _service,
)


def _task(service, task_id):
    return service._task_resource(service.store.get_task(task_id))


def _record(service, task_id):
    return next(payload for kind, payload in service._remote_grant_events(task_id)
                if kind == "task.remote_activation_granted")


def _ack(grant):
    return {key: grant[key] for key in ("activation_id", "executor_incarnation", "evidence_digest")}


@pytest.mark.parametrize("lost_reply", [BrokenPipeError, EOFError, ConflictError])
def test_acceptance_is_durable_before_reply_loss_and_same_incarnation_recovers(tmp_path, lost_reply):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        deliveries = []

        def lose_ack(handle, grant, *, accept):
            deliveries.append(handle)
            token = credentials.path_for("host").read_text().strip()
            with pytest.raises(AuthorizationError):
                credentials.require(token, "worker:execute")
            accept(grant, {"pid": 12345, "birth_id": "birth-1"})
            # A second connection sees the committed acceptance before an ACK
            # exists. Liveness and the launcher's return value cannot supply it.
            with sqlite3.connect(service.store.db_path) as reader:
                payload = reader.execute(
                    "SELECT payload_json FROM events WHERE task_id=? AND kind=?",
                    (task_id, "task.remote_activation_accepted"),
                ).fetchone()
            assert json.loads(payload[0]) == {"activation_id": grant["activation_id"]}
            assert service._latest_remote_activation(task_id) is None
            raise lost_reply("deliberately dropped private ACK")

        preparer.acknowledge = lose_ack
        qualification = launcher.activate(_task(service, task_id), ref, parked)
        assert deliveries == [parked.handle]
        assert inspector.calls == 4
        assert launcher.activation_state == "active"
        assert stat.S_IMODE(service.store.db_path.stat().st_mode) == 0o600
        record = _record(service, task_id)
        assert record["process"] == {"pid": 12345, "birth_id": "birth-1"}
        assert record["qualification"] == qualification
        service._recover_remote_grant(task_id, record, identity=OWNER)
        service._recover_remote_grant(task_id, record, identity=OWNER)
        with pytest.raises(ConflictError, match="duplicate"):
            service._accept_remote_grant(task_id, record, identity=OWNER)
        assert _claim(service, OLD, _identity(credentials), "recovered-claim")["task_id"] == task_id
    finally:
        service.close()


@pytest.mark.parametrize("reply_lost", [False, True])
def test_live_host_without_acceptance_never_enables_and_is_cleaned(tmp_path, reply_lost):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        cleaned = []

        def no_acceptance(handle, grant, *, accept):
            if reply_lost:
                raise EOFError("no acceptance committed")
            return _ack(grant)

        preparer.acknowledge = no_acceptance
        preparer.abort = cleaned.append
        with pytest.raises(ConflictError, match="acceptance is missing"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert cleaned == [parked.handle]
        assert launcher.activation_state == "inactive"
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert service.task(task_id)["task"]["status"] == "queued"
        with pytest.raises(ConflictError, match="already used"):
            launcher.activate(_task(service, task_id), ref, parked)
    finally:
        service.close()


@pytest.mark.parametrize("field", ["activation_id", "executor_incarnation", "evidence_digest", "credential_file",
                                  "pid", "birth_id"])
def test_receiver_must_accept_exact_grant_and_pid_birth(tmp_path, field):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def wrong_acceptance(handle, grant, *, accept):
            process = {"pid": 12345, "birth_id": "birth-1"}
            if field in process:
                process[field] = 54321 if field == "pid" else "other-birth"
            else:
                # Mutate the transport's grant itself; the protected digest
                # must still reject it rather than comparing two aliases.
                grant[field] = "wrong"
            accept(grant, process)
            return _ack(grant)

        preparer.acknowledge = wrong_acceptance
        with pytest.raises(ConflictError, match="exact grant or process"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert not any(kind == "task.remote_activation_accepted"
                       for kind, _ in service._remote_grant_events(task_id))
        assert credentials.actor_metadata("host") is None
        assert preparer.calls[-1] == "abort"
    finally:
        service.close()


@pytest.mark.parametrize("change", ["birth_id", "pid", "source_closure_digest", "runtime_session", "epoch", "expiry", "revoke"])
def test_accepted_lost_reply_cannot_recover_changed_or_stale_evidence(tmp_path, monkeypatch, change):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def stale_after_acceptance(handle, grant, *, accept):
            accept(grant, {"pid": 12345, "birth_id": "birth-1"})
            if change in {"birth_id", "pid"}:
                inspector.current["process"][change] = 54321 if change == "pid" else "reused-pid-birth"
            elif change == "source_closure_digest":
                inspector.current[change] = "sha256:" + "f" * 64
            elif change == "runtime_session":
                monkeypatch.setattr(service, "runtime_session_id", "different-runtime-session")
            elif change == "epoch":
                next_epoch = service.store._current_runtime_epoch() + 1
                monkeypatch.setattr(service.store, "_current_runtime_epoch", lambda: next_epoch)
            elif change == "expiry":
                class Later(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return datetime.now(timezone.utc) + timedelta(hours=2)
                monkeypatch.setattr("runtime_protocol.service.datetime", Later)
            else:
                service._revoke_remote_grant(task_id, grant["activation_id"], identity=OWNER)
            raise BrokenPipeError("reply lost after acceptance")

        preparer.acknowledge = stale_after_acceptance
        with pytest.raises(ConflictError):
            launcher.activate(_task(service, task_id), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
        assert launcher.activation_state == "inactive"
        assert preparer.calls[-1] == "abort"
    finally:
        service.close()


def test_duplicate_retry_preserves_active_generation_and_owner_receipt_is_protected(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        task = _task(service, task_id)
        qualification = launcher.activate(task, ref, parked)
        token = credentials.path_for("host").read_text()
        retry = QualifiedRemoteWorkerLauncher(runtime=service, credentials=credentials,
                                             preparer=preparer, inspector=inspector)
        with pytest.raises(ConflictError, match="already used"):
            retry.activate(task, ref, parked)
        assert credentials.path_for("host").read_text() == token
        assert _identity(credentials)["qualified_activation"] == qualification
        assert preparer.calls == ["prepare", "private_ack"]
        with pytest.raises(AuthorizationError):
            service._recover_remote_grant(task_id, _record(service, task_id), identity=_identity(credentials))
        mismatched = copy.deepcopy(_record(service, task_id))
        mismatched["grant_digest"] = "sha256:" + "f" * 64
        with pytest.raises(ConflictError, match="mismatched"):
            service._recover_remote_grant(task_id, mismatched, identity=OWNER)
    finally:
        service.close()


def test_duplicate_receiver_acceptance_is_not_reinterpreted_as_reply_loss(tmp_path):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def twice(handle, grant, *, accept):
            for _ in range(2):
                accept(grant, {"pid": 12345, "birth_id": "birth-1"})
            return _ack(grant)

        preparer.acknowledge = twice
        with pytest.raises(ConflictError, match="duplicate"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert launcher.activation_state == "inactive"
    finally:
        service.close()


@pytest.mark.parametrize("failure", ["abort", "revoke", "event"])
@pytest.mark.parametrize("after_enable", [False, True])
def test_cleanup_failure_reports_unknown_and_keeps_execution_disabled(tmp_path, monkeypatch, failure, after_enable):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def fail(*args, **kwargs):
            raise OSError("cleanup could not be confirmed")

        if failure == "abort":
            preparer.abort = fail
        elif failure == "revoke":
            monkeypatch.setattr(credentials, "revoke", fail)
        else:
            monkeypatch.setattr(service, "_revoke_remote_grant", fail)
        if after_enable:
            preparer.await_ready = fail
        else:
            preparer.acknowledge = fail
        with pytest.raises((ConflictError, OSError)):
            launcher.activate(_task(service, task_id), ref, parked)
        assert launcher.activation_state == "unknown"
        if credentials.actor_metadata("host") is not None:
            with pytest.raises(AuthorizationError):
                credentials.load(credentials.path_for("host").read_text().strip())
        if failure == "event" and after_enable:
            assert service._latest_remote_activation(task_id) is not None
        else:
            assert service._latest_remote_activation(task_id) is None
    finally:
        service.close()


def test_machine_observation_requires_one_host_without_provider_or_supervisor(tmp_path):
    service, task_id = _service(tmp_path)
    try:
        # Admit a machine placement through existing Runtime authority.
        target = {"kind": "machine", "id": "cpu-machine"}
        original = _task(service, task_id)
        task_id = service.create_task({
            "capability_id": original["capability_id"], "capability_digest": original["capability_digest"],
            "input_object_ids": [], "spec": {}, "idempotency_key": "machine-acceptance",
            "execution_request": {"schema_version": 1, "target": target},
        }, enforce_readiness=True)["task"]["id"]
        # _reference only supplies the remote target labels; replace them with
        # machine labels while retaining the admitted binding unchanged.
        old_ref = _reference(tmp_path, service, original["task_id"])
        binding = deployment_binding_from_task(_task(service, task_id))
        ref = replace(old_ref, task_id=task_id, run_id=binding.admission_identity.run_id,
                      admission_identity=binding.admission_identity, capability_identity=binding.capability_identity,
                      input_bindings=binding.input_bindings, target_ref="machine:cpu-machine",
                      effective_target_ref="machine:cpu-machine", original_target=target,
                      effective_target=target, execution_target=target)
        observation = _observation(old_ref, service)
        observation["target"] = target
        del observation["provider_identity"], observation["child"]
        observation["machine_identity"] = {"id": "cpu-machine", "uid": os.getuid()}
        observation["process"].update(uid=os.getuid(), executable=str(ref.executable.path),
                                      artifact_digest=ref.executable.digest)
        credentials = CredentialStore(tmp_path / "machine-credentials")
        preparer = Preparer()
        launcher = QualifiedRemoteWorkerLauncher(runtime=service, credentials=credentials,
                                                 preparer=preparer, inspector=Inspector(observation))
        parked = launcher.park(ref, target=target)
        result = launcher.activate(_task(service, task_id), ref, parked)
        assert result["effective_target"] == target
        assert launcher.activation_state == "active"
        assert _claim(service, target, _identity(credentials), "machine-claim")["task_id"] == task_id
    finally:
        service.close()


def test_acceptance_commit_failure_cannot_be_treated_as_a_lost_reply(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        append = service.store._append_event

        def fail_receipt(run, task, kind, payload, **kwargs):
            if kind == "task.remote_activation_accepted":
                raise OSError("acceptance could not be committed")
            return append(run, task, kind, payload, **kwargs)

        monkeypatch.setattr(service.store, "_append_event", fail_receipt)
        with pytest.raises(OSError, match="could not be committed"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert launcher.activation_state == "inactive"
        assert not any(kind == "task.remote_activation_accepted"
                       for kind, _ in service._remote_grant_events(task_id))
        assert service.doctor()["ok"]
    finally:
        service.close()


def test_reserved_generation_cannot_qualify_without_its_acceptance_receipt(tmp_path):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)

        def qualify_early(handle, grant, *, accept):
            record = _record(service, task_id)
            service.record_remote_activation(task_id, record["qualification"], identity=OWNER)

        preparer.acknowledge = qualify_early
        with pytest.raises(ConflictError, match="acceptance is missing"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert credentials.actor_metadata("host") is None
        assert service._latest_remote_activation(task_id) is None
    finally:
        service.close()


def test_readiness_rejects_a_credential_that_authenticates_while_disabled(tmp_path, monkeypatch):
    service, task_id, ref, credentials, preparer, _inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        provision = credentials.provision

        def enabled_by_mistake(*args, **kwargs):
            return provision(*args, **{**kwargs, "enabled": True})

        monkeypatch.setattr(credentials, "provision", enabled_by_mistake)
        with pytest.raises(ConflictError, match="authenticated before acceptance"):
            launcher.activate(_task(service, task_id), ref, parked)
        assert preparer.calls == ["prepare", "abort"]
        assert credentials.actor_metadata("host") is None
        assert launcher.activation_state == "inactive"
    finally:
        service.close()


def test_incarnation_cannot_be_regranted_to_another_task(tmp_path):
    service, task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        parked = launcher.park(ref, target=OLD)
        qualification = launcher.activate(_task(service, task_id), ref, parked)
        task = _task(service, task_id)
        another_id = service.create_task({
            "capability_id": task["capability_id"], "capability_digest": task["capability_digest"],
            "input_object_ids": [], "spec": {}, "idempotency_key": "another-task-same-host",
            "execution_request": {"schema_version": 1, "target": OLD},
        }, enforce_readiness=True)["task"]["id"]
        retry = QualifiedRemoteWorkerLauncher(runtime=service, credentials=credentials,
                                             preparer=preparer, inspector=inspector)
        with pytest.raises(ConflictError, match="already used"):
            retry.activate(_task(service, another_id), _reference(tmp_path, service, another_id), parked)
        assert _identity(credentials)["qualified_activation"] == qualification
        assert preparer.calls == ["prepare", "private_ack"]
        assert service._latest_remote_activation(another_id) is None
    finally:
        service.close()


@pytest.mark.parametrize("digest", ["source_closure_digest", "dependency_closure_digest", "model_inventory_digest", "session_config_digest"])
def test_missing_digest_evidence_aborts_park_without_issuing_credentials(tmp_path, digest):
    service, _task_id, ref, credentials, preparer, inspector, launcher = _fixture(tmp_path)
    try:
        inspector.current[digest] = ""
        with pytest.raises(ConflictError, match="digest evidence is missing"):
            launcher.park(ref, target=OLD)
        assert credentials.actor_metadata("host") is None
        assert preparer.calls == ["prepare", "abort"]
    finally:
        service.close()
