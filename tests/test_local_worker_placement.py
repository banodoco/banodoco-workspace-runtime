from __future__ import annotations

import os
import threading
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.auth import AuthorizationError, CredentialStore
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker import (
    PREPARATION_VERSION,
    LocalWorkerLauncher,
    LocalWorkerObservation,
    LocalWorkerProfile,
    ProcessIdentity,
)
from runtime_protocol.store import RealmStore


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _profile(tmp_path, workspace_uuid: str) -> LocalWorkerProfile:
    return LocalWorkerProfile(
        profile_id="astrid",
        workspace_uuid=workspace_uuid,
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        machine_id="machine-local",
        worker_executable=tmp_path / "worker-python",
        host_executable=tmp_path / "host-python",
        engine_executable=tmp_path / "vibecomfy-daemon-python",
        engine_listener_executable=tmp_path / "comfy-listener-python",
        worker_artifact_digest=_digest("a"),
        host_artifact_digest=_digest("b"),
        engine_artifact_digest=_digest("c"),
        engine_listener_artifact_digest=_digest("7"),
        session_config_digest=_digest("d"),
        profile_revision="profile-r1",
        profile_digest=_digest("e"),
        release_digest=_digest("f"),
    )


def _process(pid, parent, executable, digest, *, group=None, session=None) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        birth_id=f"birth-{pid}",
        uid=os.getuid(),
        parent_pid=parent,
        process_group=pid if group is None else group,
        session_id=pid if session is None else session,
        executable=executable,
        artifact_digest=digest,
    )


def _observation(profile: LocalWorkerProfile, runtime_pid: int, *, base=1000) -> LocalWorkerObservation:
    worker = _process(base, runtime_pid, profile.worker_executable, profile.worker_artifact_digest)
    host = _process(base + 1, base, profile.host_executable, profile.host_artifact_digest)
    engine = _process(base + 2, base, profile.engine_executable, profile.engine_artifact_digest)
    engine_listener = _process(
        base + 3,
        engine.pid,
        profile.engine_listener_executable,
        profile.engine_listener_artifact_digest,
        group=engine.pid,
        session=engine.pid,
    )
    return LocalWorkerObservation(
        machine_id=profile.machine_id,
        uid=os.getuid(),
        workspace_uuid=profile.workspace_uuid,
        realm_root=profile.realm_root,
        support_root=profile.support_root,
        worker=worker,
        host=host,
        engine=engine,
        engine_listener=engine_listener,
        engine_listener_socket_owner_pid=engine_listener.pid,
        session_config_digest=profile.session_config_digest,
    )


class FakePreparer:
    """Fake boundary: no OS process or engine is started by these tests."""

    def __init__(self, store, observation, *, reconnect=True):
        self.store = store
        self.observation = observation
        self.reconnect_enabled = reconnect
        self.events = []
        self.operation_id = self.channel_id = None
        self.aborted = False

    def prepare(self, _profile, *, operation_id, channel_id):
        assert self.store.actor_metadata(WORKER_ACTOR) is None
        self.operation_id, self.channel_id = operation_id, channel_id
        self.events.append("prepare")
        return object()

    def report(self, _handle):
        self.events.append("report")
        return {
            "version": PREPARATION_VERSION,
            "operation_id": self.operation_id,
            "channel_id": self.channel_id,
            "processes": {
                name: {"pid": value.pid, "birth_id": value.birth_id}
                for name, value in (
                    ("worker", self.observation.worker),
                    ("host", self.observation.host),
                    ("engine", self.observation.engine),
                    ("engine_listener", self.observation.engine_listener),
                )
            },
            "engine_binding": {
                "supervisor_pid": self.observation.engine.pid,
                "listener_pid": self.observation.engine_listener.pid,
                "listener_parent_pid": self.observation.engine_listener.parent_pid,
                "socket_owner_pid": self.observation.engine_listener_socket_owner_pid,
            },
            "session_config_digest": self.observation.session_config_digest,
        }

    def activate(self, _handle, grant):
        token = self.store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        identity = self.store.actor_metadata(WORKER_ACTOR)
        assert identity["execution_binding"]["executor_incarnation"] == grant["executor_incarnation"]
        with pytest.raises(AuthorizationError):
            self.store.load(token)
        self.events.append("activate")

    def abort(self, _handle):
        self.aborted = True
        self.events.append("abort")

    def reconnect(self, _receipt):
        self.events.append("reconnect")
        return object() if self.reconnect_enabled else None


class FakeInspector:
    """Fake boundary: returns deterministic independent OS observations."""

    def __init__(self, store, observation, *, assert_unissued=True):
        self.store = store
        self.observation = observation
        self.assert_unissued = assert_unissued
        self.calls = 0

    def observe(self, _handle):
        self.calls += 1
        if self.assert_unissued and self.calls <= 2:
            assert self.store.actor_metadata(WORKER_ACTOR) is None
        elif self.calls >= 3:
            token = self.store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
            with pytest.raises(AuthorizationError):
                self.store.load(token)
        return self.observation


def _launcher(store, profile, preparer, inspector, runtime_pid):
    return LocalWorkerLauncher(
        credentials=store,
        profiles={profile.profile_id: profile},
        preparer=preparer,
        inspector=inspector,
        workspace_uuid=profile.workspace_uuid,
        realm_root=profile.realm_root,
        support_root=profile.support_root,
        runtime_pid=runtime_pid,
        actor=WORKER_ACTOR,
        scopes=WORKER_SCOPES,
    )


def test_owner_transaction_issues_only_after_two_observations_then_activates(tmp_path):
    workspace_uuid = str(uuid.uuid4())
    profile = _profile(tmp_path, workspace_uuid)
    store = CredentialStore(tmp_path / "credentials")
    observed = _observation(profile, 77)
    preparer = FakePreparer(store, observed)
    inspector = FakeInspector(store, observed)

    result = _launcher(store, profile, preparer, inspector, 77).start("astrid", workspace_uuid)

    assert result["state"] == "active"
    assert inspector.calls == 4
    assert preparer.events == ["prepare", "report", "activate"]
    metadata = store.actor_metadata(WORKER_ACTOR)
    receipt = metadata["local_launch_receipt"]
    assert metadata["execution_binding"]["actual"]["kind"] == "machine"
    assert metadata["execution_binding"]["verification"]["evidence_digest"] == result["evidence_digest"]
    assert receipt["executor_incarnation"] == result["executor_incarnation"]
    assert receipt["engine"]["pid"] == observed.engine.pid
    assert receipt["engine_listener"]["pid"] == observed.engine_listener.pid
    assert receipt["engine_binding"] == {
        "supervisor_pid": observed.engine.pid,
        "listener_pid": observed.engine_listener.pid,
        "listener_parent_pid": observed.engine.pid,
        "socket_owner_pid": observed.engine_listener.pid,
    }
    assert observed.engine_listener.process_group == observed.engine.pid
    assert observed.engine_listener.session_id == observed.engine.pid
    token = store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
    assert store.load(token)["execution_binding"]["executor_incarnation"] == result["executor_incarnation"]


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda value: replace(value, machine_id="other-machine"), "machine identity"),
        (lambda value: replace(value, workspace_uuid=str(uuid.uuid4())), "workspace identity"),
        (lambda value: replace(value, realm_root=value.realm_root.parent / "other"), "roots"),
        (lambda value: replace(value, support_root=value.support_root.parent / "other"), "roots"),
        (lambda value: replace(value, worker=replace(value.worker, uid=value.worker.uid + 1)), "uid"),
        (lambda value: replace(value, host=replace(value.host, parent_pid=999)), "parent lineage"),
        (lambda value: replace(value, engine=replace(value.engine, session_id=999)), "process group and session"),
        (lambda value: replace(value, host=replace(value.host, executable=Path("/wrong-host"))), "executable pin"),
        (lambda value: replace(value, engine=replace(value.engine, artifact_digest=_digest("9"))), "artifact pin"),
        (
            lambda value: replace(
                value, engine_listener=replace(value.engine_listener, parent_pid=value.worker.pid)
            ),
            "parent lineage",
        ),
        (
            lambda value: replace(
                value, engine_listener=replace(value.engine_listener, executable=Path("/wrong-listener"))
            ),
            "executable pin",
        ),
        (
            lambda value: replace(
                value, engine_listener=replace(value.engine_listener, artifact_digest=_digest("8"))
            ),
            "artifact pin",
        ),
        (lambda value: replace(value, engine_listener_socket_owner_pid=999), "socket"),
        (
            lambda value: replace(
                value,
                engine_listener=replace(
                    value.engine_listener,
                    pid=value.engine.pid,
                    birth_id=value.engine.birth_id,
                ),
            ),
            "distinct",
        ),
        (
            lambda value: replace(
                value,
                engine_listener=replace(value.engine_listener, birth_id=value.engine.birth_id),
            ),
            "report conflicts",
        ),
        (lambda value: replace(value, worker=replace(value.worker, birth_id="reused-pid")), "report conflicts"),
    ],
)
def test_identity_failures_abort_without_credential(tmp_path, change, message):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    canonical = _observation(profile, 77)
    preparer = FakePreparer(store, canonical)
    inspector = FakeInspector(store, change(canonical))

    with pytest.raises(ConflictError, match=message):
        _launcher(store, profile, preparer, inspector, 77).start("astrid", profile.workspace_uuid)

    assert store.actor_metadata(WORKER_ACTOR) is None
    assert preparer.aborted is True


def test_workspace_precondition_and_wrong_channel_fail_before_bearer_activation(tmp_path):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    observed = _observation(profile, 77)
    preparer = FakePreparer(store, observed)
    launcher = _launcher(store, profile, preparer, FakeInspector(store, observed), 77)

    with pytest.raises(ConflictError, match="workspace identity"):
        launcher.start("astrid", str(uuid.uuid4()))
    assert preparer.events == []

    class WrongChannelPreparer(FakePreparer):
        def report(self, handle):
            report = dict(super().report(handle))
            report["channel_id"] = "forged-channel"
            return report

    wrong_channel = WrongChannelPreparer(store, observed)
    with pytest.raises(ConflictError, match="wrong private channel"):
        _launcher(store, profile, wrong_channel, FakeInspector(store, observed), 77).start(
            "astrid", profile.workspace_uuid
        )
    assert store.actor_metadata(WORKER_ACTOR) is None
    assert wrong_channel.aborted is True


def test_forged_listener_binding_report_fails_before_issuance(tmp_path):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    observed = _observation(profile, 77)

    class ForgedBindingPreparer(FakePreparer):
        def report(self, handle):
            report = dict(super().report(handle))
            report["engine_binding"] = dict(report["engine_binding"])
            report["engine_binding"]["socket_owner_pid"] = observed.engine.pid
            return report

    preparer = ForgedBindingPreparer(store, observed)
    with pytest.raises(ConflictError, match="conflicts with engine observation"):
        _launcher(store, profile, preparer, FakeInspector(store, observed), 77).start(
            "astrid", profile.workspace_uuid
        )

    assert store.actor_metadata(WORKER_ACTOR) is None
    assert preparer.aborted is True


def test_restart_reuses_survivor_and_replacement_rotates_bearer(tmp_path):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    first_observation = _observation(profile, 77)
    first_preparer = FakePreparer(store, first_observation)
    first = _launcher(store, profile, first_preparer, FakeInspector(store, first_observation), 77).start("astrid", profile.workspace_uuid)
    first_token = store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")

    # A restarted owner disables the durable bearer before any request can use
    # it, then allows the same surviving process to have been reparented.
    reparented_observation = replace(
        first_observation,
        worker=replace(first_observation.worker, parent_pid=1),
    )
    reconnect_preparer = FakePreparer(store, reparented_observation)
    reconnect_launcher = _launcher(
        store,
        profile,
        reconnect_preparer,
        FakeInspector(store, reparented_observation, assert_unissued=False),
        88,
    )
    with pytest.raises(AuthorizationError):
        store.load(first_token)
    reconnect = reconnect_launcher.start("astrid", profile.workspace_uuid)
    assert reconnect["state"] == "reconnected"
    assert reconnect["executor_incarnation"] == first["executor_incarnation"]
    assert reconnect["evidence_digest"] == first["evidence_digest"]
    assert store.path_for(WORKER_ACTOR).read_text(encoding="utf-8") == first_token
    assert store.load(first_token)["actor"] == WORKER_ACTOR

    replacement_observation = _observation(profile, 77, base=2000)
    replacement_preparer = FakePreparer(store, replacement_observation, reconnect=False)
    replacement = _launcher(store, profile, replacement_preparer, FakeInspector(store, replacement_observation), 77).start("astrid", profile.workspace_uuid)
    assert replacement["executor_incarnation"] != first["executor_incarnation"]
    assert store.path_for(WORKER_ACTOR).read_text(encoding="utf-8") != first_token
    with pytest.raises(AuthorizationError):
        store.load(first_token)


@pytest.mark.parametrize("replacement_field", ["pid", "birth_id"])
def test_reconnect_rejects_listener_replacement(tmp_path, replacement_field):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    observed = _observation(profile, 77)
    first = _launcher(
        store,
        profile,
        FakePreparer(store, observed),
        FakeInspector(store, observed),
        77,
    ).start("astrid", profile.workspace_uuid)
    first_token = store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")

    listener_changes = {
        "pid": {"pid": observed.engine_listener.pid + 100},
        "birth_id": {"birth_id": "replacement-listener-birth"},
    }
    replaced_listener = replace(observed.engine_listener, **listener_changes[replacement_field])
    replaced = replace(
        observed,
        worker=replace(observed.worker, parent_pid=1),
        engine_listener=replaced_listener,
        engine_listener_socket_owner_pid=replaced_listener.pid,
    )
    preparer = FakePreparer(store, replaced)

    with pytest.raises(ConflictError, match="surviving local worker identity changed"):
        _launcher(
            store,
            profile,
            preparer,
            FakeInspector(store, replaced, assert_unissued=False),
            88,
        ).start("astrid", profile.workspace_uuid)

    assert first["state"] == "active"
    assert preparer.aborted is True
    assert store.actor_metadata(WORKER_ACTOR) is None
    with pytest.raises(AuthorizationError):
        store.load(first_token)


def test_death_after_issue_and_activation_failure_revoke_disabled_bearer(tmp_path):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    observed = _observation(profile, 77)

    class DiesBeforeActivation(FakeInspector):
        def observe(self, handle):
            if self.calls == 2:
                self.calls += 1
                raise ProcessLookupError("fake Worker died after issuance")
            return super().observe(handle)

    store = CredentialStore(tmp_path / "death-credentials")
    preparer = FakePreparer(store, observed)
    with pytest.raises(ProcessLookupError, match="after issuance"):
        _launcher(store, profile, preparer, DiesBeforeActivation(store, observed), 77).start(
            "astrid", profile.workspace_uuid
        )
    assert store.actor_metadata(WORKER_ACTOR) is None
    assert preparer.events == ["prepare", "report", "abort"]

    class RejectsActivation(FakePreparer):
        def activate(self, handle, grant):
            self.rejected_token = self.store.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
            with pytest.raises(AuthorizationError):
                self.store.load(self.rejected_token)
            raise RuntimeError("fake activation rejection")

    store = CredentialStore(tmp_path / "activation-credentials")
    preparer = RejectsActivation(store, observed)
    with pytest.raises(RuntimeError, match="activation rejection"):
        _launcher(store, profile, preparer, FakeInspector(store, observed), 77).start(
            "astrid", profile.workspace_uuid
        )
    assert store.actor_metadata(WORKER_ACTOR) is None
    with pytest.raises(AuthorizationError):
        store.load(preparer.rejected_token)
    assert preparer.aborted is True


def test_concurrent_start_is_refused_without_issuing_a_second_bearer(tmp_path):
    profile = _profile(tmp_path, str(uuid.uuid4()))
    store = CredentialStore(tmp_path / "credentials")
    observed = _observation(profile, 77)

    class BlockingPreparer(FakePreparer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.entered = threading.Event()
            self.release = threading.Event()

        def prepare(self, profile, *, operation_id, channel_id):
            handle = super().prepare(profile, operation_id=operation_id, channel_id=channel_id)
            self.entered.set()
            assert self.release.wait(timeout=5), "test did not release fake preparation"
            return handle

    preparer = BlockingPreparer(store, observed)
    launcher = _launcher(store, profile, preparer, FakeInspector(store, observed), 77)
    completed = []
    failed = []

    def run_first():
        try:
            completed.append(launcher.start("astrid", profile.workspace_uuid))
        except Exception as exc:  # pragma: no cover - asserted below
            failed.append(exc)

    thread = threading.Thread(target=run_first, name="fake-local-worker-start")
    thread.start()
    assert preparer.entered.wait(timeout=5), "first fake preparation did not start"
    assert store.actor_metadata(WORKER_ACTOR) is None
    with pytest.raises(ConflictError, match="already in progress"):
        launcher.start("astrid", profile.workspace_uuid)
    assert store.actor_metadata(WORKER_ACTOR) is None
    preparer.release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert failed == []
    assert completed[0]["state"] == "active"
    assert len(list((tmp_path / "credentials").glob("*.token"))) == 1


def test_interrupted_credential_generation_fails_closed(tmp_path, monkeypatch):
    store = CredentialStore(tmp_path / "credentials")
    old_token, _ = store.provision("worker", ["worker:execute"], metadata={"generation": "old"})
    original = store._atomic_replace

    def fail_commit(path, value):
        if path.suffix == ".commit":
            raise OSError("simulated commit interruption")
        return original(path, value)

    monkeypatch.setattr(store, "_atomic_replace", fail_commit)
    with pytest.raises(OSError, match="simulated"):
        store.provision("worker", ["worker:execute"], metadata={"generation": "new"})
    with pytest.raises(AuthorizationError):
        store.load(old_token)


def test_private_owner_route_does_not_take_sqlite_mutex(tmp_path):
    root = tmp_path / "realm"
    initialized = RealmStore.initialize(root)
    workspace_uuid = initialized.realm["id"]
    initialized.close()
    profile = _profile(tmp_path, workspace_uuid)
    store_probe = {}

    class DeferredPreparer(FakePreparer):
        pass

    # The daemon constructs the CredentialStore; bind fakes after start through
    # a tiny proxy that resolves it lazily.
    class StoreProxy:
        def __getattr__(self, name):
            return getattr(store_probe["store"], name)

    proxy = StoreProxy()
    observed = _observation(profile, os.getpid())
    preparer = DeferredPreparer(proxy, observed)
    inspector = FakeInspector(proxy, observed)
    daemon = RuntimeDaemon(
        root,
        support_root=profile.support_root,
        production_worker_credentials=True,
        local_worker_profiles={"astrid": profile},
        local_worker_preparer=preparer,
        local_worker_inspector=inspector,
    ).start()
    store_probe["store"] = daemon.credentials
    try:
        # If the private route entered the service mutex, this request thread
        # would remain blocked until this context exits.
        with daemon.service.store._mutex:
            result = Api(daemon.endpoint, daemon.token).request(
                "POST",
                "/v1/control/local-worker/start",
                {"profile_id": "astrid", "expected_workspace_uuid": workspace_uuid},
            )
        assert result["state"] == "active"
        worker_token = daemon.credentials.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        with pytest.raises(RuntimeError) as forbidden:
            Api(daemon.endpoint, worker_token).request(
                "POST",
                "/v1/control/local-worker/start",
                {"profile_id": "astrid", "expected_workspace_uuid": workspace_uuid},
            )
        assert forbidden.value.status == 401
    finally:
        daemon.stop()
