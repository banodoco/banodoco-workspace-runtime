from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
from dataclasses import dataclass, replace
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

import pytest

from astrid.core.execution import generic_host
from astrid.core.execution.generic_host import GenericPackHost, RuntimeProtocolClient
from runtime_protocol.auth import CredentialStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.local_worker import (
    LocalWorkerObservation,
    LocalWorkerProfile,
    ProcessIdentity,
)
from runtime_protocol.store import RealmStore
from source.runtime import supervisor


WORKER_PID = 61001
HOST_PID = os.getpid()
ENGINE_PID = 61003
LISTENER_PID = 61004
MACHINE_ID = "machine-composed-proof"
PROFILE_REVISION = "profile-composed-proof-r1"
PROFILE_DIGEST = "sha256:" + "1" * 64
RELEASE_DIGEST = "sha256:" + "2" * 64
SESSION_DIGEST = "sha256:" + "3" * 64
WORKER_ARTIFACT = "sha256:" + "4" * 64
HOST_ARTIFACT = "sha256:" + "5" * 64
ENGINE_ARTIFACT = "sha256:" + "6" * 64
LISTENER_ARTIFACT = "sha256:" + "7" * 64
WORKER_BIRTH = "worker-birth-composed-proof"
HOST_BIRTH = "host-birth-composed-proof"
ENGINE_BIRTH = "engine-birth-composed-proof"
LISTENER_BIRTH = "listener-birth-composed-proof"


class _HttpActor:
    def __init__(self, endpoint: str, token: str):
        self.endpoint = endpoint.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None, *, key: str | None = None):
        encoded = json.dumps(body).encode() if body is not None else None
        request = Request(self.endpoint + path, data=encoded, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if key is not None:
            request.add_header("Idempotency-Key", key)
        try:
            with urlopen(request, timeout=5) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except HTTPError as exc:
            detail = json.loads(exc.read().decode())
            raise AssertionError(f"HTTP {exc.code}: {detail}") from exc


@dataclass
class _FakePopen:
    """Fake OS process that runs the real Worker control loop in a thread."""

    descriptor: int
    pid: int = WORKER_PID

    def __post_init__(self) -> None:
        self.returncode: int | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.returncode = supervisor._serve_prepared_worker(self.descriptor)

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("fake Worker process did not exit")
        return int(self.returncode or 0)


@dataclass
class _FakePreparedHost:
    operation_id: str
    channel_id: str
    activation: socket.socket
    activation_thread: threading.Thread
    activation_error: list[BaseException]
    activated: bool = False


class _FakeWorkerAdapter:
    """Fake engine/process adapter behind the real private Worker ABI."""

    credentials: CredentialStore
    events: list[str]

    def __init__(self, config, *, environ=None, activation_timeout_seconds=2.0):
        self.config = config
        self.timeout = activation_timeout_seconds
        self.active: _FakePreparedHost | None = None

    def prepare(self, profile, *, operation_id: str, channel_id: str) -> _FakePreparedHost:
        parent, parked_host = socket.socketpair()
        errors: list[BaseException] = []

        def parked_activation() -> None:
            try:
                generic_host._await_worker_activation(
                    parked_host.detach(),
                    operation_id=operation_id,
                    channel_id=channel_id,
                    credential_file=str(self.config.credential_file),
                    timeout_seconds=self.timeout,
                )
            except BaseException as exc:  # surfaced by activate below
                errors.append(exc)

        thread = threading.Thread(target=parked_activation, daemon=True)
        thread.start()
        self.active = _FakePreparedHost(operation_id, channel_id, parent, thread, errors)
        self.events.append("prepare-parked")
        return self.active

    def report(self, handle: object) -> dict[str, object]:
        assert handle is self.active
        self.events.append("worker-report")
        return {
            "version": supervisor.PREPARATION_VERSION,
            "operation_id": handle.operation_id,
            "channel_id": handle.channel_id,
            "processes": {
                "worker": {"pid": WORKER_PID, "birth_id": WORKER_BIRTH},
                "host": {"pid": HOST_PID, "birth_id": HOST_BIRTH},
                "engine": {"pid": ENGINE_PID, "birth_id": ENGINE_BIRTH},
                "engine_listener": {"pid": LISTENER_PID, "birth_id": LISTENER_BIRTH},
            },
            "engine_binding": {
                "supervisor_pid": ENGINE_PID,
                "listener_pid": LISTENER_PID,
                "listener_parent_pid": ENGINE_PID,
                "socket_owner_pid": LISTENER_PID,
            },
            "session_config_digest": SESSION_DIGEST,
        }

    def activate(self, handle: object, grant: dict[str, object]) -> None:
        assert handle is self.active
        token = self.config.credential_file.read_text(encoding="utf-8").strip()
        assert self.credentials.actor_metadata("astrid-pack-host") is not None
        with pytest.raises(AuthorizationError):
            self.credentials.load(token)
        self.events.append("credential-issued-disabled")
        wire = {
            **grant,
            "host": {"pid": HOST_PID, "birth_id": HOST_BIRTH},
        }
        handle.activation.sendall(json.dumps(wire, sort_keys=True).encode() + b"\n")
        frame = bytearray()
        while b"\n" not in frame:
            chunk = handle.activation.recv(4096)
            assert chunk, handle.activation_error
            frame.extend(chunk)
        accepted = json.loads(bytes(frame).split(b"\n", 1)[0].decode())
        assert accepted["operation_id"] == handle.operation_id
        assert accepted["channel_id"] == handle.channel_id
        assert accepted["executor_incarnation"] == grant["executor_incarnation"]
        handle.activation.close()
        handle.activation_thread.join(timeout=2)
        assert not handle.activation_thread.is_alive()
        assert not handle.activation_error
        handle.activated = True
        self.events.append("private-activation-accepted")

    def abort(self, handle: object) -> None:
        if handle is not self.active:
            return
        try:
            handle.activation.close()
        finally:
            handle.activation_thread.join(timeout=2)
            self.events.append("abort")
            self.active = None

    def reconnect(self, receipt: dict[str, object]) -> object | None:
        if self.active is not None and self.active.activated:
            self.events.append("reconnect")
            return self.active
        return None


class _FakeInspector:
    def __init__(self, observation: LocalWorkerObservation, events: list[str]):
        self.observation = observation
        self.events = events

    def observe(self, handle: object) -> LocalWorkerObservation:
        self.events.append("independent-observation")
        return self.observation


def _profile(root: Path, support: Path, realm_id: str) -> LocalWorkerProfile:
    return LocalWorkerProfile(
        profile_id="composed-proof-profile",
        workspace_uuid=realm_id,
        realm_root=root,
        support_root=support,
        machine_id=MACHINE_ID,
        worker_executable=Path("/fake/worker-python"),
        host_executable=Path("/fake/astrid-python"),
        engine_executable=Path("/fake/vibecomfy-daemon"),
        engine_listener_executable=Path("/fake/comfy-listener"),
        engine_endpoint="http://127.0.0.1:8188",
        worker_artifact_digest=WORKER_ARTIFACT,
        host_artifact_digest=HOST_ARTIFACT,
        engine_artifact_digest=ENGINE_ARTIFACT,
        engine_listener_artifact_digest=LISTENER_ARTIFACT,
        session_config_digest=SESSION_DIGEST,
        profile_revision=PROFILE_REVISION,
        profile_digest=PROFILE_DIGEST,
        release_digest=RELEASE_DIGEST,
    )


def _observation(root: Path, support: Path, realm_id: str) -> LocalWorkerObservation:
    uid = os.getuid()
    return LocalWorkerObservation(
        machine_id=MACHINE_ID,
        uid=uid,
        workspace_uuid=realm_id,
        realm_root=root,
        support_root=support,
        worker=ProcessIdentity(WORKER_PID, WORKER_BIRTH, uid, os.getpid(), WORKER_PID, WORKER_PID, Path("/fake/worker-python"), WORKER_ARTIFACT),
        host=ProcessIdentity(HOST_PID, HOST_BIRTH, uid, WORKER_PID, HOST_PID, HOST_PID, Path("/fake/astrid-python"), HOST_ARTIFACT),
        engine=ProcessIdentity(ENGINE_PID, ENGINE_BIRTH, uid, WORKER_PID, ENGINE_PID, ENGINE_PID, Path("/fake/vibecomfy-daemon"), ENGINE_ARTIFACT),
        engine_listener=ProcessIdentity(LISTENER_PID, LISTENER_BIRTH, uid, ENGINE_PID, ENGINE_PID, ENGINE_PID, Path("/fake/comfy-listener"), LISTENER_ARTIFACT),
        engine_listener_socket_owner_pid=LISTENER_PID,
        engine_endpoint="http://127.0.0.1:8188",
        session_config_digest=SESSION_DIGEST,
    )


def _target() -> dict[str, object]:
    return {
        "kind": "machine",
        "id": MACHINE_ID,
        "profile_revision": PROFILE_REVISION,
        "profile_digest": PROFILE_DIGEST,
        "release_digest": RELEASE_DIGEST,
    }


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _fixture_record(capability: str, digest: str):
    return SimpleNamespace(
        id=capability,
        capability_digest=digest,
        source_digest="sha256:" + "8" * 64,
        dependency_digest="sha256:" + "9" * 64,
        source_root=Path.cwd(),
        matrix={"adapter_family": "cpu"},
        resource_keys=(),
        estimated_scratch_bytes=0,
        estimated_output_bytes=64,
        adapter=SimpleNamespace(family="cpu"),
        ready=True,
        manifest=lambda: {"id": capability, "ready": True},
    )


def test_i06_composed_runtime_worker_astrid_proof(monkeypatch, tmp_path: Path) -> None:
    """Compose the existing owner, private Worker, Astrid, HTTP and fence seams.

    The OS/process/VibeComfy/engine facts are deliberately fake. Runtime's
    CredentialStore, HTTP server, claim/binding authority, generated Astrid
    client, and settlement/output store are real. This test makes no GPU claim.
    """

    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir()
    support.mkdir()
    realm_id = "realm-composed-proof-" + uuid.uuid4().hex
    RealmStore.initialize(root, realm_id=realm_id).close()
    profile = _profile(root, support, realm_id)
    events: list[str] = []

    fake_processes = {
        WORKER_PID: WORKER_BIRTH,
        HOST_PID: HOST_BIRTH,
        ENGINE_PID: ENGINE_BIRTH,
        LISTENER_PID: LISTENER_BIRTH,
    }
    monkeypatch.setattr(supervisor.LocalWorkerProcessPreparer, "_birth", staticmethod(lambda pid: fake_processes[pid]))
    monkeypatch.setattr(generic_host, "process_birth_identity", lambda pid=None: HOST_BIRTH)
    monkeypatch.setattr(supervisor, "LocalWorkerPreparerAdapter", _FakeWorkerAdapter)

    config = supervisor.HostLaunchConfig(
        host_python=Path("/fake/astrid-python"),
        source_checkout=tmp_path / "astrid-source",
        pack_root=tmp_path / "astrid-pack",
        runtime_endpoint="http://127.0.0.1:0",
        credential_file=support / "credentials" / "astrid-pack-host.token",
        support_root=support,
        runtime_instance_id="runtime-instance-composed-proof",
        ready_file=support / "ready.json",
        state_file=support / "state.json",
        boot_manifest_path=support / "boot-manifest.json",
        boot_manifest_hash="sha256:" + "a" * 64,
    )
    preparer = supervisor.LocalWorkerProcessPreparer(config, environ={}, timeout_seconds=2)
    preparer.control_alive = lambda handle: getattr(preparer, "_active", None) is handle
    preparer.current_handle = lambda: getattr(preparer, "_active", None)
    inspector = _FakeInspector(_observation(root, support, realm_id), events)
    daemon = RuntimeDaemon(
        root,
        support_root=support,
        host="127.0.0.1",
        port=0,
        realm_id=realm_id,
        production_worker_credentials=True,
        local_worker_profiles={profile.profile_id: profile},
        local_worker_preparer=preparer,
        local_worker_inspector=inspector,
    )
    try:
        daemon.start()
        # Patch subprocess.Popen only after RuntimeDaemon's own OS discovery
        # has completed; supervisor.subprocess is the stdlib module object.
        def fake_popen(*args, **kwargs):
            (descriptor,) = kwargs["pass_fds"]
            return _FakePopen(os.dup(descriptor))

        monkeypatch.setattr(supervisor.subprocess, "Popen", fake_popen)
        preparer.config = replace(config, runtime_endpoint=daemon.endpoint)
        _FakeWorkerAdapter.credentials = daemon.credentials
        _FakeWorkerAdapter.events = events

        owner = _HttpActor(daemon.endpoint, daemon.token)
        launch = owner.request(
            "POST",
            "/v1/control/local-worker/start",
            {"profile_id": profile.profile_id, "expected_workspace_uuid": realm_id},
        )
        assert launch["state"] == "active"
        assert events.index("prepare-parked") < events.index("credential-issued-disabled") < events.index("private-activation-accepted")
        assert events[:2] == ["prepare-parked", "worker-report"]
        assert events.count("independent-observation") >= 4

        credential_path = daemon.credentials.path_for("astrid-pack-host")
        token = credential_path.read_text(encoding="utf-8").strip()
        events.append("astrid-credential-read")
        client = RuntimeProtocolClient(daemon.endpoint, token)
        generic_host._await_enabled_runtime_credential(client, timeout_seconds=2)

        capability = "fixture.execute"
        capability_digest = _digest(capability.encode())
        host = GenericPackHost(pack_roots=[], client=client, executor_id="astrid-pack-host")
        record = _fixture_record(capability, capability_digest)
        host.capabilities = {capability: record}
        host.source_epoch = "fixture-source-epoch-1"
        host.preflight = lambda capability_id=None: (record,)
        registration = host.register()
        events.append("astrid-register-ready")
        assert registration["registration"].executor_id == "astrid-pack-host"
        assert registration["capabilities"][0]["ready"] is True

        target = _target()
        task_response = owner.request(
            "POST",
            "/v1/tasks",
            {
                "capability_id": capability,
                "capability_digest": capability_digest,
                "input_object_ids": [],
                "spec": {"params": {"boundary": "fake-engine"}},
                "execution_request": {"schema_version": 1, "target": target, "inputs": []},
            },
            key="composed-proof-task",
        )
        task_id = task_response["data"]["task_id"]
        claim = client.claim_next(
            executor_id="astrid-pack-host",
            capability_ids=[capability],
            idempotency_key="composed-proof-claim",
            target=target,
        )
        events.append("http-claim")
        assert claim is not None
        assert claim.execution_binding["actual_target"] == target
        assert claim.execution_binding["executor_incarnation"] == launch["executor_incarnation"]
        assert claim.task_id == task_id
        events.append("runtime-binding-verified")

        output = b"fake-engine-output-no-gpu"
        events.append("fake-engine-execution")
        settled = client.settle(
            task_id,
            claim.lease_id,
            result={
                "engine": "fake",
                "diagnostic": {
                    "boundary": "simulated-process-socket-clock-engine",
                    "gpu_claim": False,
                },
            },
            outputs=[
                {
                    "name": "output",
                    "kind": "object",
                    "digest": _digest(output),
                    "media_type": "application/octet-stream",
                    "size": len(output),
                    "data_base64": base64.b64encode(output).decode("ascii"),
                }
            ],
            effect=None,
            attempt_id=claim.attempt_id,
            fence=claim.fence,
        )
        events.append("fenced-settlement-receipt")
        assert settled["state"] == "succeeded"
        assert settled["result"]["outputs"][0]["digest"] == _digest(output)
        assert settled["result"]["diagnostic"]["gpu_claim"] is False
        assert settled["execution_binding"]["status"] == "released"

        second_start = owner.request(
            "POST",
            "/v1/control/local-worker/start",
            {"profile_id": profile.profile_id, "expected_workspace_uuid": realm_id},
        )
        assert second_start["state"] == "reconnected"
        assert second_start["executor_incarnation"] == launch["executor_incarnation"]
        assert second_start["evidence_digest"] == launch["evidence_digest"]
        assert events[-2:] == ["reconnect", "independent-observation"]

        assert events.index("private-activation-accepted") < events.index("astrid-credential-read") < events.index("astrid-register-ready") < events.index("http-claim") < events.index("runtime-binding-verified") < events.index("fake-engine-execution") < events.index("fenced-settlement-receipt")
    finally:
        if preparer._active is not None:
            preparer.abort(preparer._active)
        daemon.stop()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("machine_id", "wrong-machine"),
        ("workspace_uuid", "wrong-realm"),
        ("realm_root", Path("/wrong/root")),
        ("support_root", Path("/wrong/support")),
        ("host_parent_pid", WORKER_PID + 1),
        ("listener_parent_pid", ENGINE_PID + 1),
        ("listener_socket_owner", ENGINE_PID),
        ("host_artifact", "sha256:" + "f" * 64),
    ],
)
def test_i06_composed_identity_mutations_fail_before_issue(tmp_path: Path, field: str, value: object) -> None:
    """The existing owner-side observer remains the only placement authority."""

    from runtime_protocol.local_worker import LocalWorkerLauncher

    root = tmp_path / "realm"
    support = tmp_path / "support"
    base_profile = _profile(root, support, "realm")
    base_observation = _observation(root, support, "realm")
    if field in {"machine_id", "workspace_uuid", "realm_root", "support_root"}:
        observation = replace(base_observation, **{field: value})
    elif field == "host_parent_pid":
        observation = replace(base_observation, host=replace(base_observation.host, parent_pid=value))
    elif field == "listener_parent_pid":
        observation = replace(base_observation, engine_listener=replace(base_observation.engine_listener, parent_pid=value))
    elif field == "listener_socket_owner":
        observation = replace(base_observation, engine_listener_socket_owner_pid=value)
    else:
        observation = replace(base_observation, host=replace(base_observation.host, artifact_digest=value))

    credentials = CredentialStore(support / "credentials")
    handle = object()
    preparer = SimpleNamespace(
        prepare=lambda profile, operation_id, channel_id: handle,
        report=lambda handle: {
            "version": "runtime.local-worker-preparation/v2",
            "operation_id": "op",
            "channel_id": "chan",
            "processes": {},
            "engine_binding": {},
            "session_config_digest": SESSION_DIGEST,
        },
        activate=lambda handle, grant: pytest.fail("invalid identity was issued a grant"),
        abort=lambda handle: None,
        reconnect=lambda receipt: None,
        control_alive=lambda candidate: candidate is handle,
        current_handle=lambda: handle,
    )
    launcher = LocalWorkerLauncher(
        credentials=credentials,
        profiles={base_profile.profile_id: base_profile},
        preparer=preparer,
        inspector=SimpleNamespace(observe=lambda handle: observation),
        workspace_uuid="realm",
        realm_root=root,
        support_root=support,
        runtime_pid=os.getpid(),
        actor="astrid-pack-host",
        scopes=("worker:execute",),
    )
    with pytest.raises((ConflictError, AssertionError)):
        launcher.start(base_profile.profile_id, "realm")
    assert credentials.actor_metadata("astrid-pack-host") is None
