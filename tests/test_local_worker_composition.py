from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker import LocalWorkerProfile, ProcessIdentity
from runtime_protocol.local_worker_composition import (
    CrossProcessWorkerPreparer,
    OSProcessInspector,
    _PreparedWorker,
    _listening_socket_owner,
    load_local_worker_composition,
)


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _content_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _profile_document(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    source = tmp_path / "astrid"
    packs = source / "astrid" / "packs"
    packs.mkdir(parents=True)
    support = tmp_path / "support"
    support.mkdir()
    boot = support / "boot.json"
    boot.write_text("{}", encoding="utf-8")
    session_root = tmp_path / "vibecomfy" / "out" / "sessions" / "fixture"
    document = {
        "profile_id": "astrid",
        "machine_id": platform.node(),
        "engine_endpoint": "http://127.0.0.1:8188",
        "worker_environment": sys.prefix,
        "worker_executable": str(Path(sys.executable).resolve()),
        "host_executable": str(Path(sys.executable).resolve()),
        "engine_executable": str(Path(sys.executable).resolve()),
        "engine_listener_executable": str(Path(sys.executable).resolve()),
        "worker_artifact_digest": _digest("1"),
        "host_artifact_digest": _digest("2"),
        "engine_artifact_digest": _digest("3"),
        "engine_listener_artifact_digest": _digest("4"),
        "session_config_digest": _digest("5"),
        "profile_revision": "fixture-r1",
        "profile_digest": _digest("6"),
        "release_digest": _digest("7"),
        "source_checkout": str(source),
        "pack_root": str(packs),
        "boot_manifest_path": str(boot),
        "boot_manifest_hash": _digest("8"),
        "environment": {
            "ASTRID_VIBECOMFY_SESSION_DIR": str(session_root),
            "ASTRID_VIBECOMFY_PORT": "8188",
        },
    }
    return document, source, support, packs


def test_factory_derives_runtime_identity_and_roots(tmp_path: Path) -> None:
    document, source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm-from-runtime",
        realm_root=tmp_path / "runtime-realm",
        support_root=support,
        runtime_instance_id="instance-1",
    )
    profile = composition.profiles["astrid"]
    assert profile.workspace_uuid == "realm-from-runtime"
    assert profile.realm_root == (tmp_path / "runtime-realm").resolve()
    assert profile.support_root == support.resolve()
    assert profile.realm_root != source.resolve()
    composition.bind_runtime(endpoint="http://127.0.0.1:1234", runtime_instance_id="instance-2", credential_file=support / "worker.token")
    assert composition.preparer.config["runtime_endpoint"] == "http://127.0.0.1:1234"
    assert composition.preparer.config["runtime_instance_id"] == "instance-2"


def test_factory_rejects_unknown_authority_fields(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["realm_root"] = "/attacker/realm"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="unsupported fields"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_rejects_endpoint_that_disagrees_with_worker_launch_port(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["engine_endpoint"] = "http://127.0.0.1:8189"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="engine_endpoint"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_independent_inspector_rejects_worker_birth_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=support,
        runtime_instance_id="instance",
    )
    profile = composition.profiles["astrid"]
    inspector = OSProcessInspector(profile)
    pid = os.getpid()
    report = {
        "processes": {
            "worker": {"pid": pid, "birth_id": "worker-claim"},
            "host": {"pid": pid, "birth_id": "host-claim"},
            "engine": {"pid": pid, "birth_id": "engine-claim"},
            "engine_listener": {"pid": pid, "birth_id": "listener-claim"},
        },
        "engine_binding": {"socket_owner_pid": pid},
        "session_config_digest": profile.session_config_digest,
    }
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.process_birth_identity",
        lambda observed_pid: "independently-observed-birth",
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._ps",
        lambda observed_pid, field: str(os.getpid()) if field == "ppid" else str(Path(sys.executable)),
    )
    handle = SimpleNamespace(report_value=report)
    with pytest.raises(ConflictError, match="birth identity"):
        inspector.observe(handle)


@pytest.mark.parametrize(
    ("socket_name", "accepted"),
    [
        ("127.0.0.1:8188", True),
        ("127.0.0.1:8189", False),
        ("127.0.0.2:8188", False),
        ("*:8188", False),
    ],
)
def test_listener_proof_requires_exact_configured_endpoint(monkeypatch, socket_name, accepted):
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=f"p4321\nn{socket_name}\n"),
    )
    if accepted:
        assert _listening_socket_owner(4321, "http://127.0.0.1:8188") == (
            4321,
            "http://127.0.0.1:8188",
        )
    else:
        with pytest.raises(ConflictError, match="configured engine endpoint"):
            _listening_socket_owner(4321, "http://127.0.0.1:8188")


def _inspector_fixture(tmp_path: Path, *, machine_id="owner-machine", session_digest=None):
    config = b'{"port":8188,"warm_policy":"auto"}'
    config_path = tmp_path / "session" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_bytes(config)
    session_digest = session_digest or _content_digest(config)
    profile = LocalWorkerProfile(
        profile_id="astrid",
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        machine_id=machine_id,
        worker_executable=Path("/worker"),
        host_executable=Path("/host"),
        engine_executable=Path("/engine"),
        engine_listener_executable=Path("/listener"),
        engine_endpoint="http://127.0.0.1:8188",
        worker_artifact_digest=_digest("1"),
        host_artifact_digest=_digest("2"),
        engine_artifact_digest=_digest("3"),
        engine_listener_artifact_digest=_digest("4"),
        session_config_digest=session_digest,
        profile_revision="r1",
        profile_digest=_digest("6"),
        release_digest=_digest("7"),
    )
    report = {
        "processes": {
            "worker": {"pid": 100, "birth_id": "b100"},
            "host": {"pid": 101, "birth_id": "b101"},
            "engine": {"pid": 102, "birth_id": "b102"},
            "engine_listener": {"pid": 103, "birth_id": "b103"},
        },
        "engine_binding": {"socket_owner_pid": 103},
        "session_config_digest": session_digest,
    }
    return profile, SimpleNamespace(
        report_value=report,
        owner_session_config_path=config_path,
    )


def test_private_worker_v2_profile_shape_excludes_runtime_only_endpoint(tmp_path):
    profile, _handle = _inspector_fixture(tmp_path)
    payload = CrossProcessWorkerPreparer._profile_payload(profile)
    assert "engine_endpoint" not in payload
    assert set(payload) == {
        "profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
        "worker_executable", "host_executable", "engine_executable",
        "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
        "engine_artifact_digest", "engine_listener_artifact_digest",
        "session_config_digest", "profile_revision", "profile_digest", "release_digest",
    }


def _patch_inspector_os(monkeypatch, inspector):
    def identity(pid, birth, executable, digest, **kwargs):
        parents = {100: os.getpid(), 101: 100, 102: 100, 103: 102}
        groups = {100: 100, 101: 101, 102: 102, 103: 102}
        return ProcessIdentity(pid, birth, os.getuid(), parents[pid], groups[pid], groups[pid], executable, digest)

    monkeypatch.setattr(inspector, "_identity", identity)
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._listening_socket_owner",
        lambda pid, endpoint: (pid, endpoint),
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._owner_machine_id",
        lambda: "owner-machine",
    )


def test_inspector_derives_machine_and_session_from_owner_facts(tmp_path, monkeypatch):
    profile, handle = _inspector_fixture(tmp_path)
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)

    observed = inspector.observe(handle)

    assert observed.machine_id == "owner-machine"
    assert observed.session_config_digest == _content_digest(handle.owner_session_config_path.read_bytes())
    assert observed.engine_endpoint == profile.engine_endpoint


def test_forged_profile_machine_cannot_create_observed_fact(tmp_path, monkeypatch):
    profile, handle = _inspector_fixture(tmp_path, machine_id="forged-machine")
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)
    with pytest.raises(ConflictError, match="machine identity"):
        inspector.observe(handle)


@pytest.mark.parametrize("forgery", ["profile", "report", "observed_file"])
def test_forged_session_digest_cannot_create_observed_fact(tmp_path, monkeypatch, forgery):
    profile, handle = _inspector_fixture(tmp_path)
    if forgery == "profile":
        from dataclasses import replace
        profile = replace(profile, session_config_digest=_digest("9"))
    else:
        if forgery == "report":
            handle.report_value = dict(handle.report_value)
            handle.report_value["session_config_digest"] = _digest("9")
        else:
            handle.owner_session_config_path.write_bytes(b'{"port":8189}')
    inspector = OSProcessInspector(profile)
    _patch_inspector_os(monkeypatch, inspector)
    with pytest.raises(ConflictError, match="session configuration"):
        inspector.observe(handle)


def test_cross_process_abort_is_bounded_and_reaps_after_kill(tmp_path, monkeypatch):
    profile, _handle = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("worker", timeout)
            return self.returncode

    parent, peer = socket.socketpair()
    worker = Worker()
    handle = _PreparedWorker(worker, "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
        timeout_seconds=900,
        cleanup_timeout_seconds=0.05,
    )
    preparer._active = handle
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    signals = []

    def killpg(_pid, sent_signal):
        signals.append(sent_signal)
        if sent_signal == signal.SIGKILL:
            worker.returncode = -signal.SIGKILL

    monkeypatch.setattr("runtime_protocol.local_worker_composition.os.killpg", killpg)
    started = __import__("time").monotonic()
    try:
        with pytest.raises((TimeoutError, OSError)):
            preparer.abort(handle)
    finally:
        peer.close()
    elapsed = __import__("time").monotonic() - started

    assert elapsed < 0.5
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert worker.poll() == -signal.SIGKILL
    assert handle.closed is True
    assert preparer._active is None


def test_control_probe_rejects_buffered_data_from_closed_peer(tmp_path, monkeypatch):
    profile, _unused = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    parent, peer = socket.socketpair()
    handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    peer.sendall(b"unexpected")
    peer.close()
    try:
        assert preparer.control_alive(handle) is False
    finally:
        parent.close()
