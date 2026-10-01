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
import threading
import time
import textwrap
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker import LocalWorkerProfile, ProcessIdentity
from runtime_protocol.local_worker_composition import (
    CONTROL_VERSION,
    DEFAULT_WORKER_CLEANUP_TIMEOUT_SECONDS,
    DEFAULT_WORKER_SHUTDOWN_TIMEOUT_SECONDS,
    CrossProcessWorkerPreparer,
    OSProcessInspector,
    _PreparedWorker,
    _AdoptedWorkerProcess,
    _actual_executable,
    _argv_digest,
    _process_argv,
    _ps,
    _listening_socket_owner,
    _frame_receive,
    _frame_send,
    load_local_worker_composition,
)
from runtime_protocol.catalog import process_birth_identity


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def test_argv_digest_preserves_argument_boundaries() -> None:
    assert _argv_digest([b"a b", b"c"]) != _argv_digest([b"a", b"b c"])


def _content_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


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
        "host_artifact_digest": _file_digest(Path(sys.executable).resolve()),
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
    assert composition.preparer.cleanup_timeout_seconds == DEFAULT_WORKER_CLEANUP_TIMEOUT_SECONDS
    assert composition.preparer.shutdown_timeout_seconds == DEFAULT_WORKER_SHUTDOWN_TIMEOUT_SECONDS


def test_factory_installed_mode_uses_verified_package_without_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, _source, support, packs = _profile_document(tmp_path)
    document["launch_mode"] = "installed"
    document.pop("source_checkout")
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._installed_astrid_pack_root",
        lambda _host: packs.resolve(),
    )
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=support,
        runtime_instance_id="instance",
    )

    assert composition.preparer.config["launch_mode"] == "installed"
    assert composition.preparer.config["source_checkout"] is None
    assert composition.preparer.config["pack_root"] == str(packs.resolve())


def test_factory_installed_mode_preserves_virtualenv_host_launch_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, _source, support, packs = _profile_document(tmp_path)
    base_python = tmp_path / "base-python"
    base_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    base_python.chmod(0o755)
    virtualenv_python = tmp_path / "astrid-venv" / "bin" / "python"
    virtualenv_python.parent.mkdir(parents=True)
    virtualenv_python.symlink_to(base_python)
    document["host_executable"] = str(virtualenv_python)
    document["host_artifact_digest"] = _file_digest(base_python)
    document["launch_mode"] = "installed"
    document.pop("source_checkout")
    observed: dict[str, Path] = {}

    def installed_pack_root(host: Path) -> Path:
        observed["host"] = host
        return packs.resolve()

    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._installed_astrid_pack_root",
        installed_pack_root,
    )
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=support,
        runtime_instance_id="instance",
    )

    lexical = Path(os.path.abspath(virtualenv_python))
    profile = composition.profiles["astrid"]
    assert observed["host"] == lexical
    assert Path(composition.preparer.config["host_python"]) == lexical
    assert profile.host_executable == base_python.resolve()
    assert profile.host_executable != lexical


def test_factory_preserves_distinct_host_os_identity_without_exposing_it_to_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, _source, support, packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "framework" / "Python"
    kernel_host.parent.mkdir()
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    document["host_os_executable"] = str(kernel_host)
    document["host_os_artifact_digest"] = _content_digest(b"kernel-host")
    document["launch_mode"] = "installed"
    document.pop("source_checkout")
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._installed_astrid_pack_root",
        lambda _host: packs.resolve(),
    )
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
    assert profile.host_os_executable == kernel_host.resolve()
    assert profile.host_os_artifact_digest == _content_digest(b"kernel-host")
    assert "host_os_executable" not in CrossProcessWorkerPreparer._profile_payload(profile)
    assert "host_os_artifact_digest" not in CrossProcessWorkerPreparer._profile_payload(profile)


@pytest.mark.parametrize("missing", ["host_os_executable", "host_os_artifact_digest"])
def test_factory_rejects_incomplete_host_os_identity(tmp_path: Path, missing: str) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "kernel-host"
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    document["host_os_executable"] = str(kernel_host)
    document["host_os_artifact_digest"] = _content_digest(b"kernel-host")
    document.pop(missing)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="must be provided together"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


@pytest.mark.parametrize("empty", ["", None])
def test_factory_rejects_present_empty_host_os_identity(tmp_path: Path, empty) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["host_os_executable"] = empty
    document["host_os_artifact_digest"] = empty
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="cannot be empty"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_rejects_noncanonical_host_os_identity(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "framework" / "Python"
    kernel_host.parent.mkdir()
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    document["host_os_executable"] = str(kernel_host.parent / ".." / "framework" / "Python")
    document["host_os_artifact_digest"] = _content_digest(b"kernel-host")
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="canonical and not symlinked"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_rejects_non_sha256_host_os_digest(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "kernel-host"
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    document["host_os_executable"] = str(kernel_host)
    document["host_os_artifact_digest"] = "sha256:not-a-digest"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="must be a sha256 digest"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


@pytest.mark.parametrize("digest_field", ["host_artifact_digest", "host_os_artifact_digest"])
def test_factory_rejects_host_identity_digest_mismatch(
    tmp_path: Path, digest_field: str
) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "kernel-host"
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    document["host_os_executable"] = str(kernel_host)
    document["host_os_artifact_digest"] = _content_digest(b"kernel-host")
    document[digest_field] = _digest("f")
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match=f"{digest_field} does not match"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_rejects_symlinked_host_os_identity(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    kernel_host = tmp_path / "kernel-host"
    kernel_host.write_text("kernel-host", encoding="utf-8")
    kernel_host.chmod(0o755)
    symlink = tmp_path / "kernel-host-link"
    symlink.symlink_to(kernel_host)
    document["host_os_executable"] = str(symlink)
    document["host_os_artifact_digest"] = _content_digest(b"kernel-host")
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="canonical and not symlinked"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_factory_installed_mode_rejects_source_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, _source, support, packs = _profile_document(tmp_path)
    document["launch_mode"] = "installed"
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._installed_astrid_pack_root",
        lambda _host: packs.resolve(),
    )
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Exception, match="must not select a source_checkout"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


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


def test_inspector_uses_distinct_host_os_executable_pin(tmp_path, monkeypatch):
    profile, handle = _inspector_fixture(tmp_path)
    profile = LocalWorkerProfile(
        **{
            **profile.__dict__,
            "host_os_executable": Path("/framework/Python"),
            "host_os_artifact_digest": _digest("9"),
        }
    )
    inspector = OSProcessInspector(profile)
    observed: dict[int, tuple[Path, str]] = {}

    def identity(pid, birth, executable, digest, **kwargs):
        observed[pid] = (executable, digest)
        parents = {100: os.getpid(), 101: 100, 102: 100, 103: 102}
        groups = {100: 100, 101: 101, 102: 102, 103: 102}
        return ProcessIdentity(
            pid, birth, os.getuid(), parents[pid], groups[pid], groups[pid], executable, digest
        )

    monkeypatch.setattr(inspector, "_identity", identity)
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._listening_socket_owner",
        lambda pid, endpoint: (pid, endpoint),
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._owner_machine_id",
        lambda: "owner-machine",
    )

    result = inspector.observe(handle)

    assert observed[101] == (Path("/framework/Python"), _digest("9"))
    assert result.host.executable == Path("/framework/Python")


def test_inspector_rejects_live_host_path_that_disagrees_with_os_pin(tmp_path, monkeypatch):
    profile, _handle = _inspector_fixture(tmp_path)
    expected = tmp_path / "framework" / "Python"
    expected.parent.mkdir()
    expected.write_text("expected", encoding="utf-8")
    wrong = tmp_path / "other" / "Python"
    wrong.parent.mkdir()
    wrong.write_text("wrong", encoding="utf-8")
    inspector = OSProcessInspector(profile)
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.process_birth_identity", lambda _pid: "birth"
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._ps",
        lambda _pid, field: str(os.getuid()) if field == "uid" else str(os.getpid()),
    )
    monkeypatch.setattr("runtime_protocol.local_worker_composition.os.getpgid", lambda pid: pid)
    monkeypatch.setattr("runtime_protocol.local_worker_composition.os.getsid", lambda pid: pid)
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._actual_executable", lambda _pid: wrong
    )

    with pytest.raises(ConflictError, match="executable identity"):
        inspector._identity(
            101,
            "birth",
            expected,
            _content_digest(b"expected"),
            parent_pid=os.getpid(),
            session_owner=True,
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


def test_cross_process_abort_timeout_is_bounded_and_retains_custody_owner(tmp_path, monkeypatch):
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
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.os.killpg",
        lambda *_args: pytest.fail("a missing ACK must not discard the live custody owner"),
    )
    started = __import__("time").monotonic()
    try:
        with pytest.raises((TimeoutError, OSError)):
            preparer.abort(handle)
    finally:
        peer.close()
    elapsed = __import__("time").monotonic() - started

    assert elapsed < 0.5
    assert worker.poll() is None
    assert handle.closed is False
    assert handle.cleanup_started is False
    assert preparer._active is handle
    assert preparer.cleanup_uncertain


def test_private_worker_refusal_preserves_only_bounded_stage_and_code(
    tmp_path, monkeypatch
):
    profile, _handle = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    parent, peer = socket.socketpair()
    handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
    )
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")

    def refuse() -> None:
        request = _frame_receive(peer)
        assert request["command"] == "handoff_prepare"
        _frame_send(
            peer,
            {
                "version": CONTROL_VERSION,
                "status": "error",
                "error": "private detail must not cross the boundary",
                "error_code": "sealed_owner_mismatch",
                "error_stage": "handoff_prepare",
            },
        )

    responder = threading.Thread(target=refuse)
    responder.start()
    try:
        with pytest.raises(ConflictError) as raised:
            preparer._rpc_unlocked(
                handle,
                {"version": CONTROL_VERSION, "command": "handoff_prepare"},
            )
        responder.join(timeout=1)
    finally:
        peer.close()
        parent.close()

    assert "private detail" not in raised.value.message
    assert raised.value.details == {
        "handoff_error_code": "sealed_owner_mismatch",
        "handoff_stage": "handoff_prepare",
    }


def test_cross_process_abort_rejects_malformed_ack_and_retains_custody_owner(
    tmp_path, monkeypatch
):
    profile, _handle = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

        @staticmethod
        def wait(timeout=None):
            raise subprocess.TimeoutExpired("worker", timeout)

    parent, peer = socket.socketpair()
    handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "config.json")
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
        cleanup_timeout_seconds=0.25,
    )
    preparer._active = handle
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")

    def malformed_ack() -> None:
        assert _frame_receive(peer) == {"version": CONTROL_VERSION, "command": "abort"}
        _frame_send(peer, {"version": "wrong", "status": "ok"})

    responder = threading.Thread(target=malformed_ack)
    responder.start()
    try:
        with pytest.raises(ConflictError, match="control version is invalid"):
            preparer.abort(handle)
        responder.join(timeout=1)
    finally:
        peer.close()

    assert not responder.is_alive()
    assert handle.closed is False
    assert preparer._active is handle
    assert preparer.cleanup_uncertain


def test_installed_cleanup_budget_keeps_worker_control_alive_for_delayed_ack(
    tmp_path, monkeypatch
):
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
        cleanup_timeout_seconds=0.5,
        shutdown_timeout_seconds=0.75,
    )
    preparer._active = handle
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")

    def acknowledge_after_real_cleanup_delay() -> None:
        assert _frame_receive(peer) == {"version": CONTROL_VERSION, "command": "abort"}
        time.sleep(0.2)  # Demonstrably longer than the historical 100ms budget.
        worker.returncode = 0
        _frame_send(peer, {"version": CONTROL_VERSION, "status": "ok"})

    responder = threading.Thread(target=acknowledge_after_real_cleanup_delay)
    responder.start()
    try:
        preparer.abort(handle)
        responder.join(timeout=1)
    finally:
        peer.close()

    assert not responder.is_alive()
    assert worker.returncode == 0
    assert handle.closed is True
    assert preparer._active is None


def test_cancel_current_does_not_wait_unbounded_for_spawn_handoff(tmp_path):
    profile, _handle = _inspector_fixture(tmp_path)
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={},
        environment={},
        cleanup_timeout_seconds=0.05,
    )
    preparer._handoff_lock.acquire()
    started = __import__("time").monotonic()
    try:
        preparer.cancel_current()
    finally:
        preparer._handoff_lock.release()
    assert __import__("time").monotonic() - started < 0.5


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


def test_control_probe_retains_only_bounded_async_worker_failure(
    tmp_path, monkeypatch, capsys
):
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
    _frame_send(
        peer,
        {
            "version": CONTROL_VERSION,
            "status": "error",
            "error": "secret nonce must never be retained",
            "error_code": "host_control_closed",
            "error_stage": "control",
        },
    )
    try:
        assert preparer.control_alive(handle) is False
        retained = capsys.readouterr().err
        assert json.loads(retained) == {
            "error_code": "host_control_closed",
            "event": "prepared_worker_async_refusal",
            "stage": "control",
        }
        assert "secret" not in retained
        assert "nonce" not in retained
    finally:
        peer.close()
        parent.close()


def _worker_ack(request, *, status="prepared", phase="paused", bad_hash=False):
    value = {
        "version": CONTROL_VERSION,
        "command": f"{request['command']}_ack",
        "handoff_id": request["handoff_id"],
        "status": status,
        "nonce_digest": request["nonce_digest"],
        "sealed_record_digest": request["sealed_record_digest"],
        "host_ack": {"status": status},
        "worker_phase": phase,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    value["ack_sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if bad_hash:
        value["ack_sha256"] = _digest("0")
    return value


def test_handoff_command_requires_exact_binders_phase_and_ack_hash(tmp_path, monkeypatch):
    profile, _ = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    for bad_hash in (False, True):
        parent, peer = socket.socketpair()
        handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "session/config.json")
        preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
        monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
        payload = {
            "version": CONTROL_VERSION,
            "command": "handoff_prepare",
            "handoff_id": "handoff-1",
            "nonce_digest": _digest("a"),
            "sealed_record_digest": _digest("b"),
            "deadline_monotonic": 123.0,
            "deadline_unix_ms": 456,
            "old_runtime": {},
            "receipt_evidence_digest": _digest("c"),
            "credential_generation": {},
        }

        def worker_reply():
            request = json.loads(peer.recv(65536).split(b"\n", 1)[0])
            response = _worker_ack(request, bad_hash=bad_hash)
            peer.sendall(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )

        thread = threading.Thread(target=worker_reply)
        thread.start()
        try:
            if bad_hash:
                with pytest.raises(ConflictError, match="acknowledgement is invalid"):
                    preparer.handoff_command(handle, payload)
            else:
                response = preparer.handoff_command(handle, payload)
                assert response["worker_phase"] == "paused"
                assert response["handoff_id"] == payload["handoff_id"]
        finally:
            thread.join(1)
            parent.close()
            peer.close()


def test_exported_control_descriptor_preserves_channel_after_a_releases_copy(
    tmp_path, monkeypatch
):
    profile, _ = _inspector_fixture(tmp_path)

    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    parent, peer = socket.socketpair()
    handle = _PreparedWorker(Worker(), "birth", parent, {}, tmp_path / "session/config.json")
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    preparer._active = handle
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    exported = preparer.export_control_descriptor(handle)
    adopted = socket.socket(fileno=exported)
    try:
        assert os.get_inheritable(adopted.fileno()) is False
        preparer.release_exported(handle)
        assert handle.closed is True
        assert preparer.current_handle() is None
        adopted.sendall(b"custody")
        assert peer.recv(7) == b"custody"
    finally:
        adopted.close()
        peer.close()


@pytest.mark.parametrize("worker_dies_first", [False, True])
def test_adopted_unresponsive_worker_fallback_cleans_each_verified_nonchild_group(
    tmp_path, worker_dies_first
):
    support = tmp_path / "support"
    session = support / "engine-session"
    session.mkdir(parents=True)
    (session / "config.json").write_text("{}", encoding="utf-8")
    state_path = tmp_path / "graph.json"
    listener_ready = tmp_path / "listener-ready.json"
    listener_script = tmp_path / "listener.py"
    engine_script = tmp_path / "engine.py"
    host_script = tmp_path / "host.py"
    worker_script = tmp_path / "worker.py"
    broker_script = tmp_path / "broker.py"
    listener_script.write_text(textwrap.dedent("""
        import json,os,signal,socket,sys,time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind(('127.0.0.1',0));sock.listen(4)
        open(sys.argv[1],'w').write(json.dumps({'pid':os.getpid(),'port':sock.getsockname()[1]}))
        while True: time.sleep(1)
    """), encoding="utf-8")
    engine_script.write_text(textwrap.dedent("""
        import json,os,signal,subprocess,sys,time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child=subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])
        while not os.path.exists(sys.argv[2]): time.sleep(.01)
        while True: time.sleep(1)
    """), encoding="utf-8")
    host_script.write_text("import signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nexec('while True: time.sleep(1)')\n", encoding="utf-8")
    worker_script.write_text(textwrap.dedent("""
        import json,os,signal,subprocess,sys,time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        host=subprocess.Popen([sys.executable,sys.argv[1]],start_new_session=True)
        engine=subprocess.Popen([sys.executable,sys.argv[2],sys.argv[3],sys.argv[4]],start_new_session=True)
        while not os.path.exists(sys.argv[4]): time.sleep(.01)
        listener=json.load(open(sys.argv[4]))
        open(sys.argv[5],'w').write(json.dumps({'worker':os.getpid(),'host':host.pid,'engine':engine.pid,'listener':listener['pid'],'port':listener['port']}))
        while True: time.sleep(1)
    """), encoding="utf-8")
    broker_script.write_text(textwrap.dedent("""
        import subprocess,sys,time,os
        worker=subprocess.Popen([sys.executable,*sys.argv[1:]],start_new_session=True)
        while not os.path.exists(sys.argv[-1]): time.sleep(.01)
    """), encoding="utf-8")
    subprocess.run(
        [
            sys.executable, str(broker_script), str(worker_script),
            str(host_script), str(engine_script), str(listener_script),
            str(listener_ready), str(state_path),
        ],
        check=True,
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and int(_ps(state["worker"], "ppid")) != 1:
        time.sleep(.02)

    def identity(name, parent):
        pid = int(state[name])
        executable = _actual_executable(pid)
        return {
            "pid": pid,
            "birth_id": process_birth_identity(pid),
            "uid": int(_ps(pid, "uid")),
            "parent_pid": int(parent),
            "process_group": os.getpgid(pid),
            "session_id": os.getsid(pid),
            "executable": str(executable),
            "artifact_digest": _file_digest(executable),
            "command_line": _ps(pid, "command"),
            "argv_digest": _argv_digest(_process_argv(pid)),
        }

    receipt = {
        "worker": identity("worker", 1),
        "host": identity("host", state["worker"]),
        "engine": identity("engine", state["worker"]),
        "engine_listener": identity("listener", state["engine"]),
        "cleanup_groups": [
            {"role": "generic_pack_host", "leader": "host", "members": ["host"]},
            {
                "role": "engine",
                "leader": "engine",
                "members": ["engine", "engine_listener"],
            },
            {"role": "worker", "leader": "worker", "members": ["worker"]},
        ],
        "engine_binding": {"socket_owner_pid": state["listener"]},
    }
    profile, _ = _inspector_fixture(tmp_path)
    profile = __import__("dataclasses").replace(
        profile, engine_endpoint=f"http://127.0.0.1:{state['port']}"
    )
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config={"support_root": str(support)},
        environment={"ASTRID_VIBECOMFY_SESSION_DIR": str(session)},
        cleanup_timeout_seconds=.4,
    )
    control, peer = socket.socketpair()
    handle = _PreparedWorker(
        _AdoptedWorkerProcess(state["worker"], receipt["worker"]["birth_id"]),
        receipt["worker"]["birth_id"],
        control,
        {},
        session / "config.json",
        activated=True,
        adopted=True,
        receipt=receipt,
    )
    preparer._active = handle
    try:
        if worker_dies_first:
            os.killpg(int(state["worker"]), signal.SIGKILL)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and process_birth_identity(state["worker"]):
                time.sleep(.02)
            assert process_birth_identity(state["worker"]) is None
        preparer.abort(handle)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and any(
            process_birth_identity(state[name]) is not None
            for name in ("host", "engine", "listener", "worker")
        ):
            time.sleep(.02)
        assert all(process_birth_identity(state[name]) is None for name in ("host", "engine", "listener", "worker"))
        assert not session.exists()
        probe = socket.socket()
        try:
            assert probe.connect_ex(("127.0.0.1", state["port"])) != 0
        finally:
            probe.close()
    finally:
        peer.close()
        for name in ("host", "engine", "worker"):
            pid = int(state[name])
            if process_birth_identity(pid):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass
