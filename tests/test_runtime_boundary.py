import json
import fcntl
import inspect
import os
import signal
import socket
import subprocess
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from banodoco_local import runtime_boundary as runtime_boundary_module
from banodoco_local import custody_broker as custody_broker_module
from banodoco_local.bootstrap import BootstrapError, SourceProfile
from banodoco_local.runtime_boundary import (
    ADMISSION_TIMEOUT_ENV,
    LocalRuntimeBoundary,
    _is_authenticated_active_work_refusal,
    _validate_owner_a_export_offer,
)
from runtime_protocol.local_worker_handoff import (
    TRANSFER_VERSION,
    receive_frame,
    send_frame,
)
from runtime_protocol import cli as runtime_cli
from runtime_protocol.orderly_handoff import digest


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"status": "ok", "protocol": "workspace.v1"}).encode()


def _sealed_runtime_capability(tmp_path: Path, *, state: str = "sealed"):
    support = tmp_path / "support"
    ledger_root = support / "runtime-custody" / "run-a"
    ledger_root.mkdir(parents=True, mode=0o700)
    identity = {"pid": 4242, "birth_id": "ps-lstart:birth-a", "uid": os.getuid()}
    registration = {
        "pid": 4242,
        "identity": identity,
        "argv_digest": "sha256:" + "1" * 64,
        "pre_exec_audit_token_sha256": "sha256:" + "2" * 64,
        "pre_exec_pidversion": 6,
        "audit_token_words": [1, os.getuid(), 3, 4, 5, 4242, 7, 8],
        "audit_token_sha256": "sha256:" + "3" * 64,
        "audit_token_pidversion": 8,
    }
    snapshot = {
        "version": 1,
        "run_id": "sha256:" + "4" * 64,
        "role": "runtime_owner",
        "state": state,
        "sequence": 2,
        "registration": registration,
        "ack": {"status": "registered"},
    }
    event = {
        "version": 1,
        "event": "admission_sealed",
        "sequence": 2,
        "predecessor_digest": None,
        "snapshot_digest": custody_broker_module._digest_bytes(
            custody_broker_module._canonical(snapshot)
        ),
        "snapshot": snapshot,
    }
    event["event_digest"] = custody_broker_module._digest_bytes(
        custody_broker_module._canonical(event)
    )
    journal = ledger_root / "custody.journal.jsonl"
    journal.write_bytes(custody_broker_module._canonical(event) + b"\n")
    journal.chmod(0o600)
    ledger = ledger_root / "custody.ledger.json"
    custody_broker_module._atomic_owner_json(
        ledger, {**snapshot, "chain_digest": event["event_digest"]},
    )
    sidecar = support / custody_broker_module.ACTIVE_CAPABILITY_NAME
    custody_broker_module._atomic_owner_json(sidecar, {
        "version": custody_broker_module.CAPABILITY_VERSION,
        "role": "runtime_owner",
        "ledger_path": str(ledger),
        "ledger_sha256": custody_broker_module._digest_bytes(ledger.read_bytes()),
        "journal_path": str(journal),
        "journal_sha256": custody_broker_module._digest_bytes(journal.read_bytes()),
        **identity,
        "audit_token_sha256": registration["audit_token_sha256"],
        "audit_token_pidversion": registration["audit_token_pidversion"],
    })
    return sidecar, identity, registration


def test_custody_child_creates_session_before_pre_exec_registration(monkeypatch):
    events = []
    frame = {}
    target = ["/installed/runtime/bin/python", "-m", "runtime_protocol", "start"]
    monkeypatch.setenv(
        "ASTRID_RUNTIME_CUSTODY_TARGET_B64",
        custody_broker_module.base64.b64encode(
            custody_broker_module._canonical(target)
        ).decode("ascii"),
    )
    monkeypatch.setenv("ASTRID_RUNTIME_CUSTODY_SOCKET", "/private/custody.sock")
    monkeypatch.setenv("ASTRID_RUNTIME_CUSTODY_RUN_ID", "run-a")
    monkeypatch.setenv("ASTRID_RUNTIME_CUSTODY_ROLE", "runtime_owner")
    monkeypatch.setenv("ASTRID_RUNTIME_CUSTODY_START_SESSION", "1")
    monkeypatch.setattr(custody_broker_module.os, "getpid", lambda: 4242)
    monkeypatch.setattr(custody_broker_module.os, "getppid", lambda: 3131)
    monkeypatch.setattr(custody_broker_module.os, "setsid", lambda: events.append("setsid"))
    monkeypatch.setattr(
        custody_broker_module.os,
        "set_inheritable",
        lambda descriptor, value: events.append(("inheritable", descriptor, value)),
    )

    class Connection:
        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, value):
            events.append(("connect", value))

        def fileno(self):
            return 91

        def detach(self):
            events.append("detach")
            return 91

    monkeypatch.setattr(
        custody_broker_module.socket, "socket",
        lambda *_args: events.append("socket") or Connection(),
    )

    def send(_connection, value):
        frame.update(value)
        events.append("register")

    def acknowledge(_connection):
        events.append("ack")
        return {
            "status": "registered",
            "run_id": frame["run_id"],
            "role": frame["role"],
            "pid": frame["pid"],
            "registration_digest": custody_broker_module._digest_bytes(
                custody_broker_module._canonical(frame)
            ),
        }

    monkeypatch.setattr(custody_broker_module, "_send_frame", send)
    monkeypatch.setattr(custody_broker_module, "_read_frame", acknowledge)

    def execve(executable, argv, environment):
        events.append("exec")
        assert executable == target[0]
        assert argv == target
        assert not any(name.startswith("ASTRID_RUNTIME_CUSTODY_") for name in environment)
        raise RuntimeError("exec reached")

    monkeypatch.setattr(custody_broker_module.os, "execve", execve)

    with pytest.raises(RuntimeError, match="exec reached"):
        custody_broker_module.child_exec_from_environment()

    assert events.index("setsid") < events.index(("connect", "/private/custody.sock"))
    assert events.index("setsid") < events.index("register") < events.index("ack")
    assert events.count("setsid") == 1
    assert frame["pid"] == 4242
    assert frame["ppid"] == 3131
    assert frame["argv_digest"] == custody_broker_module._digest_bytes(
        custody_broker_module._canonical(target)
    )


def test_custody_broker_seals_and_signals_only_actual_exec_token(tmp_path, monkeypatch):
    if sys.platform != "darwin":
        pytest.skip("Darwin audit-token custody is unavailable")
    identity = {"pid": 4242, "birth_id": "birth-a", "uid": os.getuid()}
    pre = {
        "pid": 4242, "uid": os.getuid(), "pidversion": 17,
        "sha256": "sha256:" + "1" * 64,
        "words": [1, os.getuid(), 3, 4, 5, 4242, 7, 17],
    }
    same_pidversion_decoy = {
        **pre,
        "sha256": "sha256:" + "2" * 64,
        "words": [11, os.getuid(), 13, 14, 15, 4242, 17, 17],
    }
    actual_exec = {
        "pid": 4242, "uid": os.getuid(), "pidversion": 18,
        "sha256": "sha256:" + "3" * 64,
        "words": [21, os.getuid(), 23, 24, 25, 4242, 27, 18],
    }
    tokens = iter((pre, same_pidversion_decoy, actual_exec))
    monkeypatch.setattr(custody_broker_module, "_peer_token", lambda _connection: next(tokens))
    signalled = []
    monkeypatch.setattr(
        custody_broker_module,
        "signal_audit_token",
        lambda words, signum: signalled.append((list(words), signum)),
    )
    broker = custody_broker_module.RoleBoundCustodyBroker(
        role="runtime_owner",
        identity_provider=lambda _pid: identity,
        ledger_root=tmp_path / "custody-ledger",
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.connect(str(broker.socket_path))
        registration_frame = {
            "version": custody_broker_module.PROTOCOL_VERSION,
            "command": "register_pre_exec",
            "run_id": broker.run_id,
            "role": broker.role,
            "pid": identity["pid"],
            "ppid": os.getpid(),
            "argv_digest": "sha256:" + "4" * 64,
        }
        custody_broker_module._send_frame(connection, registration_frame)
        ack = custody_broker_module._read_frame(connection)
        assert ack["status"] == "registered"
        broker.wait_until_sealed()
    finally:
        connection.close()

    assert broker.registration["pre_exec_pidversion"] == pre["pidversion"]
    assert broker.registration["audit_token_pidversion"] == actual_exec["pidversion"]
    assert broker.registration["audit_token_words"] == actual_exec["words"]
    assert broker.registration["audit_token_words"] != same_pidversion_decoy["words"]
    broker.signal(signal.SIGTERM, expected_pid=identity["pid"])
    assert signalled == [(actual_exec["words"], signal.SIGTERM)]


def test_sealed_runtime_capability_signals_only_registered_audit_token(tmp_path):
    sidecar, identity, registration = _sealed_runtime_capability(tmp_path)
    calls = []

    receipt = custody_broker_module.signal_sealed_capability(
        sidecar,
        expected_identity=identity,
        signum=signal.SIGKILL,
        identity_provider=lambda _pid: identity,
        token_details_provider=lambda _words: {
            "pid": identity["pid"], "uid": identity["uid"],
            "pidversion": registration["audit_token_pidversion"],
            "sha256": registration["audit_token_sha256"],
        },
        signal_provider=lambda words, signum: calls.append((list(words), signum)),
    )

    assert calls == [(registration["audit_token_words"], signal.SIGKILL)]
    assert receipt["kind"] == "proc_signal_with_audittoken"
    assert receipt["pid"] == identity["pid"]


def test_sealed_runtime_capability_admits_identity_bound_rendezvous_signal(tmp_path):
    if not hasattr(signal, "SIGUSR1"):
        pytest.skip("SIGUSR1 is unavailable")
    sidecar, identity, registration = _sealed_runtime_capability(tmp_path)
    calls = []

    custody_broker_module.signal_sealed_capability(
        sidecar,
        expected_identity=identity,
        signum=signal.SIGUSR1,
        identity_provider=lambda _pid: identity,
        token_details_provider=lambda _words: {
            "pid": identity["pid"], "uid": identity["uid"],
            "pidversion": registration["audit_token_pidversion"],
            "sha256": registration["audit_token_sha256"],
        },
        signal_provider=lambda words, signum: calls.append((list(words), signum)),
    )

    assert calls == [(registration["audit_token_words"], signal.SIGUSR1)]


def test_unsealed_runtime_capability_refuses_before_signal(tmp_path):
    sidecar, identity, registration = _sealed_runtime_capability(
        tmp_path, state="accepting",
    )
    calls = []
    with pytest.raises(custody_broker_module.CustodyError, match="not an exact sealed"):
        custody_broker_module.signal_sealed_capability(
            sidecar,
            expected_identity=identity,
            signum=signal.SIGKILL,
            identity_provider=lambda _pid: identity,
            token_details_provider=lambda _words: {
                "pid": identity["pid"], "uid": identity["uid"],
                "pidversion": registration["audit_token_pidversion"],
                "sha256": registration["audit_token_sha256"],
            },
            signal_provider=lambda words, signum: calls.append((words, signum)),
        )
    assert calls == []


def test_runtime_capability_rejects_symlink_stale_and_replaced_inputs(tmp_path):
    sidecar, identity, registration = _sealed_runtime_capability(tmp_path)
    providers = {
        "identity_provider": lambda _pid: identity,
        "token_details_provider": lambda _words: {
            "pid": identity["pid"], "uid": identity["uid"],
            "pidversion": registration["audit_token_pidversion"],
            "sha256": registration["audit_token_sha256"],
        },
    }
    link = sidecar.with_name("sidecar-link.json")
    link.symlink_to(sidecar)
    with pytest.raises(custody_broker_module.CustodyError, match="symlink"):
        custody_broker_module.load_sealed_capability(
            link, expected_identity=identity, **providers,
        )
    with pytest.raises(custody_broker_module.CustodyError, match="selected owner"):
        custody_broker_module.load_sealed_capability(
            sidecar,
            expected_identity={**identity, "birth_id": "reused-birth"},
            **providers,
        )
    reference = json.loads(sidecar.read_text())
    ledger = Path(reference["ledger_path"])
    ledger.write_bytes(ledger.read_bytes() + b" ")
    with pytest.raises(custody_broker_module.CustodyError, match="content changed"):
        custody_broker_module.load_sealed_capability(
            sidecar, expected_identity=identity, **providers,
        )


def test_post_popen_custody_publish_failure_retains_handle_and_sealed_cleanup(
    tmp_path, monkeypatch,
):
    calls = []

    class Broker:
        state = "sealed"

        def __init__(self, **_kwargs):
            pass

        def child_environment(self, _argv, *, start_new_session):
            assert start_new_session is True
            return {}

        def signal(self, signum, *, expected_pid):
            calls.append((signum, expected_pid))

    class Process:
        pid = 313
        _returncode = None

        def poll(self):
            return self._returncode

        def wait(self, timeout):
            self._returncode = -15
            return self._returncode

    process = Process()
    monkeypatch.setattr(runtime_boundary_module, "RoleBoundCustodyBroker", Broker)
    monkeypatch.setattr(
        runtime_boundary_module, "custody_wrapper_argv", lambda _executable: ["wrapper"],
    )
    monkeypatch.setattr(runtime_boundary_module.subprocess, "Popen", lambda *_a, **_k: process)
    monkeypatch.setattr(
        runtime_boundary_module,
        "publish_active_capability",
        lambda *_args: (_ for _ in ()).throw(custody_broker_module.CustodyError("fsync failed")),
    )
    boundary = LocalRuntimeBoundary()
    support = tmp_path / "support"
    support.mkdir()
    with pytest.raises(runtime_boundary_module.RuntimeCustodyLaunchUncertain) as raised:
        boundary._spawn_custodied_runtime(
            [sys.executable, "-c", "pass"],
            support_root=support,
            stdout=subprocess.DEVNULL,
        )
    assert raised.value.process is process
    assert raised.value.broker is process._runtime_custody_broker

    boundary._cleanup_failed_handoff_process(
        process,
        authenticated_admission_confirmed=False,
    )
    assert calls == [(signal.SIGTERM, process.pid)]


def test_active_work_refusal_requires_exact_authenticated_frame_shape():
    exact = {
        "version": TRANSFER_VERSION,
        "command": "refused_active_work",
        "handoff_id": "handoff-1",
    }
    assert _is_authenticated_active_work_refusal(
        exact,
        transfer_version=exact["version"],
        handoff_id=exact["handoff_id"],
    )
    for changed in (
        {**exact, "extra": True},
        {**exact, "version": "wrong"},
        {**exact, "command": "seal_export"},
        {**exact, "handoff_id": "handoff-2"},
        [exact],
        None,
    ):
        assert not _is_authenticated_active_work_refusal(
            changed,
            transfer_version=exact["version"],
            handoff_id=exact["handoff_id"],
        )


def test_export_offer_maps_only_exact_active_work_refusal_to_public_reason():
    refusal = {
        "version": TRANSFER_VERSION,
        "command": "refused_active_work",
        "handoff_id": "handoff-1",
    }
    with pytest.raises(BootstrapError, match="active or unreconciled"):
        _validate_owner_a_export_offer(
            refusal,
            transfer_version=TRANSFER_VERSION,
            handoff_id="handoff-1",
            sealed_record_digest="sha256:" + "1" * 64,
        )
    for malformed in (
        {**refusal, "extra": True},
        {**refusal, "handoff_id": "other"},
        {"version": TRANSFER_VERSION, "command": "refused_active_work"},
    ):
        with pytest.raises(BootstrapError, match="export-seal request is invalid"):
            _validate_owner_a_export_offer(
                malformed,
                transfer_version=TRANSFER_VERSION,
                handoff_id="handoff-1",
                sealed_record_digest="sha256:" + "1" * 64,
            )


def test_http_health_allows_bounded_startup_latency(monkeypatch):
    observed = {}

    def delayed_health(_request, *, timeout):
        observed["timeout"] = timeout
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", delayed_health)

    assert LocalRuntimeBoundary._http_health("http://127.0.0.1:61217") is True
    assert observed["timeout"] == LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS
    assert observed["timeout"] > 0.5


def test_startup_admission_budget_is_validated_and_forwarded(tmp_path, monkeypatch):
    monkeypatch.delenv(ADMISSION_TIMEOUT_ENV, raising=False)
    assert LocalRuntimeBoundary().admission_timeout_seconds == 120.0
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "120")
    boundary = LocalRuntimeBoundary()
    assert boundary.admission_timeout_seconds == 120.0
    assert boundary.wait_seconds >= 125.0
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
    argv = boundary._argv(
        profile,
        realm_id="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        display_name="Astrid Workspace",
        owner_lock=tmp_path / "support" / "instance.lock",
        token_file=tmp_path / "support" / "bootstrap-token",
    )
    flag = argv.index("--admission-timeout")
    assert argv[flag + 1] == "120.0"


def test_worker_profile_is_validated_through_installed_source_boundary(tmp_path):
    worker_profile = tmp_path / "worker-profile.json"
    worker_profile.write_text("{}")
    profile = SourceProfile(
        profile="astrid",
        runtime_checkout=str(tmp_path),
        source_checkout=str(tmp_path),
        worker_profile=str(worker_profile),
    )

    LocalRuntimeBoundary._validate_source(profile)


def test_invalid_startup_admission_budget_fails_closed(monkeypatch):
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "not-a-duration")
    with pytest.raises(BootstrapError, match="ADMISSION_TIMEOUT"):
        LocalRuntimeBoundary()


def test_pid_liveness_uses_read_only_process_census(monkeypatch):
    observed = []

    def census(argv, **_kwargs):
        observed.append(argv)
        return type("Result", (), {"returncode": 0, "stdout": "12345\n"})()

    monkeypatch.setattr(runtime_boundary_module.subprocess, "run", census)

    assert LocalRuntimeBoundary.is_pid_alive(12345)
    assert observed == [["/bin/ps", "-ww", "-o", "pid=", "-p", "12345"]]


def test_direct_child_cleanup_requires_sole_reaper_and_rechecks_before_kill(monkeypatch):
    boundary = LocalRuntimeBoundary()
    calls = []

    class Process:
        pid = 4321
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            calls.append("terminate")

        def kill(self):
            calls.append("kill")

        def wait(self, timeout):
            calls.append(("wait", timeout))
            if timeout == 5:
                raise subprocess.TimeoutExpired("runtime", timeout)
            self.returncode = -9
            return self.returncode

    process = Process()
    parents = []
    monkeypatch.setattr(
        boundary, "_process_parent_pid",
        lambda _pid: parents.append(os.getpid()) or os.getpid(),
    )
    with pytest.raises(BootstrapError, match="sole-reaper"):
        boundary._terminate(process)
    assert calls == []

    process._runtime_boundary_owner = boundary
    process._runtime_boundary_sole_reaper = True
    boundary._terminate(process)
    assert calls == ["terminate", ("wait", 5), "kill", ("wait", 2)]
    assert parents == [os.getpid(), os.getpid()]


def test_detached_owner_cleanup_uses_only_sealed_capability_for_term_and_kill(monkeypatch, tmp_path):
    boundary = LocalRuntimeBoundary()
    calls = []
    ticks = iter((0.0, 6.0))
    monkeypatch.setattr(runtime_boundary_module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(boundary, "process_birth_identity", lambda _pid: "birth-a")
    monkeypatch.setattr(
        boundary, "_signal_registered_owner",
        lambda **kwargs: calls.append(kwargs) or {"ok": True},
    )

    boundary._terminate_detached_owner(
        support=tmp_path,
        expected_pid=987,
        expected_birth="birth-a",
    )

    assert [call["signum"] for call in calls] == [signal.SIGTERM, signal.SIGKILL]
    assert all(call["expected_pid"] == 987 for call in calls)


def test_detached_owner_signal_fails_closed_without_exact_sealed_capability(monkeypatch, tmp_path):
    boundary = LocalRuntimeBoundary()
    identity = {"pid": 987, "birth_id": "birth-a", "uid": os.getuid()}
    calls = []
    monkeypatch.setattr(boundary, "_custody_identity", lambda _pid: identity)

    def refuse(*_args, **_kwargs):
        calls.append("validator")
        raise custody_broker_module.CustodyError("missing sidecar")

    monkeypatch.setattr(runtime_boundary_module, "signal_sealed_capability", refuse)
    with pytest.raises(BootstrapError, match="sealed custody is unavailable"):
        boundary._signal_registered_owner(
            support=tmp_path,
            expected_pid=987,
            expected_birth="birth-a",
            signum=signal.SIGTERM,
        )
    assert calls == ["validator"]


def test_runtime_boundary_has_no_pid_or_process_group_signal_fallback():
    source = inspect.getsource(runtime_boundary_module)
    assert "os.kill(" not in source
    assert "os.killpg" not in source


def test_post_gate_reporting_failure_preserves_authenticated_owner_b():
    boundary = LocalRuntimeBoundary()
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        boundary._build_authenticated_handoff_result = lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected reporting failure")
        )
        with pytest.raises(RuntimeError, match="reporting failure"):
            boundary._report_authenticated_handoff(
                process=process,
                accepted={},
                discovery={},
                source=None,
                current={},
            )
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_atomic_owner_json_fsyncs_parent_directory(tmp_path, monkeypatch):
    parent = tmp_path / "support"
    parent.mkdir(mode=0o700)
    observed_modes = []
    real_fsync = os.fsync

    def capture(descriptor):
        observed_modes.append(os.fstat(descriptor).st_mode)
        return real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", capture)
    LocalRuntimeBoundary._atomic_owner_json(parent / "record.json", {"ok": True})
    assert any(stat.S_ISDIR(mode) for mode in observed_modes)


def test_create_owner_json_no_clobber_preserves_existing_gate(tmp_path):
    path = tmp_path / "orderly-handoff-request.json"
    path.write_bytes(b"existing-gate\n")
    with pytest.raises(BootstrapError, match="already exists"):
        LocalRuntimeBoundary._create_owner_json_no_clobber(path, {"new": True})
    assert path.read_bytes() == b"existing-gate\n"


def test_authenticated_success_publishes_active_adopted_owner_reference(tmp_path):
    boundary = LocalRuntimeBoundary()
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    record_path = support / "orderly-handoff-record-handoff-1.json"
    record_path.write_text("{}", encoding="utf-8")
    record = type("Record", (), {"path": record_path})()
    process = type("Process", (), {"pid": 12345})()
    current = {
        "state": "ADOPTED",
        "handoff_id": "handoff-1",
        "record_digest": "sha256:" + "4" * 64,
    }
    boundary._publish_active_adopted_owner(
        support=support,
        record=record,
        current=current,
        process=process,
        accepted={
            "runtime_birth_id": "birth-b",
            "runtime_instance_id": "runtime-b",
        },
    )
    observed = json.loads(
        (support / "orderly-handoff-adopted-owner.json").read_text()
    )
    expected = {
        "version": 1,
        "state": "ADOPTED",
        "handoff_id": "handoff-1",
        "record_path": str(record_path),
        "record_digest": current["record_digest"],
        "pid": 12345,
        "birth_id": "birth-b",
        "runtime_instance_id": "runtime-b",
    }
    assert observed == {
        **expected,
        "reference_digest": digest(expected),
    }


def test_pre_gate_failure_without_sealed_custody_retains_uncertainty():
    boundary = LocalRuntimeBoundary()
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        with pytest.raises(BootstrapError, match="cleanup is uncertain"):
            boundary._cleanup_failed_handoff_process(
                process,
                authenticated_admission_confirmed=False,
            )
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_actual_owner_b_loss_persists_gate_before_coordinator_mutex_release(tmp_path):
    boundary = LocalRuntimeBoundary()
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    pointer = support / "orderly-handoff-request.json"
    pointer.write_text("{}", encoding="utf-8")
    record_path = support / "orderly-handoff-record-loss.json"
    record_path.write_text("{}", encoding="utf-8")
    record = type("Record", (), {
        "path": record_path,
        "read": lambda _self: {
            "state": "FINALIZING",
            "record_digest": "sha256:" + "4" * 64,
        },
    })()
    mutex_path = support / "orderly-handoff-coordinator.lock"
    mutex_fd = os.open(mutex_path, os.O_RDWR | os.O_CREAT, 0o600)
    contender_fd = os.open(mutex_path, os.O_RDWR)
    owner_b = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        fcntl.flock(mutex_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        owner_b.kill()
        owner_b.wait(timeout=5)
        assert boundary._retain_failed_adopter_gate(
            support=support,
            record=record,
            handoff_id="handoff-loss",
            process=owner_b,
            owner_b_birth_id="birth-b",
        )
        marker = support / "orderly-handoff-cleanup-uncertain.json"
        assert json.loads(marker.read_text(encoding="utf-8"))["handoff_state"] == "FINALIZING"
        assert pointer.exists()
        with pytest.raises(BlockingIOError):
            fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if owner_b.poll() is None:
            owner_b.kill()
            owner_b.wait(timeout=5)
        fcntl.flock(mutex_fd, fcntl.LOCK_UN)
        os.close(mutex_fd)
        os.close(contender_fd)


@pytest.mark.parametrize("spawn_failure", [False, True], ids=["ack", "abort"])
def test_actual_handoff_spawn_normalizes_fixed_fds_and_closes_capability_channels(
    tmp_path, monkeypatch, spawn_failure
):
    boundary = LocalRuntimeBoundary()
    boundary.wait_seconds = 1.0
    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir(mode=0o700)
    support.mkdir(mode=0o700)
    (root / "owner.lock").touch()
    worker_runtime, worker_peer = socket.socketpair()
    runtime_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    runtime_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    runtime_listener.bind(("127.0.0.1", 0))
    runtime_listener.listen(1)
    endpoint = f"http://127.0.0.1:{runtime_listener.getsockname()[1]}"
    expected_pid = os.getpid()
    expected_birth = runtime_cli.process_birth_identity()
    expected_instance = "runtime-a"
    owner_errors = []
    owner_thread = None
    child_threads = []
    spawned = []
    tracked_pairs = []
    real_socketpair = socket.socketpair
    real_mkdtemp = runtime_boundary_module.tempfile.mkdtemp
    short_rendezvous = []

    class OwnerDaemon:
        def __init__(self):
            self.instance_id = expected_instance
            self.root = root
            self.service = type("Service", (), {"realm": {"id": "realm-1"}})()

        def runtime_identity(self):
            return {
                "endpoint": endpoint,
                "protocol": "workspace.v1",
                "schema_digest": "sha256:" + "1" * 64,
                "runtime_epoch": 1,
                "runtime_instance_id": expected_instance,
                "runtime_session_id": "session-a",
            }

        def begin_orderly_worker_handoff(self, _common):
            return {
                "state": "prepared",
                "export": {"receipt": {"identity": "runtime-boundary-test"}},
                "worker_control_fd": os.dup(worker_runtime.fileno()),
                "listener_fd": os.dup(runtime_listener.fileno()),
                "old_runtime": {
                    "endpoint": endpoint,
                    "protocol": "workspace.v1",
                    "schema_digest": "sha256:" + "1" * 64,
                    "runtime_epoch": 1,
                    "runtime_instance_id": expected_instance,
                    "runtime_session_id": "session-a",
                },
            }

        def seal_orderly_worker_handoff(self, *_args, **_kwargs):
            return None

        def release_orderly_worker_handoff(self, _handoff_id):
            return None

        def cancel_orderly_worker_handoff(self, *_args, **_kwargs):
            return None

        def stop(self):
            return None

    owner_daemon = OwnerDaemon()

    def tracked_socketpair():
        pair = real_socketpair()
        tracked_pairs.append(pair)
        return pair

    def short_mkdtemp(*, prefix):
        path = real_mkdtemp(prefix="rf4-", dir="/var/tmp")
        short_rendezvous.append(Path(path))
        return path

    class FakeProcess:
        pid = expected_pid

        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

    def fake_popen(argv, **kwargs):
        assert kwargs["pass_fds"] == (198, 199, 200)
        assert argv[-6:] == [
            "--handoff-worker-fd", "198",
            "--handoff-listener-fd", "199",
            "--handoff-capability-fd", "200",
        ]
        for descriptor in kwargs["pass_fds"]:
            os.fstat(descriptor)
        spawned.append((tuple(argv), dict(kwargs)))
        if spawn_failure:
            raise OSError("injected owner B spawn failure")
        process = FakeProcess()
        child_channel = socket.socket(fileno=os.dup(200))

        def owner_b():
            try:
                frame = receive_frame(child_channel)
                send_frame(child_channel, {
                    "version": TRANSFER_VERSION,
                    "command": "descriptors_accepted",
                    "handoff_id": frame["handoff_id"],
                    "runtime_pid": process.pid,
                    "runtime_birth_id": expected_birth,
                    "runtime_instance_id": "runtime-b",
                })
                bound = receive_frame(child_channel)
                assert bound["command"] == "adopter_bound"
                assert bound["adopter"]["runtime_instance_id"] == "runtime-b"
            except BaseException as exc:
                owner_errors.append(exc)
            finally:
                child_channel.close()

        thread = threading.Thread(target=owner_b)
        child_threads.append(thread)
        thread.start()
        return process

    def fake_custodied_spawn(argv, *, support_root, stdout, pass_fds=()):
        return fake_popen(
            argv,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            close_fds=True,
            pass_fds=pass_fds,
        ), object()

    def launch_owner_a(sidecar, *, expected_identity, signum, identity_provider):
        nonlocal owner_thread
        assert sidecar == support / custody_broker_module.ACTIVE_CAPABILITY_NAME
        assert expected_identity == {
            "pid": expected_pid,
            "birth_id": expected_birth,
            "uid": os.getuid(),
        }
        assert identity_provider(expected_pid) == expected_identity
        assert signum == runtime_boundary_module.signal.SIGUSR1

        def owner_a():
            try:
                assert runtime_cli._owner_handoff_request(owner_daemon, support) is True
            except BaseException as exc:
                owner_errors.append(exc)

        owner_thread = threading.Thread(target=owner_a)
        owner_thread.start()
        return {"ok": True, "pid": expected_pid, "signal": int(signum)}

    monkeypatch.setattr(runtime_boundary_module.socket, "socketpair", tracked_socketpair)
    monkeypatch.setattr(runtime_boundary_module.tempfile, "mkdtemp", short_mkdtemp)
    monkeypatch.setattr(runtime_boundary_module, "signal_sealed_capability", launch_owner_a)
    monkeypatch.setattr(
        runtime_boundary_module,
        "subprocess",
        type(
            "SubprocessStub",
            (),
            {
                "Popen": staticmethod(fake_popen),
                "STDOUT": subprocess.STDOUT,
                "TimeoutExpired": subprocess.TimeoutExpired,
            },
        ),
    )
    monkeypatch.setattr(boundary, "_predecessor_active_reference_digest", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(boundary, "_spawn_custodied_runtime", fake_custodied_spawn)
    # This test owns descriptor normalization and channel closure. Dedicated
    # custody tests cover failed-adopter cleanup, so preserve the primary
    # adoption-timeout diagnostic here instead of replacing it with a fake
    # process cleanup result.
    monkeypatch.setattr(
        boundary, "_cleanup_failed_handoff_process", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(boundary, "process_birth_identity", lambda _pid: expected_birth)
    monkeypatch.setattr(boundary, "_custody_identity", lambda _pid: {
        "pid": expected_pid,
        "birth_id": expected_birth,
        "uid": os.getuid(),
    })
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _endpoint: {
        "protocol": "workspace.v1",
        "schema_digest": "sha256:" + "1" * 64,
        "runtime_epoch": 1,
        "runtime_instance_id": expected_instance,
        "runtime_session_id": "session-a",
    })
    monkeypatch.setattr(boundary, "_argv", lambda *_args, **_kwargs: ["runtime-owner-b"])
    source = SourceProfile(profile="astrid", capability_digest="sha256:" + "2" * 64)
    try:
        expected_error = (
            "spawn failure"
            if spawn_failure
            else "Runtime owner B did not adopt before the handoff deadline"
        )
        with pytest.raises((BootstrapError, OSError), match=expected_error):
            boundary._restart_preserving_worker(
                source=source,
                root=root,
                support=support,
                realm_id="realm-1",
                owner_lock=root / "owner.lock",
                endpoint=endpoint,
                expected_pid=expected_pid,
                expected_birth=expected_birth,
                expected_instance=expected_instance,
            )
        assert spawned
        assert len(tracked_pairs) == 1
        assert tracked_pairs[0][0].fileno() == -1
        assert tracked_pairs[0][1].fileno() == -1
        for descriptor in (198, 199, 200):
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        if owner_thread is not None:
            owner_thread.join(timeout=5)
        for thread in child_threads:
            thread.join(timeout=5)
        worker_runtime.close()
        worker_peer.close()
        runtime_listener.close()
        for rendezvous in short_rendezvous:
            (rendezvous / "coordinator.sock").unlink(missing_ok=True)
            rendezvous.rmdir()
    assert owner_thread is not None and not owner_thread.is_alive()
    assert all(not thread.is_alive() for thread in child_threads)
    assert owner_errors == []


def test_validate_owner_uses_daemon_identity_when_birth_probe_is_unavailable(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    owner = tmp_path / "instance.lock"
    owner.write_text(json.dumps({"pid": 12345, "runtime_instance_id": "instance", "process_birth_id": "birth"}))

    monkeypatch.setattr(boundary, "is_pid_alive", lambda _pid: True)
    monkeypatch.setattr(boundary, "process_birth_identity", lambda _pid: None)
    monkeypatch.setattr(
        boundary,
        "_http_health_payload",
        lambda _endpoint: {"protocol": "workspace.v1", "status": "ok", "runtime_instance_id": "instance"},
    )
    monkeypatch.setattr(boundary, "_http_status", lambda _endpoint: "ok")

    assert boundary.validate_owner(
        endpoint="http://127.0.0.1:61217",
        pid=12345,
        instance_id="instance",
        owner_lock=owner,
    )
    monkeypatch.setattr(
        boundary,
        "_http_health_payload",
        lambda _endpoint: {"protocol": "workspace.v1", "status": "ok", "runtime_instance_id": "other"},
    )
    assert not boundary.validate_owner(
        endpoint="http://127.0.0.1:61217",
        pid=12345,
        instance_id="instance",
        owner_lock=owner,
    )


def test_slow_healthy_runtime_and_degraded_owner(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        status = "ok"

        def do_GET(self):
            time.sleep(0.6)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": self.status,
                "protocol": "workspace.v1",
                "runtime_instance_id": "test",
            }).encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    boundary = LocalRuntimeBoundary()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    lock = tmp_path / "instance.lock"
    lock.write_text(json.dumps({"pid": pid, "runtime_instance_id": "test", "process_birth_id": birth}))
    try:
        assert boundary._http_health(endpoint)
        Handler.status = "degraded"
        assert boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id="test", owner_lock=lock, process_birth_id=birth)
        assert not boundary.health(endpoint=endpoint, pid=pid, instance_id="test")
        assert not boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id="wrong", owner_lock=lock, process_birth_id=birth)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
