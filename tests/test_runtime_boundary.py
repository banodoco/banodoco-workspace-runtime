import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from banodoco_local.bootstrap import BootstrapError, SourceProfile
from banodoco_local.runtime_boundary import ADMISSION_TIMEOUT_ENV, LocalRuntimeBoundary


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"status": "ok", "protocol": "workspace.v1"}).encode()


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


def test_pid_liveness_treats_permission_denied_as_alive(monkeypatch):
    def deny_signal(_pid, _signal):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(os, "kill", deny_signal)

    assert LocalRuntimeBoundary.is_pid_alive(12345)


def test_validate_owner_uses_daemon_identity_when_birth_probe_is_unavailable(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    owner = tmp_path / "instance.lock"
    owner.write_text(json.dumps({"pid": 12345, "runtime_instance_id": "instance", "process_birth_id": "birth"}))

    def deny_signal(_pid, _signal):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(os, "kill", deny_signal)
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


class _CustodyChild:
    pid = 51001
    _runtime_boundary_sole_reaper = True

    def __init__(self):
        self.exited = False

    def poll(self):
        return 0 if self.exited else None

    def wait(self, *, timeout):
        assert timeout > 0
        self.exited = True
        return 0


def _stub_owner_broker(monkeypatch, child, *, exit_during_signal=False):
    from banodoco_local import runtime_boundary as boundary_module

    class Broker:
        error = None
        authority_scope_root = None

        def set_cleanup_deadline(self, deadline):
            assert deadline > time.monotonic()

        def signal(self, signum, *, expected_pid):
            assert expected_pid == child.pid
            if exit_during_signal:
                child.exited = True
            raise boundary_module.CustodyError("identity unavailable")

    monkeypatch.setattr(boundary_module, "RoleBoundCustodyBroker", Broker)
    child._runtime_custody_broker = Broker()
    monkeypatch.setattr(os, "kill", lambda *_: pytest.fail("numeric PID fallback"))
    monkeypatch.setattr(os, "killpg", lambda *_: pytest.fail("numeric PGID fallback"))
    return boundary_module


def test_token_signal_exit_race_uses_only_retained_child_exit(monkeypatch):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child, exit_during_signal=True)
    LocalRuntimeBoundary._terminate(child)
    assert child.exited


def test_unverifiable_live_owner_retains_cleanup_uncertainty(monkeypatch):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child)
    with pytest.raises(BootstrapError, match="cleanup remains uncertain"):
        LocalRuntimeBoundary._terminate(child)
    assert not child.exited
    assert isinstance(child._runtime_cleanup_error, BootstrapError)


def test_primary_start_error_retains_cleanup_uncertainty_as_cause(monkeypatch):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child)
    primary = OSError("ready reply failed")
    with pytest.raises(OSError) as result:
        try:
            raise primary
        except OSError:
            LocalRuntimeBoundary._terminate(child)
    assert result.value is primary
    assert result.value.__cause__ is child._runtime_cleanup_error
    assert not child.exited


def test_unowned_handle_does_not_infer_termination_from_poll(monkeypatch):
    child = _CustodyChild()
    child.exited = True
    child._runtime_boundary_sole_reaper = False
    _stub_owner_broker(monkeypatch, child)
    with pytest.raises(BootstrapError, match="sole-reaper"):
        LocalRuntimeBoundary._terminate(child)


def test_runtime_spawn_retains_owner_and_wires_escrow_before_seal(tmp_path, monkeypatch):
    from banodoco_local import runtime_boundary as boundary_module
    child = _CustodyChild()
    facts = {}

    class Broker:
        def __init__(self, **kwargs):
            facts.update(kwargs)
            assert kwargs["authority_scope_root"].is_dir()
            assert kwargs["authority_journal"].parent == kwargs["authority_scope_root"]

        def child_environment(self, argv, *, start_new_session):
            assert argv == ["/isolated/python", "-m", "runtime_protocol"]
            assert start_new_session
            return {"CUSTODY_TEST": "1"}

        def wait_until_sealed(self):
            assert boundary._process is child
            assert child._runtime_custody_broker is self
            assert child._runtime_boundary_owner is boundary
            raise boundary_module.CustodyError("seal persistence failed")

    monkeypatch.setattr(boundary_module, "RoleBoundCustodyBroker", Broker)
    monkeypatch.setattr(boundary_module.subprocess, "Popen", lambda *_args, **kwargs: child)
    boundary = LocalRuntimeBoundary()
    with pytest.raises(boundary_module.RuntimeCustodyLaunchUncertain) as result:
        boundary._spawn_runtime(["/isolated/python", "-m", "runtime_protocol"], support_root=tmp_path, stdout=None)
    assert result.value.process is child
    assert result.value.broker is child._runtime_custody_broker
    assert facts["role"] == "runtime_owner"
    assert boundary._process is child
