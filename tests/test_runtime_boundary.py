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


def test_invalid_startup_admission_budget_fails_closed(monkeypatch):
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "not-a-duration")
    with pytest.raises(BootstrapError, match="ADMISSION_TIMEOUT"):
        LocalRuntimeBoundary()


def test_pid_liveness_treats_permission_denied_as_alive(monkeypatch):
    def deny_signal(_pid, _signal):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(os, "kill", deny_signal)

    assert LocalRuntimeBoundary.is_pid_alive(12345)


def test_slow_healthy_runtime_and_degraded_owner(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        status = "ok"

        def do_GET(self):
            time.sleep(0.6)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"status": self.status, "protocol": "workspace.v1"}).encode())

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
