from __future__ import annotations

import subprocess
import fcntl
import os
from pathlib import Path
import socket
import threading
import time

import pytest

from banodoco_local import custody_broker


def test_default_identity_returns_none_only_for_proven_absence(monkeypatch):
    observed_timeouts = []

    def run(_argv, **kwargs):
        observed_timeouts.append(kwargs["timeout"])
        return subprocess.CompletedProcess(_argv, 1, stdout="", stderr="")

    monkeypatch.setattr(custody_broker.subprocess, "run", run)
    assert custody_broker.default_process_identity(999_999, timeout=0.25) is None
    assert observed_timeouts == [0.25]


@pytest.mark.parametrize(
    ("completed", "message"),
    [
        (subprocess.CompletedProcess(["ps"], 2, stdout="", stderr="failed"), "status 2"),
        (subprocess.CompletedProcess(["ps"], 0, stdout="", stderr=""), "no identity"),
        (subprocess.CompletedProcess(["ps"], 0, stdout="malformed", stderr=""), "malformed"),
    ],
)
def test_default_identity_rejects_unknown_observation(monkeypatch, completed, message):
    monkeypatch.setattr(
        custody_broker.subprocess, "run", lambda *_args, **_kwargs: completed,
    )
    with pytest.raises(custody_broker.CustodyError, match=message):
        custody_broker.default_process_identity(123, timeout=0.1)


def test_default_identity_timeout_is_unknown(monkeypatch):
    def timeout(*_args, **kwargs):
        raise subprocess.TimeoutExpired("ps", kwargs["timeout"])

    monkeypatch.setattr(custody_broker.subprocess, "run", timeout)
    with pytest.raises(custody_broker.CustodyError, match="observation failed"):
        custody_broker.default_process_identity(123, timeout=0.01)


def test_default_identity_rejects_expired_deadline():
    with pytest.raises(custody_broker.CustodyError, match="deadline expired"):
        custody_broker.default_process_identity(123, timeout=0)


def test_scope_close_drains_inflight_admission_and_refuses_late_admission(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir(mode=0o700)
    lease = custody_broker._acquire_scope_admission(scope, timeout=0.1)
    assert os.get_inheritable(lease) is False
    result = {}

    def close():
        result.update(custody_broker.close_authority_scope(
            scope, deadline=time.monotonic() + 1.0,
        ))

    thread = threading.Thread(target=close)
    thread.start()
    deadline = time.monotonic() + 0.5
    while not (scope / custody_broker.AUTHORITY_SCOPE_CLOSED).is_file():
        assert time.monotonic() < deadline
        time.sleep(0.005)
    assert thread.is_alive()
    fcntl.flock(lease, fcntl.LOCK_UN)
    os.close(lease)
    thread.join(timeout=1.0)
    assert result["drained"] is True
    with pytest.raises(custody_broker.CustodyError, match="scope is closed"):
        custody_broker._acquire_scope_admission(scope, timeout=0.1)


def test_scope_drain_timeout_remains_closed_and_unresolved(tmp_path):
    scope = tmp_path / "scope"
    scope.mkdir(mode=0o700)
    lease = custody_broker._acquire_scope_admission(scope, timeout=0.1)
    result = custody_broker.close_authority_scope(
        scope, deadline=time.monotonic() + 0.02,
    )
    assert result["closed"] is True
    assert result["drained"] is False
    assert result["errors"][0]["stage"] == "drain"
    fcntl.flock(lease, fcntl.LOCK_UN)
    os.close(lease)
    retry = custody_broker.close_authority_scope(
        scope, deadline=time.monotonic() + 0.1,
    )
    assert retry["drained"] is True


def test_runtime_broker_publication_completes_before_scope_close_drains(
    tmp_path, monkeypatch,
):
    pid = 43124
    identity = {"pid": pid, "birth_id": "birth-43124", "uid": os.getuid()}
    tokens = iter((
        {"pid": pid, "uid": os.getuid(), "pidversion": 10, "words": [1] * 8,
         "sha256": "sha256:" + "1" * 64},
        {"pid": pid, "uid": os.getuid(), "pidversion": 11, "words": [2] * 8,
         "sha256": "sha256:" + "2" * 64},
    ))
    monkeypatch.setattr(custody_broker.sys, "platform", "darwin")
    monkeypatch.setattr(custody_broker, "_peer_token", lambda _connection: next(tokens))
    entered, release = threading.Event(), threading.Event()
    original_append = custody_broker._append_owner_jsonl

    def blocked_append(path, value):
        entered.set()
        assert release.wait(1.0)
        original_append(path, value)

    monkeypatch.setattr(custody_broker, "_append_owner_jsonl", blocked_append)
    scope = tmp_path / "scope"
    scope.mkdir(mode=0o700)
    journal = scope / "authorities.jsonl"
    broker = custody_broker.RoleBoundCustodyBroker(
        role="worker", identity_provider=lambda observed: identity if observed == pid else None,
        ledger_root=tmp_path / "ledger", authority_journal=journal,
        authority_scope_root=scope, timeout=1.0,
    )
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(broker.socket_path))
    frame = {
        "version": custody_broker.PROTOCOL_VERSION, "command": "register_pre_exec",
        "run_id": broker.run_id, "role": broker.role, "pid": pid,
        "ppid": os.getpid(), "argv_digest": "sha256:" + "a" * 64,
    }
    custody_broker._send_frame(connection, frame)
    assert custody_broker._read_frame(connection)["status"] == "registered"
    assert entered.wait(1.0)
    closed = {}
    thread = threading.Thread(target=lambda: closed.update(
        custody_broker.close_authority_scope(scope, deadline=time.monotonic() + 1.0)
    ))
    thread.start()
    marker_deadline = time.monotonic() + 0.5
    while not (scope / custody_broker.AUTHORITY_SCOPE_CLOSED).is_file():
        assert time.monotonic() < marker_deadline
        time.sleep(0.005)
    assert thread.is_alive()
    release.set()
    broker.wait_until_sealed()
    connection.close()
    thread.join(timeout=1.0)
    assert closed["drained"] is True
    assert len(journal.read_text().splitlines()) == 1


def test_runtime_broker_pre_spawn_abort_releases_scope_lease(tmp_path, monkeypatch):
    monkeypatch.setattr(custody_broker.sys, "platform", "darwin")
    scope = tmp_path / "scope"
    scope.mkdir(mode=0o700)
    broker = custody_broker.RoleBoundCustodyBroker(
        role="worker", identity_provider=lambda _pid: None,
        ledger_root=tmp_path / "ledger", authority_journal=scope / "authorities.jsonl",
        authority_scope_root=scope, timeout=0.1,
    )
    broker.abort_before_spawn()
    result = custody_broker.close_authority_scope(
        scope, deadline=time.monotonic() + 0.1,
    )
    assert result["drained"] is True
    with pytest.raises(custody_broker.CustodyError, match="scope is closed"):
        custody_broker.RoleBoundCustodyBroker(
            role="late", identity_provider=lambda _pid: None,
            ledger_root=tmp_path / "late-ledger",
            authority_journal=scope / "authorities.jsonl",
            authority_scope_root=scope, timeout=0.1,
        )
