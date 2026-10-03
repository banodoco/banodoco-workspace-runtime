from __future__ import annotations

import subprocess

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
