from __future__ import annotations

import socket
import threading
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker_composition import (
    CONTROL_VERSION,
    CrossProcessWorkerPreparer,
    _PreparedWorker,
    _frame_receive,
    _frame_send,
    _validated_host_control_diagnostic,
)


def _diagnostic():
    return {
        "operation": "rebind_prepare",
        "handoff_phase": "export_sealed",
        "stage": "receive",
        "exception_category": "connection_reset",
        "host": {"pid": 9876, "birth_id": "ps-lstart:Thu Oct  1 10:56:00 2026"},
        "handoff_id": "handoff-1",
        "errno": 54,
    }


def _expected_host():
    return {"pid": 9876, "birth_id": "ps-lstart:Thu Oct  1 10:56:00 2026"}


def test_host_control_diagnostic_schema_accepts_exact_bounded_fields():
    value = _diagnostic()
    assert _validated_host_control_diagnostic(
        value, expected_handoff_id="handoff-1", expected_host=_expected_host()
    ) == value


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(operation="credential=secret"),
        lambda value: value.update(handoff_id="different-handoff"),
        lambda value: value.update(handoff_phase="paused"),
        lambda value: value.update(stage="send", exception_category="ack_validation"),
        lambda value: value.update(operation="idle_peek", stage="send"),
        lambda value: value.update(exception_category="raw exception text"),
        lambda value: value["host"].update(secret="must-not-cross"),
        lambda value: value["host"].update(pid=9877),
        lambda value: value["host"].update(birth_id="credential=secret"),
        lambda value: value["host"].update(
            birth_id="ps-lstart:Thu Oct  1 10:56:01 2026"
        ),
        lambda value: value.update(errno="54"),
    ],
)
def test_host_control_diagnostic_schema_drops_invalid_values(mutation):
    value = _diagnostic()
    mutation(value)
    assert _validated_host_control_diagnostic(
        value, expected_handoff_id="handoff-1", expected_host=_expected_host()
    ) is None


def test_handoff_rpc_propagates_validated_diagnostic(monkeypatch):
    class Worker:
        pid = 4321

        @staticmethod
        def poll():
            return None

    profile = SimpleNamespace(profile_id="astrid")
    parent, peer = socket.socketpair()
    handle = _PreparedWorker(
        Worker(),
        "birth",
        parent,
        {"processes": {"host": _expected_host()}},
        None,
    )
    preparer = CrossProcessWorkerPreparer(profile=profile, config={}, environment={})
    monkeypatch.setattr(preparer, "_birth", lambda _pid: "birth")
    payload = {
        "version": CONTROL_VERSION,
        "command": "handoff_adopt",
        "handoff_id": "handoff-1",
        "nonce_digest": "sha256:" + "a" * 64,
        "sealed_record_digest": "sha256:" + "b" * 64,
    }
    diagnostic = _diagnostic()

    def worker_reply():
        _frame_receive(peer)
        _frame_send(
            peer,
            {
                "version": CONTROL_VERSION,
                "status": "error",
                "error": "prepared Worker rejected the handoff",
                "error_code": "host_control_failed",
                "error_stage": "control",
                "host_control_diagnostic": diagnostic,
            },
        )

    thread = threading.Thread(target=worker_reply)
    thread.start()
    try:
        with pytest.raises(ConflictError) as raised:
            preparer.handoff_command(handle, payload)
        assert raised.value.details == {
            "handoff_error_code": "host_control_failed",
            "handoff_stage": "control",
            "host_control_diagnostic": diagnostic,
        }
    finally:
        thread.join(1)
        parent.close()
        peer.close()
