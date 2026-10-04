from __future__ import annotations

import copy
import hashlib
import json
import socket

import pytest

from runtime_protocol.local_execution_supervisor import (
    HOST_PREPARATION_VERSION, RelayError, host_prepare_request,
    receive_frame, send_frame, validate_host_prepared,
    engine_listener_signal_request, validate_engine_listener_signal, engine_listener_signal_ack,
    validate_selected_profile,
)


def _prepare_case():
    config = {"runtime_root": "/disposable", "cwd": "/disposable", "server_log_path": "/disposable/out/sessions/test/comfy.log",
              "port": 8188, "locality": "managed_local_server", "warm_policy": "auto", "ready_timeout_sec": 30}
    session_digest = "sha256:" + hashlib.sha256(json.dumps(config, indent=2, sort_keys=True).encode()).hexdigest()
    profile = {"profile_id": "fake-profile", "workspace_uuid": "fake-workspace", "realm_root": "/disposable/realm",
               "support_root": "/disposable/support", "machine_id": "fake-machine",
               **{name: "/disposable/python" for name in ("worker_executable", "host_executable", "engine_executable", "engine_listener_executable")},
               **{name: "sha256:" + "1" * 64 for name in ("worker_artifact_digest", "host_artifact_digest", "engine_artifact_digest", "engine_listener_artifact_digest", "profile_digest", "release_digest")},
               "engine_endpoint": "http://127.0.0.1:8188", "profile_revision": "fake-revision", "session_config_digest": session_digest,
               "engine_launch": {"module": "vibecomfy.commands.session", "session_root": "/disposable/out/sessions/test", "config": config,
                                 "source_revision": "1" * 40, "source_content_digest": "sha256:" + "3" * 64,
                                 "listener_argv": ["/disposable/python", "-m", "comfy.cmd.main", "serve", "--port", "8188"],
                                 "adapter_pins": {name: "sha256:" + "4" * 64 for name in ("session_source_sha256", "spawn_sha256", "cleanup_sha256", "stop_sha256", "adapter_source_sha256")}}}
    request = host_prepare_request(
        operation_id="operation", channel_id="channel", owner_epoch="runtime-epoch",
        runtime_owner={"pid": 19, "uid": 501, "birth_id": "runtime-birth", "runtime_instance_id": "runtime-epoch", "coordinator_epoch": "runtime-epoch"},
        profile=profile,
        custody_scope="/disposable/runtime-custody",
    )
    response = {
        "version": HOST_PREPARATION_VERSION, "status": "prepared",
        "operation_id": "operation", "channel_id": "channel", "owner_epoch": "runtime-epoch",
        "processes": {"host": {"pid": 21, "birth_id": "host-birth"},
                      "engine": {"pid": 22, "birth_id": "engine-birth"},
                      "engine_listener": {"pid": 23, "birth_id": "listener-birth"}},
        "engine_binding": {"supervisor_pid": 22, "listener_pid": 23,
                           "listener_parent_pid": 22, "socket_owner_pid": 23},
        "session_config_digest": session_digest,
        # Shape-only peers do not assert real kernel/installed qualification.
        "custody_capabilities": {role: {"version": "runtime.role-custody-reference/v1",
                                      "scope_root": "/disposable/runtime-custody", "role": role,
                                      "generation": 1, "target": {"pid": pid, "birth_id": birth,
                                                                   "uid": 501, "audit_token_sha256": "sha256:" + "2" * 64,
                                                                   "audit_token_pidversion": pid + 1}}
                                 for role, pid, birth in (("engine", 22, "engine-birth"), ("engine_listener", 23, "listener-birth"))},
    }
    return request, response


def test_private_utf8_frame_roundtrip_without_credential_fields():
    a, b = socket.socketpair()
    try:
        a.settimeout(1)
        b.settimeout(1)
        value = {"version": HOST_PREPARATION_VERSION, "label": "é 山"}
        send_frame(a, value)
        assert receive_frame(b) == value
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("payload", [b'{"value":NaN}\n', b'{}\n{}\n', b'[]\n'])
def test_private_frame_rejects_noncanonical_or_unsolicited_payload(payload):
    a, b = socket.socketpair()
    try:
        a.settimeout(1)
        b.settimeout(1)
        a.sendall(payload)
        with pytest.raises(RelayError):
            receive_frame(b)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("field", ["operation_id", "channel_id", "owner_epoch"])
def test_prepared_reply_rejects_stale_private_binders(field):
    request, reply = _prepare_case()
    reply[field] = "stale"
    with pytest.raises(RelayError, match="stale channel or owner epoch"):
        validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="host-birth")


def test_prepared_reply_requires_each_child_role_custody_before_success():
    request, reply = _prepare_case()
    del reply["custody_capabilities"]["engine_listener"]
    with pytest.raises(RelayError, match="per-role retained custody"):
        validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="host-birth")


def test_prepared_reply_rejects_listener_owned_by_unrelated_process():
    request, reply = _prepare_case()
    reply["engine_binding"]["socket_owner_pid"] = 99
    with pytest.raises(RelayError, match="listener ownership"):
        validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="host-birth")


def test_prepared_reply_never_accepts_a_different_host_birth():
    request, reply = _prepare_case()
    with pytest.raises(RelayError, match="retained host"):
        validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="replacement-birth")


def test_prepared_reply_refuses_secret_or_activation_fields():
    request, reply = _prepare_case()
    reply["credential"] = "synthetic-not-a-live-credential"
    with pytest.raises(RelayError, match="shape/version"):
        validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="host-birth")


def test_prepared_reply_snapshot_cannot_be_mutated_by_later_peer_change():
    request, reply = _prepare_case()
    expected = copy.deepcopy(reply)
    result = validate_host_prepared(reply, request=request, host_pid=21, host_birth_id="host-birth")
    reply["processes"]["engine"]["pid"] = 999
    assert result == expected


@pytest.mark.parametrize("field,wrong", [("operation_id", "other"), ("owner_epoch", "other"), ("generation", 2), ("role", "host")])
def test_native_signal_binds_exact_live_role_and_private_channel(field, wrong):
    preparation, prepared = _prepare_case()
    reference = prepared["custody_capabilities"]["engine_listener"]
    request = engine_listener_signal_request(preparation=preparation, reference=reference, signum=15)
    request[field] = wrong
    with pytest.raises(RelayError, match="stale"):
        validate_engine_listener_signal(request, preparation=preparation, reference=reference)


@pytest.mark.parametrize("signum", [0, 1, True, "15"])
def test_native_signal_rejects_unadmitted_signal_even_with_custody(signum):
    preparation, prepared = _prepare_case()
    with pytest.raises(RelayError, match="admitted"):
        engine_listener_signal_request(preparation=preparation, reference=prepared["custody_capabilities"]["engine_listener"], signum=signum)


def test_native_signal_ack_does_not_claim_exit_or_transfer():
    preparation, prepared = _prepare_case()
    reference = prepared["custody_capabilities"]["engine_listener"]
    request = engine_listener_signal_request(preparation=preparation, reference=reference, signum=9)
    assert validate_engine_listener_signal(request, preparation=preparation, reference=reference) == request
    ack = engine_listener_signal_ack(request)
    assert ack == {**{k: v for k, v in request.items() if k != "command"}, "status": "signaled"}
    assert not {"exited", "cleaned", "transferred", "reaped"}.intersection(ack)


@pytest.mark.parametrize("field,value", [("module", "unselected.module"), ("source_revision", "current-checkout"), ("listener_argv", ["python", "main.py"]), ("adapter_pins", {})])
def test_profile_refuses_unselected_engine_source_or_launch(field, value):
    request, _ = _prepare_case()
    profile = request["profile"]
    profile["engine_launch"][field] = value
    with pytest.raises(RelayError):
        validate_selected_profile(profile)


def test_profile_refuses_config_drift_before_any_engine_launch():
    request, _ = _prepare_case()
    request["profile"]["engine_launch"]["config"]["cache_policy"] = "new"
    with pytest.raises(RelayError, match="pinned emitted file digest"):
        validate_selected_profile(request["profile"])


def _cleaned_reply(request, prepared):
    return {**{k: v for k, v in request.items() if k != "command"}, "status": "cleaned",
            "cleanup": {role: {"generation": ref["generation"], "target": ref["target"], "exit_code": 0,
                               "proof_kind": "retained-child-exit" if role == "engine" else "authenticated-retained-child-exit"}
                        for role, ref in prepared["custody_capabilities"].items()}}


def test_runtime_relay_generic_host_prepare_report_abort_cpu_wire_journey():
    """Real private framing, synthetic child/Host facts; no native acceptance."""
    import threading
    from runtime_protocol.local_execution_supervisor import LocalExecutionRelay, serve_control, CONTROL_VERSION
    preparation, prepared = _prepare_case()
    runtime, relay = socket.socketpair()
    host, host_peer = socket.socketpair()
    for channel in (runtime, relay, host, host_peer):
        channel.settimeout(2)
    events = []
    errors = []
    refs = copy.deepcopy(prepared["custody_capabilities"])
    for role, pid, birth in (("relay", 20, "relay-birth"), ("host", 21, "host-birth")):
        refs[role] = {**refs["engine"], "role": role, "target": {**refs["engine"]["target"], "pid": pid, "birth_id": birth}}

    def host_loop():
        try:
            while True:
                request = receive_frame(host_peer)
                events.append(request["command"])
                if request["command"] == "abort_local_execution":
                    send_frame(host_peer, _cleaned_reply(request, prepared))
                    return
                send_frame(host_peer, prepared)
        except BaseException as exc:
            errors.append(exc)

    class Session:
        def __init__(self):
            def exchange(request):
                send_frame(host, request)
                return receive_frame(host)
            self.bridge = LocalExecutionRelay(host_pid=21, host_birth_id="host-birth", exchange=exchange, verify_host=lambda: events.append("verify-host"))
        def reap_host(self):
            events.append("authoritative-host-wait")
            return 0
        def activate(self, _):
            pytest.fail("preparation must not activate credentials or tasks")

    def factory(_preparation, _config, *, retain):
        session = Session()
        retain(session)
        return session

    def relay_loop():
        try:
            serve_control(relay, session_factory=factory, reference_reader=lambda scope, role: refs[role],
                          relay_identity=lambda: {"pid": 20, "birth_id": "relay-birth"})
        except RelayError as exc:
            if "channel closed" not in str(exc):
                errors.append(exc)
    threads = [threading.Thread(target=host_loop), threading.Thread(target=relay_loop)]
    for thread in threads:
        thread.start()
    try:
        send_frame(runtime, {"version": CONTROL_VERSION, "command": "prepare", "preparation": preparation, "config": {}})
        first = receive_frame(runtime)
        assert first["status"] == "ok"
        assert first["report"]["version"] == "runtime.local-worker-preparation/v3"
        assert first["report"]["owner_epoch"] == "runtime-epoch"
        assert set(first["report"]["custody_capabilities"]) == {"relay", "host", "engine", "engine_listener"}
        send_frame(runtime, {"version": CONTROL_VERSION, "command": "report"})
        assert receive_frame(runtime)["report"] == first["report"]
        send_frame(runtime, {"version": CONTROL_VERSION, "command": "abort"})
        cleaned = receive_frame(runtime)
        assert cleaned["status"] == "ok" and cleaned["host_exit_code"] == 0
        assert cleaned["host_result"]["status"] == "cleaned"
        send_frame(runtime, {"version": CONTROL_VERSION, "command": "abort"})
        assert receive_frame(runtime) == cleaned
        assert events.count("abort_local_execution") == 1
        assert events.index("abort_local_execution") < events.index("authoritative-host-wait")
        assert errors == []
    finally:
        runtime.close()
        for thread in threads:
            thread.join(2)
        for channel in (relay, host, host_peer):
            channel.close()
        assert all(not thread.is_alive() for thread in threads)


def test_partial_preparation_retains_custody_for_bound_abort_retry():
    from runtime_protocol.local_execution_supervisor import LocalExecutionRelay
    request, prepared = _prepare_case()
    sent = []
    partial = {"version": HOST_PREPARATION_VERSION, "status": "unresolved", "operation_id": "operation", "channel_id": "channel", "owner_epoch": "runtime-epoch", "error_code": "preparation_unresolved", "custody_capabilities": prepared["custody_capabilities"]}
    def exchange(value):
        sent.append(value)
        if value["command"] == "prepare_local_execution":
            return partial
        if len(sent) == 2:
            return {**{k: v for k, v in value.items() if k != "command"}, "status": "unresolved", "error_code": "cleanup_unresolved"}
        return _cleaned_reply(value, prepared)
    bridge = LocalExecutionRelay(host_pid=21, host_birth_id="host-birth", exchange=exchange, verify_host=lambda: None)
    assert bridge.prepare(request)["status"] == "unresolved"
    assert bridge.abort()["status"] == "unresolved"
    assert bridge.abort()["status"] == "cleaned"
    assert sent[1] == sent[2]
    assert sent[1]["custody_capabilities"] == prepared["custody_capabilities"]


@pytest.mark.parametrize("change", ["missing-role", "missing-wait", "changed-target", "boolean-exit"])
def test_abort_cannot_turn_unknown_or_wrong_incarnation_into_cleanup(change):
    from runtime_protocol.local_execution_supervisor import host_abort_request, validate_host_abort
    request, prepared = _prepare_case()
    abort = host_abort_request(request, prepared["custody_capabilities"])
    reply = _cleaned_reply(abort, prepared)
    if change == "missing-role":
        del reply["cleanup"]["engine_listener"]
    elif change == "missing-wait":
        reply["cleanup"]["engine"]["proof_kind"] = "pid-absent"
    elif change == "changed-target":
        reply["cleanup"]["engine"]["target"] = {**reply["cleanup"]["engine"]["target"], "birth_id": "replacement"}
    else:
        reply["cleanup"]["engine"]["exit_code"] = True
    with pytest.raises(RelayError):
        validate_host_abort(reply, request=abort)


def test_prepare_replay_changed_profile_never_spawns_or_rebinds():
    from runtime_protocol.local_execution_supervisor import LocalExecutionRelay
    request, prepared = _prepare_case()
    calls = []
    bridge = LocalExecutionRelay(host_pid=21, host_birth_id="host-birth", exchange=lambda value: calls.append(value) or prepared, verify_host=lambda: None)
    bridge.prepare(request)
    changed = copy.deepcopy(request)
    changed["profile"]["profile_revision"] = "replacement"
    with pytest.raises(RelayError, match="replay changed"):
        bridge.prepare(changed)
    assert len(calls) == 1


def test_retained_process_echild_is_not_successful_exit(monkeypatch):
    import threading
    from types import SimpleNamespace
    from runtime_protocol.local_execution_supervisor import RetainedProcess
    child = SimpleNamespace(pid=123, returncode=None, _waitpid_lock=threading.Lock())
    retained = RetainedProcess(child)
    def unavailable(*_):
        raise ChildProcessError("not ours")
    monkeypatch.setattr("os.waitpid", unavailable)
    with pytest.raises(RelayError, match="ownership is unknown"):
        retained.poll()
    assert retained.exit_code is None
