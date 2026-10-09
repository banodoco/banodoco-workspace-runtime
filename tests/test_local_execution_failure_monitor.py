"""Controlled CPU sockets prove failure disposition, never native custody."""
import copy
from contextlib import contextmanager
import os
import socket
import threading

import pytest

from runtime_protocol import local_execution_supervisor as relay
from runtime_protocol.local_execution_handoff import VERSION, digest
from test_local_execution_supervisor import _prepare_case, _cleaned_reply, _handoff_case


@contextmanager
def _controlled_relay(*, cleanup="cleaned", host_replies=None):
    preparation, prepared = _prepare_case()
    runtime, control = socket.socketpair()
    host, host_peer = socket.socketpair()
    sockets = (runtime, control, host, host_peer)
    for channel in sockets:
        channel.settimeout(2)
    events, outcomes = [], []
    refs = copy.deepcopy(prepared["custody_capabilities"])
    for role, pid, birth in (("relay", 20, "relay-birth"), ("host", 21, "host-birth")):
        refs[role] = {**refs["engine"], "role": role,
                      "target": {**refs["engine"]["target"], "pid": pid, "birth_id": birth}}

    def host_loop():
        try:
            while True:
                request = relay.receive_frame(host_peer)
                events.append(request["command"])
                if host_replies is not None and request["command"].startswith("handoff_"):
                    response = host_replies(request)
                    if response is not None:
                        relay.send_frame(host_peer, response)
                    continue
                if request["command"] == "abort_local_execution":
                    if cleanup == "raises":
                        host_peer.close()
                        return
                    response = _cleaned_reply(request, prepared) if cleanup == "cleaned" else {
                        **{k: v for k, v in request.items() if k != "command"},
                        "status": "unresolved", "error_code": "cleanup_unresolved"}
                    relay.send_frame(host_peer, response)
                    return
                relay.send_frame(host_peer, prepared)
        except (relay.RelayError, OSError):
            pass

    class Session:
        timeout = 2
        def __init__(self):
            self.control = host
            def exchange(request):
                relay.send_frame(self.control, request)
                return relay.receive_frame(self.control)
            self.bridge = relay.LocalExecutionRelay(host_pid=21, host_birth_id="host-birth",
                exchange=exchange, verify_host=lambda: events.append("verify-host"))
        def reap_host(self):
            events.append("retained-host-wait")
            return 0

    def factory(_preparation, _config, *, retain):
        session = Session(); retain(session); return session
    def control_loop():
        try:
            relay.serve_control(control, session_factory=factory,
                reference_reader=lambda scope, role: refs[role],
                relay_identity=lambda: {"pid": 20, "birth_id": "relay-birth"})
        except BaseException as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=host_loop), threading.Thread(target=control_loop)]
    for thread in threads:
        thread.start()
    try:
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "prepare",
                                  "preparation": preparation, "config": {}})
        assert relay.receive_frame(runtime)["status"] == "ok"
        yield runtime, host, host_peer, events, outcomes, threads[1]
    finally:
        runtime.close()
        for thread in threads:
            thread.join(3)
        for channel in sockets:
            channel.close()
        for thread in threads:
            thread.join(3)
        assert not any(thread.is_alive() for thread in threads)


@pytest.mark.parametrize("event", ["eof", "unsolicited"])
def test_idle_host_failure_is_explicit_and_does_not_consume_or_clean(event):
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        if event == "eof":
            peer.shutdown(socket.SHUT_WR)
        else:
            peer.sendall(b"unexpected-private-frame\n")
        response = relay.receive_frame(runtime)
        assert response == {"version": relay.CONTROL_VERSION, "status": "unresolved",
                            "error_code": "host_control_closed" if event == "eof" else "host_control_unsolicited"}
        thread.join(2)
        assert len(outcomes) == 1 and isinstance(outcomes[0], relay._RelaySupervisionFailure)
        assert not outcomes[0].cleanup_verified
        assert "cleanup remains unresolved" in str(outcomes[0])
        assert "abort_local_execution" not in events and "retained-host-wait" not in events
        if event == "unsolicited":
            assert host.recv(1024) == b"unexpected-private-frame\n"


def test_expected_bridge_replies_are_consumed_by_bridge_and_clean_abort_replays():
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "report"})
        assert relay.receive_frame(runtime)["status"] == "ok"
        for _ in range(2):
            relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "abort"})
            assert relay.receive_frame(runtime)["host_result"]["status"] == "cleaned"
        runtime.close(); thread.join(2)
        assert not outcomes and events.count("abort_local_execution") == 1
        assert events.count("retained-host-wait") == 1


@pytest.mark.parametrize("cleanup", ["cleaned", "unresolved", "raises"])
def test_last_runtime_channel_loss_uses_only_retained_cleanup(cleanup):
    with _controlled_relay(cleanup=cleanup) as (runtime, host, peer, events, outcomes, thread):
        runtime.close(); thread.join(2)
        assert len(outcomes) == 1 and isinstance(outcomes[0], relay._RelaySupervisionFailure)
        assert outcomes[0].reason == "runtime_control_closed"
        assert outcomes[0].cleanup_verified is (cleanup == "cleaned")
        assert events.count("abort_local_execution") == 1
        assert events.count("retained-host-wait") == int(cleanup == "cleaned")


def _timer_request(tmp_path):
    request, reply = _handoff_case(tmp_path)
    request["binding"]["deadline_unix_ms"] = 100_500
    b = request["binding"]
    b["intent_digest"] = digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}})
    return request, reply


@pytest.mark.parametrize("outcome", ["unresolved", "conflict", "active_work", "report"])
def test_rejected_or_reported_binding_cannot_create_or_extend_deadline(tmp_path, outcome):
    request, reply = _timer_request(tmp_path)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 100.0)
    rejected = copy.deepcopy(request)
    rejected_reply = {**reply, "status": outcome if outcome != "report" else "ok"}
    if outcome == "report":
        rejected["command"] = "handoff_report"
    monitor.accepted(rejected, rejected_reply)
    assert monitor.deadline is None
    monitor.accepted(request, reply)
    assert monitor.deadline == 0.5
    rejected["binding"]["deadline_unix_ms"] += 999_999
    monitor.accepted(rejected, rejected_reply)
    clock[0] = 0.5
    assert monitor.expired() and monitor.deadline == 0.5


def test_finalized_handoff_does_not_expire_on_replayed_prior_phase(tmp_path):
    request, reply = _timer_request(tmp_path)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 100.0)
    monitor.accepted(request, reply)
    monitor.accepted({**request, "command": "handoff_finalize"}, {**reply, "phase": "finalized"})
    monitor.accepted(request, reply)
    clock[0] = 10_000
    assert monitor.deadline is None and not monitor.expired()


def test_durable_finalized_phase_dominates_replayed_old_reply(tmp_path):
    request, reply = _timer_request(tmp_path)
    monitor = relay._RelayFailureMonitor(monotonic=lambda: 1000.0, wall_time=lambda: 1000.0)
    monitor.accepted(request, reply, current_phase="finalized")
    assert monitor.deadline is None and not monitor.expired()


def test_accepted_deadline_fails_before_cleanup_and_preserves_failure(monkeypatch, tmp_path):
    request, reply = _timer_request(tmp_path)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 100.0)
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    class Endpoint:
        successor_listener = None
        def handoff(self, received, **_):
            assert received == request
            return reply
    monkeypatch.setattr(relay, "_native_handoff_endpoint", lambda *_: Endpoint())
    with _controlled_relay(cleanup="unresolved") as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
        assert relay.receive_frame(runtime)["handoff"]["status"] == "ok"
        clock[0] = 0.5
        assert relay.receive_frame(runtime) == {"version": relay.CONTROL_VERSION,
            "status": "unresolved", "error_code": "deadline_expired"}
        thread.join(2)
        assert outcomes[0].reason == "deadline_expired" and not outcomes[0].cleanup_verified
        assert events.count("abort_local_execution") == 1 and "retained-host-wait" not in events


@pytest.mark.parametrize("connect_before_a_loss", [False, True])
def test_source_eof_preserves_selected_successor_route(monkeypatch, tmp_path, connect_before_a_loss):
    request, reply = _handoff_case(tmp_path)
    listener_socket, incoming = socket.socketpair()
    successor, successor_control = socket.socketpair()
    for channel in (listener_socket, incoming, successor, successor_control):
        channel.settimeout(2)
    class Peer:
        channel = successor_control
    class Listener:
        socket = listener_socket
        closed = False
        def accept(self):
            return Peer(), relay.receive_frame(self.socket)
    class Endpoint:
        successor_listener = Listener()
        def handoff(self, received, **_):
            return {**reply, "phase": "finalized"}
    monkeypatch.setattr(relay, "_native_handoff_endpoint", lambda *_: Endpoint())
    frame = {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request}
    try:
        with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
            relay.send_frame(runtime, frame)
            assert relay.receive_frame(runtime)["handoff"]["status"] == "ok"
            if connect_before_a_loss:
                relay.send_frame(incoming, frame)
                assert relay.receive_frame(successor)["status"] == "ok"
            runtime.close()
            if not connect_before_a_loss:
                relay.send_frame(incoming, frame)
                assert relay.receive_frame(successor)["status"] == "ok"
            relay.send_frame(successor, {"version": relay.CONTROL_VERSION, "command": "report"})
            assert relay.receive_frame(successor)["status"] == "ok"
            assert thread.is_alive() and not outcomes and "abort_local_execution" not in events
            # End with an observed host failure, without changing ownership.
            peer.shutdown(socket.SHUT_WR)
            assert relay.receive_frame(successor)["error_code"] == "host_control_closed"
            thread.join(2)
    finally:
        for channel in (listener_socket, incoming, successor, successor_control):
            channel.close()


def test_main_failure_is_nonzero_and_explicitly_unresolved(monkeypatch, capfd):
    runtime, control = socket.socketpair()
    fd = os.dup(control.fileno())
    def fail(_):
        raise relay._RelaySupervisionFailure("host_control_closed")
    monkeypatch.setattr(relay, "serve_control", fail)
    try:
        assert relay.main(["--prepared-control-fd", str(fd)]) == 78
        assert "host_control_closed; cleanup remains unresolved" in capfd.readouterr().err
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        runtime.close(); control.close()


@pytest.mark.parametrize("chunks", [(b"{",), (b"{", b'"v')])
def test_partial_or_trickled_runtime_frame_cannot_reset_active_deadline(monkeypatch, tmp_path, chunks):
    request, reply = _timer_request(tmp_path)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 100.0)
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    class Endpoint:
        successor_listener = None
        _phase = "host_paused"
        def handoff(self, received, **_):
            return reply
    monkeypatch.setattr(relay, "_native_handoff_endpoint", lambda *_: Endpoint())
    received = [threading.Event() for _ in chunks]
    original_recv = relay._DeadlineIO.recv
    def trickled_read(io, *args):
        data = original_recv(io, *args)
        if data in chunks:
            index = chunks.index(data)
            clock[0] = 0.5 * (index + 1) / len(chunks)
            received[index].set()
        return data
    monkeypatch.setattr(relay._DeadlineIO, "recv", trickled_read)
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
        assert relay.receive_frame(runtime)["handoff"]["status"] == "ok"
        for index, chunk in enumerate(chunks):
            runtime.sendall(chunk)
            assert received[index].wait(2)
        thread.join(2)
        assert len(outcomes) == 1 and outcomes[0].reason == "deadline_expired"
        assert isinstance(outcomes[0].__cause__, relay._DeadlineExpired)
        assert not thread.is_alive()


@pytest.mark.parametrize("state", ["idle", "outstanding", "failed"])
def test_expiry_with_queued_host_frame_never_consumes_or_aborts(state):
    runtime, control = socket.socketpair()
    host, peer = socket.socketpair()
    events = []
    class Bridge:
        def abort(self):
            events.append("unsafe-abort")
            pytest.fail("queued or unresolved host stream cannot accept cleanup RPC")
    class Session:
        control = host
        bridge = Bridge()
    stream = relay._HostStreamState(); stream.state = state
    original = relay._DeadlineExpired("original deadline failure")
    try:
        peer.sendall(b"queued-unsolicited-frame\n")
        with pytest.raises(relay._RelaySupervisionFailure) as caught:
            relay._fail_supervision({control: None}, Session(), "deadline_expired", stream=stream, cause=original)
        assert caught.value.__cause__ is original and not caught.value.cleanup_verified
        assert relay.receive_frame(runtime)["error_code"] == "deadline_expired"
        assert host.recv(1024) == b"queued-unsolicited-frame\n" and not events
    finally:
        for channel in (runtime, control, host, peer):
            channel.close()


@pytest.mark.parametrize("surviving_successor", [False, True])
def test_runtime_response_loss_preserves_valid_successor_route(monkeypatch, tmp_path, surviving_successor):
    request, reply = _handoff_case(tmp_path)
    listener_socket, incoming = socket.socketpair()
    successor, successor_control = socket.socketpair()
    for channel in (listener_socket, incoming, successor, successor_control):
        channel.settimeout(2)
    class Peer:
        channel = successor_control
    class Listener:
        socket = listener_socket
        closed = False
        def accept(self):
            return Peer(), relay.receive_frame(self.socket)
    class Endpoint:
        successor_listener = Listener()
        _phase = "export_sealed"
        def handoff(self, received, **_):
            return {**reply, "phase": "export_sealed"}
    monkeypatch.setattr(relay, "_native_handoff_endpoint", lambda *_: Endpoint())
    original_send = relay.send_frame
    sends = [0]
    lost = BrokenPipeError("Runtime disappeared during response")
    owner = {}
    def response_loss(channel, frame):
        if frame.get("status") == "ok" and "report" in frame:
            sends[0] += 1
            if sends[0] == 2:
                owner["runtime"].close()
                raise lost
        return original_send(channel, frame)
    monkeypatch.setattr(relay, "send_frame", response_loss)
    frame = {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request}
    try:
        with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
            owner["runtime"] = runtime
            if surviving_successor:
                relay.send_frame(runtime, frame)
                assert relay.receive_frame(runtime)["status"] == "ok"
                relay.send_frame(incoming, frame)
                assert relay.receive_frame(successor)["status"] == "ok"
            relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "report"})
            if surviving_successor:
                relay.send_frame(successor, {"version": relay.CONTROL_VERSION, "command": "report"})
                assert relay.receive_frame(successor)["status"] == "ok"
                assert thread.is_alive() and not outcomes and "abort_local_execution" not in events
                peer.shutdown(socket.SHUT_WR)
                assert relay.receive_frame(successor)["error_code"] == "host_control_closed"
            thread.join(2)
            if not surviving_successor:
                assert len(outcomes) == 1 and outcomes[0].reason == "runtime_control_failed"
                assert outcomes[0].__cause__ is lost
                assert events.count("abort_local_execution") == 1
    finally:
        for channel in (listener_socket, incoming, successor, successor_control):
            channel.close()


def test_a_eof_keeps_real_unexpired_pending_transfer_and_journal(monkeypatch, tmp_path):
    from runtime_protocol.local_execution_handoff import HandoffJournal, read_protected
    request, reply = _handoff_case(tmp_path)
    listener_socket, incoming = socket.socketpair()
    selected = {}
    source_eof = threading.Event()
    original_recv = relay._DeadlineIO.recv
    def observe_eof(io, *args):
        data = original_recv(io, *args)
        if not data:
            source_eof.set()
        return data
    monkeypatch.setattr(relay._DeadlineIO, "recv", observe_eof)
    class Listener:
        socket = listener_socket
        closed = False
    def endpoint_factory(_channel, session, _preparation, _binding):
        journal = HandoffJournal(tmp_path / "custody" / "pending.json",
            writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
        endpoint = relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: None, verify_fence=lambda _: None)
        selected.update(endpoint=endpoint, journal=journal)
        return endpoint
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    try:
        with _controlled_relay(host_replies=lambda _: reply) as (runtime, host, peer, events, outcomes, thread):
            relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
            assert relay.receive_frame(runtime)["handoff"]["phase"] == "host_paused"
            # Retained, selected transport is a CPU fixture; protocol and
            # protected journal are real, authentication is not qualified.
            selected["endpoint"].successor_listener = Listener()
            before = selected["journal"].path.read_bytes()
            runtime.close()
            assert source_eof.wait(2)
            assert thread.is_alive() and not outcomes
            assert read_protected(selected["journal"].path)["phase"] == "host_paused"
            assert selected["journal"].path.read_bytes() == before
            assert "abort_local_execution" not in events
            peer.shutdown(socket.SHUT_WR)
            thread.join(2)
            assert outcomes[0].reason == "host_control_closed"
            assert selected["journal"].path.read_bytes() == before
    finally:
        listener_socket.close(); incoming.close()


def test_deadline_io_preserves_stricter_timeout_and_successful_ancillary_parser(tmp_path, monkeypatch):
    import array
    from runtime_protocol import local_worker_handoff as handoff
    source, target = socket.socketpair()
    descriptor = os.open(tmp_path / "fd", os.O_WRONLY | os.O_CREAT, 0o600)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 0.0)
    monitor.deadline = 10.0
    target.settimeout(0.01)
    closed = []
    original_close = handoff._close_descriptors
    def record_close(descriptors):
        closed.extend(descriptors)
        original_close(descriptors)
    monkeypatch.setattr(handoff, "_close_descriptors", record_close)
    class CrossingSocket:
        def __getattr__(self, name):
            return getattr(target, name)
        def recvmsg(self, *args):
            received = target.recvmsg(*args)
            clock[0] = 20.0
            return received
    try:
        rights = array.array("i", [descriptor])
        source.sendmsg([b"{}\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
        # Existing receive_frame owns rejection and closure of unexpected FDs.
        with pytest.raises(Exception, match="unexpected authority"):
            handoff.receive_frame(relay._DeadlineIO(CrossingSocket(), monitor))
        assert len(closed) == 1
        with pytest.raises(OSError):
            os.fstat(closed[0])
        assert target.gettimeout() == 0.01
        clock[0] = 0.0
        source.sendall(b"x")
        assert relay._DeadlineIO(target, monitor).recv(1) == b"x"
        assert target.gettimeout() == 0.01
    finally:
        os.close(descriptor); source.close(); target.close()


@pytest.mark.parametrize("chunks", [(b"{",), (b"{", b'"v')])
def test_successor_accept_and_trickled_frame_share_absolute_budget(monkeypatch, tmp_path, chunks):
    import tempfile
    from pathlib import Path
    from runtime_protocol import local_worker_handoff as handoff
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 0.0)
    monitor.deadline = 0.5
    received = [threading.Event() for _ in chunks]
    original_call = relay._DeadlineIO._call
    def observe(io, name, *args):
        result = original_call(io, name, *args)
        data = result[0] if name == "recvmsg" else result if name == "recv" else None
        if data in chunks:
            index = chunks.index(data); clock[0] = 0.5 * (index + 1) / len(chunks); received[index].set()
        return result
    monkeypatch.setattr(relay._DeadlineIO, "_call", observe)
    errors = []
    with tempfile.TemporaryDirectory(prefix="i05-succ-") as root:
        listener = handoff.HandoffSuccessorListener.__new__(handoff.HandoffSuccessorListener)
        listener.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.socket.settimeout(0.2); listener.timeout = 0.2
        listener.socket.bind(str(Path(root) / "s")); listener.socket.listen(1)
        listener._frame_io = lambda control: relay._DeadlineIO(control, monitor)
        def accept():
            try:
                listener.accept()
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=accept); thread.start()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(Path(root) / "s"))
            for index, chunk in enumerate(chunks):
                client.sendall(chunk); assert received[index].wait(2)
            thread.join(2)
            assert not thread.is_alive() and len(errors) == 1
            assert isinstance(errors[0], relay._DeadlineExpired)
            assert listener.socket.gettimeout() == 0.2
        finally:
            client.close(); listener.socket.close(); thread.join(2)


def test_host_exchange_trickle_exhausts_budget_and_forbids_cleanup(monkeypatch):
    host, peer = socket.socketpair()
    runtime, control = socket.socketpair()
    for channel in (host, peer, runtime, control):
        channel.settimeout(2)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 0.0)
    monitor.deadline = 0.5
    stream = relay._HostStreamState()
    read_partial = threading.Event()
    errors, aborts = [], []
    original_recv = relay._DeadlineIO.recv
    def cross_deadline(io, *args):
        data = original_recv(io, *args)
        if data == b"{":
            clock[0] = 0.5; read_partial.set()
        return data
    monkeypatch.setattr(relay._DeadlineIO, "recv", cross_deadline)
    class Bridge:
        def abort(self):
            aborts.append(True)
            pytest.fail("failed host exchange cannot accept abort RPC")
    class Session:
        control = host
        bridge = Bridge()
    session = Session()
    def exchange():
        relay.send_frame(session.control, {"request": "controlled"})
        return relay.receive_frame(session.control)
    def run():
        try:
            relay._host_call(session, monitor, stream, exchange)
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=run); thread.start()
    try:
        assert relay.receive_frame(peer) == {"request": "controlled"}
        peer.sendall(b"{")
        assert read_partial.wait(2); thread.join(2)
        assert not thread.is_alive() and isinstance(errors[0], relay._DeadlineExpired)
        assert stream.state == "failed" and session.control is host and host.gettimeout() == 2
        with pytest.raises(relay._RelaySupervisionFailure) as caught:
            relay._fail_supervision({control: None}, session, "deadline_expired", stream=stream, cause=errors[0])
        assert caught.value.__cause__ is errors[0] and not caught.value.cleanup_verified
        assert not aborts
    finally:
        for channel in (host, peer, runtime, control):
            channel.close()
        thread.join(2)


def test_accept_syscall_uses_remaining_budget_and_restores_timeout():
    clock = [0.4]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=lambda: 0.0)
    monitor.deadline = 0.5
    observed = []
    class Socket:
        timeout = 0.25
        def gettimeout(self):
            return self.timeout
        def settimeout(self, value):
            self.timeout = value
        def fileno(self):
            return 3
        def accept(self):
            observed.append(self.timeout)
            return "accepted", "peer"
    selected = Socket()
    assert relay._DeadlineIO(selected, monitor).accept() == ("accepted", "peer")
    assert observed[0] == pytest.approx(0.1) and selected.timeout == 0.25


def _expired_copy(request):
    expired = copy.deepcopy(request)
    b = expired["binding"]
    b["deadline_unix_ms"] = 1
    b["intent_digest"] = digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}})
    return expired


def test_expired_unseen_input_is_refused_without_transition_or_cleanup(monkeypatch, tmp_path):
    from runtime_protocol.local_execution_handoff import HandoffJournal
    request, _ = _handoff_case(tmp_path)
    selected = {}
    def endpoint_factory(_channel, session, _preparation, binding):
        # Explicit CPU substitute for the native factory's source check.
        assert binding == _expired_copy(request)["binding"]
        selected["factory_source_checked"] = True
        journal = HandoffJournal(tmp_path / "custody" / "unseen.json",
            writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
        selected["journal"] = journal
        return relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: pytest.fail("unseen expiry must not start a transition"), verify_fence=lambda _: None)
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": _expired_copy(request)})
        assert relay.receive_frame(runtime) == {"version": relay.CONTROL_VERSION,
            "status": "unresolved", "error_code": "deadline_expired"}
        assert selected["factory_source_checked"] and not selected["journal"].path.exists()
        with selected["journal"].locked() as state:
            assert state["phase"] == "owned" and state["entries"] == {} and state["binding_digest"] is None
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "report"})
        assert relay.receive_frame(runtime)["status"] == "ok"
        assert thread.is_alive() and not outcomes and "abort_local_execution" not in events
        peer.shutdown(socket.SHUT_WR)
        thread.join(2)
        assert outcomes[0].reason == "host_control_closed" and not outcomes[0].cleanup_verified
        assert "abort_local_execution" not in events


@pytest.mark.parametrize("input_kind", ["conflicting_prepare", "stale_a_adopt"])
def test_expired_unaccepted_input_keeps_real_pending_binding_and_successor(monkeypatch, tmp_path, input_kind):
    import time
    from runtime_protocol.local_execution_handoff import HandoffJournal
    request, reply = _handoff_case(tmp_path)
    monitor = relay._RelayFailureMonitor(monotonic=lambda: 0.0, wall_time=time.time)
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    listener_socket, incoming = socket.socketpair()
    selected = {}
    class Listener:
        socket = listener_socket
        closed = False
    def endpoint_factory(_channel, session, _preparation, _binding):
        journal = HandoffJournal(tmp_path / "custody" / "pending.json",
            writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
        endpoint = relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: None, verify_fence=lambda _: None)
        selected.update(endpoint=endpoint, journal=journal)
        return endpoint
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    expired = _expired_copy(request)
    if input_kind == "stale_a_adopt":
        expired["command"] = "handoff_adopt"
        expired["payload"] = {"export_digest": "sha256:" + "1" * 64,
            "sealed_record_digest": "sha256:" + "2" * 64, "task_fence_digest": "sha256:" + "3" * 64,
            "relay_transfer_ack": {}, "successor_authentication_digest": "sha256:" + "4" * 64}
    try:
        with _controlled_relay(host_replies=lambda _: reply) as (runtime, host, peer, events, outcomes, thread):
            relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
            assert relay.receive_frame(runtime)["handoff"]["phase"] == "host_paused"
            selected["endpoint"].successor_listener = Listener()
            before = selected["journal"].path.read_bytes()
            binding, deadline = monitor.binding_digest, monitor.deadline
            relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": expired})
            result = relay.receive_frame(runtime)["handoff"]
            assert result["status"] == ("conflict" if input_kind == "conflicting_prepare" else "unresolved")
            assert result["error_code"] == ("binding_conflict" if input_kind == "conflicting_prepare" else "identity_unresolved")
            assert selected["journal"].path.read_bytes() == before
            assert monitor.binding_digest == binding and monitor.deadline == deadline and not monitor.expired()
            assert selected["endpoint"].successor_listener.socket is listener_socket
            assert not selected["endpoint"].successor_listener.closed
            assert events.count("handoff_prepare") == 1 and "handoff_adopt" not in events
            assert "abort_local_execution" not in events and not outcomes and thread.is_alive()
            peer.shutdown(socket.SHUT_WR)
            thread.join(2)
            assert outcomes[0].reason == "host_control_closed" and selected["journal"].path.read_bytes() == before
    finally:
        listener_socket.close(); incoming.close()


@pytest.mark.parametrize("failure", ["swallowed_timeout", "complete_reply_crossing_expiry"])
def test_real_endpoint_failed_host_exchange_retains_original_and_pending_journal(monkeypatch, tmp_path, failure):
    import time
    from runtime_protocol.local_execution_handoff import HandoffJournal, read_protected
    request, reply = _handoff_case(tmp_path)
    clock = [0.0]
    monitor = relay._RelayFailureMonitor(monotonic=lambda: clock[0], wall_time=time.time)
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    stream = relay._HostStreamState()
    monkeypatch.setattr(relay, "_HostStreamState", lambda: stream)
    selected = {}
    original_timeout = TimeoutError("original host frame timeout")
    host_observed = threading.Event()
    requester_observations = []
    original_recv = relay._DeadlineIO.recv
    def fail_or_cross(io, *args):
        if io.channel is selected.get("host") and selected.get("armed"):
            if failure == "swallowed_timeout":
                raise original_timeout
            data = original_recv(io, *args)
            if data.endswith(b"\n"):
                clock[0] = monitor.current_deadline() + 1.0
            return data
        return original_recv(io, *args)
    monkeypatch.setattr(relay._DeadlineIO, "recv", fail_or_cross)
    def endpoint_factory(_channel, session, _preparation, _binding):
        journal = HandoffJournal(tmp_path / "custody" / "pending.json",
            writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
        endpoint = relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: None, verify_fence=lambda _: None)
        def verify_requester(control):
            assert control is _channel
            requester_observations.append((stream.state, stream.original_failure, journal.path.read_bytes()))
        # Observed CPU substitute; no native authentication claim.
        endpoint.verify_control_requester = verify_requester
        selected.update(endpoint=endpoint, journal=journal, host=session.control, armed=True)
        return endpoint
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    def host_reply(_):
        selected["pending_bytes"] = selected["journal"].path.read_bytes()
        host_observed.set()
        return None if failure == "swallowed_timeout" else reply
    with _controlled_relay(host_replies=host_reply) as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
        result = relay.receive_frame(runtime)
        assert host_observed.wait(2)
        assert result == {"version": relay.CONTROL_VERSION, "status": "unresolved",
            "error_code": "host_exchange_timeout" if failure == "swallowed_timeout" else "deadline_expired"}
        original = stream.original_failure
        if failure == "swallowed_timeout":
            assert original is original_timeout
        else:
            assert isinstance(original, relay._DeadlineExpired)
        assert stream.state == "failed" and monitor.binding_digest is None and monitor.deadline is None
        assert selected["endpoint"].bridge._exchange.__name__ == "exchange"
        assert selected["journal"].path.read_bytes() == selected["pending_bytes"]
        state = read_protected(selected["journal"].path)
        assert state["phase"] == "owned" and all(entry["reply"] is None for entry in state["entries"].values())
        # A failed exchange cannot be reused even for an explicit cleanup RPC.
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "abort"})
        assert relay.receive_frame(runtime)["error_code"] == "cleanup_unresolved"
        assert requester_observations == [("failed", original, selected["pending_bytes"])]
        assert "abort_local_execution" not in events and selected["journal"].path.read_bytes() == selected["pending_bytes"]
        peer.shutdown(socket.SHUT_WR)
        thread.join(2)
        assert outcomes[0].__cause__ is original and not outcomes[0].cleanup_verified
        assert "abort_local_execution" not in events and "retained-host-wait" not in events


@pytest.mark.parametrize("terminal", ["successful_handoff_abort", "committed_active_work"])
def test_owned_committed_key_after_deadline_uses_authenticated_replay_or_conflict(monkeypatch, tmp_path, terminal):
    from runtime_protocol import local_execution_handoff as handoff
    request, prepared_reply = _handoff_case(tmp_path)
    earlier_prepare = copy.deepcopy(request)
    journal = handoff.HandoffJournal(tmp_path / "custody" / "terminal.json",
        writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
    journal.begin(request)
    if terminal == "successful_handoff_abort":
        journal.finish(request, prepared_reply)
        request = {**request, "command": "handoff_abort", "payload": {"reason_code": "owner_cancelled"}}
        durable_reply = {**prepared_reply, "command": "handoff_abort", "request_digest": digest(request), "phase": "owned"}
        journal.begin(request)
    else:
        durable_reply = {**prepared_reply, "status": "active_work", "phase": "owned", "error_code": "active_work"}
    journal.finish(request, durable_reply)
    before = journal.path.read_bytes()
    expired_wall = request["binding"]["deadline_unix_ms"] / 1000 + 1.0
    monitor = relay._RelayFailureMonitor(monotonic=lambda: 0.0, wall_time=lambda: expired_wall)
    def forbidden_admission(*_, **__):
        pytest.fail("terminal replay must not admit any lifecycle timer")
    monitor.accepted = forbidden_admission
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    monkeypatch.setattr(handoff.time, "time_ns", lambda: int(expired_wall * 1_000_000_000))
    observations = []
    original_replay = journal.replay
    def observed_replay(received):
        observations.append("durable_replay")
        return original_replay(received)
    journal.replay = observed_replay
    def endpoint_factory(_channel, session, _preparation, _binding):
        return relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: observations.append("authenticate_binding"),
            verify_fence=lambda _: pytest.fail("durable replay must precede new-transition fence validation"))
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        frame = {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request}
        for _ in range(2):
            relay.send_frame(runtime, frame)
            assert relay.receive_frame(runtime) == {"version": relay.CONTROL_VERSION, "status": "ok", "handoff": durable_reply}
            assert journal.path.read_bytes() == before
        assert observations == ["authenticate_binding", "durable_replay"] * 2
        expected_observations = ["authenticate_binding", "durable_replay"] * 2
        if terminal == "successful_handoff_abort":
            # Rollback left the journal owned; the earlier prepare receipt
            # truthfully retains its historical host_paused reply phase.
            relay.send_frame(runtime, {**frame, "request": earlier_prepare})
            assert relay.receive_frame(runtime) == {"version": relay.CONTROL_VERSION,
                "status": "ok", "handoff": prepared_reply}
            expected_observations += ["authenticate_binding", "durable_replay"]
            assert observations == expected_observations and journal.path.read_bytes() == before
        assert monitor.binding_digest is None and monitor.deadline is None and monitor.dispatch_deadline is None
        changed = copy.deepcopy(request)
        if terminal == "successful_handoff_abort":
            changed["payload"]["reason_code"] = "different_input"
        else:
            changed["binding"]["nonce_digest"] = "sha256:" + "9" * 64
            b = changed["binding"]
            b["intent_digest"] = digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}})
        relay.send_frame(runtime, {**frame, "request": changed})
        conflict = relay.receive_frame(runtime)["handoff"]
        assert conflict["status"] == "conflict" and conflict["error_code"] == "binding_conflict"
        expected_observations += ["authenticate_binding", "durable_replay"]
        assert journal.path.read_bytes() == before and observations == expected_observations
        new_key = copy.deepcopy(earlier_prepare)
        new_key["binding"]["handoff_id"] = "new-expired-transition"
        b = new_key["binding"]
        b["intent_digest"] = digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}})
        relay.send_frame(runtime, {**frame, "request": new_key})
        assert relay.receive_frame(runtime)["error_code"] == "deadline_expired"
        assert journal.path.read_bytes() == before and observations == expected_observations
        assert not any(command.startswith("handoff_") for command in events)
        assert "abort_local_execution" not in events and not outcomes and thread.is_alive()
        peer.shutdown(socket.SHUT_WR)
        thread.join(2)
        assert outcomes[0].reason == "host_control_closed" and not outcomes[0].cleanup_verified
        assert journal.path.read_bytes() == before and "abort_local_execution" not in events


def test_owned_pending_key_after_deadline_is_refused_without_journal_advance(monkeypatch, tmp_path):
    from runtime_protocol.local_execution_handoff import HandoffJournal
    request, _ = _handoff_case(tmp_path)
    journal = HandoffJournal(tmp_path / "custody" / "pending-owned.json",
        writer=request["binding"]["current_roles"]["relay"]["target"], owner_epoch="A", authority=lambda: None)
    journal.begin(request)
    before = journal.path.read_bytes()
    monitor = relay._RelayFailureMonitor(monotonic=lambda: 0.0,
        wall_time=lambda: request["binding"]["deadline_unix_ms"] / 1000 + 1.0)
    monkeypatch.setattr(relay, "_RelayFailureMonitor", lambda: monitor)
    def endpoint_factory(_channel, session, _preparation, binding):
        assert binding == request["binding"]  # CPU factory source-check substitute.
        return relay.RelayHandoffEndpoint(session.bridge, journal,
            verify_binding=lambda _: pytest.fail("expired pending input cannot start a transition"),
            verify_fence=lambda _: pytest.fail("expired pending input cannot reach a fence mutation"))
    monkeypatch.setattr(relay, "_native_handoff_endpoint", endpoint_factory)
    with _controlled_relay() as (runtime, host, peer, events, outcomes, thread):
        relay.send_frame(runtime, {"version": relay.CONTROL_VERSION, "command": "handoff", "request": request})
        assert relay.receive_frame(runtime) == {"version": relay.CONTROL_VERSION,
            "status": "unresolved", "error_code": "deadline_expired"}
        assert journal.path.read_bytes() == before
        assert monitor.binding_digest is None and monitor.deadline is None and monitor.dispatch_deadline is None
        assert not any(command.startswith("handoff_") for command in events)
        assert "abort_local_execution" not in events and not outcomes and thread.is_alive()
        peer.shutdown(socket.SHUT_WR)
        thread.join(2)
        assert outcomes[0].reason == "host_control_closed" and not outcomes[0].cleanup_verified
        assert journal.path.read_bytes() == before and "abort_local_execution" not in events
