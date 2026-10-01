from __future__ import annotations

import array
import fcntl
import json
import os
import socket
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import runtime_protocol.local_worker_handoff as handoff
from runtime_protocol import cli as runtime_cli
from runtime_protocol import daemon as runtime_daemon
from runtime_protocol.errors import ConflictError, RuntimeErrorBase, ValidationError
from runtime_protocol.local_worker_handoff import (
    TRANSFER_VERSION,
    peer_uid,
    receive_authority_transfer,
    send_authority_transfer,
)
from runtime_protocol.orderly_handoff import HandoffRecord, RECORD_VERSION, digest, nonce_digest


def _authorities():
    worker_runtime, worker_peer = socket.socketpair()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return worker_runtime, worker_peer, listener


def _frame():
    return {
        "version": TRANSFER_VERSION,
        "handoff_id": "handoff-1",
        "nonce": "private-only-value",
        "nonce_digest": "sha256:" + "a" * 64,
        "sealed_record_digest": "sha256:" + "b" * 64,
        "deadline_unix_ms": int(time.time() * 1000) + 30_000,
    }


def test_authority_transfer_receives_exact_sockets_and_sets_cloexec():
    sender, receiver = socket.socketpair()
    worker_runtime, worker_peer, listener = _authorities()
    try:
        frame = _frame()
        send_authority_transfer(
            sender,
            frame,
            worker_control_fd=worker_runtime.fileno(),
            listener_fd=listener.fileno(),
        )
        transfer = receive_authority_transfer(
            receiver,
            expected_uid=os.getuid(),
            expected_listener=listener.getsockname(),
        )
        try:
            assert transfer.frame == frame
            for descriptor in (transfer.worker_control_fd, transfer.listener_fd):
                assert fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
            adopted_listener = socket.socket(fileno=os.dup(transfer.listener_fd))
            try:
                assert adopted_listener.getsockname() == listener.getsockname()
                observed = subprocess.run(
                    [
                        "/usr/sbin/lsof",
                        "-a",
                        "-p",
                        str(os.getpid()),
                        "-d",
                        str(adopted_listener.fileno()),
                        "-n",
                        "-P",
                        "-iTCP",
                        "-sTCP:LISTEN",
                        "-Ff",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert observed.returncode == 0
                assert f"f{adopted_listener.fileno()}" in observed.stdout.splitlines()
            finally:
                adopted_listener.close()
        finally:
            transfer.close()
    finally:
        sender.close()
        receiver.close()
        worker_runtime.close()
        worker_peer.close()
        listener.close()


def test_authority_transfer_rejects_wrong_descriptor_count():
    sender, receiver = socket.socketpair()
    worker_runtime, worker_peer, listener = _authorities()
    try:
        baseline = len(os.listdir("/dev/fd"))
        descriptors = array.array("i", [worker_runtime.fileno()])
        sender.sendmsg(
            [(json.dumps(_frame(), sort_keys=True, separators=(",", ":")) + "\n").encode()],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors.tobytes())],
        )
        with pytest.raises(ConflictError, match="exactly two"):
            receive_authority_transfer(
                receiver,
                expected_uid=os.getuid(),
                expected_listener=listener.getsockname(),
            )
        assert len(os.listdir("/dev/fd")) == baseline
    finally:
        sender.close()
        receiver.close()
        worker_runtime.close()
        worker_peer.close()
        listener.close()


@pytest.mark.parametrize(
    ("flags", "extra_ancillary", "message"),
    [
        (getattr(socket, "MSG_CTRUNC", 0x8), False, "truncated"),
        (0, True, "one descriptor record"),
    ],
)
def test_authority_transfer_closes_all_rights_on_truncation_or_extra_ancillary(
    monkeypatch, flags, extra_ancillary, message
):
    first_read, first_write = os.pipe()
    second_read, second_write = os.pipe()
    received = [os.dup(first_read), os.dup(second_read)]
    rights = array.array("i", received).tobytes()
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
    if extra_ancillary:
        ancillary.append((socket.SOL_SOCKET, 0x7FFF, b""))

    class FakeChannel:
        def recvmsg(self, *_args):
            return (
                (json.dumps(_frame(), sort_keys=True, separators=(",", ":")) + "\n").encode(),
                ancillary,
                flags,
                None,
            )

    monkeypatch.setattr(handoff, "peer_uid", lambda _channel: os.getuid())
    try:
        with pytest.raises(ConflictError, match=message):
            receive_authority_transfer(
                FakeChannel(),
                expected_uid=os.getuid(),
                expected_listener=("127.0.0.1", 1),
            )
        for descriptor in received:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        for descriptor in (first_read, first_write, second_read, second_write):
            os.close(descriptor)


def test_authority_transfer_malformed_frame_closes_every_received_descriptor():
    sender, receiver = socket.socketpair()
    worker_runtime, worker_peer, listener = _authorities()
    try:
        baseline = len(os.listdir("/dev/fd"))
        descriptors = array.array("i", [worker_runtime.fileno(), listener.fileno()])
        sender.sendmsg(
            [b"{not-json}\n"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors.tobytes())],
        )
        with pytest.raises(ConflictError, match="malformed"):
            receive_authority_transfer(
                receiver,
                expected_uid=os.getuid(),
                expected_listener=listener.getsockname(),
            )
        assert len(os.listdir("/dev/fd")) == baseline
    finally:
        sender.close()
        receiver.close()
        worker_runtime.close()
        worker_peer.close()
        listener.close()


def test_authority_transfer_rejects_swapped_socket_roles_and_wrong_endpoint():
    for swap, wrong_endpoint, expected_message in (
        (True, False, "Worker-control"),
        (False, True, "expected loopback endpoint"),
    ):
        sender, receiver = socket.socketpair()
        worker_runtime, worker_peer, listener = _authorities()
        try:
            send_authority_transfer(
                sender,
                _frame(),
                worker_control_fd=(listener if swap else worker_runtime).fileno(),
                listener_fd=(worker_runtime if swap else listener).fileno(),
            )
            endpoint = listener.getsockname()
            if wrong_endpoint:
                endpoint = (endpoint[0], endpoint[1] + 1)
            with pytest.raises(ConflictError, match=expected_message):
                receive_authority_transfer(
                    receiver, expected_uid=os.getuid(), expected_listener=endpoint
                )
        finally:
            sender.close()
            receiver.close()
            worker_runtime.close()
            worker_peer.close()
            listener.close()


def test_peer_uid_requires_a_unix_channel():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(ConflictError, match="Unix socket"):
            peer_uid(tcp)
    finally:
        tcp.close()


def test_wrong_owned_pointer_is_rejected_without_owner_mutation(tmp_path, capsys):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    pointer = support / "orderly-handoff-request.json"
    pointer.write_text('{"version":"wrong"}', encoding="utf-8")
    pointer.chmod(0o600)
    launcher = object()
    daemon = SimpleNamespace(local_worker_launcher=launcher)
    before = pointer.read_bytes()
    assert runtime_cli._attempt_owner_handoff(daemon, support) is False
    assert pointer.read_bytes() == before
    assert daemon.local_worker_launcher is launcher
    assert json.loads(capsys.readouterr().err) == {
        "error_code": "runtime_error",
        "event": "orderly_handoff_owner_a_refused",
        "stage": "owner_a_request",
    }


def test_owner_handoff_emits_only_bounded_worker_stage_and_code(
    tmp_path, capsys, monkeypatch
):
    daemon = SimpleNamespace(local_worker_launcher=object())

    def reject(_daemon, _support):
        raise ConflictError(
            "private detail must not be emitted",
            details={
                "handoff_error_code": "sealed_owner_mismatch",
                "handoff_stage": "handoff_prepare",
                "raw_nonce": "must-not-be-emitted",
            },
        )

    monkeypatch.setattr(runtime_cli, "_owner_handoff_request", reject)
    assert runtime_cli._attempt_owner_handoff(daemon, tmp_path) is False
    output = capsys.readouterr().err
    assert "private detail" not in output
    assert "must-not-be-emitted" not in output
    assert json.loads(output) == {
        "error_code": "sealed_owner_mismatch",
        "event": "orderly_handoff_owner_a_refused",
        "stage": "handoff_prepare",
    }


def test_runtime_handoff_stage_error_maps_validation_without_private_details():
    error = runtime_daemon._handoff_stage_error(
        ValidationError("credential generation is inconsistent"),
        "handoff_fence",
    )

    assert error.message == "credential generation is inconsistent"
    assert error.details == {
        "handoff_error_code": "credential_generation_inconsistent",
        "handoff_stage": "handoff_fence",
    }


def test_runtime_handoff_stage_error_preserves_worker_bounded_tuple():
    error = runtime_daemon._handoff_stage_error(
        ConflictError(
            "private body",
            details={
                "handoff_error_code": "host_ack_binding",
                "handoff_stage": "handoff_prepare",
                "private": "not emitted by the caller",
            },
        ),
        "handoff_fence",
    )

    assert error.details["handoff_error_code"] == "host_ack_binding"
    assert error.details["handoff_stage"] == "handoff_prepare"


def test_owner_handoff_stage_error_adds_only_bounded_phase_and_code():
    error = runtime_cli._owner_handoff_stage_error(
        ValidationError("private validation detail"),
        "export_offer",
    )

    assert error.message == "private validation detail"
    assert error.details == {
        "handoff_error_code": "validation_error",
        "handoff_stage": "export_offer",
    }


def test_owner_handoff_stage_error_preserves_inner_bounded_tuple():
    error = runtime_cli._owner_handoff_stage_error(
        ConflictError(
            "private body",
            details={
                "handoff_error_code": "registered_state_invalid",
                "handoff_stage": "handoff_prepare",
                "raw_nonce": "never emitted",
            },
        ),
        "export_offer",
    )

    assert error.details == {
        "handoff_error_code": "registered_state_invalid",
        "handoff_stage": "handoff_prepare",
        "raw_nonce": "never emitted",
    }


def test_digest_valid_malformed_owned_record_is_nonfatal_and_nonmutating(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    rendezvous = tmp_path / "rendezvous"
    rendezvous.mkdir(mode=0o700)
    runtime_identity = {
        "endpoint": "http://127.0.0.1:47001", "protocol": "workspace.v1",
        "schema_digest": "sha256:" + "1" * 64, "runtime_epoch": 1,
        "runtime_instance_id": "runtime-a", "runtime_session_id": "session-a",
    }
    launcher = object()
    daemon = SimpleNamespace(
        local_worker_launcher=launcher,
        instance_id="runtime-a",
        root=tmp_path / "realm",
        service=SimpleNamespace(realm={"id": "realm-1"}),
        runtime_identity=lambda: runtime_identity,
    )
    record = HandoffRecord(rendezvous / "record.json")
    created = record.create({
        "version": RECORD_VERSION, "state": "OWNED", "handoff_id": "handoff-1",
        "realm_id": "realm-1", "realm_root": str(daemon.root),
        "support_root": str(support), "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int(time.time() * 1000) + 30_000,
        "nonce_digest": None, "sealed_record_digest": None,
        "old_owner": {
            "pid": os.getpid(), "birth_id": runtime_cli.process_birth_identity(),
            "runtime_instance_id": "runtime-a", "runtime": runtime_identity,
        },
        "export": None, "export_sealed_digest": None, "adopter": None,
        "predecessor_active_ref_digest": None,
    })
    malformed = {**created, "deadline_monotonic": "not-a-number"}
    malformed["record_digest"] = digest({
        key: value for key, value in malformed.items() if key != "record_digest"
    })
    record.path.write_text(json.dumps(malformed, sort_keys=True, separators=(",", ":")))
    record.path.chmod(0o600)
    pointer = support / "orderly-handoff-request.json"
    pointer.write_text(json.dumps({
        "version": TRANSFER_VERSION, "handoff_id": "handoff-1",
        "record_path": str(record.path), "socket_path": str(rendezvous / "socket"),
        "coordinator_pid": os.getpid(),
        "coordinator_birth_id": runtime_cli.process_birth_identity(),
    }, sort_keys=True, separators=(",", ":")))
    pointer.chmod(0o600)
    before = {"pointer": pointer.read_bytes(), "record": record.path.read_bytes()}
    assert runtime_cli._attempt_owner_handoff(daemon, support) is False
    assert pointer.read_bytes() == before["pointer"]
    assert record.path.read_bytes() == before["record"]
    assert daemon.local_worker_launcher is launcher


def test_owner_a_active_work_refusal_emits_exact_frame_without_authority_mutation(
    tmp_path,
):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    rendezvous = Path(tempfile.mkdtemp(prefix="x3-refusal-", dir="/tmp"))
    rendezvous.chmod(0o700)
    socket_path = rendezvous / "coordinator.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen(1)
    handoff_id = "active-work"
    runtime_identity = {
        "endpoint": "http://127.0.0.1:47001",
        "protocol": "workspace.v1",
        "schema_digest": "sha256:" + "1" * 64,
        "runtime_epoch": 1,
        "runtime_instance_id": "runtime-a",
        "runtime_session_id": "session-a",
    }
    record = HandoffRecord(support / f"orderly-handoff-record-{handoff_id}.json")
    created = record.create({
        "version": RECORD_VERSION,
        "state": "OWNED",
        "handoff_id": handoff_id,
        "realm_id": "realm-1",
        "realm_root": str(tmp_path / "realm"),
        "support_root": str(support),
        "deadline_monotonic": time.monotonic() + 30,
        "deadline_unix_ms": int(time.time() * 1000) + 30_000,
        "nonce_digest": None,
        "sealed_record_digest": None,
        "old_owner": {
            "pid": os.getpid(),
            "birth_id": runtime_cli.process_birth_identity(),
            "runtime_instance_id": "runtime-a",
            "runtime": runtime_identity,
        },
        "export": None,
        "export_sealed_digest": None,
        "adopter": None,
        "predecessor_active_ref_digest": None,
    })
    pointer = support / "orderly-handoff-request.json"
    pointer.write_text(json.dumps({
        "version": TRANSFER_VERSION,
        "handoff_id": handoff_id,
        "record_path": str(record.path),
        "socket_path": str(socket_path),
        "coordinator_pid": os.getpid(),
        "coordinator_birth_id": runtime_cli.process_birth_identity(),
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    pointer.chmod(0o600)
    authority = support / "worker-authority.json"
    authority.write_bytes(b'{"generation":"unchanged"}')
    authority.chmod(0o600)
    authority_before = (
        authority.read_bytes(), authority.lstat().st_dev, authority.lstat().st_ino,
        stat.S_IMODE(authority.lstat().st_mode),
    )
    observed = {}

    def coordinator():
        channel, _ = listener.accept()
        try:
            observed["hello"] = handoff.receive_frame(channel)
            handoff.send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "seal_challenge",
                "handoff_id": handoff_id,
                "record_digest": created["record_digest"],
            })
            capability = handoff.receive_frame(channel)
            sealed = record.seal(
                expected_record_digest=created["record_digest"],
                nonce_sha256=capability["nonce_digest"],
            )
            handoff.send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "sealed",
                "handoff_id": handoff_id,
                "nonce_digest": capability["nonce_digest"],
                "sealed_record_digest": sealed["sealed_record_digest"],
            })
            observed["refusal"] = handoff.receive_frame(channel)
        finally:
            channel.close()

    thread = threading.Thread(target=coordinator)
    thread.start()
    daemon = SimpleNamespace(
        local_worker_launcher=object(),
        instance_id="runtime-a",
        root=tmp_path / "realm",
        service=SimpleNamespace(realm={"id": "realm-1"}),
        runtime_identity=lambda: runtime_identity,
        begin_orderly_worker_handoff=lambda _common: {
            "state": "active_work",
            "audit": {"safe": False},
        },
    )
    try:
        assert runtime_cli._attempt_owner_handoff(daemon, support) is False
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert observed["refusal"] == {
            "version": TRANSFER_VERSION,
            "command": "refused_active_work",
            "handoff_id": handoff_id,
        }
        assert (
            authority.read_bytes(), authority.lstat().st_dev,
            authority.lstat().st_ino, stat.S_IMODE(authority.lstat().st_mode),
        ) == authority_before
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)
        rendezvous.rmdir()


def test_wrong_committed_orphan_contender_is_nonmutating_then_valid_b_adopts(tmp_path):
    directory = tmp_path / "handoff"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    record = HandoffRecord(directory / "record.json")
    raw_nonce = "n" * 32
    old_owner = {"pid": os.getpid(), "birth_id": "owner-a-birth"}
    deadline_monotonic = time.monotonic() + 30
    deadline_unix_ms = int(time.time() * 1000) + 30_000
    created = record.create({
        "version": RECORD_VERSION,
        "state": "OWNED",
        "handoff_id": "handoff-contender",
        "realm_id": "realm-1",
        "realm_root": str(tmp_path / "realm"),
        "support_root": str(tmp_path / "support"),
        "deadline_monotonic": deadline_monotonic,
        "deadline_unix_ms": deadline_unix_ms,
        "nonce_digest": None,
        "sealed_record_digest": None,
        "old_owner": old_owner,
        "export": None,
        "export_sealed_digest": None,
        "adopter": None,
        "predecessor_active_ref_digest": None,
    })
    sealed = record.seal(
        expected_record_digest=created["record_digest"],
        nonce_sha256=nonce_digest(raw_nonce),
    )
    export = {"receipt": {"version": "runtime.local-worker-receipt/v3"}}
    exported = record.bind_export(
        handoff_id="handoff-contender",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=sealed["record_digest"],
        export=export,
    )
    prepared = record.transition(
        expected_state="OWNED", new_state="PREPARED",
        handoff_id="handoff-contender",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=exported["record_digest"],
    )
    committed = record.transition(
        expected_state="PREPARED", new_state="COMMITTED_ORPHAN",
        handoff_id="handoff-contender",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=prepared["record_digest"],
        updates={"owner_a_released": True},
    )
    worker_runtime, worker_peer, listener = _authorities()
    coordinator, adopter_channel = socket.socketpair()
    endpoint = listener.getsockname()
    valid = {
        "version": TRANSFER_VERSION,
        "command": "adopt",
        "handoff_id": "handoff-contender",
        "nonce": raw_nonce,
        "nonce_digest": sealed["nonce_digest"],
        "sealed_record_digest": sealed["sealed_record_digest"],
        "export_sealed_digest": exported["export_sealed_digest"],
        "export_record_digest": exported["record_digest"],
        "committed_record_digest": committed["record_digest"],
        "export": export,
        "old_owner": old_owner,
        "old_runtime": {"endpoint": f"http://{endpoint[0]}:{endpoint[1]}"},
    }
    observed = {}

    def send_frames():
        before = record.path.read_bytes()
        malformed = [
            {key: value for key, value in valid.items() if key != "nonce"},
            {**valid, "nonce": "short"},
            {**valid, "nonce": 7},
            {**valid, "nonce": "x" * 32},
        ]
        observed["rejections"] = []
        for value in malformed:
            handoff.send_frame(coordinator, value)
            observed["rejections"].append(handoff.receive_frame(coordinator))
        observed["unchanged"] = record.path.read_bytes() == before
        handoff.send_frame(coordinator, valid)

    sender = threading.Thread(target=send_frames)
    sender.start()
    args = SimpleNamespace(
        handoff_record=str(record.path),
        handoff_worker_fd=worker_runtime.fileno(),
        handoff_listener_fd=listener.fileno(),
        handoff_capability_fd=adopter_channel.detach(),
    )
    try:
        capability, frame, expected = runtime_cli._adopter_handoff_frame(args)
        assert frame == valid
        assert expected == endpoint
        assert observed["unchanged"] is True
        assert observed["rejections"] == [{
            "version": TRANSFER_VERSION,
            "command": "adopt_rejected",
            "handoff_id": "handoff-contender",
            "record_digest": committed["record_digest"],
        }] * 4
        capability.close()

        # Once a valid contender is parsed, any inherited-authority
        # normalization failure must immediately close both authority FDs and
        # the capability FD rather than waiting for process exit.
        coordinator2, adopter2 = socket.socketpair()
        capability_fd = adopter2.detach()
        worker_fd = worker_runtime.detach()
        listener_fd = listener.detach()
        bad = {**valid, "old_runtime": {"endpoint": "https://not-loopback.invalid"}}
        sender2 = threading.Thread(target=lambda: handoff.send_frame(coordinator2, bad))
        sender2.start()
        args2 = SimpleNamespace(
            handoff_record=str(record.path),
            handoff_worker_fd=worker_fd,
            handoff_listener_fd=listener_fd,
            handoff_capability_fd=capability_fd,
        )
        with pytest.raises(RuntimeErrorBase, match="endpoint"):
            runtime_cli._adopter_handoff_frame(args2)
        sender2.join(timeout=2)
        coordinator2.close()
        for descriptor in (worker_fd, listener_fd, capability_fd):
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        sender.join(timeout=2)
        coordinator.close()
        worker_runtime.close()
        worker_peer.close()
        listener.close()
