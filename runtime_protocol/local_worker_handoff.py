"""Private POSIX descriptor custody for an orderly local Worker handoff."""

from __future__ import annotations

import array
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from .errors import ConflictError, ValidationError


TRANSFER_VERSION = "runtime.local-worker-handoff-transfer/v1"
# The sealed export contains the complete registered Worker state and process
# identity evidence.  A real installed graph with the full capability census
# is larger than the former 64 KiB control-frame ceiling.  Keep the channel
# bounded, while allowing that already-validated export to cross both the
# seal and authority-transfer phases.
TRANSFER_FRAME_LIMIT = 1024 * 1024
AUTHORITY_FD_COUNT = 2


def _canonical_frame(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "handoff transfer frame must be JSON-compatible",
            details={"handoff_error_code": "transfer_frame_not_json"},
        ) from exc
    if len(encoded) > TRANSFER_FRAME_LIMIT:
        raise ValidationError(
            "handoff transfer frame is too large",
            details={
                "handoff_error_code": "transfer_frame_too_large",
                "frame_bytes": len(encoded),
                "frame_limit": TRANSFER_FRAME_LIMIT,
            },
        )
    return encoded + b"\n"


def _set_and_verify_cloexec(descriptor: int) -> None:
    try:
        current = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        fcntl.fcntl(descriptor, fcntl.F_SETFD, current | fcntl.FD_CLOEXEC)
        observed = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as exc:
        raise ConflictError("cannot normalize inherited handoff descriptor") from exc
    if not observed & fcntl.FD_CLOEXEC:
        raise ConflictError("inherited handoff descriptor is not close-on-exec")


def _close_descriptors(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def peer_uid(channel: socket.socket) -> int:
    """Return the kernel-authenticated UID of a connected Unix peer."""

    if channel.family != socket.AF_UNIX:
        raise ConflictError("handoff transfer channel must be a Unix socket")
    getpeereid = getattr(channel, "getpeereid", None)
    if callable(getpeereid):
        try:
            uid, _ = getpeereid()
            return int(uid)
        except OSError as exc:
            raise ConflictError("cannot authenticate handoff transfer peer") from exc
    local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
    if local_peercred is not None:
        # Darwin exposes struct xucred through SOL_LOCAL (numeric level 0) but
        # does not expose getpeereid(3) through every Python build.  Its first
        # two unsigned fields are the ABI version and authenticated UID.
        try:
            credentials = channel.getsockopt(
                getattr(socket, "SOL_LOCAL", 0), local_peercred, struct.calcsize("2I")
            )
            version, uid = struct.unpack("2I", credentials)
            if version != 0:
                raise ConflictError("handoff transfer peer credentials have an invalid version")
            return int(uid)
        except OSError as exc:
            raise ConflictError("cannot authenticate handoff transfer peer") from exc
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ConflictError("platform cannot authenticate handoff transfer peer")
    try:
        credentials = channel.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        return int(uid)
    except (OSError, struct.error) as exc:
        raise ConflictError("cannot authenticate handoff transfer peer") from exc


def peer_pid(channel: socket.socket) -> int:
    """Return the kernel-authenticated PID of a connected Unix peer."""

    if channel.family != socket.AF_UNIX:
        raise ConflictError("handoff transfer channel must be a Unix socket")
    if sys.platform == "darwin":
        try:
            # LOCAL_PEERPID is Darwin's SOL_LOCAL option 2. Python does not
            # expose the symbolic constant in every supported build.
            return int(struct.unpack("i", channel.getsockopt(0, 2, 4))[0])
        except (OSError, struct.error) as exc:
            raise ConflictError("cannot authenticate handoff transfer peer PID") from exc
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ConflictError("platform cannot authenticate handoff transfer peer PID")
    try:
        credentials = channel.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        pid, _, _ = struct.unpack("3i", credentials)
        return int(pid)
    except (OSError, struct.error) as exc:
        raise ConflictError("cannot authenticate handoff transfer peer PID") from exc


def send_authority_transfer(
    channel: socket.socket,
    frame: Mapping[str, Any],
    *,
    worker_control_fd: int,
    listener_fd: int,
) -> None:
    """Send one transfer frame and exactly two live authority descriptors."""

    if frame.get("version") != TRANSFER_VERSION:
        raise ValidationError("handoff transfer version is invalid")
    descriptors = array.array("i", [int(worker_control_fd), int(listener_fd)])
    encoded = _canonical_frame(frame)
    try:
        sent = channel.sendmsg(
            [encoded],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors.tobytes())],
        )
        if sent <= 0:
            raise ConflictError("handoff authority transfer was incomplete")
        if sent < len(encoded):
            channel.sendall(encoded[sent:])
    except OSError as exc:
        raise ConflictError("handoff authority transfer failed") from exc


def send_frame(channel: socket.socket, frame: Mapping[str, Any]) -> None:
    """Send one bounded canonical newline frame without authority FDs."""

    try:
        channel.sendall(_canonical_frame(frame))
    except OSError as exc:
        raise ConflictError("handoff control frame could not be sent") from exc


def _receive_frame(channel: socket.socket) -> tuple[dict[str, Any], list[tuple[int, int, bytes]]]:
    ancillary_size = socket.CMSG_SPACE(AUTHORITY_FD_COUNT * array.array("i").itemsize)
    try:
        payload, ancillary, flags, _ = channel.recvmsg(TRANSFER_FRAME_LIMIT + 2, ancillary_size)
    except OSError as exc:
        raise ConflictError("handoff authority transfer could not be read") from exc
    try:
        if not payload:
            raise ConflictError("handoff authority transfer channel closed")
        if flags & getattr(socket, "MSG_CTRUNC", 0):
            raise ConflictError("handoff authority descriptors were truncated")
        if flags & getattr(socket, "MSG_TRUNC", 0):
            raise ConflictError("handoff authority frame was truncated")
        frame_bytes = bytearray(payload)
        while b"\n" not in frame_bytes:
            if len(frame_bytes) > TRANSFER_FRAME_LIMIT:
                raise ConflictError("handoff transfer frame is too large")
            chunk = channel.recv(min(4096, TRANSFER_FRAME_LIMIT + 1 - len(frame_bytes)))
            if not chunk:
                raise ConflictError("handoff transfer frame is incomplete")
            frame_bytes.extend(chunk)
        encoded, remainder = bytes(frame_bytes).split(b"\n", 1)
        if remainder or len(encoded) > TRANSFER_FRAME_LIMIT:
            raise ConflictError("handoff transfer carried an invalid frame boundary")
        try:
            from .local_execution_handoff import decode
            value = decode(encoded)
        except (UnicodeDecodeError, ValueError, ValidationError) as exc:
            raise ConflictError("handoff transfer frame is malformed") from exc
        if not isinstance(value, dict):
            raise ConflictError("handoff transfer frame must be an object")
        return value, ancillary
    except BaseException:
        _close_descriptors(_all_rights_descriptors(ancillary))
        raise


def _all_rights_descriptors(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    """Extract every complete received SCM_RIGHTS integer for cleanup."""

    descriptors: list[int] = []
    itemsize = array.array("i").itemsize
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        usable = len(payload) - (len(payload) % itemsize)
        if usable:
            values = array.array("i")
            values.frombytes(payload[:usable])
            descriptors.extend(values)
    return descriptors


def _received_descriptors(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    if len(ancillary) != 1:
        raise ConflictError("handoff transfer must carry one descriptor record")
    level, kind, payload = ancillary[0]
    itemsize = array.array("i").itemsize
    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(payload) % itemsize:
        raise ConflictError("handoff transfer descriptor record is invalid")
    descriptors = array.array("i")
    descriptors.frombytes(payload)
    return list(descriptors)


def receive_frame(channel: socket.socket) -> dict[str, Any]:
    """Receive one bounded frame and reject any attached descriptor."""

    frame, ancillary = _receive_frame(channel)
    leaked = _all_rights_descriptors(ancillary)
    try:
        if ancillary:
            raise ConflictError("handoff control frame carried unexpected authority")
        return frame
    finally:
        _close_descriptors(leaked)


def _validate_deadline(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConflictError("handoff transfer deadline is invalid")
    deadline = float(value)
    if not math.isfinite(deadline) or deadline <= 0:
        raise ConflictError("handoff transfer deadline is invalid")


def _inspect_socket(descriptor: int, *, listener: bool) -> tuple[int, int, Any]:
    duplicate = os.dup(descriptor)
    try:
        inspected = socket.socket(fileno=duplicate)
        family = inspected.family
        kind = inspected.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        address = inspected.getsockname()
        if listener:
            try:
                accepting = inspected.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            except OSError as exc:
                if sys.platform != "darwin":
                    raise
                # Darwin does not implement SO_ACCEPTCONN.  Observe the exact
                # descriptor's kernel LISTEN state without calling accept(2)
                # (which could consume a queued client during transfer).
                observed = subprocess.run(
                    [
                        "/usr/sbin/lsof",
                        "-a",
                        "-p",
                        str(os.getpid()),
                        "-d",
                        str(duplicate),
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
                if observed.returncode not in (0, 1):
                    raise ConflictError("cannot observe inherited listener state") from exc
                accepting = int(f"f{duplicate}" in observed.stdout.splitlines())
            detail = (accepting, address)
        else:
            # A connected Unix socketpair is the only valid Worker-control
            # authority.  SO_ACCEPTCONN is unavailable for AF_UNIX on Darwin,
            # so connected-peer observation supplies the stronger role check.
            detail = (inspected.getpeername(), address)
        inspected.close()
        duplicate = -1
        return family, kind, detail
    except OSError as exc:
        raise ConflictError("handoff authority descriptor is not an observable socket") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)


def _validate_authority_sockets(
    worker_control_fd: int,
    listener_fd: int,
    *,
    expected_listener: tuple[str, int],
) -> None:
    try:
        worker_family, worker_kind, _ = _inspect_socket(worker_control_fd, listener=False)
    except ConflictError as exc:
        raise ConflictError("handoff Worker-control descriptor identity is invalid") from exc
    if worker_family != socket.AF_UNIX or worker_kind != socket.SOCK_STREAM:
        raise ConflictError("handoff Worker-control descriptor identity is invalid")

    try:
        listener_family, listener_kind, listener_value = _inspect_socket(
            listener_fd, listener=True
        )
    except ConflictError as exc:
        raise ConflictError("handoff listener descriptor identity is invalid") from exc
    listener_accepting, listener_address = listener_value
    if listener_family not in (socket.AF_INET, socket.AF_INET6):
        raise ConflictError("handoff listener must be an Internet socket")
    if listener_kind != socket.SOCK_STREAM or not listener_accepting:
        raise ConflictError("handoff listener descriptor is not accepting")
    try:
        observed_host = ipaddress.ip_address(listener_address[0])
        expected_host = ipaddress.ip_address(expected_listener[0])
        observed_port = int(listener_address[1])
        expected_port = int(expected_listener[1])
    except (ValueError, TypeError, IndexError) as exc:
        raise ConflictError("handoff listener address is invalid") from exc
    if not observed_host.is_loopback or (observed_host, observed_port) != (
        expected_host,
        expected_port,
    ):
        raise ConflictError("handoff listener does not match the expected loopback endpoint")


def validate_inherited_authority_descriptors(
    worker_control_fd: int,
    listener_fd: int,
    *,
    expected_listener: tuple[str, int],
) -> None:
    """Repeat receiver-side normalization and role checks inside owner B."""

    descriptors = (int(worker_control_fd), int(listener_fd))
    for descriptor in descriptors:
        _set_and_verify_cloexec(descriptor)
    _validate_authority_sockets(
        descriptors[0], descriptors[1], expected_listener=expected_listener
    )


@dataclass(frozen=True)
class AuthorityTransfer:
    frame: dict[str, Any]
    worker_control_fd: int
    listener_fd: int

    def close(self) -> None:
        _close_descriptors((self.worker_control_fd, self.listener_fd))


def receive_authority_transfer(
    channel: socket.socket,
    *,
    expected_uid: int,
    expected_listener: tuple[str, int],
) -> AuthorityTransfer:
    """Receive, normalize and validate one exact authority transfer.

    All received descriptors are closed on every validation failure.  The
    caller owns both returned descriptors and must close them after adoption or
    abort.
    """

    if peer_uid(channel) != int(expected_uid):
        raise ConflictError("handoff transfer peer UID is invalid")
    frame, ancillary = _receive_frame(channel)
    descriptors = _all_rights_descriptors(ancillary)
    try:
        strict_descriptors = _received_descriptors(ancillary)
        if strict_descriptors != descriptors or len(descriptors) != AUTHORITY_FD_COUNT:
            raise ConflictError("handoff transfer must carry exactly two authority descriptors")
        for descriptor in descriptors:
            _set_and_verify_cloexec(descriptor)
        if frame.get("version") != TRANSFER_VERSION:
            raise ConflictError("handoff transfer version is invalid")
        _validate_deadline(frame.get("deadline_unix_ms"))
        _validate_authority_sockets(
            descriptors[0], descriptors[1], expected_listener=expected_listener
        )
        return AuthorityTransfer(frame, descriptors[0], descriptors[1])
    except BaseException:
        _close_descriptors(descriptors)
        raise


def relay_transition_id(binding):
    from .local_execution_handoff import digest
    return "relay-transfer:" + digest({"handoff_id": binding["handoff_id"], "intent_digest": binding["intent_digest"], "source_relay_reference": binding["source_relay_reference"]})


def successor_authentication_digest(binding, successor):
    from .local_execution_handoff import digest
    return digest({"version": "runtime.local-execution-successor-auth/v1", "binding_digest": digest(binding), "successor_peer": successor, "relay_peer": binding["source_relay_reference"]["target"]})


@dataclass(frozen=True)
class FreshSuccessorPeer:
    channel: socket.socket
    actor: Any
    binding_digest: str
    sealed_record_digest: str

    def verify_binding(self, binding):
        from .local_execution_handoff import digest
        actual = self.actor.verify()
        if self.binding_digest != digest(binding) or actual != binding["new_owner"]:
            raise ConflictError("fresh successor binding/incarnation changed")
        return actual

    def verify(self, request):
        from .local_execution_handoff import digest, validate_request
        validate_request(request)
        b = request["binding"]
        actual = self.verify_binding(b)
        if (self.binding_digest != digest(b) or actual != b["new_owner"]
                or request["payload"].get("sealed_record_digest") != self.sealed_record_digest
                or request["payload"].get("successor_authentication_digest") != successor_authentication_digest(b, actual)):
            raise ConflictError("fresh successor operation/incarnation/seal differs")
        return actual


def authenticate_fresh_successor(channel, request, *, binding, sealed_record_digest):
    """Pin the actual peer at the endpoint consuming B's authority."""
    from banodoco_local.custody_broker import AuthenticatedCleanupActor
    from .local_execution_handoff import digest, validate_request
    validate_request(request)
    if request["command"] != "handoff_adopt" or request["binding"] != binding:
        raise ConflictError("fresh successor operation binding differs")
    actor = AuthenticatedCleanupActor.private_peer(channel)
    peer = FreshSuccessorPeer(channel, actor, digest(binding), sealed_record_digest)
    peer.verify(request)
    return peer


class HandoffSuccessorListener:
    """One selected handoff's fresh peer listener, never cold reconnection.

    It remains owned by the retained relay. Same UID/path possession does not
    authorize B; every accept pins the exact selected kernel incarnation.
    """
    def __init__(self, binding, sealed_record_digest, *, timeout=5.0):
        from banodoco_local.custody_broker import _create_compact_socket_root
        from .local_execution_handoff import digest, write_protected
        self.binding = dict(binding); self.sealed_record_digest = sealed_record_digest
        self.root = _create_compact_socket_root(); self.path = self.root / "s"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.set_inheritable(False); self.socket.settimeout(timeout)
        self.timeout = timeout; self.closed = False
        self.manifest_path = Path(binding["custody_scope"]) / "successor-transport.json"
        self.manifest = {"version": "runtime.local-execution-successor-transport/v1", "path": str(self.path), "binding_digest": digest(binding), "sealed_record_digest": sealed_record_digest, "successor": binding["new_owner"], "relay": binding["source_relay_reference"]["target"]}
        try:
            self.socket.bind(str(self.path)); os.chmod(self.path, 0o600); self.socket.listen(4)
            write_protected(self.manifest_path, self.manifest)
        except BaseException:
            self.close(); raise

    def accept(self):
        frame_io = getattr(self, "_frame_io", None)
        acceptor = self.socket if frame_io is None else frame_io(self.socket)
        channel, _ = acceptor.accept()
        channel.set_inheritable(False); channel.settimeout(self.timeout)
        try:
            frame = receive_frame(channel if frame_io is None else frame_io(channel))
            from .local_execution_handoff import exact
            exact(frame, ("version", "command", "request"))
            if frame["version"] != "runtime.local-execution-control/v1" or frame["command"] != "handoff":
                raise ConflictError("successor connection is not selected handoff control")
            peer = authenticate_fresh_successor(channel, frame["request"], binding=self.binding, sealed_record_digest=self.sealed_record_digest)
            return peer, frame
        except BaseException:
            channel.close(); raise

    def close(self):
        if self.closed:
            return
        self.closed = True; self.socket.close()
        # Only this listener's generated socket/root; no donor or installed
        # state is renamed/deleted. A manifest is retained as nonauthority.
        self.path.unlink(missing_ok=True)
        self.root.rmdir()


def connect_fresh_successor(binding, sealed_record_digest, *, timeout=5.0):
    from banodoco_local.custody_broker import AuthenticatedCleanupActor
    from .local_execution_handoff import digest, exact, read_protected
    manifest = read_protected(Path(binding["custody_scope"]) / "successor-transport.json")
    exact(manifest, ("version", "path", "binding_digest", "sealed_record_digest", "successor", "relay"))
    if (manifest["version"] != "runtime.local-execution-successor-transport/v1" or manifest["binding_digest"] != digest(binding)
            or manifest["sealed_record_digest"] != sealed_record_digest or manifest["successor"] != binding["new_owner"] or manifest["relay"] != binding["source_relay_reference"]["target"]):
        raise ConflictError("selected successor transport manifest differs")
    if AuthenticatedCleanupActor.current().verify() != binding["new_owner"]:
        raise ConflictError("this Runtime is not the selected successor incarnation")
    path = Path(manifest["path"])
    observed = path.lstat(); parent = path.parent.lstat()
    import stat
    if (path.is_symlink() or path.parent.is_symlink() or not stat.S_ISSOCK(observed.st_mode)
            or observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
        raise ConflictError("successor socket path is unprotected")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.set_inheritable(False); channel.settimeout(timeout)
    try:
        channel.connect(str(path))
        relay = AuthenticatedCleanupActor.private_peer(channel)
        if relay.verify() != manifest["relay"]:
            raise ConflictError("fresh successor channel is not the retained relay")
        return channel, relay
    except BaseException:
        channel.close(); raise


def committed_relay_transfer(binding, *, successor_actor, authority):
    """Read the exact protected transition; a supplied ACK is insufficient."""
    from .local_execution_handoff import digest, read_protected
    if successor_actor.verify() != binding["new_owner"]:
        raise ConflictError("relay reconciliation successor differs")
    reference = {**binding["source_relay_reference"], "generation": binding["source_relay_reference"]["generation"] + 1}
    authority.verify_reference(reference, expected_actor=binding["new_owner"], owner_epoch=binding["new_owner_epoch"])
    record = read_protected(authority.path)
    if record.get("digest") != digest({k: v for k, v in record.items() if k != "digest"}):
        raise ConflictError("relay transition ledger digest differs")
    if (record.get("state") != "active" or record.get("actor") != binding["new_owner"]
            or record.get("owner_epoch") != binding["new_owner_epoch"] or record.get("generation") != reference["generation"]
            or {k: v for k, v in record.get("target", {}).items() if k != "audit_token_words"} != reference["target"]):
        raise ConflictError("relay transition is no longer current successor custody")
    transition_id = relay_transition_id(binding)
    expected_intent = {"transition_id": transition_id, "from_generation": binding["source_relay_reference"]["generation"], "requester": binding["source_owner"], "next_actor": binding["new_owner"], "owner_epoch": binding["new_owner_epoch"]}
    matches = [entry for entry in record["transitions"] if entry["transition_id"] == transition_id]
    if len(matches) != 1 or matches[0]["intent"] != expected_intent:
        raise ConflictError("relay transition has no exact authoritative intent")
    authority.verify_reference(reference, expected_actor=binding["new_owner"], owner_epoch=binding["new_owner_epoch"])
    return matches[0]["ack"]


def transfer_relay_to_successor(request, *, peer, source_actor, runtime_journal, authority, verify_fence):
    """Split commit: prepared A journal, existing relay ledger, B writer.

    Only the relay designation moves. Each durable step releases its guard
    before the next; no guard spans connection waits or host/control RPC.
    """
    import time
    from .local_execution_handoff import digest, read_protected, validate_request
    validate_request(request); b = request["binding"]
    peer.verify(request); verify_fence(request)
    state = read_protected(runtime_journal.path)
    sealed = state.get("sealed_export")
    if (state.get("binding_digest") != digest(b) or sealed is None
            or request["payload"]["sealed_record_digest"] != sealed["sealed_record_digest"]
            or request["payload"]["export_digest"] != digest(sealed["export_metadata"])
            or request["payload"]["task_fence_digest"] != sealed["seal_record"]["task_fence_digest"]):
        raise ConflictError("successor differs from durable sealed export")
    transition_id = relay_transition_id(b)
    expected = {"version": "runtime.role-custody-designation/v1", "transition_id": transition_id, "role": "relay", "generation": b["source_relay_reference"]["generation"] + 1, "owner_epoch": b["new_owner_epoch"], "actor": b["new_owner"], "target": b["source_relay_reference"]["target"]}
    if request["payload"]["relay_transfer_ack"] != expected:
        raise ConflictError("successor selected relay ACK differs")
    current = authority.reference()
    if current == b["source_relay_reference"]:
        if time.time_ns() // 1_000_000 > b["deadline_unix_ms"]:
            raise ConflictError("uncommitted successor transfer deadline expired")
        if source_actor.verify() != b["source_owner"]:
            raise ConflictError("relay source actor differs")
        authority.verify_reference(current, expected_actor=b["source_owner"], owner_epoch=b["source_owner_epoch"])
        runtime_journal.prepare_writer_transfer(b, transition_id=transition_id, source_actor=source_actor, successor_actor=peer.actor)
        authority.transfer(actor=source_actor, next_actor=peer.actor, generation=current["generation"], transition_id=transition_id, owner_epoch=b["new_owner_epoch"])
    ack_reader = lambda: committed_relay_transfer(b, successor_actor=peer.actor, authority=authority)
    ack = ack_reader()
    if ack != expected:
        raise ConflictError("authoritative successor transfer differs")
    result = runtime_journal.reconcile_writer_transfer(b, transition_id=transition_id, successor_actor=peer.actor, authoritative_ack=ack_reader)
    peer.verify(request); verify_fence(request)
    return result


def receive_bound_authority_transfer(channel, *, binding, sealed_record_digest, expected_listener):
    """Validate sealed A export and clean every received FD on rejection.

    These FDs do not authenticate B; B still needs its fresh relay connection.
    """
    from banodoco_local.custody_broker import AuthenticatedCleanupActor
    from .local_execution_handoff import digest, exact
    if AuthenticatedCleanupActor.private_peer(channel).verify() != binding["source_owner"]:
        raise ConflictError("authority export peer incarnation differs")
    transfer = receive_authority_transfer(channel, expected_uid=binding["source_owner"]["uid"], expected_listener=expected_listener)
    try:
        exact(transfer.frame, ("version", "deadline_unix_ms", "binding_digest", "sealed_record_digest"))
        if (transfer.frame["binding_digest"] != digest(binding) or transfer.frame["sealed_record_digest"] != sealed_record_digest or transfer.frame["deadline_unix_ms"] != binding["deadline_unix_ms"]):
            raise ConflictError("authority export operation/seal differs")
        return transfer
    except BaseException:
        transfer.close(); raise


__all__ = [
    "AUTHORITY_FD_COUNT",
    "AuthorityTransfer",
    "TRANSFER_FRAME_LIMIT",
    "TRANSFER_VERSION",
    "peer_uid",
    "peer_pid",
    "receive_frame",
    "receive_authority_transfer",
    "send_authority_transfer",
    "send_frame",
    "validate_inherited_authority_descriptors",
]
