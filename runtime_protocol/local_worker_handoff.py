"""Private POSIX descriptor custody for an orderly local Worker handoff."""

from __future__ import annotations

import array
import fcntl
import ipaddress
import json
import math
import os
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
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
