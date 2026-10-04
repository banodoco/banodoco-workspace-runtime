"""Darwin audit-token custody for the long-lived local Runtime owner.

The launcher owns the broker only until admission is sealed.  The durable
owner-only sidecar and hash-chained ledger retain the exact final-ready audit
token so a later installed qualification controller can signal that process
incarnation without using a numeric PID signal.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, Mapping, Sequence


PROTOCOL_VERSION = 1
CAPABILITY_VERSION = "runtime.role-bound-custody/v2"
ACTIVE_CAPABILITY_NAME = "runtime-custody-active.json"
SOL_LOCAL = 0
LOCAL_PEERTOKEN = 0x006
TOKEN_BYTES = 32
TASK_AUDIT_TOKEN = 15
TASK_AUDIT_TOKEN_COUNT = 8
FRAME_LIMIT = 16 * 1024
DARWIN_UNIX_SOCKET_PATH_MAX_BYTES = 103
DARWIN_CUSTODY_SOCKET_PARENT = Path("/private/tmp")
AUTHORITY_SCOPE_LOCK = "admission.lock"
AUTHORITY_SCOPE_CLOSED = "admission.closed.json"
PENDING_AUTHORITY_VERSION = "astrid.plan-a.authority-admission-pending/v1"
RESOLVED_AUTHORITY_VERSION = "astrid.plan-a.authority-admission-resolved/v1"
DESIGNATION_VERSION = "runtime.role-custody-designation/v1"
ROLE_REFERENCE_VERSION = "runtime.role-custody-reference/v1"


class CustodyError(RuntimeError):
    """The exact registered Runtime incarnation cannot be proved or signalled."""


def _create_compact_socket_root() -> Path:
    """Create an owner-only socket directory below Darwin's short temp alias."""

    parent = DARWIN_CUSTODY_SOCKET_PARENT
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise CustodyError("custody socket parent is unavailable") from exc
    if (
        not parent.is_absolute()
        or stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or (parent_stat.st_mode & stat.S_IWOTH and not parent_stat.st_mode & stat.S_ISVTX)
    ):
        raise CustodyError("custody socket parent is unsafe")
    root = Path(tempfile.mkdtemp(prefix="runtime-cb-", dir=parent))
    os.chmod(root, 0o700)
    if len(os.fsencode(str(root / "s"))) > DARWIN_UNIX_SOCKET_PATH_MAX_BYTES:
        try:
            root.rmdir()
        finally:
            raise CustodyError("custody socket path exceeds Darwin AF_UNIX limit")
    return root


class _AuditToken(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint32 * 8)]


def _admitted_signals() -> set[int]:
    admitted = {int(signal.SIGTERM), int(signal.SIGKILL)}
    if hasattr(signal, "SIGUSR1"):
        admitted.add(int(signal.SIGUSR1))
    return admitted


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _send_frame(connection: socket.socket, value: Mapping[str, object]) -> None:
    encoded = _canonical(dict(value)) + b"\n"
    if len(encoded) > FRAME_LIMIT:
        raise CustodyError("custody frame exceeds its hard limit")
    connection.sendall(encoded)


def _read_frame(connection: socket.socket) -> dict[str, object]:
    raw = bytearray()
    while not raw.endswith(b"\n"):
        part = connection.recv(min(4096, FRAME_LIMIT + 1 - len(raw)))
        if not part:
            raise CustodyError("custody peer closed before a complete frame")
        raw.extend(part)
        if len(raw) > FRAME_LIMIT:
            raise CustodyError("custody frame exceeds its hard limit")
    if b"\n" in raw[:-1]:
        raise CustodyError("custody frame contains trailing data")
    value = json.loads(bytes(raw[:-1]).decode("utf-8"))
    if not isinstance(value, dict):
        raise CustodyError("custody frame is not an object")
    return value


def _token_from_words(words: Sequence[int]) -> _AuditToken:
    if len(words) != 8 or any(
        isinstance(value, bool) or not isinstance(value, int)
        or value < 0 or value > 0xFFFFFFFF
        for value in words
    ):
        raise CustodyError("registered audit token is invalid")
    token = _AuditToken()
    for index, value in enumerate(words):
        token.value[index] = value
    return token


def audit_token_details(words: Sequence[int]) -> dict[str, object]:
    if sys.platform != "darwin":
        raise CustodyError("Darwin audit-token custody is unavailable")
    token = _token_from_words(words)
    libbsm = ctypes.CDLL("/usr/lib/libbsm.0.dylib", use_errno=True)
    libbsm.audit_token_to_pid.argtypes = [_AuditToken]
    libbsm.audit_token_to_pid.restype = ctypes.c_int
    libbsm.audit_token_to_pidversion.argtypes = [_AuditToken]
    libbsm.audit_token_to_pidversion.restype = ctypes.c_int
    raw = bytes(token)
    return {
        "pid": int(libbsm.audit_token_to_pid(token)),
        "pidversion": int(libbsm.audit_token_to_pidversion(token)),
        "uid": int(token.value[1]),
        "sha256": _digest_bytes(raw),
    }


def _peer_token(connection: socket.socket) -> dict[str, object]:
    if sys.platform != "darwin":
        raise CustodyError("Darwin audit-token custody is unavailable")
    raw = connection.getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, TOKEN_BYTES)
    if len(raw) != TOKEN_BYTES:
        raise CustodyError("LOCAL_PEERTOKEN returned an invalid token size")
    token = _AuditToken.from_buffer_copy(raw)
    details = audit_token_details([int(value) for value in token.value])
    return {**details, "words": [int(value) for value in token.value]}


def current_process_audit_token(pid: int) -> dict[str, object]:
    """Read one live process token through a retained Mach task-name port."""

    if sys.platform != "darwin" or int(pid) <= 0:
        raise CustodyError("Darwin audit-token custody is unavailable")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.task_name_for_pid.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
    ]
    library.task_name_for_pid.restype = ctypes.c_int
    library.task_info.argtypes = [
        ctypes.c_uint32, ctypes.c_int,
        ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint32),
    ]
    library.task_info.restype = ctypes.c_int
    library.pid_for_task.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
    library.pid_for_task.restype = ctypes.c_int
    library.mach_port_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    library.mach_port_deallocate.restype = ctypes.c_int
    task_self = ctypes.c_uint32.in_dll(library, "mach_task_self_").value
    task_name = ctypes.c_uint32(0)
    if int(library.task_name_for_pid(task_self, int(pid), ctypes.byref(task_name))) != 0:
        raise CustodyError("final-ready Runtime task-name port is unavailable")

    def read_token() -> list[int]:
        token = _AuditToken()
        count = ctypes.c_uint32(TASK_AUDIT_TOKEN_COUNT)
        result = int(library.task_info(
            task_name.value,
            TASK_AUDIT_TOKEN,
            ctypes.cast(ctypes.byref(token), ctypes.POINTER(ctypes.c_int32)),
            ctypes.byref(count),
        ))
        if result != 0 or count.value != TASK_AUDIT_TOKEN_COUNT:
            raise CustodyError("final-ready Runtime audit token is unavailable")
        return [int(value) for value in token.value]

    try:
        first = read_token()
        bound_pid = ctypes.c_int(0)
        if (
            int(library.pid_for_task(task_name.value, ctypes.byref(bound_pid))) != 0
            or bound_pid.value != int(pid)
        ):
            raise CustodyError("final-ready Runtime task port changed process")
        second = read_token()
        if first != second:
            raise CustodyError("final-ready Runtime audit token changed while binding")
        return {**audit_token_details(first), "words": first}
    finally:
        if int(library.mach_port_deallocate(task_self, task_name.value)) != 0:
            raise CustodyError("final-ready Runtime task-name port release failed")


def signal_audit_token(words: Sequence[int], signum: int) -> None:
    if int(signum) not in _admitted_signals():
        raise CustodyError("custody signal is outside the admitted set")
    if sys.platform != "darwin":
        raise CustodyError("Darwin audit-token custody is unavailable")
    token = _token_from_words(words)
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_signal_with_audittoken
    function.argtypes = [ctypes.POINTER(_AuditToken), ctypes.c_int]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = int(function(ctypes.byref(token), int(signum)))
    observed_errno = int(ctypes.get_errno())
    if result != 0:
        raise CustodyError(
            "proc_signal_with_audittoken failed for registered target "
            f"(returncode={result}, errno={observed_errno})"
        )


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise CustodyError("custody write was incomplete")
        offset += written


def _atomic_owner_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, _canonical(dict(value)) + b"\n")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _append_owner_jsonl(path: Path, value: Mapping[str, object]) -> None:
    """Durably append one owner-only authority record without replacing peers."""

    if not path.is_absolute() or path.is_symlink():
        raise CustodyError("custody authority journal path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = os.lstat(path.parent)
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise CustodyError("custody authority journal parent is not owner-only")
    encoded = _canonical(dict(value)) + b"\n"
    if len(encoded) > FRAME_LIMIT:
        raise CustodyError("custody authority journal record exceeds its hard limit")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CustodyError("custody authority journal is not owner-only")
        if os.write(descriptor, encoded) != len(encoded):
            raise CustodyError("custody authority journal append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_authority_scope_lock(scope_root: Path) -> int:
    root = Path(os.path.abspath(scope_root))
    if not root.is_absolute() or root.is_symlink():
        raise CustodyError("custody authority scope is unsafe")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    observed_root = os.lstat(root)
    if (
        not stat.S_ISDIR(observed_root.st_mode)
        or observed_root.st_uid != os.getuid()
        or stat.S_IMODE(observed_root.st_mode) != 0o700
    ):
        raise CustodyError("custody authority scope is not owner-only")
    descriptor = os.open(
        root / AUTHORITY_SCOPE_LOCK,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    os.set_inheritable(descriptor, False)
    observed = os.fstat(descriptor)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise CustodyError("custody authority scope lock is not owner-only")
    return descriptor


def _acquire_scope_admission(scope_root: Path, *, timeout: float) -> int:
    descriptor = _open_authority_scope_lock(scope_root)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CustodyError("custody authority scope admission timed out")
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        if (Path(scope_root) / AUTHORITY_SCOPE_CLOSED).exists():
            raise CustodyError("custody authority scope is closed")
        return descriptor
    except BaseException:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        raise


def close_authority_scope(scope_root: Path, *, deadline: float) -> dict[str, object]:
    """Deny later admissions and drain every admission begun before the close."""

    root = Path(os.path.abspath(scope_root))
    descriptor = _open_authority_scope_lock(root)
    marker = root / AUTHORITY_SCOPE_CLOSED
    errors: list[dict[str, object]] = []
    try:
        try:
            marker_descriptor = os.open(
                marker,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            marker_descriptor = -1
        if marker_descriptor >= 0:
            try:
                payload = _canonical({
                    "version": "astrid.plan-a.authority-scope-close/v1",
                    "closed": True,
                }) + b"\n"
                _write_all(marker_descriptor, payload)
                os.fsync(marker_descriptor)
            finally:
                os.close(marker_descriptor)
            directory = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        drained = False
        while time.monotonic() < deadline:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                drained = True
                break
            except BlockingIOError:
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        if not drained:
            errors.append({
                "stage": "drain", "type": "TimeoutError",
                "message": "custody authority scope admission drain exceeded its deadline",
            })
        return {
            "version": "astrid.plan-a.authority-scope-close/v1",
            "closed": True, "drained": drained, "errors": errors,
            "deadline_monotonic": deadline,
        }
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_owner_file(path: Path) -> tuple[bytes, os.stat_result]:
    if path.is_symlink():
        raise CustodyError("custody file must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CustodyError("custody file is not an owner-only regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), observed
    finally:
        os.close(descriptor)


def _incarnation(identity: Mapping[str, object], token: Mapping[str, object]) -> dict[str, object]:
    pid, uid, birth = identity.get("pid"), identity.get("uid"), identity.get("birth_id")
    if (
        isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
        or isinstance(uid, bool) or not isinstance(uid, int) or uid < 0
        or not isinstance(birth, str) or not birth
        or token.get("pid") != pid or token.get("uid") != uid
        or isinstance(token.get("pidversion"), bool) or not isinstance(token.get("pidversion"), int)
        or not isinstance(token.get("sha256"), str)
    ):
        raise CustodyError("custody incarnation lacks authenticated identity")
    return {"pid": pid, "uid": uid, "birth_id": birth,
            "audit_token_sha256": token["sha256"], "audit_token_pidversion": token["pidversion"]}


class AuthenticatedCleanupActor:
    """An actor pinned from our own kernel identity or a retained private peer.

    RPC payloads never construct this object. The retained channel (or our own
    process) supplies the token again at each use, including replay.
    """

    def __init__(self, token_reader: Callable[[], Mapping[str, object]],
                 identity_provider: Callable[[int], Mapping[str, object] | None]) -> None:
        self._token_reader = token_reader
        self._identity_provider = identity_provider
        token = dict(token_reader())
        identity = identity_provider(int(token.get("pid", 0)))
        if identity is None:
            raise CustodyError("cleanup actor incarnation is unavailable")
        self._pinned = _incarnation(identity, token)

    @classmethod
    def current(cls, *, identity_provider: Callable[[int], Mapping[str, object] | None] | None = None) -> AuthenticatedCleanupActor:
        return cls(lambda: current_process_audit_token(os.getpid()),
                   identity_provider or default_process_identity)

    @classmethod
    def private_peer(cls, channel: socket.socket,
                     *, identity_provider: Callable[[int], Mapping[str, object] | None] | None = None) -> AuthenticatedCleanupActor:
        return cls(lambda: _peer_token(channel), identity_provider or default_process_identity)

    def verify(self) -> dict[str, object]:
        token = dict(self._token_reader())
        identity = self._identity_provider(int(self._pinned["pid"]))
        if identity is None or _incarnation(identity, token) != self._pinned:
            raise CustodyError("designated cleanup actor incarnation changed or is unknown")
        return dict(self._pinned)


class RetainedChildActor:
    """Positive exit proof only from a handle retained while its peer was live.

    PID absence/reuse, socket EOF and ps failures cannot create exit evidence.
    Nonchild recovery must instead replay an explicit durable relinquishment.
    """

    def __init__(self, child: subprocess.Popen[bytes], actor: AuthenticatedCleanupActor) -> None:
        pinned = actor.verify()
        if child.pid != pinned["pid"] or child.poll() is not None:
            raise CustodyError("cleanup actor is not this live retained child")
        self._child = child
        self._pinned = pinned

    def prove_exit(self, expected: Mapping[str, object]) -> None:
        if dict(expected) != self._pinned or self._child.poll() is None:
            raise CustodyError("designated cleanup actor has no positive retained-child exit proof")


class RoleCustodyAuthority:
    """Protected per-role designation, fenced through every destructive call.

    The atomic designation contains its bounded transition history, so one
    fsynced rename is the commit point and a lost ACK has an exact replay.
    Runtime ownership epochs are metadata; only a role transition advances its
    custody generation. No operation sweeps or invalidates delegated roles.
    """

    def __init__(self, scope_root: Path, role: str, *, timeout: float = 5.0) -> None:
        if not role or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in role):
            raise CustodyError("custody role is invalid")
        if not scope_root.is_absolute() or scope_root.is_symlink():
            raise CustodyError("custody scope is unsafe")
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
            raise CustodyError("custody guard timeout is invalid")
        descriptor = _open_authority_scope_lock(scope_root)
        os.close(descriptor)
        self.root, self.role, self.timeout = scope_root, role, timeout
        self.path = scope_root / ("designation-" + role + ".json")

    @contextmanager
    def _guard(self, *, exclusive: bool):
        descriptor = os.open(self.root / "cleanup.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600:
                raise CustodyError("custody cleanup guard is unsafe")
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CustodyError("custody cleanup guard timed out; authority unresolved")
                    time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read(self) -> dict[str, object]:
        raw, _ = _read_owner_file(self.path)
        if len(raw) > 256 * 1024:
            raise CustodyError("custody designation exceeds its bound")
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CustodyError("custody designation is malformed") from exc
        if (
            not isinstance(record, dict)
            or set(record) != {"version", "role", "generation", "owner_epoch", "state", "actor", "target", "transitions", "digest"}
            or record["version"] != DESIGNATION_VERSION or record["role"] != self.role
            or isinstance(record["generation"], bool) or not isinstance(record["generation"], int) or record["generation"] < 1
            or record["state"] not in {"pending", "active"}
            or not isinstance(record["actor"], dict) or not isinstance(record["target"], dict)
            or not isinstance(record["transitions"], list)
            or record["digest"] != _digest_bytes(_canonical({k: v for k, v in record.items() if k != "digest"}))
        ):
            raise CustodyError("custody designation is invalid")
        return record

    def _write(self, record: dict[str, object]) -> None:
        record = {k: v for k, v in record.items() if k != "digest"}
        record["digest"] = _digest_bytes(_canonical(record))
        if len(_canonical(record)) > 256 * 1024:
            raise CustodyError("custody transition history exceeds its bound")
        _atomic_owner_json(self.path, record)

    def designate_pending(self, *, actor: AuthenticatedCleanupActor, identity: Mapping[str, object],
                          token: Mapping[str, object], owner_epoch: str) -> None:
        if not isinstance(owner_epoch, str) or not owner_epoch or len(owner_epoch) > 256:
            raise CustodyError("custody owner epoch is invalid")
        with self._guard(exclusive=True):
            if self.path.exists():
                raise CustodyError("custody role already has a designation")
            self._write({"version": DESIGNATION_VERSION, "role": self.role, "generation": 1,
                         "owner_epoch": owner_epoch, "state": "pending", "actor": actor.verify(),
                         "target": _incarnation(identity, token), "transitions": []})

    def reserve_before_spawn(self, *, actor: AuthenticatedCleanupActor, owner_epoch: str,
                             admission_id: str) -> None:
        """Record the owner of an unbound launch obligation before Popen."""
        if not isinstance(owner_epoch, str) or not owner_epoch or len(owner_epoch) > 256 or not admission_id:
            raise CustodyError("pending launch custody binding is invalid")
        with self._guard(exclusive=True):
            if self.path.exists():
                raise CustodyError("custody role already has a designation")
            self._write({"version": DESIGNATION_VERSION, "role": self.role, "generation": 1,
                         "owner_epoch": owner_epoch, "state": "pending", "actor": actor.verify(),
                         "target": {"admission_id": admission_id}, "transitions": []})

    def bind_pending(self, *, actor: AuthenticatedCleanupActor, admission_id: str,
                     identity: Mapping[str, object], token: Mapping[str, object]) -> None:
        with self._guard(exclusive=True):
            record = self._read()
            self._check_actor(record, actor, 1)
            if record["state"] != "pending" or record["target"] != {"admission_id": admission_id}:
                raise CustodyError("pending launch obligation differs from registration")
            record["target"] = _incarnation(identity, token)
            self._write(record)

    def bind_target(self, *, actor: AuthenticatedCleanupActor, generation: int,
                    identity: Mapping[str, object], token: Mapping[str, object]) -> dict[str, object]:
        with self._guard(exclusive=True):
            record = self._read()
            self._check_actor(record, actor, generation)
            target = _incarnation(identity, token)
            if any(record["target"].get(k) != target.get(k) for k in ("pid", "birth_id", "uid")):
                raise CustodyError("custody target incarnation changed during exec binding")
            words = token.get("words")
            if not isinstance(words, list) or audit_token_details(words) != {k: token[k] for k in ("pid", "uid", "pidversion", "sha256")}:
                raise CustodyError("custody target kernel token is invalid")
            record.update(state="active", target={**target, "audit_token_words": words})
            self._write(record)
            return self._reference(record)

    def _check_actor(self, record: Mapping[str, object], actor: AuthenticatedCleanupActor, generation: int) -> None:
        if isinstance(generation, bool) or record["generation"] != generation or record["actor"] != actor.verify():
            raise CustodyError("stale cleanup actor or custody generation")

    def _reference(self, record: Mapping[str, object]) -> dict[str, object]:
        return {"version": ROLE_REFERENCE_VERSION, "scope_root": str(self.root), "role": self.role,
                "generation": record["generation"], "target": {k: v for k, v in record["target"].items() if k != "audit_token_words"}}

    def reference(self) -> dict[str, object]:
        with self._guard(exclusive=False):
            return self._reference(self._read())

    def signal(self, *, actor: AuthenticatedCleanupActor, generation: int,
               expected_target: Mapping[str, object], signum: int,
               identity_provider: Callable[[int], Mapping[str, object] | None],
               signal_provider: Callable[[Sequence[int], int], None] = signal_audit_token,
               request_authorizer: Callable[[], None] | None = None) -> None:
        if isinstance(signum, bool) or int(signum) not in _admitted_signals():
            raise CustodyError("custody signal is outside the admitted set")
        # This guard deliberately spans observation AND the kernel signal. Exit
        # waits and RPCs belong outside it; TERM and KILL each reacquire it.
        with self._guard(exclusive=False):
            record = self._read()
            self._check_actor(record, actor, generation)
            if request_authorizer is not None:
                request_authorizer()
            target = record["target"]
            if record["state"] != "active" or {k: v for k, v in target.items() if k != "audit_token_words"} != dict(expected_target):
                raise CustodyError("custody target is pending, stale or differs from selected role")
            observed = identity_provider(int(target["pid"]))
            if observed is None or any(observed.get(k) != target[k] for k in ("pid", "birth_id", "uid")):
                raise CustodyError("custody target identity is unknown, absent or replaced")
            signal_provider(target["audit_token_words"], signum)

    def transfer(self, *, actor: AuthenticatedCleanupActor, next_actor: AuthenticatedCleanupActor,
                 generation: int, transition_id: str, owner_epoch: str,
                 dead_actor: RetainedChildActor | None = None) -> dict[str, object]:
        if not isinstance(transition_id, str) or not transition_id or len(transition_id) > 256:
            raise CustodyError("custody transfer identity is invalid")
        if not isinstance(owner_epoch, str) or not owner_epoch or len(owner_epoch) > 256:
            raise CustodyError("custody owner epoch is invalid")
        with self._guard(exclusive=True):
            record = self._read()
            requester, successor = actor.verify(), next_actor.verify()
            intent = {"transition_id": transition_id, "from_generation": generation,
                      "requester": requester, "next_actor": successor, "owner_epoch": owner_epoch}
            for transition in record["transitions"]:
                if transition["transition_id"] == transition_id:
                    if transition["intent"] != intent:
                        raise CustodyError("custody transfer replay conflicts with durable intent")
                    return dict(transition["ack"])
            if isinstance(generation, bool) or record["generation"] != generation or record["state"] != "active":
                raise CustodyError("custody transfer has a stale generation or pending target")
            if dead_actor is None:
                if record["actor"] != requester:
                    raise CustodyError("only the designated live actor may relinquish custody")
            else:
                if requester != successor:
                    raise CustodyError("dead-actor recovery must name the authenticated recovering actor")
                dead_actor.prove_exit(record["actor"])
            ack = {"version": DESIGNATION_VERSION, "transition_id": transition_id,
                   "role": self.role, "generation": generation + 1, "owner_epoch": owner_epoch,
                   "actor": successor, "target": {k: v for k, v in record["target"].items() if k != "audit_token_words"}}
            record["transitions"].append({"transition_id": transition_id, "intent": intent, "ack": ack})
            record.update(generation=generation + 1, owner_epoch=owner_epoch, actor=successor)
            self._write(record)  # Durable commit BEFORE reply/ACK; replay uses this exact record.
            return ack


class RoleBoundCustodyBroker:
    """One-role broker whose sealed durable ledger is later signal authority."""

    def __init__(
        self,
        *,
        role: str,
        identity_provider: Callable[[int], Mapping[str, object] | None],
        ledger_root: Path,
        timeout: float = 5.0,
        authority_journal: Path | None = None,
        authority_scope_root: Path | None = None,
        owner_epoch: str | None = None,
        launch_parent: AuthenticatedCleanupActor | None = None,
    ) -> None:
        if not role or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in role):
            raise CustodyError("custody role is invalid")
        if sys.platform != "darwin":
            raise CustodyError("Darwin audit-token custody is unavailable")
        self.role = role
        self.identity_provider = identity_provider
        self.timeout = timeout
        self.authority_journal = (
            Path(os.path.abspath(authority_journal))
            if authority_journal is not None else None
        )
        self.authority_scope_root = (
            Path(os.path.abspath(authority_scope_root))
            if authority_scope_root is not None else None
        )
        if (self.authority_journal is None) != (self.authority_scope_root is None):
            raise CustodyError("custody authority journal and scope must be configured together")
        self._authority_scope_descriptor: int | None = None
        self._authority_scope_guard = threading.Lock()
        self.run_id = _digest_bytes(os.urandom(32))
        ledger_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(ledger_root, 0o700)
        self.root = ledger_root
        self.journal_path = ledger_root / "custody.journal.jsonl"
        self.ledger_path = ledger_root / "custody.ledger.json"
        self.cleanup_actor = AuthenticatedCleanupActor.current()
        self.launch_parent = launch_parent or self.cleanup_actor
        self.role_authority = RoleCustodyAuthority(self.authority_scope_root or (ledger_root / "authority"), role, timeout=timeout)
        self.owner_epoch = owner_epoch or self.run_id
        self.custody_generation = 1
        self.role_authority.reserve_before_spawn(actor=self.cleanup_actor, owner_epoch=self.owner_epoch,
                                                 admission_id=self.run_id)
        self.socket_root = _create_compact_socket_root()
        self.socket_path = self.socket_root / "s"
        listener: socket.socket | None = None
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            listener.listen(1)
            listener.settimeout(timeout)
        except BaseException:
            if listener is not None:
                listener.close()
            self.socket_path.unlink(missing_ok=True)
            try:
                self.socket_root.rmdir()
            except OSError:
                pass
            if self._authority_scope_descriptor is not None:
                fcntl.flock(self._authority_scope_descriptor, fcntl.LOCK_UN)
                os.close(self._authority_scope_descriptor)
                self._authority_scope_descriptor = None
            raise
        self.listener = listener
        try:
            self._authority_scope_descriptor = (
                _acquire_scope_admission(self.authority_scope_root, timeout=timeout)
                if self.authority_scope_root is not None else None
            )
        except BaseException:
            self.listener.close()
            self.socket_path.unlink(missing_ok=True)
            try:
                self.socket_root.rmdir()
            except OSError:
                pass
            raise
        self.sequence = 0
        self.chain_head: str | None = None
        self.state = "accepting"
        self.registration: dict[str, object] | None = None
        self.ack: dict[str, object] | None = None
        self.error: BaseException | None = None
        self._post_exec_authority_validated = False
        self._cleanup_deadline: float | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self.listener.close()
            self.socket_path.unlink(missing_ok=True)
            try:
                self.socket_root.rmdir()
            except OSError:
                pass
            self._release_authority_scope()
            raise

    def _release_authority_scope(self) -> None:
        with self._authority_scope_guard:
            descriptor = self._authority_scope_descriptor
            self._authority_scope_descriptor = None
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def abort_before_spawn(self) -> None:
        """Release an admission that never reached a workload Popen call."""

        if self.registration is not None:
            raise CustodyError("registered custody cannot use pre-spawn abort")
        self.listener.close()
        self.socket_path.unlink(missing_ok=True)
        try:
            self.socket_root.rmdir()
        except OSError:
            pass
        self._release_authority_scope()

    def child_environment(self, argv: Sequence[str], *, start_new_session: bool) -> dict[str, str]:
        candidate = Path(argv[0])
        if not candidate.is_absolute():
            located = shutil.which(argv[0])
            if located is None:
                raise CustodyError("custodied executable is unavailable")
            candidate = Path(located)
        lexical_executable = str(Path(os.path.abspath(candidate)))
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise CustodyError("custodied executable is not executable")
        # Preserve the validated lexical venv executable for exec. Resolving a
        # venv symlink here would silently leave its installed environment.
        normalized = [lexical_executable, *list(argv[1:])]
        return {
            "ASTRID_RUNTIME_CUSTODY_SOCKET": str(self.socket_path),
            "ASTRID_RUNTIME_CUSTODY_RUN_ID": self.run_id,
            "ASTRID_RUNTIME_CUSTODY_ROLE": self.role,
            "ASTRID_RUNTIME_CUSTODY_START_SESSION": "1" if start_new_session else "0",
            "ASTRID_RUNTIME_CUSTODY_TIMEOUT_SECONDS": repr(self.timeout),
            "ASTRID_RUNTIME_CUSTODY_TARGET_B64": base64.b64encode(
                _canonical(normalized)
            ).decode("ascii"),
        }

    def wait_until_sealed(self) -> None:
        if not self._ready.wait(self.timeout):
            raise CustodyError("custody registration timed out")
        self._thread.join(timeout=self.timeout)
        if self.error is not None:
            raise CustodyError(f"custody registration failed: {self.error}") from self.error
        if (
            self._thread.is_alive()
            or self.state not in {"sealed", "ready-bound"}
            or self.registration is None
        ):
            raise CustodyError("custody admission did not seal")

    def set_cleanup_deadline(self, deadline: float) -> None:
        self._cleanup_deadline = deadline

    def _observe_registered_identity(self, pid: int) -> Mapping[str, object] | None:
        if self.identity_provider is default_process_identity:
            remaining = (
                1.0 if self._cleanup_deadline is None
                else self._cleanup_deadline - time.monotonic()
            )
            return default_process_identity(pid, timeout=min(1.0, remaining))
        return self.identity_provider(pid)

    def signal(self, signum: int, *, expected_pid: int) -> None:
        """Signal only the sealed role and exact process incarnation."""

        if int(signum) not in _admitted_signals():
            raise CustodyError("custody signal is outside the admitted set")
        if self.state not in {"sealed", "ready-bound"} or self.registration is None:
            raise CustodyError("custody admission is not sealed")
        identity = self.registration.get("identity")
        if not isinstance(identity, dict) or identity.get("pid") != expected_pid:
            raise CustodyError("registered custody PID differs from the process handle")
        self.role_authority.signal(
            actor=self.cleanup_actor, generation=self.custody_generation,
            expected_target=self.role_authority.reference()["target"], signum=signum,
            identity_provider=self._observe_registered_identity,
        )

    def signal_failed_admission(self, signum: int, *, expected_pid: int) -> None:
        """Clean up only a failed admission with authenticated post-exec authority.

        A persistence or final-seal failure must not discard the live child.  This
        path does not admit that child: it is available only after the broker has
        authenticated the post-exec audit token and current process incarnation.
        """

        if int(signum) not in _admitted_signals():
            raise CustodyError("custody signal is outside the admitted set")
        if (
            self.error is None
            or not self._post_exec_authority_validated
            or self.registration is None
        ):
            raise CustodyError("failed admission has no validated post-exec authority")
        identity = self.registration.get("identity")
        if not isinstance(identity, dict) or identity.get("pid") != expected_pid:
            raise CustodyError("registered custody PID differs from the process handle")
        self.role_authority.signal(
            actor=self.cleanup_actor, generation=self.custody_generation,
            expected_target=self.role_authority.reference()["target"], signum=signum,
            identity_provider=self._observe_registered_identity,
        )

    def signal_from_launch_parent(self, *, requester: AuthenticatedCleanupActor,
                                  generation: int, expected_target: Mapping[str, object], signum: int) -> None:
        """Execute a child's signal request as its designated host owner.

        The engine's retained private identity authorizes a request to its host;
        it receives no token possession or active cleanup designation itself.
        """
        if self.role != "engine_listener" or int(signum) not in {int(signal.SIGTERM), int(signal.SIGKILL)}:
            raise CustodyError("delegated engine signal is outside the listener contract")

        def authenticate_request() -> None:
            if requester.verify() != self.launch_parent.verify():
                raise CustodyError("listener signal requester differs from authenticated engine parent")

        self.role_authority.signal(actor=self.cleanup_actor, generation=generation,
                                   expected_target=expected_target, signum=signum,
                                   identity_provider=self._observe_registered_identity,
                                   request_authorizer=authenticate_request)

    def bind_ready_token(
        self,
        *,
        expected_pid: int,
        expected_identity: Mapping[str, object],
        token_provider: Callable[[int], Mapping[str, object]] = current_process_audit_token,
    ) -> None:
        """Replace the provisional post-exec token with the final ready owner."""

        if self.state != "sealed" or self.registration is None:
            raise CustodyError("custody admission is not provisionally sealed")
        pinned = self.registration.get("identity")
        expected = {key: expected_identity.get(key) for key in ("pid", "birth_id", "uid")}
        if (
            not isinstance(pinned, Mapping)
            or expected_pid != expected.get("pid")
            or {key: pinned.get(key) for key in expected} != expected
        ):
            raise CustodyError("final-ready Runtime identity differs from provisional custody")
        before = self.identity_provider(expected_pid)
        if before is None or {key: before.get(key) for key in expected} != expected:
            raise CustodyError("final-ready Runtime incarnation is unavailable")
        token = dict(token_provider(expected_pid))
        after = self.identity_provider(expected_pid)
        if after is None or {key: after.get(key) for key in expected} != expected:
            raise CustodyError("final-ready Runtime incarnation changed while binding")
        words = token.get("words")
        if (
            token.get("pid") != expected_pid
            or token.get("uid") != expected.get("uid")
            or not isinstance(token.get("pidversion"), int)
            or not isinstance(token.get("sha256"), str)
            or not isinstance(words, list)
            or audit_token_details(words) != {
                key: token[key] for key in ("pid", "pidversion", "uid", "sha256")
            }
        ):
            raise CustodyError("final-ready Runtime audit token is invalid")
        self.registration.update({
            "post_exec_audit_token_sha256": self.registration.get("audit_token_sha256"),
            "post_exec_pidversion": self.registration.get("audit_token_pidversion"),
            "identity": dict(after),
            "audit_token_words": list(words),
            "audit_token_sha256": token["sha256"],
            "audit_token_pidversion": token["pidversion"],
        })
        self.role_authority.bind_target(actor=self.cleanup_actor, generation=self.custody_generation,
                                        identity=after, token=token)
        self.sequence = 3
        self.state = "ready-bound"
        self._persist("readiness_token_bound")

    def _persist(self, event_name: str) -> None:
        snapshot = {
            "version": PROTOCOL_VERSION,
            "run_id": self.run_id,
            "role": self.role,
            "state": self.state,
            "sequence": self.sequence,
            "registration": self.registration,
            "ack": self.ack,
        }
        event: dict[str, object] = {
            "version": PROTOCOL_VERSION,
            "event": event_name,
            "sequence": self.sequence,
            "predecessor_digest": self.chain_head,
            "snapshot_digest": _digest_bytes(_canonical(snapshot)),
            "snapshot": snapshot,
        }
        event["event_digest"] = _digest_bytes(_canonical(event))
        descriptor = os.open(
            self.journal_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, _canonical(event) + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.chain_head = str(event["event_digest"])
        _atomic_owner_json(self.ledger_path, {**snapshot, "chain_digest": self.chain_head})

    def _serve(self) -> None:
        connection: socket.socket | None = None
        try:
            connection, _ = self.listener.accept()
            connection.settimeout(self.timeout)
            frame = _read_frame(connection)
            required = {"version", "command", "run_id", "role", "pid", "ppid", "argv_digest"}
            if (
                set(frame) != required
                or frame["version"] != PROTOCOL_VERSION
                or frame["command"] != "register_pre_exec"
                or frame["run_id"] != self.run_id
                or frame["role"] != self.role
                or frame["ppid"] != self.launch_parent.verify()["pid"]
                or isinstance(frame["pid"], bool)
                or not isinstance(frame["pid"], int)
                or frame["pid"] <= 0
            ):
                raise CustodyError("custody registration frame is invalid")
            pre = _peer_token(connection)
            if pre["pid"] != frame["pid"] or pre["uid"] != os.getuid():
                raise CustodyError("custody registration kernel identity differs")
            before = self.identity_provider(int(frame["pid"]))
            if before is None:
                raise CustodyError("pre-exec process identity is unavailable")
            if before.get("parent_pid") != self.launch_parent.verify()["pid"]:
                raise CustodyError("registered process does not have the authenticated launch parent")
            self.sequence = 1
            self.registration = {
                "pid": frame["pid"], "identity": dict(before),
                "argv_digest": frame["argv_digest"],
                "pre_exec_audit_token_sha256": pre["sha256"],
                "pre_exec_pidversion": pre["pidversion"],
                "audit_token_words": pre["words"],
            }
            # Pending cleanup ownership is durable before registration can ACK
            # and let exec proceed. It conveys no destructive signal authority.
            self.role_authority.bind_pending(actor=self.cleanup_actor, admission_id=self.run_id,
                                             identity=before, token=pre)
            self._persist("registration_pre_exec")
            self.ack = {
                "version": PROTOCOL_VERSION, "status": "registered",
                "run_id": self.run_id, "role": self.role, "pid": frame["pid"],
                "registration_digest": _digest_bytes(_canonical(frame)),
                "ledger_state_digest": self.chain_head,
            }
            self._persist("registration_ack_checkpoint")
            if self.authority_journal is not None:
                identity = dict(self.registration["identity"])  # type: ignore[arg-type]
                _append_owner_jsonl(self.authority_journal, {
                    "version": PENDING_AUTHORITY_VERSION,
                    "admission_id": self.run_id,
                    "role": self.role,
                    "pid": int(frame["pid"]),
                    "identity": identity,
                    "binding": {
                        "admission_id": self.run_id,
                        "role": self.role,
                        "pid": int(frame["pid"]),
                        "birth_id": identity.get("birth_id"),
                        "uid": identity.get("uid"),
                        "state": "pre-exec-ack-pending",
                        "registration_before_exec": True,
                        "authenticated_signal_authority": False,
                    },
                })
            _send_frame(connection, self.ack)
            deadline = time.monotonic() + self.timeout
            post: dict[str, object] | None = None
            while time.monotonic() < deadline:
                candidate = _peer_token(connection)
                if candidate["pidversion"] != pre["pidversion"]:
                    post = candidate
                    break
                time.sleep(0.005)
            if post is None or post["pid"] != frame["pid"] or post["uid"] != os.getuid():
                raise CustodyError("post-exec audit token did not bind the registered process")
            after = self.identity_provider(int(frame["pid"]))
            if after is None or any(after.get(k) != before.get(k) for k in ("pid", "birth_id", "uid")):
                raise CustodyError("pre/post-exec process incarnation differs")
            self.registration.update({
                "identity": dict(after), "audit_token_words": post["words"],
                "audit_token_sha256": post["sha256"],
                "audit_token_pidversion": post["pidversion"],
            })
            self.role_authority.bind_target(actor=self.cleanup_actor, generation=self.custody_generation,
                                            identity=after, token=post)
            self._post_exec_authority_validated = True
            if self.authority_journal is not None:
                identity = dict(self.registration["identity"])  # type: ignore[arg-type]
                _append_owner_jsonl(self.authority_journal, {
                    "version": "astrid.plan-a.retained-audit-authority/v1",
                    "role": self.role,
                    "pid": int(frame["pid"]),
                    "identity": identity,
                    "audit_token_words": list(self.registration["audit_token_words"]),  # type: ignore[arg-type]
                    "binding": {
                        "admission_id": self.run_id,
                        "role": self.role,
                        "pid": int(frame["pid"]),
                        "birth_id": identity.get("birth_id"),
                        "uid": identity.get("uid"),
                        "state": "post-exec-authority-validated",
                        "registration_before_exec": True,
                        "pre_post_exec_incarnation_bound": True,
                        "signal_primitive": "proc_signal_with_audittoken",
                    },
                })
                _append_owner_jsonl(self.authority_journal, {
                    "version": RESOLVED_AUTHORITY_VERSION,
                    "admission_id": self.run_id,
                    "resolution": "validated-authority-exported",
                    "role": self.role,
                    "pid": int(frame["pid"]),
                    "identity": identity,
                })
            self.sequence = 2
            self._persist("registration_post_exec")
            self.state = "sealed"
            self._persist("admission_sealed")
        except BaseException as exc:
            self.error = exc
        finally:
            self._ready.set()
            if connection is not None:
                connection.close()
            self.listener.close()
            self.socket_path.unlink(missing_ok=True)
            try:
                self.socket_root.rmdir()
            except OSError:
                pass
            self._release_authority_scope()


def custody_wrapper_argv(executable: str) -> list[str]:
    return [executable, "-I", "-m", "banodoco_local.custody_broker", "--custody-exec"]


def child_exec_from_environment() -> int:
    encoded = os.environ.get("ASTRID_RUNTIME_CUSTODY_TARGET_B64", "")
    try:
        argv = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CustodyError("custody target argv is invalid") from exc
    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or "\0" in v for v in argv):
        raise CustodyError("custody target argv is invalid")
    # Session creation changes Darwin's audit-token pidversion.  Complete it
    # before the broker samples the pre-exec token.  The target may perform
    # further launcher execs, so this provisional token is rebound only after
    # Runtime readiness by the parent that retains the direct-child handle.
    if os.environ.get("ASTRID_RUNTIME_CUSTODY_START_SESSION") == "1":
        os.setsid()
    try:
        timeout = float(os.environ.get("ASTRID_RUNTIME_CUSTODY_TIMEOUT_SECONDS", "5"))
    except ValueError as exc:
        raise CustodyError("custody registration timeout is invalid") from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
        raise CustodyError("custody registration timeout is invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # The broker durably checkpoints the pre-exec registration before its ACK.
    # Use the broker's own bounded timeout so a slow fsync cannot make the child
    # abandon a registration the broker is still entitled to complete.
    connection.settimeout(timeout)
    connection.connect(os.environ.get("ASTRID_RUNTIME_CUSTODY_SOCKET", ""))
    os.set_inheritable(connection.fileno(), True)
    frame = {
        "version": PROTOCOL_VERSION, "command": "register_pre_exec",
        "run_id": os.environ.get("ASTRID_RUNTIME_CUSTODY_RUN_ID", ""),
        "role": os.environ.get("ASTRID_RUNTIME_CUSTODY_ROLE", ""),
        "pid": os.getpid(), "ppid": os.getppid(),
        "argv_digest": _digest_bytes(_canonical(argv)),
    }
    _send_frame(connection, frame)
    ack = _read_frame(connection)
    if (
        ack.get("status") != "registered" or ack.get("run_id") != frame["run_id"]
        or ack.get("role") != frame["role"] or ack.get("pid") != os.getpid()
        or ack.get("registration_digest") != _digest_bytes(_canonical(frame))
    ):
        raise CustodyError("custody registration acknowledgement is invalid")
    for name in tuple(os.environ):
        if name.startswith("ASTRID_RUNTIME_CUSTODY_"):
            os.environ.pop(name, None)
    descriptor = connection.detach()
    os.set_inheritable(descriptor, True)
    os.execve(argv[0], argv, dict(os.environ))
    raise AssertionError("execve returned")


def publish_active_capability(sidecar_path: Path, broker: RoleBoundCustodyBroker) -> dict[str, object]:
    broker.wait_until_sealed()
    raw, _ = _read_owner_file(broker.ledger_path)
    ledger = json.loads(raw)
    registration = ledger.get("registration") if isinstance(ledger, dict) else None
    identity = registration.get("identity") if isinstance(registration, dict) else None
    if ledger.get("state") != "ready-bound" or not isinstance(identity, dict):
        raise CustodyError("custody admission is not bound to the ready owner")
    reference = {
        "version": CAPABILITY_VERSION, "role": broker.role,
        "ledger_path": str(broker.ledger_path.resolve()),
        "ledger_sha256": _digest_bytes(raw),
        "journal_path": str(broker.journal_path.resolve()),
        "journal_sha256": _digest_bytes(_read_owner_file(broker.journal_path)[0]),
        "pid": identity.get("pid"), "birth_id": identity.get("birth_id"),
        "uid": identity.get("uid"),
        "audit_token_sha256": registration.get("audit_token_sha256"),
        "audit_token_pidversion": registration.get("audit_token_pidversion"),
        "role_custody": broker.role_authority.reference(),
    }
    _atomic_owner_json(sidecar_path, reference)
    return reference


def default_process_identity(pid: int, *, timeout: float = 1.0) -> dict[str, object] | None:
    """Return identity, None only for proven absence, and raise on observation failure."""

    if timeout <= 0:
        raise CustodyError("process identity observation deadline expired")
    try:
        result = subprocess.run(
            ["/bin/ps", "-ww", "-o", "uid=", "-o", "ppid=", "-o", "lstart=", "-p", str(pid)],
            text=True, capture_output=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CustodyError("process identity observation failed") from exc
    rendered = result.stdout.strip()
    if result.returncode == 1 and not rendered and not result.stderr.strip():
        return None
    if result.returncode != 0:
        raise CustodyError(
            f"process identity observation failed with status {result.returncode}"
        )
    if not rendered:
        raise CustodyError("process identity observation returned no identity")
    parts = rendered.split(None, 2)
    if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
        raise CustodyError("process identity observation was malformed")
    return {"pid": pid, "uid": int(parts[0]), "parent_pid": int(parts[1]), "birth_id": "ps-lstart:" + parts[2]}


def load_sealed_capability(
    sidecar_path: Path,
    *,
    expected_identity: Mapping[str, object],
    identity_provider: Callable[[int], Mapping[str, object] | None] = default_process_identity,
    token_details_provider: Callable[[Sequence[int]], Mapping[str, object]] = audit_token_details,
) -> dict[str, object]:
    if not sidecar_path.is_absolute():
        raise CustodyError("Runtime custody capability path must be absolute")
    sidecar_raw, _ = _read_owner_file(sidecar_path)
    support_root = sidecar_path.parent.resolve(strict=True)
    reference = json.loads(sidecar_raw)
    required_reference = {
        "version", "role", "ledger_path", "ledger_sha256", "journal_path", "journal_sha256",
        "pid", "birth_id", "uid",
        "audit_token_sha256", "audit_token_pidversion",
        "role_custody",
    }
    if (
        not isinstance(reference, dict) or set(reference) != required_reference
        or reference["version"] != CAPABILITY_VERSION
        or reference["role"] != "runtime_owner"
    ):
        raise CustodyError("Runtime custody capability reference is invalid")
    ledger_path = Path(str(reference["ledger_path"]))
    if not ledger_path.is_absolute() or ledger_path.is_symlink():
        raise CustodyError("Runtime custody ledger path is invalid")
    try:
        ledger_path.resolve(strict=True).relative_to((support_root / "runtime-custody").resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise CustodyError("Runtime custody ledger escaped its support root") from exc
    ledger_raw, _ = _read_owner_file(ledger_path)
    if _digest_bytes(ledger_raw) != reference["ledger_sha256"]:
        raise CustodyError("Runtime custody ledger content changed")
    journal_path = Path(str(reference["journal_path"]))
    if not journal_path.is_absolute() or journal_path.is_symlink():
        raise CustodyError("Runtime custody journal path is invalid")
    if journal_path.parent.resolve(strict=True) != ledger_path.parent.resolve(strict=True):
        raise CustodyError("Runtime custody journal does not match its ledger")
    journal_raw, _ = _read_owner_file(journal_path)
    if _digest_bytes(journal_raw) != reference["journal_sha256"]:
        raise CustodyError("Runtime custody journal content changed")
    ledger = json.loads(ledger_raw)
    required_ledger = {
        "version", "run_id", "role", "state", "sequence", "registration", "ack", "chain_digest",
    }
    registration = ledger.get("registration") if isinstance(ledger, dict) else None
    identity = registration.get("identity") if isinstance(registration, dict) else None
    if (
        not isinstance(ledger, dict) or set(ledger) != required_ledger
        or ledger["version"] != PROTOCOL_VERSION or ledger["role"] != reference["role"]
        or ledger["state"] != "ready-bound" or ledger["sequence"] != 3
        or not isinstance(registration, dict) or not isinstance(identity, dict)
        or not isinstance(ledger.get("chain_digest"), str)
    ):
        raise CustodyError("Runtime custody ledger is not an exact sealed admission")
    predecessor: str | None = None
    events: list[dict[str, object]] = []
    for encoded in journal_raw.splitlines():
        event = json.loads(encoded)
        claimed = event.get("event_digest") if isinstance(event, dict) else None
        unsigned = {key: value for key, value in event.items() if key != "event_digest"} if isinstance(event, dict) else {}
        if (
            not isinstance(event, dict)
            or set(event) != {
                "version", "event", "sequence", "predecessor_digest",
                "snapshot_digest", "snapshot", "event_digest",
            }
            or event["version"] != PROTOCOL_VERSION
            or event["predecessor_digest"] != predecessor
            or event["snapshot_digest"] != _digest_bytes(_canonical(event["snapshot"]))
            or claimed != _digest_bytes(_canonical(unsigned))
        ):
            raise CustodyError("Runtime custody journal chain is invalid")
        predecessor = str(claimed)
        events.append(event)
    terminal_snapshot = {key: ledger[key] for key in required_ledger if key != "chain_digest"}
    if (
        not events or events[-1]["event"] != "readiness_token_bound"
        or predecessor != ledger["chain_digest"]
        or events[-1]["snapshot"] != terminal_snapshot
    ):
        raise CustodyError("Runtime custody journal does not bind the sealed ledger")
    expected = {k: expected_identity.get(k) for k in ("pid", "birth_id", "uid")}
    pinned = {k: identity.get(k) for k in ("pid", "birth_id", "uid")}
    referenced = {k: reference.get(k) for k in ("pid", "birth_id", "uid")}
    if pinned != expected or referenced != expected:
        raise CustodyError("Runtime custody identity does not match the selected owner")
    pid = int(expected["pid"] or 0)
    observed = identity_provider(pid)
    if observed is None or {k: observed.get(k) for k in expected} != expected:
        raise CustodyError("Runtime custody process incarnation is absent or replaced")
    words = registration.get("audit_token_words")
    if not isinstance(words, list):
        raise CustodyError("Runtime custody audit token is missing")
    token = dict(token_details_provider(words))
    if (
        token.get("pid") != pid or token.get("uid") != expected["uid"]
        or token.get("sha256") != registration.get("audit_token_sha256")
        or token.get("pidversion") != registration.get("audit_token_pidversion")
        or reference["audit_token_sha256"] != registration.get("audit_token_sha256")
        or reference["audit_token_pidversion"] != registration.get("audit_token_pidversion")
    ):
        raise CustodyError("Runtime custody audit token binding changed")
    return {
        "reference": reference, "registration": registration,
        "sidecar_sha256": _digest_bytes(sidecar_raw), "ledger_sha256": _digest_bytes(ledger_raw),
        "journal_sha256": _digest_bytes(journal_raw),
    }


def signal_sealed_capability(
    sidecar_path: Path,
    *,
    expected_identity: Mapping[str, object],
    signum: int,
    identity_provider: Callable[[int], Mapping[str, object] | None] = default_process_identity,
    token_details_provider: Callable[[Sequence[int]], Mapping[str, object]] = audit_token_details,
    signal_provider: Callable[[Sequence[int], int], None] = signal_audit_token,
) -> dict[str, object]:
    if int(signum) not in _admitted_signals():
        raise CustodyError("custody signal is outside the admitted set")
    loaded = load_sealed_capability(
        sidecar_path, expected_identity=expected_identity,
        identity_provider=identity_provider, token_details_provider=token_details_provider,
    )
    # Possession of the sealed token is escrow, not permission to signal. A
    # controller must still be the current authenticated designated actor.
    role_reference = loaded["reference"].get("role_custody")
    if not isinstance(role_reference, dict) or set(role_reference) != {"version", "scope_root", "role", "generation", "target"} or role_reference["version"] != ROLE_REFERENCE_VERSION or role_reference["role"] != "runtime_owner":
        raise CustodyError("Runtime owner lacks fenced role custody")
    authority = RoleCustodyAuthority(Path(str(role_reference["scope_root"])), "runtime_owner")
    authority.signal(actor=AuthenticatedCleanupActor.current(), generation=role_reference["generation"],
                     expected_target=role_reference["target"], signum=signum,
                     identity_provider=identity_provider, signal_provider=signal_provider)
    sidecar_raw, _ = _read_owner_file(sidecar_path)
    ledger_raw, _ = _read_owner_file(Path(str(loaded["reference"]["ledger_path"])))  # type: ignore[index]
    journal_raw, _ = _read_owner_file(Path(str(loaded["reference"]["journal_path"])))  # type: ignore[index]
    if (
        _digest_bytes(sidecar_raw) != loaded["sidecar_sha256"]
        or _digest_bytes(ledger_raw) != loaded["ledger_sha256"]
        or _digest_bytes(journal_raw) != loaded["journal_sha256"]
    ):
        raise CustodyError("Runtime custody capability changed during signal")
    return {
        "ok": True, "kind": "proc_signal_with_audittoken", "signal": int(signum),
        "role": loaded["reference"]["role"], "pid": expected_identity["pid"],
        "birth_id": expected_identity["birth_id"],
        "audit_token_sha256": loaded["registration"]["audit_token_sha256"],
        "sidecar_sha256": loaded["sidecar_sha256"], "ledger_sha256": loaded["ledger_sha256"],
    }


def main() -> int:
    if sys.argv[1:] == ["--custody-exec"]:
        return child_exec_from_environment()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("signal")
    command.add_argument("--sidecar", type=Path, required=True)
    command.add_argument("--pid", type=int, required=True)
    command.add_argument("--birth-id", required=True)
    command.add_argument("--uid", type=int, required=True)
    command.add_argument("--signal", type=int, choices=(int(signal.SIGTERM), int(signal.SIGKILL)), required=True)
    args = parser.parse_args()
    result = signal_sealed_capability(
        args.sidecar,
        expected_identity={"pid": args.pid, "birth_id": args.birth_id, "uid": args.uid},
        signum=args.signal,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
