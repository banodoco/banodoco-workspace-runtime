"""Darwin audit-token custody for the long-lived local Runtime owner.

The launcher owns the broker only until admission is sealed.  The durable
owner-only sidecar and hash-chained ledger retain the exact post-exec audit
token so a later installed qualification controller can signal that process
incarnation without using a numeric PID signal.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
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
CAPABILITY_VERSION = "runtime.role-bound-custody/v1"
ACTIVE_CAPABILITY_NAME = "runtime-custody-active.json"
SOL_LOCAL = 0
LOCAL_PEERTOKEN = 0x006
TOKEN_BYTES = 32
FRAME_LIMIT = 16 * 1024


class CustodyError(RuntimeError):
    """The exact registered Runtime incarnation cannot be proved or signalled."""


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


class RoleBoundCustodyBroker:
    """One-role broker whose sealed durable ledger is later signal authority."""

    def __init__(
        self,
        *,
        role: str,
        identity_provider: Callable[[int], Mapping[str, object] | None],
        ledger_root: Path,
        timeout: float = 5.0,
    ) -> None:
        if not role or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in role):
            raise CustodyError("custody role is invalid")
        if sys.platform != "darwin":
            raise CustodyError("Darwin audit-token custody is unavailable")
        self.role = role
        self.identity_provider = identity_provider
        self.timeout = timeout
        self.run_id = _digest_bytes(os.urandom(32))
        ledger_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(ledger_root, 0o700)
        self.root = ledger_root
        self.journal_path = ledger_root / "custody.journal.jsonl"
        self.ledger_path = ledger_root / "custody.ledger.json"
        self.socket_root = Path(tempfile.mkdtemp(prefix="runtime-cb-"))
        os.chmod(self.socket_root, 0o700)
        self.socket_path = self.socket_root / "s"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(1)
        self.listener.settimeout(timeout)
        self.sequence = 0
        self.chain_head: str | None = None
        self.state = "accepting"
        self.registration: dict[str, object] | None = None
        self.ack: dict[str, object] | None = None
        self.error: BaseException | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

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
        if self._thread.is_alive() or self.state != "sealed" or self.registration is None:
            raise CustodyError("custody admission did not seal")

    def signal(self, signum: int, *, expected_pid: int) -> None:
        """Signal only the sealed role and exact process incarnation."""

        if int(signum) not in _admitted_signals():
            raise CustodyError("custody signal is outside the admitted set")
        if self.state != "sealed" or self.registration is None:
            raise CustodyError("custody admission is not sealed")
        identity = self.registration.get("identity")
        if not isinstance(identity, dict) or identity.get("pid") != expected_pid:
            raise CustodyError("registered custody PID differs from the process handle")
        observed = self.identity_provider(expected_pid)
        if observed is None or any(
            observed.get(name) != identity.get(name)
            for name in ("pid", "birth_id", "uid")
        ):
            raise CustodyError("registered process incarnation is absent or changed")
        signal_audit_token(self.registration["audit_token_words"], signum)  # type: ignore[arg-type]

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
                or frame["ppid"] != os.getpid()
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
            self.sequence = 1
            self.registration = {
                "pid": frame["pid"], "identity": dict(before),
                "argv_digest": frame["argv_digest"],
                "pre_exec_audit_token_sha256": pre["sha256"],
                "pre_exec_pidversion": pre["pidversion"],
                "audit_token_words": pre["words"],
            }
            self._persist("registration_pre_exec")
            self.ack = {
                "version": PROTOCOL_VERSION, "status": "registered",
                "run_id": self.run_id, "role": self.role, "pid": frame["pid"],
                "registration_digest": _digest_bytes(_canonical(frame)),
                "ledger_state_digest": self.chain_head,
            }
            self._persist("registration_ack_checkpoint")
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
    # before the broker samples the pre-exec token so the only pidversion
    # transition after acknowledgement is the target exec itself.
    if os.environ.get("ASTRID_RUNTIME_CUSTODY_START_SESSION") == "1":
        os.setsid()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5.0)
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
    if ledger.get("state") != "sealed" or not isinstance(identity, dict):
        raise CustodyError("custody admission is not sealed")
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
    }
    _atomic_owner_json(sidecar_path, reference)
    return reference


def default_process_identity(pid: int) -> dict[str, object] | None:
    result = subprocess.run(
        ["/bin/ps", "-ww", "-o", "uid=", "-o", "lstart=", "-p", str(pid)],
        text=True, capture_output=True, check=False,
    )
    rendered = result.stdout.strip()
    if result.returncode or not rendered:
        return None
    parts = rendered.split(None, 1)
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return {"pid": pid, "uid": int(parts[0]), "birth_id": "ps-lstart:" + parts[1]}


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
        or ledger["state"] != "sealed" or ledger["sequence"] != 2
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
        not events or events[-1]["event"] != "admission_sealed"
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
    signal_provider(loaded["registration"]["audit_token_words"], signum)  # type: ignore[index]
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
