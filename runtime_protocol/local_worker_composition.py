"""Installed local Worker composition owned by Runtime.

This module is deliberately small: Runtime owns the profile, private control
channel, and OS observation; the Python 3.10 Worker remains a separate
installed process.  No Worker implementation is imported into Runtime.
"""

from __future__ import annotations

import hashlib
import ctypes
import json
import os
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import platform
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import shutil
import struct
from typing import Any, Mapping
from urllib.parse import urlsplit

from .catalog import process_birth_identity
from .errors import ConflictError, ValidationError
from .local_worker import (
    ACTIVATION_VERSION,
    LocalWorkerObservation,
    LocalWorkerPreparer,
    LocalWorkerProfile,
    ProcessIdentity,
    PREPARATION_VERSION,
    _engine_endpoint,
)


CONTROL_VERSION = "reigh.local-worker-control/v2"
CONTROL_FRAME_LIMIT = 64 * 1024
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DEFAULT_WORKER_CLEANUP_TIMEOUT_SECONDS = 45.0
DEFAULT_WORKER_SHUTDOWN_TIMEOUT_SECONDS = 50.0
PROFILE_FIELDS = (
    "profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
    "worker_executable", "host_executable", "engine_executable",
    "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
    "engine_artifact_digest", "engine_listener_artifact_digest", "session_config_digest",
    "profile_revision", "profile_digest", "release_digest",
)


def _darwin_process_argv(pid: int) -> tuple[bytes, ...] | None:
    libc = ctypes.CDLL(None, use_errno=True)
    sysctl = libc.sysctl
    sysctl.argtypes = (
        ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
    )
    sysctl.restype = ctypes.c_int
    mib = (ctypes.c_int * 3)(1, 49, int(pid))
    size = ctypes.c_size_t(0)
    if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value < 4:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        return None
    raw = buffer.raw[: size.value]
    argc = struct.unpack_from("=i", raw)[0]
    if argc < 1 or argc > 1_000_000:
        return None
    offset = 4
    executable_end = raw.find(b"\0", offset)
    if executable_end < 0:
        return None
    offset = executable_end + 1
    while offset < len(raw) and raw[offset] == 0:
        offset += 1
    argv: list[bytes] = []
    while len(argv) < argc and offset < len(raw):
        end = raw.find(b"\0", offset)
        if end < 0:
            return None
        argv.append(raw[offset:end])
        offset = end + 1
    return tuple(argv) if len(argv) == argc else None


def _process_argv(pid: int) -> tuple[bytes, ...] | None:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return _darwin_process_argv(pid) if sys.platform == "darwin" else None
    return tuple(value for value in raw.split(b"\0") if value) or None


def _argv_digest(argv: tuple[bytes, ...] | list[bytes]) -> str:
    encoded = bytearray(b"astrid.argv.v1\0")
    encoded.extend(len(argv).to_bytes(8, "big"))
    for value in argv:
        encoded.extend(len(value).to_bytes(8, "big"))
        encoded.extend(value)
    return "sha256:" + hashlib.sha256(bytes(encoded)).hexdigest()


def _frame_send(channel: socket.socket, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > CONTROL_FRAME_LIMIT:
        raise ConflictError("local Worker control frame is too large")
    channel.sendall(encoded + b"\n")


def _frame_receive(channel: socket.socket) -> dict[str, Any]:
    frame = bytearray()
    while b"\n" not in frame:
        chunk = channel.recv(min(4096, CONTROL_FRAME_LIMIT + 1 - len(frame)))
        if not chunk:
            raise ConflictError("local Worker control channel closed")
        frame.extend(chunk)
        if len(frame) > CONTROL_FRAME_LIMIT:
            raise ConflictError("local Worker control frame is too large")
    encoded, remainder = bytes(frame).split(b"\n", 1)
    if remainder:
        raise ConflictError("local Worker control channel carried multiple frames")
    try:
        value = json.loads(encoded.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConflictError("local Worker control frame is malformed") from exc
    if not isinstance(value, dict):
        raise ConflictError("local Worker control frame must be an object")
    return value


@dataclass
class _PreparedWorker:
    worker: Any
    birth_id: str
    control: socket.socket
    report_value: dict[str, Any]
    owner_session_config_path: Path
    activated: bool = False
    closed: bool = False
    rpc_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_started: bool = False
    adopted: bool = False
    receipt: dict[str, Any] | None = None


@dataclass(frozen=True)
class _AdoptedWorkerProcess:
    """Non-child process identity; deliberately has no waitpid interface."""

    pid: int
    birth_id: str

    def poll(self) -> int | None:
        observed = process_birth_identity(self.pid)
        return None if observed == self.birth_id else 0


def _ack_digest(value: Mapping[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "ack_sha256"}
    return "sha256:" + hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class CrossProcessWorkerPreparer(LocalWorkerPreparer):
    """Runtime-side transport for the installed Worker private ABI."""

    def __init__(self, *, profile: LocalWorkerProfile, config: Mapping[str, Any], environment: Mapping[str, str], timeout_seconds: float = 900.0, cleanup_timeout_seconds: float = 0.1, shutdown_timeout_seconds: float | None = None):
        self.profile = profile
        self.config = dict(config)
        self.environment = dict(environment)
        self.timeout_seconds = float(timeout_seconds)
        self.cleanup_timeout_seconds = max(0.05, float(cleanup_timeout_seconds))
        self.shutdown_timeout_seconds = max(
            self.cleanup_timeout_seconds,
            float(shutdown_timeout_seconds)
            if shutdown_timeout_seconds is not None
            else self.cleanup_timeout_seconds,
        )
        self._active: _PreparedWorker | None = None
        self._prepare_cancel = threading.Event()
        # The only uninterruptible handoff is spawn -> handle construction ->
        # publication. Cancellation waits for this tiny critical section so a
        # just-spawned child can never exist without an owner-visible handle.
        self._handoff_lock = threading.Lock()
        self.cleanup_uncertain: str | None = None

    def set_prepare_cancel_event(self, event: threading.Event) -> None:
        self._prepare_cancel = event

    def cancel_current(self) -> None:
        """Interrupt a prepare RPC without waiting for its normal timeout."""
        if not self._handoff_lock.acquire(timeout=self.cleanup_timeout_seconds):
            return
        try:
            handle = self._active
        finally:
            self._handoff_lock.release()
        if handle is None or handle.closed:
            return
        try:
            self.abort(handle)
        except BaseException:
            # The owner has already fenced authority. The prepare caller will
            # observe the closed channel and run its own bounded abort path.
            pass

    def bind_runtime(self, *, endpoint: str, runtime_instance_id: str, credential_file: Path) -> None:
        self.config.update({
            "runtime_endpoint": str(endpoint).rstrip("/"),
            "runtime_instance_id": str(runtime_instance_id),
            "credential_file": str(credential_file),
        })

    @staticmethod
    def _birth(pid: int) -> str:
        value = process_birth_identity(pid)
        if not value:
            raise ConflictError("prepared Worker birth identity is unavailable")
        return value

    @staticmethod
    def _profile_payload(profile: LocalWorkerProfile) -> dict[str, Any]:
        return {
            name: str(getattr(profile, name)) if isinstance(getattr(profile, name), Path) else getattr(profile, name)
            for name in PROFILE_FIELDS
        }

    def _rpc_unlocked(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        if handle.closed or handle.worker.poll() is not None:
            raise ConflictError("prepared Worker is not alive")
        if self._birth(handle.worker.pid) != handle.birth_id:
            raise ConflictError("prepared Worker identity changed")
        _frame_send(handle.control, payload)
        response = _frame_receive(handle.control)
        if response.get("version") != CONTROL_VERSION:
            raise ConflictError("prepared Worker control version is invalid")
        if response.get("status") != "ok":
            error_code = response.get("error_code")
            error_stage = response.get("error_stage")
            if (
                not isinstance(error_code, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code) is None
            ):
                error_code = "worker_rejected"
            if (
                not isinstance(error_stage, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_stage) is None
            ):
                error_stage = "worker_control"
            raise ConflictError(
                "prepared Worker rejected the operation",
                details={
                    "handoff_error_code": error_code,
                    "handoff_stage": error_stage,
                },
            )
        return response

    def _rpc(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        with handle.rpc_lock:
            return self._rpc_unlocked(handle, payload)

    def _handoff_rpc(
        self,
        handle: _PreparedWorker,
        payload: Mapping[str, Any],
        *,
        statuses: frozenset[str],
        phases: frozenset[str],
    ) -> dict[str, Any]:
        with handle.rpc_lock:
            if handle.closed or handle.worker.poll() is not None:
                raise ConflictError("handoff Worker is not alive")
            if self._birth(handle.worker.pid) != handle.birth_id:
                raise ConflictError("handoff Worker identity changed")
            _frame_send(handle.control, payload)
            response = _frame_receive(handle.control)
        command = str(payload.get("command") or "")
        expected_keys = {
            "version",
            "command",
            "handoff_id",
            "status",
            "nonce_digest",
            "sealed_record_digest",
            "host_ack",
            "worker_phase",
            "ack_sha256",
        }
        if set(response) != expected_keys:
            # Worker error frames and malformed acknowledgements never carry
            # enough authority to change custody.  Keep the error secret-free.
            raise ConflictError("handoff Worker rejected the private operation")
        if (
            response.get("version") != CONTROL_VERSION
            or response.get("command") != f"{command}_ack"
            or response.get("handoff_id") != payload.get("handoff_id")
            or response.get("nonce_digest") != payload.get("nonce_digest")
            or response.get("sealed_record_digest")
            != payload.get("sealed_record_digest")
            or response.get("status") not in statuses
            or response.get("worker_phase") not in phases
            or not isinstance(response.get("host_ack"), Mapping)
            or response.get("ack_sha256") != _ack_digest(response)
        ):
            raise ConflictError("handoff Worker acknowledgement is invalid")
        return response

    def handoff_command(
        self, handle: _PreparedWorker, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Execute one strict v2 handoff command over the live private channel."""

        command = str(payload.get("command") or "")
        expected = {
            "handoff_prepare": (frozenset({"prepared", "active_work"}), frozenset({"paused", "owned"})),
            "handoff_seal": (frozenset({"sealed"}), frozenset({"export_sealed"})),
            "handoff_adopt": (frozenset({"prepared"}), frozenset({"adopt_prepared"})),
            "handoff_commit": (frozenset({"committed"}), frozenset({"rebind_committed"})),
            "resume_prepare": (frozenset({"prepared"}), frozenset({"resume_armed"})),
            "resume_commit": (frozenset({"committed"}), frozenset({"resumed"})),
            "handoff_finalize": (frozenset({"finalized"}), frozenset({"finalized"})),
            "handoff_abort": (frozenset({"cancelled", "aborted"}), frozenset({"owned", "aborted"})),
        }.get(command)
        if payload.get("version") != CONTROL_VERSION or expected is None:
            raise ConflictError("handoff Worker request is invalid")
        return self._handoff_rpc(
            handle, payload, statuses=expected[0], phases=expected[1]
        )

    def export_control_descriptor(self, handle: _PreparedWorker) -> int:
        """Duplicate the live control authority without releasing A's copy."""

        with handle.rpc_lock:
            if handle.closed or handle.worker.poll() is not None:
                raise ConflictError("handoff Worker is not alive")
            if self._birth(handle.worker.pid) != handle.birth_id:
                raise ConflictError("handoff Worker identity changed")
            descriptor = os.dup(handle.control.fileno())
            try:
                os.set_inheritable(descriptor, False)
                if os.get_inheritable(descriptor):
                    raise ConflictError("exported Worker control descriptor is inheritable")
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise

    def release_exported(self, handle: _PreparedWorker) -> None:
        """Close owner A's copy after the coordinator acknowledges custody."""

        with handle.rpc_lock:
            if handle.closed:
                return
            handle.control.close()
            handle.closed = True
            if self._active is handle:
                self._active = None

    @staticmethod
    def _report_from_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
        processes: dict[str, dict[str, Any]] = {}
        for name in ("worker", "host", "engine", "engine_listener"):
            value = receipt.get(name)
            if not isinstance(value, Mapping):
                raise ConflictError("handoff receipt process identity is missing")
            try:
                processes[name] = {
                    "pid": int(value["pid"]),
                    "birth_id": str(value["birth_id"]),
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise ConflictError("handoff receipt process identity is invalid") from exc
        binding = receipt.get("engine_binding")
        if not isinstance(binding, Mapping):
            raise ConflictError("handoff receipt engine binding is missing")
        return {
            "processes": processes,
            "engine_binding": {
                key: binding[key]
                for key in (
                    "supervisor_pid",
                    "listener_pid",
                    "listener_parent_pid",
                    "socket_owner_pid",
                )
            },
            "session_config_digest": receipt.get("session_config_digest"),
        }

    def adopt_control_descriptor(
        self, descriptor: int, receipt: Mapping[str, Any]
    ) -> _PreparedWorker:
        """Construct B custody from a transferred descriptor and receipt.

        The resulting process is deliberately represented as a non-child;
        cleanup must never call waitpid on it.
        """

        if self._active is not None:
            raise ConflictError("a local Worker control authority is already active")
        try:
            os.set_inheritable(descriptor, False)
            if os.get_inheritable(descriptor):
                raise ConflictError("adopted Worker control descriptor is inheritable")
            control = socket.socket(fileno=descriptor)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        try:
            worker_value = receipt.get("worker")
            if not isinstance(worker_value, Mapping):
                raise ConflictError("handoff receipt Worker identity is missing")
            pid = int(worker_value["pid"])
            birth_id = str(worker_value["birth_id"])
            if self._birth(pid) != birth_id:
                raise ConflictError("handoff Worker identity changed before adoption")
            control.settimeout(self.timeout_seconds)
            handle = _PreparedWorker(
                _AdoptedWorkerProcess(pid, birth_id),
                birth_id,
                control,
                self._report_from_receipt(receipt),
                _session_config_path(self.environment),
                activated=True,
                adopted=True,
                receipt=dict(receipt),
            )
            self._active = handle
            return handle
        except BaseException:
            control.close()
            raise

    def abort_adopted_descriptor(
        self, descriptor: int, receipt: Mapping[str, Any]
    ) -> None:
        """Clean a committed graph when adoption failed before handle return."""

        try:
            os.close(descriptor)
        except OSError:
            pass
        provisional = type(
            "_ProvisionalAdoptedCustody",
            (),
            {
                "receipt": dict(receipt),
                "owner_session_config_path": _session_config_path(self.environment),
            },
        )()
        try:
            self._force_cleanup_adopted_graph(provisional)
        except BaseException as exc:
            self.cleanup_uncertain = str(exc)
            raise

    def prepare(self, profile: LocalWorkerProfile, *, operation_id: str, channel_id: str) -> _PreparedWorker:
        if self._active is not None:
            self.abort(self._active)
        if self._prepare_cancel.is_set():
            raise ConflictError("local Worker preparation cancelled")
        parent, child = socket.socketpair()
        worker: subprocess.Popen[bytes] | None = None
        handle: _PreparedWorker | None = None
        try:
            with self._handoff_lock:
                if self._prepare_cancel.is_set():
                    raise ConflictError("local Worker preparation cancelled")
                executable = Path(profile.worker_executable)
                environment = dict(self.environment)
                environment.pop("PYTHONPATH", None)
                worker_environment = environment.pop("ASTRID_WORKER_ENVIRONMENT", "")
                if worker_environment:
                    env_root = Path(worker_environment).expanduser().resolve()
                    # A venv's ``bin/python`` carries the environment's package
                    # boundary through its adjacent pyvenv.cfg.  Its kernel
                    # executable may resolve to the base interpreter, which is
                    # checked independently by OSProcessInspector below.
                    candidate = env_root / "bin" / "python"
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        executable = candidate
                    environment["VIRTUAL_ENV"] = str(env_root)
                    environment["PATH"] = str(env_root / "bin") + os.pathsep + environment.get("PATH", "")
                worker = subprocess.Popen(
                    [str(executable), "-m", "source.runtime.supervisor", "--prepared-control-fd", str(child.fileno())],
                    cwd=str(Path(self.config["support_root"])),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(child.fileno(),),
                )
                child.close()
                parent.settimeout(self.timeout_seconds)
                handle = _PreparedWorker(
                    worker,
                    self._birth(worker.pid),
                    parent,
                    {},
                    _session_config_path(environment),
                )
                # Publish Runtime custody before the first potentially blocking
                # control RPC. cancel_current() cannot pass the handoff lock
                # until this handle is visible, so no spawned child can be
                # missed by owner shutdown.
                self._active = handle
            if self._prepare_cancel.is_set():
                self.abort(handle)
                raise ConflictError("local Worker preparation cancelled")
            response = self._rpc(handle, {
                "version": CONTROL_VERSION,
                "command": "prepare",
                "operation_id": operation_id,
                "channel_id": channel_id,
                "profile": self._profile_payload(profile),
                "config": dict(self.config),
            })
            report = response.get("report")
            if not isinstance(report, dict):
                raise ConflictError("prepared Worker returned no process report")
            handle.report_value = report
            return handle
        except BaseException:
            child.close()
            if handle is not None:
                try:
                    self.abort(handle)
                except BaseException:
                    pass
            else:
                parent.close()
            if handle is None and worker is not None and worker.poll() is None:
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    worker.wait(timeout=self.cleanup_timeout_seconds)
                except (subprocess.TimeoutExpired, TimeoutError):
                    pass
            raise

    def report(self, handle: _PreparedWorker) -> Mapping[str, Any]:
        response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "report"})
        report = response.get("report")
        if not isinstance(report, dict):
            raise ConflictError("prepared Worker returned no process report")
        handle.report_value = report
        return report

    def activate(self, handle: _PreparedWorker, grant: Mapping[str, Any]) -> None:
        response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "activate", "grant": dict(grant)})
        if response.get("status") != "ok":
            raise ConflictError("prepared Worker rejected activation")
        handle.activated = True

    def abort(self, handle: _PreparedWorker) -> None:
        if not isinstance(handle, _PreparedWorker) or handle.closed:
            return
        with handle.cleanup_lock:
            if handle.cleanup_started:
                return
            handle.cleanup_started = True
        failure: BaseException | None = None
        try:
            if self._birth(handle.worker.pid) != handle.birth_id:
                raise ConflictError("prepared Worker identity changed before cleanup")
            acquired = handle.rpc_lock.acquire(timeout=self.cleanup_timeout_seconds)
            if acquired:
                try:
                    previous_timeout = handle.control.gettimeout()
                    handle.control.settimeout(self.cleanup_timeout_seconds)
                    try:
                        self._rpc_unlocked(handle, {"version": CONTROL_VERSION, "command": "abort"})
                    finally:
                        handle.control.settimeout(previous_timeout)
                finally:
                    handle.rpc_lock.release()
            if handle.adopted:
                deadline = __import__("time").monotonic() + self.cleanup_timeout_seconds
                while handle.worker.poll() is None and __import__("time").monotonic() < deadline:
                    __import__("time").sleep(0.01)
                if handle.worker.poll() is None:
                    raise ConflictError("adopted Worker did not exit after bounded abort")
            else:
                handle.worker.wait(timeout=self.cleanup_timeout_seconds)
        except BaseException as exc:
            failure = exc
        finally:
            if handle.adopted:
                try:
                    handle.control.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                handle.control.close()
                if self._adopted_graph_has_survivors(handle):
                    try:
                        self._force_cleanup_adopted_graph(handle)
                        failure = None
                    except BaseException as exc:
                        self.cleanup_uncertain = str(exc)
                        failure = exc
                handle.closed = True
                if self._active is handle:
                    self._active = None
            elif failure is None:
                try:
                    handle.control.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                handle.control.close()
                handle.closed = True
                if self._active is handle:
                    self._active = None
            else:
                # The private Worker still owns the only live engine broker.
                # A missing/malformed ACK or control failure cannot justify
                # terminating that owner and discarding its cleanup authority.
                self.cleanup_uncertain = str(failure)
                with handle.cleanup_lock:
                    handle.cleanup_started = False
        if failure is not None:
            raise failure

    @staticmethod
    def _receipt_process(receipt: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        value = receipt.get(name)
        required = {
            "pid", "birth_id", "uid", "parent_pid", "process_group",
            "session_id", "executable", "artifact_digest", "command_line", "argv_digest",
        }
        if not isinstance(value, Mapping) or not required.issubset(value):
            raise ConflictError(f"adopted {name} cleanup identity is incomplete")
        return value

    def _verify_cleanup_member(
        self,
        receipt: Mapping[str, Any],
        name: str,
        *,
        expected_parent: int | None,
        allow_reparented: bool = False,
    ) -> bool:
        expected = self._receipt_process(receipt, name)
        pid = int(expected["pid"])
        observed_birth = process_birth_identity(pid)
        if observed_birth is None:
            return False
        if observed_birth != expected["birth_id"]:
            raise ConflictError(f"adopted {name} cleanup birth identity changed")
        try:
            uid = int(_ps(pid, "uid"))
            parent = int(_ps(pid, "ppid"))
            command = _ps(pid, "command")
            argv = _process_argv(pid)
            group = os.getpgid(pid)
            session = os.getsid(pid)
        except (OSError, ValueError) as exc:
            if process_birth_identity(pid) is None:
                return False
            try:
                if _ps(pid, "state").startswith("Z"):
                    return False
            except ConflictError:
                return False
            raise ConflictError(f"adopted {name} cleanup identity is unobservable") from exc
        if uid != int(expected["uid"]):
            raise ConflictError(f"adopted {name} cleanup UID changed")
        if allow_reparented:
            # An adopted member may still have its receipt parent, or PID 1
            # after that parent exits.  B itself can never become its parent.
            if parent not in {int(expected["parent_pid"]), 1} or parent == os.getpid():
                raise ConflictError(f"adopted {name} parent identity is invalid")
        elif expected_parent is not None and parent != int(expected_parent):
            raise ConflictError(f"adopted {name} cleanup parent identity changed")
        if group != int(expected["process_group"]) or session != int(expected["session_id"]):
            raise ConflictError(f"adopted {name} cleanup process group/session changed")
        executable = Path(str(expected["executable"]))
        if _actual_executable(pid) != executable or _file_digest(executable) != expected["artifact_digest"]:
            raise ConflictError(f"adopted {name} cleanup executable identity changed")
        if not expected["command_line"] or not command:
            raise ConflictError(f"adopted {name} cleanup command line is unavailable")
        if not argv or _argv_digest(argv) != expected["argv_digest"]:
            raise ConflictError(f"adopted {name} cleanup argv identity changed")
        return True

    def _signal_verified_group(
        self,
        receipt: Mapping[str, Any],
        names: tuple[str, ...],
        *,
        leader: str,
        parents: Mapping[str, int | None],
    ) -> None:
        leader_value = self._receipt_process(receipt, leader)
        group = int(leader_value["process_group"])
        if group != int(leader_value["pid"]) or int(leader_value["session_id"]) != int(leader_value["pid"]):
            raise ConflictError(f"adopted {leader} cleanup group is not independently owned")

        def live_members() -> list[str]:
            live = [
                name for name in names
                if self._verify_cleanup_member(
                    receipt,
                    name,
                    expected_parent=parents.get(name),
                    allow_reparented=True,
                )
            ]
            if "engine_listener" in names:
                listener = self._receipt_process(receipt, "engine_listener")
                if "engine_listener" in live:
                    owner, _endpoint = _listening_socket_owner(
                        int(listener["pid"]), self.profile.engine_endpoint
                    )
                    if owner != int(listener["pid"]):
                        raise ConflictError("adopted engine listener ownership changed")
                else:
                    parsed = urlsplit(self.profile.engine_endpoint)
                    probe = socket.socket(
                        socket.AF_INET6 if ":" in (parsed.hostname or "") else socket.AF_INET,
                        socket.SOCK_STREAM,
                    )
                    try:
                        probe.settimeout(self.cleanup_timeout_seconds)
                        if probe.connect_ex((str(parsed.hostname), int(parsed.port))) == 0:
                            raise ConflictError("adopted engine listener was replaced")
                    finally:
                        probe.close()
            return live

        current = live_members()
        if not current:
            return
        # Every surviving named member is revalidated immediately before each
        # group signal.  No PID-only signal is ever used.
        os.killpg(group, signal.SIGTERM)
        deadline = time.monotonic() + self.cleanup_timeout_seconds
        while time.monotonic() < deadline:
            if not any(process_birth_identity(int(self._receipt_process(receipt, name)["pid"])) == self._receipt_process(receipt, name)["birth_id"] for name in names):
                return
            time.sleep(0.01)
        current = live_members()
        if current:
            os.killpg(group, signal.SIGKILL)
            deadline = time.monotonic() + self.cleanup_timeout_seconds
            while time.monotonic() < deadline:
                if not any(process_birth_identity(int(self._receipt_process(receipt, name)["pid"])) == self._receipt_process(receipt, name)["birth_id"] for name in names):
                    return
                time.sleep(0.01)
        if live_members():
            raise ConflictError(f"adopted {leader} process group survived verified cleanup")

    def _adopted_graph_has_survivors(self, handle: _PreparedWorker) -> bool:
        receipt = handle.receipt
        if not isinstance(receipt, Mapping):
            return True
        for name in ("worker", "host", "engine", "engine_listener"):
            try:
                expected = self._receipt_process(receipt, name)
            except ConflictError:
                return True
            if process_birth_identity(int(expected["pid"])) == expected["birth_id"]:
                return True
        return False

    @staticmethod
    def _cleanup_partition(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
        expected = [
            {"role": "generic_pack_host", "leader": "host", "members": ["host"]},
            {
                "role": "engine",
                "leader": "engine",
                "members": ["engine", "engine_listener"],
            },
            {"role": "worker", "leader": "worker", "members": ["worker"]},
        ]
        if receipt.get("cleanup_groups") != expected:
            raise ConflictError("adopted cleanup group partition is invalid")
        return expected

    def _force_cleanup_adopted_graph(self, handle: _PreparedWorker) -> None:
        """Birth/executable/session checked fallback for an unresponsive Worker."""

        receipt = handle.receipt
        if not isinstance(receipt, Mapping):
            raise ConflictError("adopted Worker cleanup receipt is unavailable")
        cleanup_groups = self._cleanup_partition(receipt)
        worker_pid = int(self._receipt_process(receipt, "worker")["pid"])
        engine_pid = int(self._receipt_process(receipt, "engine")["pid"])
        # Establish one complete immutable graph snapshot before the first
        # signal.  Each group helper repeats these checks immediately before
        # TERM and again before KILL.
        live = {
            "worker": self._verify_cleanup_member(
                receipt, "worker", expected_parent=None, allow_reparented=True
            ),
            "host": self._verify_cleanup_member(
                receipt, "host", expected_parent=worker_pid, allow_reparented=True
            ),
            "engine": self._verify_cleanup_member(
                receipt, "engine", expected_parent=worker_pid, allow_reparented=True
            ),
            "engine_listener": self._verify_cleanup_member(
                receipt, "engine_listener", expected_parent=engine_pid,
                allow_reparented=True,
            ),
        }
        if not any(live.values()):
            return
        # Prove the listener still belongs to the recorded listener before any
        # signal; this also prevents cleaning an unrelated process graph after
        # endpoint replacement.
        listener = self._receipt_process(receipt, "engine_listener")
        endpoint = self.profile.engine_endpoint
        if live["engine_listener"]:
            owner, endpoint = _listening_socket_owner(
                int(listener["pid"]), self.profile.engine_endpoint
            )
            if owner != int(listener["pid"]):
                raise ConflictError("adopted engine listener ownership changed")
        else:
            parsed_endpoint = urlsplit(endpoint)
            replacement = socket.socket(
                socket.AF_INET6 if ":" in (parsed_endpoint.hostname or "") else socket.AF_INET,
                socket.SOCK_STREAM,
            )
            try:
                replacement.settimeout(self.cleanup_timeout_seconds)
                if replacement.connect_ex((str(parsed_endpoint.hostname), int(parsed_endpoint.port))) == 0:
                    raise ConflictError("adopted engine listener was replaced")
            finally:
                replacement.close()
        parents = {
            "worker": None,
            "host": worker_pid,
            "engine": worker_pid,
            "engine_listener": engine_pid,
        }
        for group in cleanup_groups:
            self._signal_verified_group(
                receipt,
                tuple(group["members"]),
                leader=str(group["leader"]),
                parents=parents,
            )
        parsed = urlsplit(endpoint)
        probe = socket.socket(socket.AF_INET6 if ":" in (parsed.hostname or "") else socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(self.cleanup_timeout_seconds)
            if probe.connect_ex((str(parsed.hostname), int(parsed.port))) == 0:
                raise ConflictError("adopted engine listener survived verified cleanup")
        finally:
            probe.close()
        session_root = handle.owner_session_config_path.parent
        support_root = Path(str(self.config["support_root"])).resolve()
        try:
            session_root.resolve().relative_to(support_root)
            identity = session_root.lstat()
        except (OSError, ValueError) as exc:
            raise ConflictError("adopted engine registry root is unsafe") from exc
        if session_root.is_symlink() or not stat.S_ISDIR(identity.st_mode) or identity.st_uid != os.getuid():
            raise ConflictError("adopted engine registry root is unsafe")
        shutil.rmtree(session_root)
        if session_root.exists() or session_root.is_symlink():
            raise ConflictError("adopted engine registry survived verified cleanup")

    def control_alive(self, handle: _PreparedWorker) -> bool:
        if not isinstance(handle, _PreparedWorker) or handle.closed or handle.worker.poll() is not None:
            return False
        if not handle.rpc_lock.acquire(blocking=False):
            # A Runtime-owned RPC currently holds the channel. Its bounded
            # operation is itself positive control-channel activity.
            return True
        try:
            if self._birth(handle.worker.pid) != handle.birth_id:
                return False
            readable, _, exceptional = select.select([handle.control], [], [handle.control], 0)
            if exceptional or readable:
                # With no RPC in flight, either EOF or unsolicited bytes are
                # a protocol/control-channel failure. Do not leave bytes
                # perpetually buffered and mistake a closed peer for liveness.
                return False
            return True
        except (OSError, ValueError):
            return False
        finally:
            handle.rpc_lock.release()

    def current_handle(self) -> _PreparedWorker | None:
        handle = self._active
        return None if handle is None or handle.closed else handle

    def reconnect(self, receipt: Mapping[str, Any]) -> _PreparedWorker | None:
        handle = self._active
        if handle is None or handle.closed or not handle.activated:
            return None
        response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "reconnect", "receipt": dict(receipt)})
        return handle if response.get("reconnected") is True else None


def _ps(pid: int, field: str) -> str:
    result = subprocess.run(["ps", "-p", str(int(pid)), "-o", f"{field}="], capture_output=True, text=True, check=False)
    if result.returncode != 0 or not result.stdout.strip():
        raise ConflictError(f"cannot independently observe process {pid}")
    return result.stdout.strip().splitlines()[0].strip()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ConflictError(f"cannot independently read executable artifact {path}") from exc
    return "sha256:" + digest.hexdigest()


def _session_config_digest(path: Path) -> str:
    try:
        identity = path.lstat()
    except OSError as exc:
        raise ConflictError(f"cannot independently observe session configuration {path}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != getattr(os, "getuid", lambda: identity.st_uid)()
    ):
        raise ConflictError("owner session configuration is not a regular owner-controlled file")
    return _file_digest(path)


def _actual_executable(pid: int) -> Path:
    """Resolve the kernel-reported executable for one live process."""
    try:
        if sys.platform == "darwin":
            library = ctypes.CDLL("/usr/lib/libproc.dylib")
            buffer = ctypes.create_string_buffer(4096)
            result = library.proc_pidpath(int(pid), buffer, len(buffer))
            if result <= 0:
                raise OSError("proc_pidpath returned no path")
            return Path(buffer.value.decode()).resolve()
        return Path(os.readlink(f"/proc/{int(pid)}/exe")).resolve()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConflictError(f"cannot independently resolve executable identity for process {pid}") from exc


def _owner_machine_id() -> str:
    value = platform.node().strip()
    if not value:
        raise ConflictError("cannot independently observe machine identity")
    return value


def _session_config_path(environment: Mapping[str, str]) -> Path:
    raw = str(environment.get("ASTRID_VIBECOMFY_SESSION_DIR") or "").strip()
    root = Path(raw).expanduser()
    if not raw or not root.is_absolute() or root.is_symlink():
        raise ConflictError("owner launch configuration has no safe VibeComfy session directory")
    return root / "config.json"


def _socket_address(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None:
    text = value.strip()
    if text.startswith("TCP "):
        text = text[4:]
    if "->" in text or text.startswith("*:"):
        return None
    try:
        if text.startswith("["):
            closing = text.index("]")
            address_text, port_text = text[1:closing], text[closing + 1 :]
            if not port_text.startswith(":"):
                return None
            port_text = port_text[1:]
        else:
            address_text, port_text = text.rsplit(":", 1)
        return ipaddress.ip_address(address_text), int(port_text)
    except (ValueError, TypeError):
        return None


def _listening_socket_owner(pid: int, endpoint: str) -> tuple[int, str]:
    canonical = _engine_endpoint(endpoint)
    parsed = urlsplit(canonical)
    expected = (ipaddress.ip_address(parsed.hostname or ""), int(parsed.port or 0))
    result = subprocess.run(
        ["lsof", "-a", "-p", str(int(pid)), "-n", "-P", "-iTCP", "-sTCP:LISTEN", "-Fpn"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ConflictError(f"cannot independently observe listening sockets for process {pid}")
    owner = None
    for row in result.stdout.splitlines():
        if row.startswith("p") and row[1:].isdigit():
            owner = int(row[1:])
        elif row.startswith("n") and owner == int(pid) and _socket_address(row[1:]) == expected:
            return int(pid), canonical
    raise ConflictError(f"process {pid} does not independently own configured engine endpoint {canonical}")


class OSProcessInspector:
    """Independent owner-side observation; Worker reports are only selectors."""

    def __init__(self, profile: LocalWorkerProfile):
        self.profile = profile

    def _identity(self, pid: int, birth: str, executable: Path, digest: str, *, parent_pid: int | None, session_owner: bool) -> ProcessIdentity:
        if pid <= 0:
            raise ConflictError("observed process PID is invalid")
        observed_birth = process_birth_identity(pid)
        if not observed_birth or observed_birth != birth:
            raise ConflictError("independent process birth identity disagrees with Worker report")
        observed_parent = int(_ps(pid, "ppid"))
        if parent_pid is not None and observed_parent != parent_pid:
            raise ConflictError("independent process parent identity disagrees with Worker report")
        try:
            uid = int(_ps(pid, "uid"))
        except ValueError as exc:
            raise ConflictError("independent process UID observation is invalid") from exc
        try:
            group = os.getpgid(pid)
            session = os.getsid(pid)
        except OSError as exc:
            raise ConflictError("independent process group/session observation failed") from exc
        if session_owner and (group != pid or session != pid):
            raise ConflictError("observed process does not own its process group/session")
        if _actual_executable(pid) != executable:
            raise ConflictError("independent executable identity disagrees with profile")
        observed_digest = _file_digest(executable)
        if observed_digest != digest:
            raise ConflictError("independent executable artifact digest disagrees with profile")
        command_line = _ps(pid, "command")
        argv = _process_argv(pid)
        if not command_line or not argv:
            raise ConflictError("independent process command line is unavailable")
        return ProcessIdentity(
            pid, observed_birth, uid, observed_parent, group, session,
            executable, observed_digest, command_line, _argv_digest(argv),
        )

    def observe(self, handle: _PreparedWorker) -> LocalWorkerObservation:
        report = getattr(handle, "report_value", None)
        if not isinstance(report, Mapping):
            raise ConflictError("Worker report is unavailable for independent observation")
        processes = report.get("processes")
        binding = report.get("engine_binding")
        if not isinstance(processes, Mapping) or not isinstance(binding, Mapping):
            raise ConflictError("Worker process report is incomplete")
        worker_data = processes.get("worker")
        host_data = processes.get("host")
        engine_data = processes.get("engine")
        listener_data = processes.get("engine_listener")
        if not all(isinstance(item, Mapping) for item in (worker_data, host_data, engine_data, listener_data)):
            raise ConflictError("Worker process report is incomplete")
        worker = self._identity(
            int(worker_data["pid"]),
            str(worker_data["birth_id"]),
            self.profile.worker_executable,
            self.profile.worker_artifact_digest,
            parent_pid=None if getattr(handle, "adopted", False) else os.getpid(),
            session_owner=True,
        )
        host = self._identity(
            int(host_data["pid"]),
            str(host_data["birth_id"]),
            self.profile.host_os_executable or self.profile.host_executable,
            self.profile.host_os_artifact_digest or self.profile.host_artifact_digest,
            parent_pid=worker.pid,
            session_owner=True,
        )
        engine = self._identity(int(engine_data["pid"]), str(engine_data["birth_id"]), self.profile.engine_executable, self.profile.engine_artifact_digest, parent_pid=worker.pid, session_owner=True)
        listener = self._identity(int(listener_data["pid"]), str(listener_data["birth_id"]), self.profile.engine_listener_executable, self.profile.engine_listener_artifact_digest, parent_pid=engine.pid, session_owner=False)
        reported_socket_owner = int(binding.get("socket_owner_pid", -1))
        observed_socket_owner, observed_endpoint = _listening_socket_owner(
            listener.pid, self.profile.engine_endpoint
        )
        if reported_socket_owner != observed_socket_owner:
            raise ConflictError("independent listener socket-owner observation disagrees with Worker report")
        if observed_socket_owner != listener.pid:
            raise ConflictError("independent listener socket-owner observation failed")
        observed_machine = _owner_machine_id()
        if observed_machine != self.profile.machine_id:
            raise ConflictError("independent machine identity disagrees with profile")
        config_path = getattr(handle, "owner_session_config_path", None)
        if not isinstance(config_path, Path):
            raise ConflictError("owner VibeComfy session configuration path is unavailable")
        observed_session_digest = _session_config_digest(config_path)
        if observed_session_digest != self.profile.session_config_digest:
            raise ConflictError("engine session configuration does not match profile")
        if str(report.get("session_config_digest")) != observed_session_digest:
            raise ConflictError("Worker session configuration claim disagrees with owner observation")
        return LocalWorkerObservation(
            machine_id=observed_machine,
            uid=os.getuid(),
            workspace_uuid=self.profile.workspace_uuid,
            realm_root=self.profile.realm_root,
            support_root=self.profile.support_root,
            worker=worker,
            host=host,
            engine=engine,
            engine_listener=listener,
            engine_listener_socket_owner_pid=observed_socket_owner,
            engine_endpoint=observed_endpoint,
            session_config_digest=observed_session_digest,
        )


@dataclass
class LocalWorkerComposition:
    profiles: dict[str, LocalWorkerProfile]
    preparer: CrossProcessWorkerPreparer
    inspector: OSProcessInspector

    def bind_runtime(self, *, endpoint: str, runtime_instance_id: str, credential_file: Path) -> None:
        self.preparer.bind_runtime(endpoint=endpoint, runtime_instance_id=runtime_instance_id, credential_file=credential_file)


def _path(value: Any, label: str, *, directory: bool | None = None) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"worker profile {label} is required")
    target = Path(value).expanduser()
    if not target.is_absolute():
        raise ValidationError(f"worker profile {label} must be absolute")
    target = target.resolve()
    if directory is True and not target.is_dir():
        raise ValidationError(f"worker profile {label} must be an existing directory")
    if directory is False and not target.is_file():
        raise ValidationError(f"worker profile {label} must be an existing file")
    return target


def _executable_path(value: Any, label: str) -> Path:
    """Validate an executable while preserving a virtualenv's lexical path."""

    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"worker profile {label} is required")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ValidationError(f"worker profile {label} must be absolute")
    target = Path(os.path.abspath(candidate))
    if not target.is_file() or not os.access(target, os.X_OK):
        raise ValidationError(f"worker profile {label} must be an existing executable file")
    return target


def _canonical_executable_path(value: Any, label: str) -> Path:
    """Validate an OS identity pin that must already be canonical."""

    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"worker profile {label} is required")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ValidationError(f"worker profile {label} must be absolute")
    try:
        target = candidate.resolve(strict=True)
        if candidate.is_symlink() or target != candidate:
            raise ValidationError(f"worker profile {label} must be canonical and not symlinked")
    except OSError as exc:
        raise ValidationError(f"worker profile {label} must be an existing executable file") from exc
    if not target.is_file() or not os.access(target, os.X_OK):
        raise ValidationError(f"worker profile {label} must be an existing executable file")
    return target


def _installed_astrid_pack_root(host_executable: Path) -> Path:
    """Resolve Astrid's packaged pack root without cwd or PYTHONPATH input."""
    script = (
        "import importlib.metadata as m, json, pathlib, astrid; "
        "root=pathlib.Path(astrid.__file__).resolve().parent; "
        "direct=m.distribution('astrid').read_text('direct_url.json'); "
        "editable=bool(direct and json.loads(direct).get('dir_info',{}).get('editable')); "
        "print(json.dumps({'pack_root':str(root / 'packs'),'editable':editable}))"
    )
    try:
        completed = subprocess.run(
            [str(host_executable), "-I", "-c", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        )
        value = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError) as exc:
        raise ValidationError("installed Astrid package origin could not be verified") from exc
    if not isinstance(value, Mapping) or value.get("editable") is not False:
        raise ValidationError("installed Astrid package must be a non-editable artifact")
    return _path(value.get("pack_root"), "installed Astrid pack_root", directory=True)


def load_local_worker_composition(path: str | Path, *, workspace_uuid: str, realm_root: Path, support_root: Path, runtime_instance_id: str) -> LocalWorkerComposition:
    target = _path(str(path), "path", directory=False)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"worker profile is missing or invalid: {target}") from exc
    if not isinstance(raw, Mapping):
        raise ValidationError("worker profile must be an object")
    allowed = {
        "profile_id", "machine_id", "engine_endpoint", "worker_environment", "worker_executable", "host_executable",
        "engine_executable", "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
        "engine_artifact_digest", "engine_listener_artifact_digest", "session_config_digest", "profile_revision",
        "profile_digest", "release_digest", "launch_mode", "source_checkout", "pack_root", "boot_manifest_path",
        "boot_manifest_hash", "capability_matrix", "environment", "worker_timeout_seconds",
        "host_os_executable", "host_os_artifact_digest",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError("worker profile contains unsupported fields: " + ", ".join(unknown))
    worker_executable = _path(raw.get("worker_executable"), "worker_executable", directory=False)
    host_launch_executable = _executable_path(raw.get("host_executable"), "host_executable")
    host_executable = host_launch_executable.resolve()
    host_artifact_digest = str(raw.get("host_artifact_digest") or "")
    if _file_digest(host_executable) != host_artifact_digest:
        raise ValidationError("worker profile host_artifact_digest does not match host_executable")
    engine_executable = _path(raw.get("engine_executable"), "engine_executable", directory=False)
    listener_executable = _path(raw.get("engine_listener_executable"), "engine_listener_executable", directory=False)
    host_os_path_present = "host_os_executable" in raw
    host_os_digest_present = "host_os_artifact_digest" in raw
    host_os_executable_raw = raw.get("host_os_executable")
    host_os_digest_raw = raw.get("host_os_artifact_digest")
    if host_os_path_present != host_os_digest_present:
        raise ValidationError(
            "worker profile host_os_executable and host_os_artifact_digest must be provided together"
        )
    if host_os_path_present and (
        not isinstance(host_os_executable_raw, str)
        or not host_os_executable_raw.strip()
        or not isinstance(host_os_digest_raw, str)
        or not host_os_digest_raw.strip()
    ):
        raise ValidationError(
            "worker profile host_os_executable and host_os_artifact_digest cannot be empty"
        )
    if host_os_digest_present and not _SHA256_DIGEST.fullmatch(str(host_os_digest_raw)):
        raise ValidationError(
            "worker profile host_os_artifact_digest must be a sha256 digest"
        )
    host_os_executable = (
        _canonical_executable_path(host_os_executable_raw, "host_os_executable")
        if host_os_path_present
        else None
    )
    host_os_artifact_digest = str(host_os_digest_raw) if host_os_digest_present else None
    if (
        host_os_executable is not None
        and _file_digest(host_os_executable) != host_os_artifact_digest
    ):
        raise ValidationError(
            "worker profile host_os_artifact_digest does not match host_os_executable"
        )
    worker_environment = _path(raw.get("worker_environment"), "worker_environment", directory=True)
    environment = raw.get("environment", {})
    if not isinstance(environment, Mapping) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items()):
        raise ValidationError("worker profile environment must be a string mapping")
    try:
        engine_port = int(environment.get("ASTRID_VIBECOMFY_PORT", "8188"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("worker profile ASTRID_VIBECOMFY_PORT must be an integer") from exc
    if not 1 <= engine_port <= 65535:
        raise ValidationError("worker profile ASTRID_VIBECOMFY_PORT is outside the valid range")
    machine_id = str(raw.get("machine_id") or "").strip()
    if not machine_id:
        raise ValidationError("worker profile machine_id is required")
    profile = LocalWorkerProfile(
        profile_id=str(raw.get("profile_id") or "astrid"),
        workspace_uuid=str(workspace_uuid),
        realm_root=Path(realm_root).resolve(),
        support_root=Path(support_root).resolve(),
        machine_id=machine_id,
        worker_executable=worker_executable,
        host_executable=host_executable,
        engine_executable=engine_executable,
        engine_listener_executable=listener_executable,
        engine_endpoint=_engine_endpoint(str(raw.get("engine_endpoint") or "")),
        worker_artifact_digest=str(raw.get("worker_artifact_digest") or ""),
        host_artifact_digest=host_artifact_digest,
        engine_artifact_digest=str(raw.get("engine_artifact_digest") or ""),
        engine_listener_artifact_digest=str(raw.get("engine_listener_artifact_digest") or ""),
        session_config_digest=str(raw.get("session_config_digest") or ""),
        profile_revision=str(raw.get("profile_revision") or ""),
        profile_digest=str(raw.get("profile_digest") or ""),
        release_digest=str(raw.get("release_digest") or ""),
        host_os_executable=host_os_executable,
        host_os_artifact_digest=host_os_artifact_digest,
    )
    if profile.engine_endpoint != f"http://127.0.0.1:{engine_port}":
        raise ValidationError("worker profile engine_endpoint does not match the Worker launch port")
    launch_mode = str(raw.get("launch_mode") or "editable").strip()
    if launch_mode not in {"editable", "installed"}:
        raise ValidationError("worker profile launch_mode must be 'editable' or 'installed'")
    pack_root = _path(raw.get("pack_root"), "pack_root", directory=True)
    source_checkout: Path | None
    if launch_mode == "editable":
        source_checkout = _path(raw.get("source_checkout"), "source_checkout", directory=True)
        if not pack_root.is_relative_to(source_checkout):
            raise ValidationError("worker profile pack_root must be inside source_checkout")
    else:
        if raw.get("source_checkout") not in {None, ""}:
            raise ValidationError("installed worker profile must not select a source_checkout")
        source_checkout = None
        installed_pack_root = _installed_astrid_pack_root(host_launch_executable)
        if pack_root != installed_pack_root:
            raise ValidationError(
                "worker profile pack_root does not match the installed Astrid package"
            )
    boot_manifest_path = _path(raw.get("boot_manifest_path"), "boot_manifest_path", directory=False)
    capability = raw.get("capability_matrix")
    capability_path = _path(capability, "capability_matrix", directory=False) if capability else None
    support = Path(support_root).resolve()
    config = {
        "host_python": str(host_launch_executable),
        "launch_mode": launch_mode,
        "source_checkout": str(source_checkout) if source_checkout is not None else None,
        "pack_root": str(pack_root),
        "runtime_endpoint": "http://127.0.0.1:0",
        "credential_file": str(support / "credentials" / "astrid-pack-host.token"),
        "support_root": str(support),
        "runtime_instance_id": str(runtime_instance_id),
        "ready_file": str(support / f"worker-{profile.profile_id}-ready.json"),
        "state_file": str(support / f"worker-{profile.profile_id}-state.json"),
        "boot_manifest_path": str(boot_manifest_path),
        "boot_manifest_hash": str(raw.get("boot_manifest_hash") or ""),
        "capability_matrix": str(capability_path) if capability_path else None,
        "readiness_profile_path": None,
        "readiness_profile_hash": None,
    }
    preparer = CrossProcessWorkerPreparer(
        profile=profile,
        config=config,
        environment={**{str(k): str(v) for k, v in environment.items()}, "ASTRID_WORKER_ENVIRONMENT": str(worker_environment)},
        timeout_seconds=float(raw.get("worker_timeout_seconds") or 900.0),
        # Worker abort acknowledges only after its GenericPackHost and
        # separately sessioned engine/listener are verified, stopped, and
        # reaped.  The transport's historical 100ms default could terminate
        # the Worker while that cleanup was still in progress.
        cleanup_timeout_seconds=DEFAULT_WORKER_CLEANUP_TIMEOUT_SECONDS,
        shutdown_timeout_seconds=DEFAULT_WORKER_SHUTDOWN_TIMEOUT_SECONDS,
    )
    inspector = OSProcessInspector(profile)
    return LocalWorkerComposition({profile.profile_id: profile}, preparer, inspector)


__all__ = ["CrossProcessWorkerPreparer", "LocalWorkerComposition", "OSProcessInspector", "load_local_worker_composition"]
