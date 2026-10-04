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
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from .catalog import process_birth_identity
from .errors import ConflictError, ValidationError
from .local_worker import (
    LocalWorkerObservation,
    LocalWorkerPreparer,
    LocalWorkerProfile,
    ProcessIdentity,
    _engine_endpoint,
    _selected_profile_payload,
)


CONTROL_VERSION = "reigh.local-worker-control/v1"
CONTROL_FRAME_LIMIT = 64 * 1024
PROFILE_FIELDS = (
    "profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
    "worker_executable", "host_executable", "engine_executable",
    "engine_listener_executable", "worker_artifact_digest", "host_artifact_digest",
    "engine_artifact_digest", "engine_listener_artifact_digest", "session_config_digest",
    "profile_revision", "profile_digest", "release_digest",
)


def _frame_send(channel: socket.socket, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(dict(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
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
    worker: subprocess.Popen[bytes]
    birth_id: str
    control: socket.socket
    report_value: dict[str, Any]
    owner_session_config_path: Path
    activated: bool = False
    closed: bool = False
    rpc_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_lock: threading.Lock = field(default_factory=threading.Lock)
    cleanup_started: bool = False
    relay: bool = False
    retained: Any = None
    broker: Any = None
    owner_epoch: str | None = None
    custody_scope: str | None = None


class CrossProcessWorkerPreparer(LocalWorkerPreparer):
    """Runtime-side transport for the installed Worker private ABI."""

    def __init__(self, *, profile: LocalWorkerProfile, config: Mapping[str, Any], environment: Mapping[str, str], timeout_seconds: float = 900.0, cleanup_timeout_seconds: float = 0.1):
        self.profile = profile
        self.config = dict(config)
        self.environment = dict(environment)
        self.timeout_seconds = float(timeout_seconds)
        self.cleanup_timeout_seconds = max(0.05, float(cleanup_timeout_seconds))
        self._active: _PreparedWorker | None = None
        self._activation_binding = None
        self._prepare_cancel = threading.Event()
        # The only uninterruptible handoff is spawn -> handle construction ->
        # publication. Cancellation waits for this tiny critical section so a
        # just-spawned child can never exist without an owner-visible handle.
        self._handoff_lock = threading.Lock()

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
        if handle.closed or (handle.retained.poll() if handle.relay else handle.worker.poll()) is not None:
            raise ConflictError("prepared Worker is not alive")
        if self._birth(handle.worker.pid) != handle.birth_id:
            raise ConflictError("prepared Worker identity changed")
        _frame_send(handle.control, payload)
        response = _frame_receive(handle.control)
        expected_version = "runtime.local-execution-control/v1" if handle.relay else CONTROL_VERSION
        if response.get("version") != expected_version:
            raise ConflictError("prepared Worker control version is invalid")
        if response.get("status") != "ok":
            raise ConflictError(str(response.get("error") or "prepared Worker rejected the operation"))
        return response

    def _rpc(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        with handle.rpc_lock:
            return self._rpc_unlocked(handle, payload)

    def prepare(self, profile: LocalWorkerProfile, *, operation_id: str, channel_id: str) -> _PreparedWorker:
        if profile.engine_launch is not None:
            return self._prepare_relay(profile, operation_id=operation_id, channel_id=channel_id)
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

    def _prepare_relay(self, profile, *, operation_id, channel_id):
        from .local_execution_supervisor import host_prepare_request, RetainedProcess
        from banodoco_local.custody_broker import RoleBoundCustodyBroker, default_process_identity, custody_wrapper_argv
        if self._active is not None:
            self.abort(self._active)
        if self._prepare_cancel.is_set():
            raise ConflictError("local execution preparation cancelled")
        selected = _selected_profile_payload(profile)
        epoch = self.config.get("runtime_instance_id")
        owner = default_process_identity(os.getpid())
        if owner is None or not isinstance(epoch, str) or not epoch:
            raise ConflictError("Runtime launch owner identity is unavailable")
        owner.update(runtime_instance_id=epoch, coordinator_epoch=epoch)
        owner.pop("parent_pid", None)
        # Operation IDs originate in Runtime. Reject path syntax before using
        # one to select this private, launch-specific protected scope.
        if not isinstance(operation_id, str) or not operation_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in operation_id):
            raise ConflictError("Runtime local execution operation identity is invalid")
        scope = profile.support_root / "local-execution-custody" / operation_id
        request = host_prepare_request(operation_id=operation_id, channel_id=channel_id, owner_epoch=epoch,
            runtime_owner=owner, profile=selected, custody_scope=str(scope))
        if _actual_executable(os.getpid()) != profile.worker_executable or _file_digest(profile.worker_executable) != profile.worker_artifact_digest:
            raise ConflictError("selected relay interpreter differs from current Runtime kernel artifact")
        parent, child = socket.socketpair()
        broker = None
        handle = None
        try:
            with self._handoff_lock:
                broker = RoleBoundCustodyBroker(role="relay", identity_provider=default_process_identity,
                    ledger_root=scope / "relay-admission", authority_scope_root=scope,
                    authority_journal=scope / "admissions.jsonl", owner_epoch=epoch,
                    timeout=min(self.timeout_seconds, 60.0))
                argv = [sys.executable, "-I", "-m", "runtime_protocol.local_execution_supervisor", "--prepared-control-fd", str(child.fileno())]
                environment = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"} and not k.startswith("ASTRID_RUNTIME_CUSTODY_")}
                environment.update({k: v for k, v in self.environment.items() if k in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "XDG_RUNTIME_DIR", "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "ASTRID_EXECUTION_TARGET_JSON"}})
                environment.update(broker.child_environment(argv, start_new_session=True))
                process = subprocess.Popen(custody_wrapper_argv(sys.executable), cwd=str(profile.support_root),
                    env=environment, stdin=subprocess.DEVNULL, close_fds=True, pass_fds=(child.fileno(),))
                retained = RetainedProcess(process)
                # Publish before birth/token/seal observations can fail.
                handle = _PreparedWorker(process, "", parent, {}, Path(profile.engine_launch["session_root"]) / "config.json",
                    relay=True, retained=retained, broker=broker, owner_epoch=epoch, custody_scope=str(scope))
                self._active = handle
                child.close()
                parent.settimeout(self.timeout_seconds)
                broker.wait_until_sealed()
                retained.bind_actor()
                handle.birth_id = retained.verify()["birth_id"]
            response = self._rpc(handle, {"version": "runtime.local-execution-control/v1", "command": "prepare", "preparation": request, "config": dict(self.config)})
            value = response.get("report")
            if not isinstance(value, dict):
                raise ConflictError("neutral relay returned no process report")
            handle.report_value = value
            return handle
        except BaseException as primary:
            child.close()
            if handle is None:
                parent.close()
                if broker is not None:
                    broker.abort_before_spawn()
            else:
                # Retain the launch obligation; failed sealing grants no PID
                # cleanup fallback and cannot be represented as closed.
                try:
                    self.abort(handle)
                except BaseException as cleanup:
                    primary.add_note("local execution cleanup remains unresolved: " + type(cleanup).__name__)
            raise

    def _relay_abort(self, handle):
        with handle.cleanup_lock:
            return self._relay_abort_locked(handle)

    def _relay_abort_locked(self, handle):
        if handle.closed:
            return
        response = self._rpc(handle, {"version": "runtime.local-execution-control/v1", "command": "abort"})
        if not isinstance(response.get("host_exit_code"), int) or isinstance(response["host_exit_code"], bool) or response.get("host_result", {}).get("status") != "cleaned":
            raise ConflictError("relay has no verified full host cleanup acknowledgement")
        if handle.retained.poll() is None:
            handle.broker.signal(signal.SIGTERM, expected_pid=handle.worker.pid)
            try:
                handle.retained.wait(max(1.0, self.cleanup_timeout_seconds))
            except BaseException:
                handle.broker.signal(signal.SIGKILL, expected_pid=handle.worker.pid)
                handle.retained.wait(max(1.0, self.cleanup_timeout_seconds))
        handle.control.close()
        handle.closed = True
        if self._active is handle:
            self._active = None

    def report(self, handle: _PreparedWorker) -> Mapping[str, Any]:
        response = self._rpc(handle, {"version": "runtime.local-execution-control/v1" if handle.relay else CONTROL_VERSION, "command": "report"})
        report = response.get("report")
        if not isinstance(report, dict):
            raise ConflictError("prepared Worker returned no process report")
        handle.report_value = report
        return report

    def bind_activation_acceptor(self, handle, grant, acceptor):
        if handle is not self._active or not handle.relay or handle.closed or not callable(acceptor):
            raise ConflictError("Runtime activation publisher lacks this retained relay")
        self._activation_binding = (handle, json.loads(json.dumps(dict(grant))), acceptor)

    def activate(self, handle: _PreparedWorker, grant: Mapping[str, Any]) -> None:
        if not handle.relay:
            response = self._rpc(handle, {"version": CONTROL_VERSION, "command": "activate", "grant": dict(grant)})
            if response.get("status") != "ok":
                raise ConflictError("prepared Worker rejected activation")
            handle.activated = True
            return
        from .local_execution_supervisor import send_frame, receive_frame, CONTROL_VERSION as relay_version
        binding = self._activation_binding
        if binding is None or binding[0] is not handle or binding[1] != dict(grant):
            raise ConflictError("local relay has no exact Runtime activation publisher")
        with handle.rpc_lock:
            handle.retained.verify()
            send_frame(handle.control, {"version": relay_version, "command": "activate", "grant": dict(grant)})
            response = receive_frame(handle.control)
            if set(response) != {"version", "status", "request"} or response.get("version") != relay_version or response.get("status") != "activation_requested":
                raise ConflictError("relay has no exact host activation request")
            recorded = binding[2](response["request"])
            # Publisher returns only after its protected file+directory fsync.
            send_frame(handle.control, {"version": relay_version, "command": "record_activation_receipt", "receipt": recorded})
            final = receive_frame(handle.control)
            expected = {"version": "astrid.local-worker-activation-accepted/v1", **{k: grant[k] for k in ("operation_id", "channel_id", "activation_id", "executor_incarnation", "evidence_digest")}, "host": response["request"]["host"]}
            if final != {"version": relay_version, "status": "ok", "accepted": expected}:
                raise ConflictError("relay final activation acknowledgement differs from recorded grant")
            handle.retained.verify()
            handle.activated = True

    def abort(self, handle: _PreparedWorker) -> None:
        if isinstance(handle, _PreparedWorker) and handle.closed:
            return
        if isinstance(handle, _PreparedWorker) and handle.relay:
            return self._relay_abort(handle)
        if not isinstance(handle, _PreparedWorker) or handle.closed:
            return
        with handle.cleanup_lock:
            if handle.cleanup_started:
                return
            handle.cleanup_started = True
        failure: BaseException | None = None
        owned = False
        try:
            owned = self._birth(handle.worker.pid) == handle.birth_id
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
            handle.worker.wait(timeout=self.cleanup_timeout_seconds)
        except BaseException as exc:
            failure = exc
        finally:
            try:
                handle.control.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            handle.control.close()
            if owned and handle.worker.poll() is None:
                try:
                    os.killpg(handle.worker.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    handle.worker.wait(timeout=self.cleanup_timeout_seconds)
                except (subprocess.TimeoutExpired, TimeoutError):
                    try:
                        os.killpg(handle.worker.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        handle.worker.wait(timeout=self.cleanup_timeout_seconds)
                    except (subprocess.TimeoutExpired, TimeoutError):
                        pass
            handle.closed = True
            if self._active is handle:
                self._active = None
        if failure is not None:
            raise failure

    def stop_owned(self, receipt: Mapping[str, Any], handle: _PreparedWorker | None = None) -> bool:
        """Stop only PIDs whose current birth marker matches the exact receipt.

        This works after a daemon restart when the private control handle is
        gone. A missing or reused PID is already absent from this generation;
        an unobservable PID leaves the handover unresolved.
        """
        if self.profile.engine_launch is not None:
            retained = handle or self._active
            if not isinstance(retained, _PreparedWorker) or not retained.relay or retained.closed:
                raise ConflictError("relay capability recovery requires retained control")
            worker = receipt.get("worker")
            if not isinstance(worker, Mapping) or (worker.get("pid"), worker.get("birth_id")) != (retained.worker.pid, retained.birth_id) or receipt.get("custody_capabilities") != retained.report_value.get("custody_capabilities"):
                raise ConflictError("relay retained control differs from exact custody receipt")
            self.abort(retained)
            return True
        names = ("engine_listener", "engine", "host", "worker")
        processes = []
        for name in names:
            item = receipt.get(name)
            if not isinstance(item, Mapping) or not isinstance(item.get("pid"), int) or not isinstance(item.get("birth_id"), str):
                raise ConflictError("local Worker relinquish receipt has invalid process identity")
            processes.append((item["pid"], item["birth_id"]))
        if handle is not None and (handle.worker.pid, handle.birth_id) != processes[-1]:
            raise ConflictError("local Worker handle does not match relinquish receipt")

        def live() -> list[int]:
            remaining = []
            for pid, birth in processes:
                if handle is not None and pid == handle.worker.pid:
                    # Popen.poll reaps an exited child; an unreaped zombie
                    # still has the same birth marker in /proc or ps.
                    handle.worker.poll()
                current = process_birth_identity(pid)
                if current == birth:
                    remaining.append(pid)
                elif current is None:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        continue
                    except PermissionError as exc:
                        raise ConflictError("receipt-owned process state is unobservable") from exc
                    raise ConflictError("receipt-owned process birth is unobservable")
            return remaining

        for pid in live():
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + max(1.0, self.cleanup_timeout_seconds)
        while time.monotonic() < deadline and live():
            time.sleep(0.02)
        for pid in live():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + max(1.0, self.cleanup_timeout_seconds)
        while time.monotonic() < deadline and live():
            time.sleep(0.02)
        if live():
            raise ConflictError("receipt-owned local Worker processes remain alive")
        if handle is not None:
            try:
                handle.control.close()
            except OSError:
                pass
            handle.closed = True
            if self._active is handle:
                self._active = None
        return True

    def control_alive(self, handle: _PreparedWorker) -> bool:
        if not isinstance(handle, _PreparedWorker) or handle.closed or (handle.retained.poll() if handle.relay else handle.worker.poll()) is not None:
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
        if self.profile.engine_launch is not None:
            # The activation record does not confer recovery/signal authority.
            # Until capability recovery is implemented, a restarted owner may
            # not replace a surviving graph merely because control is absent.
            raise ConflictError("local relay capability recovery remains unresolved")
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
        return ProcessIdentity(pid, observed_birth, uid, observed_parent, group, session, executable, observed_digest)

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
        worker = self._identity(int(worker_data["pid"]), str(worker_data["birth_id"]), self.profile.worker_executable, self.profile.worker_artifact_digest, parent_pid=os.getpid(), session_owner=True)
        host = self._identity(int(host_data["pid"]), str(host_data["birth_id"]), self.profile.host_os_executable or self.profile.host_executable, self.profile.host_os_artifact_digest or self.profile.host_artifact_digest, parent_pid=worker.pid, session_owner=True)
        engine = self._identity(int(engine_data["pid"]), str(engine_data["birth_id"]), self.profile.engine_executable, self.profile.engine_artifact_digest, parent_pid=host.pid if self.profile.engine_launch is not None else worker.pid, session_owner=True)
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
        custody = None
        if self.profile.engine_launch is not None:
            from banodoco_local.custody_broker import RoleCustodyAuthority, current_process_audit_token, default_process_identity, _incarnation
            from .local_execution_supervisor import validate_role_reference
            custody = report.get("custody_capabilities")
            if not handle.relay or not isinstance(custody, Mapping) or set(custody) != {"relay", "host", "engine", "engine_listener"} or report.get("owner_epoch") != handle.owner_epoch or report.get("custody_scope") != handle.custody_scope:
                raise ConflictError("relay report lacks exact retained Runtime scope/epoch")
            if report.get("profile_binding_digest") != "sha256:" + hashlib.sha256(json.dumps(_selected_profile_payload(self.profile), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest():
                raise ConflictError("relay report selected profile binding differs")
            actors = {}
            for role, pid in (("relay", os.getpid()), ("host", worker.pid), ("engine", host.pid), ("engine_listener", host.pid)):
                observed = default_process_identity(pid)
                if observed is None:
                    raise ConflictError("retained cleanup actor is unavailable")
                actors[role] = _incarnation(observed, current_process_audit_token(pid))
            for role, identity in (("relay", worker), ("host", host), ("engine", engine), ("engine_listener", listener)):
                validate_role_reference(custody[role], role=role, scope_root=handle.custody_scope, process={"pid": identity.pid, "birth_id": identity.birth_id})
                RoleCustodyAuthority(Path(handle.custody_scope), role).verify_reference(custody[role],
                    expected_actor=actors[role], owner_epoch=handle.owner_epoch)
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
            owner_epoch=handle.owner_epoch if self.profile.engine_launch is not None else None,
            custody_scope=handle.custody_scope if self.profile.engine_launch is not None else None,
            custody_capabilities=json.loads(json.dumps(custody)) if custody is not None else None,
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
        "profile_digest", "release_digest", "source_checkout", "pack_root", "boot_manifest_path",
        "boot_manifest_hash", "capability_matrix", "environment", "worker_timeout_seconds",
        "engine_launch", "host_os_executable", "host_os_artifact_digest",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError("worker profile contains unsupported fields: " + ", ".join(unknown))
    worker_executable = _path(raw.get("worker_executable"), "worker_executable", directory=False)
    host_executable = _path(raw.get("host_executable"), "host_executable", directory=False)
    engine_executable = _path(raw.get("engine_executable"), "engine_executable", directory=False)
    listener_executable = _path(raw.get("engine_listener_executable"), "engine_listener_executable", directory=False)
    worker_environment = _path(raw.get("worker_environment"), "worker_environment", directory=True) if raw.get("engine_launch") is None else None
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
        host_artifact_digest=str(raw.get("host_artifact_digest") or ""),
        engine_artifact_digest=str(raw.get("engine_artifact_digest") or ""),
        engine_listener_artifact_digest=str(raw.get("engine_listener_artifact_digest") or ""),
        session_config_digest=str(raw.get("session_config_digest") or ""),
        profile_revision=str(raw.get("profile_revision") or ""),
        profile_digest=str(raw.get("profile_digest") or ""),
        release_digest=str(raw.get("release_digest") or ""),
        engine_launch=raw.get("engine_launch"),
        host_os_executable=_path(raw["host_os_executable"], "host_os_executable", directory=False) if raw.get("host_os_executable") else None,
        host_os_artifact_digest=raw.get("host_os_artifact_digest"),
    )
    if profile.engine_launch is not None:
        _selected_profile_payload(profile)
    if profile.engine_launch is None and profile.engine_endpoint != f"http://127.0.0.1:{engine_port}":
        raise ValidationError("worker profile engine_endpoint does not match the Worker launch port")
    source_checkout = _path(raw.get("source_checkout"), "source_checkout", directory=True)
    pack_root = _path(raw.get("pack_root"), "pack_root", directory=True)
    if not pack_root.is_relative_to(source_checkout):
        raise ValidationError("worker profile pack_root must be inside source_checkout")
    boot_manifest_path = _path(raw.get("boot_manifest_path"), "boot_manifest_path", directory=False)
    capability = raw.get("capability_matrix")
    capability_path = _path(capability, "capability_matrix", directory=False) if capability else None
    support = Path(support_root).resolve()
    config = {
        "host_python": str(host_executable),
        "source_checkout": str(source_checkout),
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
        environment={**{str(k): str(v) for k, v in environment.items()}, **({"ASTRID_WORKER_ENVIRONMENT": str(worker_environment)} if worker_environment is not None else {})},
        timeout_seconds=float(raw.get("worker_timeout_seconds") or 900.0),
    )
    inspector = OSProcessInspector(profile)
    return LocalWorkerComposition({profile.profile_id: profile}, preparer, inspector)


__all__ = ["CrossProcessWorkerPreparer", "LocalWorkerComposition", "OSProcessInspector", "load_local_worker_composition"]
