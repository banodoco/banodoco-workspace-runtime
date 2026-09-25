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


class CrossProcessWorkerPreparer(LocalWorkerPreparer):
    """Runtime-side transport for the installed Worker private ABI."""

    def __init__(self, *, profile: LocalWorkerProfile, config: Mapping[str, Any], environment: Mapping[str, str], timeout_seconds: float = 900.0, cleanup_timeout_seconds: float = 0.1):
        self.profile = profile
        self.config = dict(config)
        self.environment = dict(environment)
        self.timeout_seconds = float(timeout_seconds)
        self.cleanup_timeout_seconds = max(0.05, float(cleanup_timeout_seconds))
        self._active: _PreparedWorker | None = None

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
            raise ConflictError(str(response.get("error") or "prepared Worker rejected the operation"))
        return response

    def _rpc(self, handle: _PreparedWorker, payload: Mapping[str, Any]) -> dict[str, Any]:
        with handle.rpc_lock:
            return self._rpc_unlocked(handle, payload)

    def prepare(self, profile: LocalWorkerProfile, *, operation_id: str, channel_id: str) -> _PreparedWorker:
        if self._active is not None:
            self.abort(self._active)
        parent, child = socket.socketpair()
        worker: subprocess.Popen[bytes] | None = None
        handle: _PreparedWorker | None = None
        try:
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
            # control RPC so owner shutdown can always fence and abort it.
            self._active = handle
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
        host = self._identity(int(host_data["pid"]), str(host_data["birth_id"]), self.profile.host_executable, self.profile.host_artifact_digest, parent_pid=worker.pid, session_owner=True)
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
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError("worker profile contains unsupported fields: " + ", ".join(unknown))
    worker_executable = _path(raw.get("worker_executable"), "worker_executable", directory=False)
    host_executable = _path(raw.get("host_executable"), "host_executable", directory=False)
    engine_executable = _path(raw.get("engine_executable"), "engine_executable", directory=False)
    listener_executable = _path(raw.get("engine_listener_executable"), "engine_listener_executable", directory=False)
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
        host_artifact_digest=str(raw.get("host_artifact_digest") or ""),
        engine_artifact_digest=str(raw.get("engine_artifact_digest") or ""),
        engine_listener_artifact_digest=str(raw.get("engine_listener_artifact_digest") or ""),
        session_config_digest=str(raw.get("session_config_digest") or ""),
        profile_revision=str(raw.get("profile_revision") or ""),
        profile_digest=str(raw.get("profile_digest") or ""),
        release_digest=str(raw.get("release_digest") or ""),
    )
    if profile.engine_endpoint != f"http://127.0.0.1:{engine_port}":
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
        environment={**{str(k): str(v) for k, v in environment.items()}, "ASTRID_WORKER_ENVIRONMENT": str(worker_environment)},
        timeout_seconds=float(raw.get("worker_timeout_seconds") or 900.0),
    )
    inspector = OSProcessInspector(profile)
    return LocalWorkerComposition({profile.profile_id: profile}, preparer, inspector)


__all__ = ["CrossProcessWorkerPreparer", "LocalWorkerComposition", "OSProcessInspector", "load_local_worker_composition"]
