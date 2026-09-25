"""Runtime-owned issuance for one verified local Worker launch.

The process adapter is intentionally narrow.  I-06b supplies the parked Worker
implementation; this module owns the authority ordering and independently
checks the process facts supplied by an OS inspector before issuing anything.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import uuid
import weakref
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .auth import CredentialStore
from .errors import ConflictError, ValidationError


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PREPARATION_VERSION = "runtime.local-worker-preparation/v2"
ACTIVATION_VERSION = "runtime.local-worker-activation/v1"
RECEIPT_VERSION = "runtime.local-worker-receipt/v3"


@dataclass(frozen=True)
class LocalWorkerProfile:
    profile_id: str
    workspace_uuid: str
    realm_root: Path
    support_root: Path
    machine_id: str
    worker_executable: Path
    host_executable: Path
    engine_executable: Path
    engine_listener_executable: Path
    engine_endpoint: str
    worker_artifact_digest: str
    host_artifact_digest: str
    engine_artifact_digest: str
    engine_listener_artifact_digest: str
    session_config_digest: str
    profile_revision: str
    profile_digest: str
    release_digest: str


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    birth_id: str
    uid: int
    parent_pid: int
    process_group: int
    session_id: int
    executable: Path
    artifact_digest: str


@dataclass(frozen=True)
class LocalWorkerObservation:
    machine_id: str
    uid: int
    workspace_uuid: str
    realm_root: Path
    support_root: Path
    worker: ProcessIdentity
    host: ProcessIdentity
    engine: ProcessIdentity
    engine_listener: ProcessIdentity
    engine_listener_socket_owner_pid: int
    engine_endpoint: str
    session_config_digest: str


class LocalWorkerPreparer(Protocol):
    def prepare(self, profile: LocalWorkerProfile, *, operation_id: str, channel_id: str) -> object: ...
    def report(self, handle: object) -> Mapping[str, Any]: ...
    # Deliver and accept the private grant, but do not wait for HTTP
    # registration: the bearer remains disabled until this method returns and
    # Runtime completes its final process-identity observation.
    def activate(self, handle: object, grant: Mapping[str, Any]) -> None: ...
    def abort(self, handle: object) -> None: ...
    def reconnect(self, receipt: Mapping[str, Any]) -> object | None: ...
    def control_alive(self, handle: object) -> bool: ...
    def current_handle(self) -> object | None: ...
    def set_prepare_cancel_event(self, event: threading.Event) -> None: ...
    def cancel_current(self) -> None: ...


class LocalWorkerInspector(Protocol):
    def observe(self, handle: object) -> LocalWorkerObservation: ...


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("local worker identity must be JSON-compatible") from exc


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _absolute_pin(value: Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValidationError(f"{label} must be absolute")
    if path.is_symlink():
        raise ValidationError(f"{label} must not be a symlink")
    return path


def _require_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValidationError(f"{label} must be a SHA-256 digest")
    return value


def _engine_endpoint(value: str) -> str:
    """Return one unambiguous local HTTP endpoint suitable for socket proof."""
    try:
        parsed = urlsplit(str(value))
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise ValidationError("engine_endpoint must be an HTTP loopback IP endpoint") from exc
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or not address.is_loopback
        or port is None
        or not 1 <= port <= 65535
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationError("engine_endpoint must be an HTTP loopback IP endpoint")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}:{port}"


class LocalWorkerLauncher:
    """Serialize prepare/verify/issue/activate for the reserved Worker actor."""

    def __init__(
        self,
        *,
        credentials: CredentialStore,
        profiles: Mapping[str, LocalWorkerProfile],
        preparer: LocalWorkerPreparer,
        inspector: LocalWorkerInspector,
        workspace_uuid: str,
        realm_root: Path,
        support_root: Path,
        runtime_pid: int,
        actor: str,
        scopes: tuple[str, ...],
    ):
        self.credentials = credentials
        self.profiles = dict(profiles)
        self.preparer = preparer
        self.inspector = inspector
        self.workspace_uuid = str(workspace_uuid)
        self.realm_root = Path(realm_root)
        self.support_root = Path(support_root)
        self.runtime_pid = int(runtime_pid)
        self.actor = actor
        self.scopes = tuple(scopes)
        self._operation_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._shutdown = threading.Event()
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._active_handle: object | None = None
        self._active_profile: LocalWorkerProfile | None = None
        self._active_identity: dict[str, Any] | None = None
        self._preparing_handle: object | None = None
        self._active_receipt: dict[str, Any] | None = None
        self._cleanup_handles: list[object] = []
        self._prepare_cancel = threading.Event()
        for method in ("control_alive", "current_handle"):
            if not callable(getattr(preparer, method, None)):
                raise ValueError(f"local worker preparer must implement {method}")
        set_cancel = getattr(preparer, "set_prepare_cancel_event", None)
        if callable(set_cancel):
            set_cancel(self._prepare_cancel)
        existing = credentials.actor_metadata(actor)
        if existing:
            # Every durable bearer is unusable after owner restart until the
            # surviving process identity is independently revalidated. A
            # pre-I-06 generation has no receipt and can never be revalidated.
            credentials.disable_actor(actor)
            if not self._receipt_shape_valid(existing):
                self._revoke_actor()

    def _revoke_actor(self) -> None:
        """Synchronously fence authentication even if durable cleanup fails."""
        self.credentials.disable_actor(self.actor)
        try:
            self.credentials.revoke(self.actor)
        except OSError:
            pass

    def _receipt_shape_valid(self, metadata: Mapping[str, Any]) -> bool:
        receipt = metadata.get("local_launch_receipt")
        binding = metadata.get("execution_binding")
        if not isinstance(receipt, Mapping) or receipt.get("version") != RECEIPT_VERSION:
            return False
        profile_id = receipt.get("profile_id")
        if not isinstance(profile_id, str):
            return False
        profile = self.profiles.get(profile_id)
        engine_binding = receipt.get("engine_binding")
        verification = binding.get("verification") if isinstance(binding, Mapping) else None
        actual = binding.get("actual") if isinstance(binding, Mapping) else None
        incarnation = receipt.get("executor_incarnation")
        evidence = receipt.get("evidence_digest")
        try:
            endpoint = _engine_endpoint(engine_binding.get("endpoint")) if isinstance(engine_binding, Mapping) else None
        except ValidationError:
            return False
        return bool(
            profile is not None
            and receipt.get("workspace_uuid") == self.workspace_uuid
            and isinstance(receipt.get("machine_id"), str) and bool(receipt.get("machine_id"))
            and isinstance(receipt.get("session_config_digest"), str)
            and bool(_DIGEST.fullmatch(receipt.get("session_config_digest")))
            and all(isinstance(receipt.get(name), Mapping) for name in ("worker", "host", "engine", "engine_listener"))
            and endpoint == profile.engine_endpoint
            and isinstance(incarnation, str) and incarnation
            and isinstance(evidence, str) and _DIGEST.fullmatch(evidence)
            and isinstance(binding, Mapping)
            and binding.get("executor_incarnation") == incarnation
            and isinstance(verification, Mapping)
            and verification.get("verified") is True
            and verification.get("evidence_digest") == evidence
            and isinstance(actual, Mapping)
            and actual.get("kind") == "machine"
            and actual.get("id") == receipt.get("machine_id")
            and actual.get("profile_revision") == profile.profile_revision
            and actual.get("profile_digest") == profile.profile_digest
            and actual.get("release_digest") == profile.release_digest
        )

    def _profile(self, profile_id: str, expected_workspace_uuid: str) -> LocalWorkerProfile:
        if not isinstance(profile_id, str) or not profile_id:
            raise ValidationError("profile_id is required")
        profile = self.profiles.get(profile_id)
        if profile is None:
            raise ValidationError("local worker profile is not installed")
        if not isinstance(expected_workspace_uuid, str) or not expected_workspace_uuid:
            raise ValidationError("expected_workspace_uuid is required")
        if expected_workspace_uuid != self.workspace_uuid or profile.workspace_uuid != self.workspace_uuid:
            raise ConflictError("local worker workspace identity does not match the selected Runtime realm")
        if Path(profile.realm_root) != self.realm_root or Path(profile.support_root) != self.support_root:
            raise ConflictError("local worker profile roots do not match Runtime authority")
        if not profile.machine_id:
            raise ValidationError("local worker profile machine identity is required")
        for field in (
            "worker_executable", "host_executable", "engine_executable",
            "engine_listener_executable",
        ):
            _absolute_pin(Path(getattr(profile, field)), field)
        if _engine_endpoint(profile.engine_endpoint) != profile.engine_endpoint:
            raise ValidationError("engine_endpoint must be canonical")
        for field in (
            "worker_artifact_digest", "host_artifact_digest", "engine_artifact_digest",
            "engine_listener_artifact_digest", "session_config_digest", "profile_digest",
            "release_digest",
        ):
            _require_digest(str(getattr(profile, field)), field)
        if not profile.profile_revision:
            raise ValidationError("profile_revision is required")
        return profile

    @staticmethod
    def _process_payload(value: ProcessIdentity) -> dict[str, Any]:
        payload = asdict(value)
        payload["executable"] = str(value.executable)
        return payload

    def _identity_payload(self, profile: LocalWorkerProfile, observed: LocalWorkerObservation) -> dict[str, Any]:
        return {
            "profile_id": profile.profile_id,
            "workspace_uuid": observed.workspace_uuid,
            "realm_root": str(observed.realm_root),
            "support_root": str(observed.support_root),
            "machine_id": observed.machine_id,
            "uid": observed.uid,
            "worker": self._process_payload(observed.worker),
            "host": self._process_payload(observed.host),
            "engine": self._process_payload(observed.engine),
            "engine_listener": self._process_payload(observed.engine_listener),
            "engine_binding": {
                "supervisor_pid": observed.engine.pid,
                "listener_pid": observed.engine_listener.pid,
                "listener_parent_pid": observed.engine_listener.parent_pid,
                "socket_owner_pid": observed.engine_listener_socket_owner_pid,
                "endpoint": observed.engine_endpoint,
            },
            "session_config_digest": observed.session_config_digest,
            "profile_revision": profile.profile_revision,
            "profile_digest": profile.profile_digest,
            "release_digest": profile.release_digest,
        }

    def _validate_process(
        self,
        value: ProcessIdentity,
        *,
        label: str,
        parent_pid: int | None,
        executable: Path,
        artifact_digest: str,
        require_session_owner: bool = True,
    ) -> None:
        if value.pid <= 0 or not value.birth_id:
            raise ConflictError(f"{label} process identity is incomplete")
        if value.uid != getattr(os, "getuid", lambda: value.uid)():
            raise ConflictError(f"{label} process uid does not match Runtime owner")
        if parent_pid is not None and value.parent_pid != parent_pid:
            raise ConflictError(f"{label} process parent lineage is invalid")
        if require_session_owner and (value.process_group != value.pid or value.session_id != value.pid):
            raise ConflictError(f"{label} process does not own its process group and session")
        if Path(value.executable) != Path(executable):
            raise ConflictError(f"{label} executable pin does not match")
        if value.artifact_digest != artifact_digest:
            raise ConflictError(f"{label} artifact pin does not match")

    def _validate_observation(
        self,
        profile: LocalWorkerProfile,
        observed: LocalWorkerObservation,
        *,
        report: Mapping[str, Any] | None,
        operation_id: str | None = None,
        channel_id: str | None = None,
        reconnect: bool = False,
    ) -> dict[str, Any]:
        if observed.machine_id != profile.machine_id:
            raise ConflictError("observed machine identity does not match the installed profile")
        if observed.uid != getattr(os, "getuid", lambda: observed.uid)():
            raise ConflictError("observed owner uid does not match Runtime")
        if observed.workspace_uuid != self.workspace_uuid:
            raise ConflictError("observed workspace identity does not match Runtime")
        if Path(observed.realm_root) != self.realm_root or Path(observed.support_root) != self.support_root:
            raise ConflictError("observed local worker roots do not match Runtime")
        self._validate_process(
            # The original Runtime parent is part of initial launch lineage,
            # but a surviving Worker may be reparented after that Runtime
            # exits. Its PID birth identity, UID, group/session and pins remain
            # mandatory during a reconnect.
            observed.worker, label="worker", parent_pid=None if reconnect else self.runtime_pid,
            executable=profile.worker_executable, artifact_digest=profile.worker_artifact_digest,
        )
        self._validate_process(
            observed.host, label="host", parent_pid=observed.worker.pid,
            executable=profile.host_executable, artifact_digest=profile.host_artifact_digest,
        )
        self._validate_process(
            observed.engine, label="engine", parent_pid=observed.worker.pid,
            executable=profile.engine_executable, artifact_digest=profile.engine_artifact_digest,
        )
        self._validate_process(
            observed.engine_listener, label="engine listener", parent_pid=observed.engine.pid,
            executable=profile.engine_listener_executable,
            artifact_digest=profile.engine_listener_artifact_digest,
            require_session_owner=False,
        )
        if (
            observed.engine_listener.process_group != observed.engine.process_group
            or observed.engine_listener.session_id != observed.engine.session_id
        ):
            raise ConflictError("engine listener is outside the verified engine process group or session")
        if len({
            observed.worker.pid,
            observed.host.pid,
            observed.engine.pid,
            observed.engine_listener.pid,
        }) != 4:
            raise ConflictError("local worker process identities must be distinct")
        if observed.engine_listener_socket_owner_pid != observed.engine_listener.pid:
            raise ConflictError("engine listener socket is not owned by the verified listener process")
        if observed.engine_endpoint != profile.engine_endpoint:
            raise ConflictError("observed engine endpoint does not match the installed profile")
        if observed.session_config_digest != profile.session_config_digest:
            raise ConflictError("engine session configuration does not match the installed profile")
        if report is not None:
            expected_keys = {
                "version", "operation_id", "channel_id", "processes", "engine_binding",
                "session_config_digest",
            }
            if not isinstance(report, Mapping) or set(report) != expected_keys:
                raise ConflictError("Worker preparation report has an invalid shape")
            if report.get("version") != PREPARATION_VERSION or report.get("operation_id") != operation_id or report.get("channel_id") != channel_id:
                raise ConflictError("Worker preparation report came from the wrong private channel")
            process_reports = report.get("processes")
            if not isinstance(process_reports, Mapping) or set(process_reports) != {
                "worker", "host", "engine", "engine_listener",
            }:
                raise ConflictError("Worker preparation process report is invalid")
            for name, identity in (
                ("worker", observed.worker),
                ("host", observed.host),
                ("engine", observed.engine),
                ("engine_listener", observed.engine_listener),
            ):
                item = process_reports.get(name)
                if not isinstance(item, Mapping) or set(item) != {"pid", "birth_id"}:
                    raise ConflictError("Worker preparation process report is invalid")
                if item.get("pid") != identity.pid or item.get("birth_id") != identity.birth_id:
                    raise ConflictError("Worker preparation report conflicts with OS observation")
            expected_binding = {
                "supervisor_pid": observed.engine.pid,
                "listener_pid": observed.engine_listener.pid,
                "listener_parent_pid": observed.engine_listener.parent_pid,
                "socket_owner_pid": observed.engine_listener_socket_owner_pid,
            }
            binding = report.get("engine_binding")
            if (
                not isinstance(binding, Mapping)
                or set(binding) != set(expected_binding)
                or dict(binding) != expected_binding
                or report.get("session_config_digest") != observed.session_config_digest
            ):
                raise ConflictError("Worker preparation report conflicts with engine observation")
        payload = self._identity_payload(profile, observed)
        stable_identity = dict(payload)
        stable_identity["worker"] = dict(payload["worker"])
        # Runtime PID/epoch is not executor identity. Excluding only the
        # Worker's mutable parent preserves a stable digest for the same
        # surviving process while all immutable birth and launch pins remain.
        stable_identity["worker"].pop("parent_pid")
        payload["evidence_digest"] = _digest(stable_identity)
        return payload

    def _abort(self, handle: object | None, *, timeout: float = 1.0) -> None:
        if handle is None:
            return
        with self._state_lock:
            if any(handle is current for current in self._cleanup_handles):
                return
            self._cleanup_handles.append(handle)
        def cleanup() -> None:
            try:
                self.preparer.abort(handle)
            except BaseException:
                # The adapter must itself signal only positively identified
                # owned children. Cleanup failure cannot restore authority.
                pass

        thread = threading.Thread(target=cleanup, name="local-worker-abort", daemon=True)
        thread.start()
        thread.join(max(0.0, float(timeout)))

    def _control_alive(self, handle: object) -> bool:
        return bool(self.preparer.control_alive(handle))

    def _install_active(
        self,
        handle: object,
        profile: LocalWorkerProfile,
        identity: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        with self._state_lock:
            if self._shutdown.is_set():
                raise ConflictError("Runtime owner is shutting down")
            if self._active_handle is not None and self._active_handle is not handle:
                # A reconnect failure can fall through to a fresh launch while
                # the previous generation's watcher is still healthy. Retire
                # its event before _start_watcher evaluates the old thread.
                self._watch_stop.set()
            self._active_handle = handle
            self._active_profile = profile
            self._active_identity = dict(identity)
            self._active_receipt = dict(receipt)
            self._preparing_handle = None

    def _enable_active_generation(self, handle: object) -> None:
        """Enable a bearer only while this exact generation still owns it."""
        with self._state_lock:
            if self._shutdown.is_set() or self._active_handle is not handle:
                raise ConflictError("local Worker generation is no longer active")
            # Fencing and enablement share the lifecycle lock. A failed durable
            # revoke therefore cannot be followed by a stale enable operation.
            self.credentials.enable_actor(self.actor)

    def _start_watcher(self) -> None:
        with self._state_lock:
            if self._shutdown.is_set() or self._active_handle is None:
                return
            if (
                self._watch_thread is not None
                and self._watch_thread.is_alive()
                and not self._watch_stop.is_set()
            ):
                return
            # A failed generation may still be unwinding its final check. Use
            # a fresh stop event and capture the handle so that old watcher
            # work cannot fence a replacement generation.
            stop = threading.Event()
            handle = self._active_handle
            self._watch_stop = stop
            self._watch_thread = threading.Thread(
                target=self._watch_liveness,
                args=(weakref.ref(self), stop, handle),
                name="local-worker-liveness",
                daemon=True,
            )
            self._watch_thread.start()

    @staticmethod
    def _watch_liveness(
        owner_ref: "weakref.ReferenceType[LocalWorkerLauncher]",
        stop: threading.Event,
        handle: object,
    ) -> None:
        while not stop.wait(1.0):
            owner = owner_ref()
            if owner is None or not owner.check_liveness(handle):
                return
            del owner

    def check_liveness(self, expected_handle: object | None = None) -> bool:
        """Run one deterministic owner-side liveness check and fence on loss."""
        with self._state_lock:
            handle = self._active_handle
            profile = self._active_profile
            expected = self._active_identity
        if expected_handle is not None and handle is not expected_handle:
            # This watcher belongs to an older generation. It must not fence
            # a replacement that was activated before the old thread exited.
            return True
        if handle is None or profile is None or expected is None:
            return False
        try:
            if not self._control_alive(handle):
                raise ConflictError("local Worker control channel is not alive")
            current = self._validate_observation(
                profile, self.inspector.observe(handle), report=None, reconnect=True
            )
            if current != expected:
                raise ConflictError("active local Worker identity changed")
            return True
        except BaseException:
            self._fence_generation(handle, abort=True)
            return False

    def _fence_generation(self, handle: object, *, abort: bool) -> bool:
        with self._state_lock:
            if self._active_handle is not handle and self._preparing_handle is not handle:
                return False
            self._revoke_actor()
            if self._active_handle is handle:
                self._active_handle = None
                self._active_profile = None
                self._active_identity = None
                self._active_receipt = None
            if self._preparing_handle is handle:
                self._preparing_handle = None
            self._watch_stop.set()
        if abort:
            self._abort(handle)
        return True

    def begin_shutdown(self) -> list[object]:
        """Fence authority synchronously; return owned handles for later cleanup."""
        self._shutdown.set()
        self._watch_stop.set()
        self._prepare_cancel.set()
        with self._state_lock:
            self._revoke_actor()
            self._active_handle = None
            self._active_profile = None
            self._active_identity = None
            self._active_receipt = None
            self._preparing_handle = None
        cancel_current = getattr(self.preparer, "cancel_current", None)
        if callable(cancel_current):
            try:
                cancel_current()
            except BaseException:
                # Authority is already fenced. Cleanup is retried through the
                # bounded handle path below and must not make stop unbounded.
                pass
        # A request thread may already be inside prepare(). Let the bounded
        # cancellation above unwind that operation before Runtime closes its
        # HTTP/server state. Adapters without cancellation still get a hard
        # upper bound; their late result is rejected by _shutdown and aborted
        # by start()'s exception path.
        acquired = self._operation_lock.acquire(timeout=1.0)
        if acquired:
            self._operation_lock.release()
        with self._state_lock:
            handles = [
                value for value in (
                    self._active_handle,
                    self._preparing_handle,
                    self.preparer.current_handle(),
                )
                if value is not None
            ]
        unique = []
        for handle in handles:
            if not any(handle is current for current in unique):
                unique.append(handle)
        return unique

    def finish_shutdown(self, handles: list[object]) -> None:
        watcher = self._watch_thread
        if watcher is not None and watcher is not threading.current_thread():
            watcher.join(0.5)
        for handle in handles:
            self._abort(handle)

    def _try_reconnect(self, profile: LocalWorkerProfile, metadata: Mapping[str, Any]) -> dict[str, Any] | None:
        receipt = metadata.get("local_launch_receipt")
        if not isinstance(receipt, Mapping) or receipt.get("version") != RECEIPT_VERSION:
            return None
        if receipt.get("profile_id") != profile.profile_id or receipt.get("workspace_uuid") != self.workspace_uuid:
            return None
        handle = self.preparer.reconnect(receipt)
        if handle is None:
            return None
        try:
            observed = self.inspector.observe(handle)
            identity = self._validate_observation(profile, observed, report=None, reconnect=True)
            if identity.get("evidence_digest") != receipt.get("evidence_digest"):
                raise ConflictError("surviving local worker identity changed")
            binding = metadata.get("execution_binding")
            verification = binding.get("verification") if isinstance(binding, Mapping) else None
            actual = binding.get("actual") if isinstance(binding, Mapping) else None
            if (
                not isinstance(binding, Mapping)
                or binding.get("executor_incarnation") != receipt.get("executor_incarnation")
                or not isinstance(verification, Mapping)
                or verification.get("verified") is not True
                or verification.get("evidence_digest") != receipt.get("evidence_digest")
                or not isinstance(actual, Mapping)
                or actual.get("kind") != "machine"
                or actual.get("id") != identity.get("machine_id")
                or actual.get("profile_revision") != profile.profile_revision
                or actual.get("profile_digest") != profile.profile_digest
                or actual.get("release_digest") != profile.release_digest
            ):
                raise ConflictError("surviving local worker incarnation is inconsistent")
            result = dict(receipt)
            result["state"] = "reconnected"
            self._install_active(handle, profile, identity, receipt)
            self._enable_active_generation(handle)
            self._start_watcher()
            return result
        except Exception:
            if not self._fence_generation(handle, abort=True):
                self._abort(handle)
            raise

    def start(self, profile_id: str, expected_workspace_uuid: str) -> dict[str, Any]:
        if not self._operation_lock.acquire(blocking=False):
            raise ConflictError("a local worker launch operation is already in progress")
        handle: object | None = None
        credential_issued = False
        try:
            if self._shutdown.is_set():
                raise ConflictError("Runtime owner is shutting down")
            profile = self._profile(profile_id, expected_workspace_uuid)
            with self._state_lock:
                if self._shutdown.is_set():
                    raise ConflictError("Runtime owner is shutting down")
                self._prepare_cancel.clear()
            existing = self.credentials.actor_metadata(self.actor)
            if existing:
                self.credentials.disable_actor(self.actor)
                try:
                    reconnected = self._try_reconnect(profile, existing)
                except Exception:
                    self._revoke_actor()
                    raise
                if reconnected is not None:
                    return reconnected
                self._revoke_actor()

            operation_id = uuid.uuid4().hex
            channel_id = uuid.uuid4().hex
            handle = self.preparer.prepare(profile, operation_id=operation_id, channel_id=channel_id)
            with self._state_lock:
                if self._shutdown.is_set():
                    raise ConflictError("Runtime owner is shutting down")
                self._preparing_handle = handle
            report = self.preparer.report(handle)
            first = self._validate_observation(
                profile, self.inspector.observe(handle), report=report,
                operation_id=operation_id, channel_id=channel_id,
            )
            second = self._validate_observation(
                profile, self.inspector.observe(handle), report=report,
                operation_id=operation_id, channel_id=channel_id,
            )
            if first != second:
                raise ConflictError("local worker identity changed before credential issuance")
            incarnation = uuid.uuid4().hex
            receipt = {
                "version": RECEIPT_VERSION,
                **second,
                "executor_incarnation": incarnation,
            }
            binding = {
                "actual": {
                    "kind": "machine",
                    "id": second["machine_id"],
                    "profile_revision": profile.profile_revision,
                    "profile_digest": profile.profile_digest,
                    "release_digest": profile.release_digest,
                },
                "verification": {
                    "method": "credential_claim",
                    "verified": True,
                    "evidence_digest": second["evidence_digest"],
                },
                "executor_incarnation": incarnation,
            }
            _token, credential_path = self.credentials.provision(
                self.actor,
                list(self.scopes),
                metadata={"execution_binding": binding, "local_launch_receipt": receipt},
                enabled=False,
            )
            credential_issued = True
            final = self._validate_observation(
                profile, self.inspector.observe(handle), report=report,
                operation_id=operation_id, channel_id=channel_id,
            )
            if final != second:
                raise ConflictError("local worker identity changed after credential issuance")
            grant = {
                "version": ACTIVATION_VERSION,
                "operation_id": operation_id,
                "channel_id": channel_id,
                "credential_file": str(credential_path),
                "executor_incarnation": incarnation,
                "evidence_digest": second["evidence_digest"],
            }
            self.preparer.activate(handle, grant)
            activated = self._validate_observation(
                profile, self.inspector.observe(handle), report=report,
                operation_id=operation_id, channel_id=channel_id,
            )
            if activated != second:
                raise ConflictError("activated local worker is not the verified parked host")
            # Publication is last: neither the parked process nor another
            # holder of the file can authenticate before the private grant is
            # accepted and the same process identity is observed once more.
            self._install_active(handle, profile, activated, receipt)
            self._enable_active_generation(handle)
            self._start_watcher()
            return {
                "state": "active",
                "operation_id": operation_id,
                "profile_id": profile.profile_id,
                "workspace_uuid": self.workspace_uuid,
                "machine_id": second["machine_id"],
                "executor_incarnation": incarnation,
                "evidence_digest": second["evidence_digest"],
            }
        except Exception:
            if credential_issued:
                self._revoke_actor()
            with self._state_lock:
                if self._preparing_handle is handle:
                    self._preparing_handle = None
                if self._active_handle is handle:
                    self._active_handle = None
                    self._active_profile = None
                    self._active_identity = None
                    self._active_receipt = None
                    self._watch_stop.set()
            self._abort(handle)
            raise
        finally:
            self._operation_lock.release()


__all__ = [
    "ACTIVATION_VERSION",
    "LocalWorkerInspector",
    "LocalWorkerLauncher",
    "LocalWorkerObservation",
    "LocalWorkerPreparer",
    "LocalWorkerProfile",
    "PREPARATION_VERSION",
    "ProcessIdentity",
    "RECEIPT_VERSION",
]
