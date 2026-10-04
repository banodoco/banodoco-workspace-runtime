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
from .util import atomic_json_write


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PREPARATION_VERSION = "runtime.local-worker-preparation/v2"
ACTIVATION_VERSION = "runtime.local-worker-activation/v1"
RECEIPT_VERSION = "runtime.local-worker-receipt/v3"
RELAY_RECEIPT_VERSION = "runtime.local-worker-receipt/v4"
RELAY_PREPARATION_VERSION = "runtime.local-worker-preparation/v3"


def _receipt_version(profile):
    return RELAY_RECEIPT_VERSION if profile.engine_launch is not None else RECEIPT_VERSION


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
    # Framework interpreters can launch through one executable artifact while
    # the kernel reports a different executable for the live process (notably
    # macOS Python.framework).  These optional pins preserve both identities:
    # host_executable remains the launch artifact shared with the Worker ABI,
    # while the OS pins are used for independent live-process observation.
    host_os_executable: Path | None = None
    host_os_artifact_digest: str | None = None
    # Explicit selected Vibe package/launch/seam closure. Absence keeps the
    # historical profile on its legacy ABI; it never selects ambient Vibe.
    engine_launch: Mapping[str, Any] | None = None


def _selected_profile_payload(profile: LocalWorkerProfile) -> dict[str, Any]:
    from .local_execution_supervisor import PROFILE_FIELDS, validate_selected_profile
    payload = {name: str(getattr(profile, name)) if isinstance(getattr(profile, name), Path) else getattr(profile, name) for name in PROFILE_FIELDS}
    if profile.host_os_executable is not None:
        payload.update(host_os_executable=str(profile.host_os_executable), host_os_artifact_digest=profile.host_os_artifact_digest)
    return validate_selected_profile(payload)


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
    # Exact kernel/ps-rendered command line observed at issuance.  It is part
    # of receipt-v3 evidence and lets an adopter refuse to signal a different
    # process that merely reused a PID/group/executable tuple.
    command_line: str = ""
    # Lossless, length-delimited kernel argv digest.  The rendered command
    # remains diagnostic only because ps output cannot preserve boundaries.
    argv_digest: str = ""


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
    owner_epoch: str | None = None
    custody_scope: str | None = None
    custody_capabilities: Mapping[str, Any] | None = None


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
    def handoff_command(self, handle: object, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def export_control_descriptor(self, handle: object) -> int: ...
    def release_exported(self, handle: object) -> None: ...
    def adopt_control_descriptor(self, descriptor: int, receipt: Mapping[str, Any]) -> object: ...
    def abort_adopted_descriptor(self, descriptor: int, receipt: Mapping[str, Any]) -> None: ...


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


def _receipt_identity_digest_valid(
    profile: LocalWorkerProfile,
    receipt: Mapping[str, Any],
    *,
    workspace_uuid: str,
    realm_root: Path,
    support_root: Path,
) -> bool:
    """Validate the complete stable receipt projection and its digest.

    The Worker's parent is the sole stable-field exception: it can lawfully
    become PID 1 after a Runtime owner exits.  Every other serialized custody
    fact remains digest-bound exactly as it was at issuance.
    """

    identity_keys = {
        "profile_id", "workspace_uuid", "realm_root", "support_root",
        "machine_id", "uid", "worker", "host", "engine",
        "engine_listener", "cleanup_groups", "engine_binding",
        "session_config_digest", "profile_revision", "profile_digest",
        "release_digest",
    }
    if profile.engine_launch is not None:
        identity_keys |= {"owner_epoch", "custody_scope", "custody_capabilities", "profile_binding_digest"}
    if set(receipt) != identity_keys | {
        "version", "evidence_digest", "executor_incarnation",
    }:
        return False
    if (
        receipt.get("version") != _receipt_version(profile)
        or receipt.get("profile_id") != profile.profile_id
        or receipt.get("workspace_uuid") != str(workspace_uuid)
        or receipt.get("realm_root") != str(Path(realm_root))
        or receipt.get("support_root") != str(Path(support_root))
        or receipt.get("machine_id") != profile.machine_id
        or receipt.get("session_config_digest") != profile.session_config_digest
        or receipt.get("profile_revision") != profile.profile_revision
        or receipt.get("profile_digest") != profile.profile_digest
        or receipt.get("release_digest") != profile.release_digest
        or not isinstance(receipt.get("executor_incarnation"), str)
        or not receipt.get("executor_incarnation")
    ):
        return False
    projection = {key: receipt.get(key) for key in identity_keys}
    worker = projection.get("worker")
    if not isinstance(worker, Mapping):
        return False
    projection["worker"] = dict(worker)
    projection["worker"].pop("parent_pid", None)
    try:
        return receipt.get("evidence_digest") == _digest(projection)
    except (TypeError, ValueError):
        return False


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


@dataclass
class _OrderlyHandoff:
    handoff_id: str
    handle: object
    profile: LocalWorkerProfile
    identity: dict[str, Any]
    receipt: dict[str, Any]
    generation: dict[str, str]
    common: dict[str, Any]
    registered_state: dict[str, Any]
    phase: str
    old_owner: dict[str, Any] | None = None
    new_owner: dict[str, Any] | None = None


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
        self._orderly_handoff: _OrderlyHandoff | None = None
        self._cleanup_uncertain: str | None = None
        self._startup_receipt_rejection: str | None = None
        if any(profile.engine_launch is not None for profile in self.profiles.values()):
            marker = self.support_root / "orderly-handoff-cleanup-uncertain.json"
            if marker.exists():
                # Reuse the existing durable cleanup fence on owner restart;
                # credential revocation cannot erase an unresolved graph.
                self._cleanup_uncertain = "retained cleanup uncertainty requires capability recovery"
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
                receipt = existing.get("local_launch_receipt")
                profile = (
                    self.profiles.get(receipt.get("profile_id"))
                    if isinstance(receipt, Mapping) else None
                )
                if (
                    isinstance(receipt, Mapping)
                    and profile is not None
                    and receipt.get("workspace_uuid") == self.workspace_uuid
                    and receipt.get("profile_revision") == profile.profile_revision
                    and receipt.get("profile_digest") == profile.profile_digest
                    and receipt.get("release_digest") == profile.release_digest
                ):
                    self._startup_receipt_rejection = (
                        "existing local Worker receipt contradicts current profile authority"
                    )
                self._revoke_actor()

    def _revoke_actor(self) -> None:
        """Synchronously fence authentication even if durable cleanup fails."""
        self.credentials.disable_actor(self.actor)
        try:
            self.credentials.revoke(self.actor)
        except OSError:
            pass

    def _latch_cleanup_uncertain(self, reason: BaseException | str) -> None:
        """Persist a fail-closed replacement fence at the first cleanup failure."""

        message = type(reason).__name__ if isinstance(reason, BaseException) else str(reason)
        with self._state_lock:
            if self._cleanup_uncertain is None:
                self._cleanup_uncertain = message
        atomic_json_write(
            self.support_root / "orderly-handoff-cleanup-uncertain.json",
            {
                "version": 1,
                "state": "cleanup_uncertain",
                "runtime_pid": self.runtime_pid,
                "reason": self._cleanup_uncertain,
            },
        )

    def _receipt_shape_valid(self, metadata: Mapping[str, Any]) -> bool:
        receipt = metadata.get("local_launch_receipt")
        binding = metadata.get("execution_binding")
        if not isinstance(receipt, Mapping) or receipt.get("version") not in {RECEIPT_VERSION, RELAY_RECEIPT_VERSION}:
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
        expected_cleanup_groups = [
            {"role": "generic_pack_host", "leader": "host", "members": ["host"]},
            {
                "role": "engine",
                "leader": "engine",
                "members": ["engine", "engine_listener"],
            },
            {"role": "worker", "leader": "worker", "members": ["worker"]},
        ]
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
            and receipt.get("cleanup_groups") == expected_cleanup_groups
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
            and self._receipt_identity_digest_valid(profile, receipt)
        )

    def _receipt_identity_digest_valid(
        self, profile: LocalWorkerProfile, receipt: Mapping[str, Any],
    ) -> bool:
        return _receipt_identity_digest_valid(
            profile,
            receipt,
            workspace_uuid=self.workspace_uuid,
            realm_root=self.realm_root,
            support_root=self.support_root,
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
        if (profile.host_os_executable is None) != (profile.host_os_artifact_digest is None):
            raise ValidationError(
                "host_os_executable and host_os_artifact_digest must be provided together"
            )
        if profile.host_os_executable is not None:
            _absolute_pin(Path(profile.host_os_executable), "host_os_executable")
            _require_digest(str(profile.host_os_artifact_digest), "host_os_artifact_digest")
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
        if profile.engine_launch is not None:
            from .local_execution_supervisor import validate_selected_profile
            validate_selected_profile(_selected_profile_payload(profile))
        return profile

    @staticmethod
    def _process_payload(value: ProcessIdentity) -> dict[str, Any]:
        payload = asdict(value)
        payload["executable"] = str(value.executable)
        return payload

    def _identity_payload(self, profile: LocalWorkerProfile, observed: LocalWorkerObservation) -> dict[str, Any]:
        payload = {
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
            # State the independently-owned cleanup groups explicitly.  An
            # adopter must never infer the signal partition from field names.
            "cleanup_groups": [
                {"role": "generic_pack_host", "leader": "host", "members": ["host"]},
                {
                    "role": "engine",
                    "leader": "engine",
                    "members": ["engine", "engine_listener"],
                },
                {"role": "worker", "leader": "worker", "members": ["worker"]},
            ],
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
        if profile.engine_launch is not None:
            payload.update({"owner_epoch": observed.owner_epoch, "custody_scope": observed.custody_scope,
                            "custody_capabilities": json.loads(_canonical(observed.custody_capabilities)),
                            "profile_binding_digest": _digest(_selected_profile_payload(profile))})
        return payload

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
            executable=profile.host_os_executable or profile.host_executable,
            artifact_digest=profile.host_os_artifact_digest or profile.host_artifact_digest,
        )
        self._validate_process(
            observed.engine, label="engine", parent_pid=observed.host.pid if profile.engine_launch is not None else observed.worker.pid,
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
        if profile.engine_launch is not None:
            from .local_execution_supervisor import validate_role_reference
            if not isinstance(observed.owner_epoch, str) or not observed.owner_epoch or not isinstance(observed.custody_scope, str) or not Path(observed.custody_scope).is_absolute():
                raise ConflictError("relay observation lacks retained ownership epoch/scope")
            capabilities = observed.custody_capabilities
            if not isinstance(capabilities, Mapping) or set(capabilities) != {"relay", "host", "engine", "engine_listener"}:
                raise ConflictError("relay observation lacks independently verified role custody")
            for role, process in (("relay", observed.worker), ("host", observed.host), ("engine", observed.engine), ("engine_listener", observed.engine_listener)):
                validate_role_reference(capabilities[role], role=role, scope_root=observed.custody_scope, process={"pid": process.pid, "birth_id": process.birth_id})
                if capabilities[role]["target"]["uid"] != observed.uid:
                    raise ConflictError("relay custody target UID differs from observed owner")
            if report is not None and any(report.get(k) != v for k, v in {"owner_epoch": observed.owner_epoch, "custody_scope": observed.custody_scope, "custody_capabilities": capabilities, "profile_binding_digest": _digest(_selected_profile_payload(profile))}.items()):
                raise ConflictError("relay report conflicts with independently verified custody")
        if report is not None:
            expected_keys = {
                "version", "operation_id", "channel_id", "processes", "engine_binding",
                "session_config_digest",
            }
            if profile.engine_launch is not None:
                expected_keys |= {"owner_epoch", "custody_scope", "custody_capabilities", "profile_binding_digest"}
            if not isinstance(report, Mapping) or set(report) != expected_keys:
                raise ConflictError("Worker preparation report has an invalid shape")
            if report.get("version") != (RELAY_PREPARATION_VERSION if profile.engine_launch is not None else PREPARATION_VERSION) or report.get("operation_id") != operation_id or report.get("channel_id") != channel_id:
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
        failures: list[BaseException] = []
        def cleanup() -> None:
            try:
                self.preparer.abort(handle)
            except BaseException as exc:
                # The adapter must itself signal only positively identified
                # owned children. Cleanup failure cannot restore authority.
                failures.append(exc)
                self._latch_cleanup_uncertain(exc)

        thread = threading.Thread(target=cleanup, name="local-worker-abort", daemon=True)
        thread.start()
        thread.join(max(0.0, float(timeout)))
        if thread.is_alive():
            self._latch_cleanup_uncertain("cleanup_deadline_exceeded")

    def _control_alive(self, handle: object) -> bool:
        return bool(self.preparer.control_alive(handle))

    def is_idle(self) -> bool:
        """Whether remote credential control may use the shared Worker actor."""
        existing = self.credentials.actor_metadata(self.actor)
        restart_receipt_pending = (
            isinstance(existing, Mapping)
            and isinstance(existing.get("local_launch_receipt"), Mapping)
        )
        with self._state_lock:
            watcher_alive = bool(
                self._watch_thread is not None
                and self._watch_thread.is_alive()
                and not self._watch_stop.is_set()
            )
            return bool(
                not self._operation_lock.locked()
                and self._active_handle is None
                and self._preparing_handle is None
                and not watcher_alive
                and not restart_receipt_pending
            )

    def relinquish_handle(self, receipt: Mapping[str, Any]) -> object | None:
        """Fence this launcher's exact generation before owner-directed stop.

        The daemon has already disabled the bearer under the claim mutex.
        A surviving preparer handle is only usable when it belongs to the
        receipt being relinquished; restart reconciliation may have no handle.
        """
        if not self._operation_lock.acquire(blocking=False):
            raise ConflictError("a local Worker launch operation is in progress")
        try:
            with self._state_lock:
                if self._active_receipt is not None and self._active_receipt != dict(receipt):
                    raise ConflictError("local Worker generation changed")
                handle = self._active_handle
                if handle is None:
                    handle = self.preparer.current_handle()
                self._shutdown.set()
                self._watch_stop.set()
                self._active_handle = None
                self._active_profile = None
                self._active_identity = None
                self._active_receipt = None
                return handle
        finally:
            self._operation_lock.release()

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
            if self._active_profile is not None and self._active_profile.engine_launch is not None:
                from banodoco_local.custody_broker import _read_owner_file
                with self.credentials._lock:
                    record = json.loads(_read_owner_file(Path(self._active_identity["custody_scope"]) / "activation-record.json")[0])
                    commit = self.credentials.path_for(self.actor).with_suffix(".commit")
                    generation = "sha256:" + hashlib.sha256(_read_owner_file(commit)[0]).hexdigest()
                    metadata = self.credentials.actor_metadata(self.actor)
                    if record.get("credential_generation") != generation or record.get("executor_incarnation") != self._active_receipt.get("executor_incarnation") or metadata is None or metadata.get("local_launch_receipt") != self._active_receipt:
                        raise ConflictError("local activation credential generation changed before enablement")
                    self.credentials.enable_actor(self.actor)
            else:
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

    def prepare_orderly_handoff(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Pause an idle host without disabling or mutating owner authority."""

        handoff_id = str(request.get("handoff_id") or "")
        if not handoff_id:
            raise ValidationError("handoff_id is required")
        with self._operation_lock:
            with self._state_lock:
                if self._shutdown.is_set() or self._orderly_handoff is not None:
                    raise ConflictError("local Worker is not available for orderly handoff")
                handle = self._active_handle
                profile = self._active_profile
                identity = self._active_identity
                receipt = self._active_receipt
            if handle is None or profile is None or identity is None or receipt is None:
                raise ConflictError("no active local Worker can be handed off")
            if not self._control_alive(handle):
                raise ConflictError("local Worker control channel is not alive")
            generation = self.credentials.generation_snapshot(self.actor)
            if request.get("credential_generation") != generation:
                raise ConflictError("handoff credential generation changed")
            if request.get("receipt_evidence_digest") != receipt.get("evidence_digest"):
                raise ConflictError("handoff receipt evidence digest changed")
            response = dict(self.preparer.handoff_command(handle, request))
            if response.get("status") == "active_work":
                return {
                    "state": "active_work",
                    "handoff_id": handoff_id,
                    "ack": response,
                }
            host_ack = response.get("host_ack")
            registered_state = (
                host_ack.get("registered_state") if isinstance(host_ack, Mapping) else None
            )
            if not isinstance(registered_state, Mapping):
                raise ConflictError("handoff prepare acknowledgement lacks registered state")
            session = _OrderlyHandoff(
                handoff_id=handoff_id,
                handle=handle,
                profile=profile,
                identity=dict(identity),
                receipt=dict(receipt),
                generation=dict(generation),
                common={
                    key: request[key]
                    for key in (
                        "version",
                        "handoff_id",
                        "nonce_digest",
                        "sealed_record_digest",
                        "deadline_monotonic",
                        "deadline_unix_ms",
                    )
                },
                registered_state=dict(registered_state),
                phase="host_paused",
                old_owner=dict(request["old_owner"]),
            )
            with self._state_lock:
                if self._active_handle is not handle or self._orderly_handoff is not None:
                    raise ConflictError("local Worker ownership changed during handoff prepare")
                self._orderly_handoff = session
            return {
                "state": "host_paused",
                "handoff_id": handoff_id,
                "ack": response,
                "registered_state": dict(registered_state),
            }

    def orderly_handoff_source_facts(self) -> dict[str, Any]:
        """Return secret-free facts needed to bind A's sealed request."""

        with self._state_lock:
            handle = self._active_handle
            receipt = self._active_receipt
            identity = self._active_identity
        if handle is None or receipt is None or identity is None or not self._control_alive(handle):
            raise ConflictError("no live local Worker can be handed off")
        return {
            "receipt": dict(receipt),
            "identity": dict(identity),
            "credential_generation": self.credentials.generation_snapshot(self.actor),
        }

    def fence_orderly_handoff(self, handoff_id: str) -> dict[str, Any]:
        """Disable the retained bearer after the caller holds the DB fence."""

        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if session is None or session.handoff_id != handoff_id:
                    raise ConflictError("orderly handoff is not host-paused")
                if session.phase != "host_paused":
                    raise ConflictError("orderly handoff phase is invalid")
                if self._active_handle is not session.handle:
                    raise ConflictError("local Worker ownership changed before fencing")
                self.credentials.disable_actor(self.actor)
                if self.credentials.generation_snapshot(self.actor) != session.generation:
                    raise ConflictError("handoff credential generation changed while fencing")
                observed = self._validate_observation(
                    session.profile,
                    self.inspector.observe(session.handle),
                    report=None,
                    reconnect=True,
                )
                if observed != session.identity:
                    raise ConflictError("local Worker identity changed while fencing handoff")
                session.phase = "prepared"
                self._watch_stop.set()
                return {
                    "state": "PREPARED",
                    "handoff_id": handoff_id,
                    "receipt": dict(session.receipt),
                    "identity": dict(session.identity),
                    "credential_generation": dict(session.generation),
                    "registered_state": dict(session.registered_state),
                }

    def cancel_orderly_handoff(self, handoff_id: str, *, reason_code: str) -> None:
        """Rollback A custody before descriptor export."""

        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if session is None or session.handoff_id != handoff_id:
                    return
            payload = {
                **session.common,
                "command": "handoff_abort",
                "reason_code": str(reason_code),
                "old_owner": dict(session.old_owner or {}),
            }
            response = self.preparer.handoff_command(session.handle, payload)
            if response.get("worker_phase") != "owned":
                raise ConflictError("Worker did not restore owner A custody")
            if self.credentials.generation_snapshot(self.actor) != session.generation:
                raise ConflictError("handoff credential generation changed during rollback")
            self.credentials.enable_actor(self.actor)
            with self._state_lock:
                self._orderly_handoff = None
            self._start_watcher()

    def export_orderly_handoff(self, handoff_id: str) -> tuple[int, dict[str, Any]]:
        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if session is None or session.handoff_id != handoff_id or session.phase != "prepared":
                    raise ConflictError("orderly handoff is not prepared for export")
            descriptor = self.preparer.export_control_descriptor(session.handle)
            session.phase = "exported"
            return descriptor, {
                "receipt": dict(session.receipt),
                "identity": dict(session.identity),
                "credential_generation": dict(session.generation),
                "registered_state": dict(session.registered_state),
            }

    def seal_orderly_handoff(
        self, handoff_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Make Worker verify the nonce/export digest chain before FD release."""

        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if (
                    session is None
                    or session.handoff_id != handoff_id
                    or session.phase != "exported"
                ):
                    raise ConflictError("orderly handoff is not exported for sealing")
            response = dict(self.preparer.handoff_command(session.handle, request))
            if response.get("worker_phase") != "export_sealed":
                raise ConflictError("Worker did not verify the export seal")
            session.phase = "export_sealed"
            return response

    def release_exported_handoff(self, handoff_id: str) -> None:
        """Relinquish A's Worker descriptor after coordinator custody ack."""

        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if session is None or session.handoff_id != handoff_id or session.phase != "export_sealed":
                    raise ConflictError("orderly handoff was not exported")
                self._watch_stop.set()
                self._active_handle = None
                self._active_profile = None
                self._active_identity = None
                self._active_receipt = None
            self.preparer.release_exported(session.handle)
            session.phase = "released"

    def adopt_orderly_handoff(
        self,
        *,
        descriptor: int,
        profile_id: str,
        receipt: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Prepare B custody while retaining disabled registration-only authority."""

        with self._operation_lock:
            handle = None
            try:
                profile = self._profile(profile_id, self.workspace_uuid)
                if self._orderly_handoff is not None or self._active_handle is not None:
                    raise ConflictError("Runtime B already owns a local Worker")
                metadata = self.credentials.actor_metadata(self.actor)
                if not isinstance(metadata, Mapping) or metadata.get("local_launch_receipt") != receipt:
                    raise ConflictError("handoff receipt does not match retained credential metadata")
                generation = self.credentials.generation_snapshot(self.actor)
                if request.get("credential_generation") != generation:
                    raise ConflictError("handoff credential generation changed before adoption")
                # From this point B is the committed custodian. The cleanup
                # boundary begins before any fallible descriptor adaptation,
                # rather than after a fully constructed handle is returned.
                handle = self.preparer.adopt_control_descriptor(descriptor, receipt)
                first = self._validate_observation(
                    profile, self.inspector.observe(handle), report=None, reconnect=True
                )
                second = self._validate_observation(
                    profile, self.inspector.observe(handle), report=None, reconnect=True
                )
                if first != second or first.get("evidence_digest") != receipt.get("evidence_digest"):
                    raise ConflictError("handoff graph identity changed before adoption")
                response = dict(self.preparer.handoff_command(handle, request))
                if response.get("worker_phase") != "adopt_prepared":
                    raise ConflictError("Worker did not prepare adopter custody")
                host_ack = response.get("host_ack")
                registered_state = (
                    host_ack.get("registered_state")
                    if isinstance(host_ack, Mapping)
                    else None
                )
                if not isinstance(registered_state, Mapping):
                    raise ConflictError("handoff adopter acknowledgement lacks registered state")
                session = _OrderlyHandoff(
                    handoff_id=str(request["handoff_id"]),
                    handle=handle,
                    profile=profile,
                    identity=second,
                    receipt=dict(receipt),
                    generation=dict(generation),
                    common={
                        key: request[key]
                        for key in (
                            "version",
                            "handoff_id",
                            "nonce_digest",
                            "sealed_record_digest",
                            "deadline_monotonic",
                            "deadline_unix_ms",
                        )
                    },
                    registered_state=dict(registered_state),
                    phase="adopt_prepared",
                    old_owner=dict(request["old_owner"]),
                    new_owner=dict(request["new_owner"]),
                )
                self._install_active(handle, profile, second, receipt)
                self.credentials.disable_actor(self.actor)
                self._orderly_handoff = session
                return {
                    "state": "adopt_prepared",
                    "ack": response,
                    "registered_state": dict(registered_state),
                }
            except BaseException:
                self.credentials.disable_actor(self.actor)
                try:
                    # B already owns the preserved graph at this point.  A
                    # plain descriptor close would orphan the Worker, host,
                    # engine and listener.  Run the adopted non-child cleanup
                    # path, which uses receipt-bound full identities and
                    # deliberately never waitpid(2)s these processes.
                    if handle is None:
                        cleanup = getattr(self.preparer, "abort_adopted_descriptor", None)
                        if not callable(cleanup):
                            raise ConflictError(
                                "adopted descriptor cleanup capability is unavailable"
                            )
                        cleanup(descriptor, receipt)
                    else:
                        self.preparer.abort(handle)
                except BaseException as cleanup_error:
                    self._latch_cleanup_uncertain(cleanup_error)
                    raise ConflictError(
                        "adopted local Worker graph cleanup is uncertain"
                    ) from cleanup_error
                raise

    def _handoff_phase_command(
        self,
        handoff_id: str,
        *,
        command: str,
        extras: Mapping[str, Any],
        expected_phase: str,
    ) -> dict[str, Any]:
        with self._operation_lock:
            with self._state_lock:
                session = self._orderly_handoff
                if session is None or session.handoff_id != handoff_id:
                    raise ConflictError("orderly handoff adopter is unavailable")
            request = {**session.common, "command": command, **dict(extras)}
            response = dict(self.preparer.handoff_command(session.handle, request))
            if response.get("worker_phase") != expected_phase:
                raise ConflictError("Worker handoff phase acknowledgement is invalid")
            session.phase = expected_phase
            return response

    def commit_orderly_handoff(
        self, handoff_id: str, *, new_runtime: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._state_lock:
            session = self._orderly_handoff
            if session is None or session.phase != "adopt_prepared":
                raise ConflictError("orderly handoff is not adoption-prepared")
            if self.credentials.generation_snapshot(self.actor) != session.generation:
                raise ConflictError("handoff credential generation changed before commit")
            self.credentials.enable_actor(self.actor)
        try:
            return self._handoff_phase_command(
                handoff_id,
                command="handoff_commit",
                extras={
                    "new_owner": dict(session.new_owner or {}),
                    "new_runtime": dict(new_runtime),
                    "credential_generation": dict(session.generation),
                    "registered_state": dict(session.registered_state),
                },
                expected_phase="rebind_committed",
            )
        except BaseException:
            self.credentials.disable_actor(self.actor)
            raise

    def resume_orderly_handoff(
        self, handoff_id: str, *, new_runtime: Mapping[str, Any], commit: bool
    ) -> dict[str, Any]:
        expected_before = (
            frozenset({"resume_armed"})
            if commit
            else frozenset({"rebind_committed", "resume_armed"})
        )
        with self._state_lock:
            session = self._orderly_handoff
            if session is None or session.phase not in expected_before:
                raise ConflictError("orderly handoff resume phase is invalid")
        return self._handoff_phase_command(
            handoff_id,
            command="resume_commit" if commit else "resume_prepare",
            extras={
                "new_owner": dict(session.new_owner or {}),
                "new_runtime": dict(new_runtime),
            },
            expected_phase="resumed" if commit else "resume_armed",
        )

    def finalize_orderly_handoff(self, handoff_id: str) -> dict[str, Any]:
        """Terminally consume handoff authority before Runtime publishes ready."""

        with self._state_lock:
            session = self._orderly_handoff
            if session is None or session.handoff_id != handoff_id or session.phase != "resumed":
                raise ConflictError("orderly handoff has not completed resume")
            if self.credentials.generation_snapshot(self.actor) != session.generation:
                raise ConflictError("handoff credential generation changed before publication")
            new_runtime = session.registered_state.get("runtime")
            if not isinstance(new_runtime, Mapping):
                raise ConflictError("handoff registered Runtime identity is unavailable")
        request = {
            **session.common,
            "command": "handoff_finalize",
            "new_owner": dict(session.new_owner or {}),
        }
        response = self._handoff_phase_command(
            handoff_id,
            command="handoff_finalize",
            extras={"new_owner": dict(session.new_owner or {})},
            expected_phase="finalized",
        )
        with self._state_lock:
            if self._orderly_handoff is not session or session.phase != "finalized":
                raise ConflictError("orderly handoff terminal state changed")
            self._orderly_handoff = None
        self._start_watcher()
        host_ack = response.get("host_ack")
        if not isinstance(host_ack, Mapping):
            raise ConflictError("Worker final acknowledgement lacks the host acknowledgement")
        return {
            "request_digest": _digest(request),
            "worker_ack_digest": _digest(response),
            "host_ack_digest": _digest(host_ack),
            "ack": response,
        }

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

    def cleanup_receipt_snapshot(self) -> dict[str, Any] | None:
        """Return the secret-free receipt before shutdown clears custody."""

        with self._state_lock:
            return dict(self._active_receipt) if self._active_receipt is not None else None

    def begin_shutdown(self) -> list[object]:
        """Fence authority synchronously; return owned handles for later cleanup."""
        self._shutdown.set()
        self._watch_stop.set()
        self._prepare_cancel.set()
        with self._state_lock:
            active_before_fence = self._active_handle
            preparing_before_fence = self._preparing_handle
            owned_before_fence = (
                active_before_fence,
                preparing_before_fence,
                self.preparer.current_handle(),
            )
            self._revoke_actor()
            self._active_handle = None
            self._active_profile = None
            self._active_identity = None
            self._active_receipt = None
            self._preparing_handle = None
        cancel_current = getattr(self.preparer, "cancel_current", None)
        # A steady active graph is cleaned exactly once by finish_shutdown(),
        # where the acknowledgement and custody result remain observable.  The
        # cancellation hook exists for the narrower prepare-in-flight window;
        # using it for an already-active graph raced the watcher/cleanup path,
        # swallowed the concrete failure, and could leave only a generic
        # cleanup-uncertain latch even after every child had exited.
        cancel_prepare = active_before_fence is None
        if cancel_prepare and callable(cancel_current):
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
                    *owned_before_fence,
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
        failures = []
        for handle in handles:
            completed = threading.Event()
            failure: list[BaseException] = []

            def cleanup() -> None:
                try:
                    self.preparer.abort(handle)
                except BaseException as exc:
                    failure.append(exc)
                finally:
                    completed.set()

            thread = threading.Thread(target=cleanup, name="local-worker-final-cleanup", daemon=True)
            thread.start()
            timeout = max(
                1.0,
                float(getattr(
                    self.preparer,
                    "shutdown_timeout_seconds",
                    getattr(self.preparer, "cleanup_timeout_seconds", 0.1),
                )),
            )
            thread.join(timeout)
            if not completed.is_set():
                failures.append(ConflictError("local Worker cleanup exceeded its bounded deadline"))
            failures.extend(failure)
        uncertain = getattr(self.preparer, "cleanup_uncertain", None)
        if failures or uncertain:
            # Preserve a bounded, credential-free operational reason.  The
            # caller persists this after the private control channel is gone;
            # replacing it with a generic ConflictError made a failed ACK,
            # timeout, and malformed response indistinguishable in retained
            # product-down evidence.
            details: list[str] = []
            for failure in failures:
                value = " ".join(str(failure).split())[:384]
                details.append(f"{type(failure).__name__}:{value or 'no_detail'}")
            if uncertain:
                value = " ".join(str(uncertain).split())[:384]
                entry = f"preparer:{value or 'no_detail'}"
                if entry not in details:
                    details.append(entry)
            detail = ";".join(details)[:768]
            raise ConflictError(
                "local Worker graph cleanup is uncertain"
                + (f" [{detail}]" if detail else "")
            )

    def _try_reconnect(self, profile: LocalWorkerProfile, metadata: Mapping[str, Any]) -> dict[str, Any] | None:
        receipt = metadata.get("local_launch_receipt")
        if not isinstance(receipt, Mapping) or receipt.get("version") != _receipt_version(profile):
            raise ConflictError("surviving local Worker receipt shape or version is invalid")
        if receipt.get("profile_id") != profile.profile_id or receipt.get("workspace_uuid") != self.workspace_uuid:
            raise ConflictError("surviving local Worker receipt authority differs")
        if not self._receipt_identity_digest_valid(profile, receipt):
            raise ConflictError("surviving local Worker receipt identity digest is invalid")
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

    def _current_active_result(
        self, profile: LocalWorkerProfile, metadata: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Return the already-owned generation without reconnect side effects.

        A repeated start request can arrive while this Runtime still owns the
        active handle.  The durable credential is public-to-the-owner input,
        not cleanup custody: if its receipt or binding was replaced, reject it
        before disabling authority, reconnecting, preparing, or signaling the
        verified graph.  This also gives installed negative controls a real
        consumer boundary without corrupting cleanup authority.
        """

        with self._state_lock:
            handle = self._active_handle
            active_profile = self._active_profile
            active_identity = (
                dict(self._active_identity)
                if self._active_identity is not None else None
            )
            active_receipt = (
                dict(self._active_receipt)
                if self._active_receipt is not None else None
            )
        if handle is None:
            return None
        if active_profile != profile or active_identity is None or active_receipt is None:
            raise ConflictError("active local Worker custody is incomplete")
        receipt = metadata.get("local_launch_receipt")
        binding = metadata.get("execution_binding")
        verification = binding.get("verification") if isinstance(binding, Mapping) else None
        actual = binding.get("actual") if isinstance(binding, Mapping) else None
        if (
            not isinstance(receipt, Mapping)
            or dict(receipt) != active_receipt
            or not isinstance(binding, Mapping)
            or binding.get("executor_incarnation")
            != active_receipt.get("executor_incarnation")
            or not isinstance(verification, Mapping)
            or verification.get("verified") is not True
            or verification.get("evidence_digest")
            != active_receipt.get("evidence_digest")
            or not isinstance(actual, Mapping)
            or actual.get("kind") != "machine"
            or actual.get("id") != active_identity.get("machine_id")
            or actual.get("profile_revision") != profile.profile_revision
            or actual.get("profile_digest") != profile.profile_digest
            or actual.get("release_digest") != profile.release_digest
        ):
            raise ConflictError(
                "active local Worker durable receipt differs from Runtime custody"
            )
        observed = self.inspector.observe(handle)
        current = self._validate_observation(
            profile, observed, report=None, reconnect=True,
        )
        if current != active_identity:
            raise ConflictError("active local Worker identity changed")
        result = dict(active_receipt)
        result["state"] = "reconnected"
        return result

    def _activation_acceptor(self, *, handle, profile, report, identity, receipt, grant, credential_path):
        """Return the one Runtime-owned durable receipt publisher for a launch."""
        from banodoco_local.custody_broker import _read_owner_file, _atomic_owner_json
        expected_request = {
            "version": "astrid.local-worker-activation-request/v1",
            "operation_id": grant["operation_id"], "channel_id": grant["channel_id"],
            "grant": {k: grant[k] for k in ("activation_id", "credential_file", "executor_incarnation", "evidence_digest")},
            "host": {k: receipt["host"][k] for k in ("pid", "birth_id")},
        }
        with self.credentials._lock:
            generation = "sha256:" + hashlib.sha256(_read_owner_file(credential_path.with_suffix(".commit"))[0]).hexdigest()
            expected_metadata = self.credentials.actor_metadata(self.actor)
        scope = Path(identity["custody_scope"])
        record_path = scope / "activation-record.json"

        def accept(request):
            if not isinstance(request, Mapping) or dict(request) != expected_request:
                raise ConflictError("local activation request differs from exact grant/host")
            with self._state_lock, self.credentials._lock:
                if self._shutdown.is_set() or self._prepare_cancel.is_set() or self._preparing_handle is not handle:
                    raise ConflictError("local activation owner was fenced")
                current = self.credentials.actor_metadata(self.actor)
                current_generation = "sha256:" + hashlib.sha256(_read_owner_file(credential_path.with_suffix(".commit"))[0]).hexdigest()
                if current != expected_metadata or current_generation != generation or not isinstance(current, Mapping) or current.get("local_launch_receipt") != receipt:
                    raise ConflictError("local activation credential generation changed or was revoked")
                observed = self._validate_observation(profile, self.inspector.observe(handle), report=report,
                    operation_id=grant["operation_id"], channel_id=grant["channel_id"])
                if observed != identity:
                    raise ConflictError("local activation graph changed before durable acceptance")
                recorded = {**expected_request, "version": "runtime.local-worker-activation-recorded/v1"}
                record = {"version": "runtime.local-worker-activation-record/v1", "state": "recorded",
                    "operation_id": grant["operation_id"], "channel_id": grant["channel_id"],
                    "workspace_uuid": self.workspace_uuid, "profile_id": profile.profile_id,
                    "profile_digest": profile.profile_digest, "profile_binding_digest": identity["profile_binding_digest"],
                    "original_owner_epoch": identity["owner_epoch"], "host": receipt["host"],
                    "executor_incarnation": receipt["executor_incarnation"], "evidence_digest": receipt["evidence_digest"],
                    "custody_capabilities": identity["custody_capabilities"], "credential_generation": generation,
                    "request": expected_request, "receipt": recorded}
                if record_path.exists():
                    previous = json.loads(_read_owner_file(record_path)[0])
                    if previous != record:
                        raise ConflictError("local activation replay conflicts with durable acceptance")
                    # A previous writer may have lost its ACK after rename
                    # but before directory fsync. Replay reestablishes durability
                    # of the exact retained record before returning the receipt.
                    descriptor = os.open(record_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    directory = os.open(scope, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                else:
                    _atomic_owner_json(record_path, record)
                # _atomic_owner_json fsyncs file and containing directory before
                # this exact echo is allowed onto the private control channel.
                return json.loads(_canonical(recorded))
        return accept

    def start(self, profile_id: str, expected_workspace_uuid: str) -> dict[str, Any]:
        if not self._operation_lock.acquire(blocking=False):
            raise ConflictError("a local worker launch operation is already in progress")
        handle: object | None = None
        credential_issued = False
        try:
            if self._shutdown.is_set():
                raise ConflictError("Runtime owner is shutting down")
            if self._startup_receipt_rejection is not None:
                raise ConflictError(self._startup_receipt_rejection)
            if self._cleanup_uncertain is not None or getattr(self.preparer, "cleanup_uncertain", None):
                raise ConflictError("local Worker graph cleanup is uncertain")
            profile = self._profile(profile_id, expected_workspace_uuid)
            with self._state_lock:
                if self._shutdown.is_set():
                    raise ConflictError("Runtime owner is shutting down")
                self._prepare_cancel.clear()
            existing = self.credentials.actor_metadata(self.actor)
            if existing:
                active = self._current_active_result(profile, existing)
                if active is not None:
                    return active
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
                "version": _receipt_version(profile),
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
            if profile.engine_launch is not None:
                directory = os.open(credential_path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
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
            if profile.engine_launch is not None:
                grant.update(acceptance_mode="runtime-owner-receipt/v1", activation_id=uuid.uuid4().hex)
                bind = getattr(self.preparer, "bind_activation_acceptor", None)
                if not callable(bind):
                    raise ConflictError("local relay cannot retain Runtime activation receipt publisher")
                bind(handle, grant, self._activation_acceptor(handle=handle, profile=profile, report=report,
                    identity=second, receipt=receipt, grant=grant, credential_path=credential_path))
            self.preparer.activate(handle, grant)
            activated = self._validate_observation(
                profile, self.inspector.observe(handle), report=report,
                operation_id=operation_id, channel_id=channel_id,
            )
            if activated != second:
                raise ConflictError("activated local worker is not the verified parked host")
            seal_cleanup_receipt = getattr(
                self.preparer, "seal_cleanup_receipt", None
            )
            if callable(seal_cleanup_receipt):
                seal_cleanup_receipt(handle, receipt)
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
