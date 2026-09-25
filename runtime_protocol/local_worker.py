"""Runtime-owned issuance for one verified local Worker launch.

The process adapter is intentionally narrow.  I-06b supplies the parked Worker
implementation; this module owns the authority ordering and independently
checks the process facts supplied by an OS inspector before issuing anything.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .auth import CredentialStore
from .errors import ConflictError, ValidationError


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PREPARATION_VERSION = "runtime.local-worker-preparation/v2"
ACTIVATION_VERSION = "runtime.local-worker-activation/v1"
RECEIPT_VERSION = "runtime.local-worker-receipt/v2"


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
        self._active_receipt: dict[str, Any] | None = None
        existing = credentials.actor_metadata(actor)
        if existing and existing.get("local_launch_receipt"):
            # A durable bearer is not usable after owner restart until the
            # surviving process identity is independently revalidated.
            credentials.disable_actor(actor)

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

    def _abort(self, handle: object | None) -> None:
        if handle is None:
            return
        try:
            self.preparer.abort(handle)
        except Exception:
            # The adapter must itself signal only positively identified owned
            # children.  Cleanup failure cannot restore credential authority.
            pass

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
            self.credentials.enable_actor(self.actor)
            result = dict(receipt)
            result["state"] = "reconnected"
            self._active_receipt = dict(receipt)
            return result
        except Exception:
            self._abort(handle)
            raise

    def start(self, profile_id: str, expected_workspace_uuid: str) -> dict[str, Any]:
        if not self._operation_lock.acquire(blocking=False):
            raise ConflictError("a local worker launch operation is already in progress")
        handle: object | None = None
        credential_issued = False
        try:
            profile = self._profile(profile_id, expected_workspace_uuid)
            existing = self.credentials.actor_metadata(self.actor)
            if existing:
                self.credentials.disable_actor(self.actor)
                try:
                    reconnected = self._try_reconnect(profile, existing)
                except Exception:
                    self.credentials.revoke(self.actor)
                    raise
                if reconnected is not None:
                    return reconnected
                self.credentials.revoke(self.actor)

            operation_id = uuid.uuid4().hex
            channel_id = uuid.uuid4().hex
            handle = self.preparer.prepare(profile, operation_id=operation_id, channel_id=channel_id)
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
            self.credentials.enable_actor(self.actor)
            self._active_receipt = dict(receipt)
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
                self.credentials.revoke(self.actor)
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
