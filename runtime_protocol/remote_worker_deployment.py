"""Immutable deployment references and deterministic worker launch projection.

This module is deliberately a pure, stdlib-only boundary.  It describes the
already-admitted work and the already-selected worker profile; it does not
issue credentials, mutate Runtime authority, claim work, or contact a
provider.  A coordinator can use the resulting argument vector and
environment policy as the single handoff to a remote generic host.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from .local_worker import LocalWorkerProfile
from .store import task_spec_for_request_hash
from .util import canonical_json


SCHEMA_VERSION = 1
PROJECTION_VERSION = "runtime.remote-worker-deployment/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$")
_SECRET_PREFIXES = ("rpa_", "sk-", "ghp_", "xoxb-")


class DeploymentReferenceError(ValueError):
    """The deployment reference is incomplete, unsafe, or contradictory."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeploymentReferenceError(f"{field} is required")
    value = value.strip()
    if any(char in value for char in "\x00\r\n"):
        raise DeploymentReferenceError(f"{field} contains a control character")
    return value


def _identifier(value: Any, field: str) -> str:
    value = _text(value, field)
    if _ID.fullmatch(value) is None:
        raise DeploymentReferenceError(f"{field} is not a valid reference")
    return value


def _digest(value: Any, field: str) -> str:
    value = _text(value, field).lower()
    if _DIGEST.fullmatch(value) is None:
        raise DeploymentReferenceError(f"{field} must be a sha256 digest")
    return value


def _computed_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _absolute_path(value: Any, field: str) -> Path:
    if isinstance(value, Path):
        path = value.expanduser()
    else:
        path = Path(_text(value, field)).expanduser()
    if not path.is_absolute():
        raise DeploymentReferenceError(f"{field} must be absolute")
    if path.is_symlink():
        raise DeploymentReferenceError(f"{field} must not be a symlink")
    return path


def _optional_absolute_path(value: Any, field: str) -> Path | None:
    if value in (None, ""):
        return None
    return _absolute_path(value, field)


def _bare_digest(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    text = _text(value, field).removeprefix("sha256:").lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise DeploymentReferenceError(f"{field} must be a SHA-256 digest")
    return text


def _credential_path(value: Any) -> Path:
    text = _secret_free_reference(value, "credential_ref")
    if text.startswith("file:"):
        text = text[5:]
    return _absolute_path(text, "credential file")


def _endpoint(value: Any) -> str:
    value = _text(value, "runtime_endpoint")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DeploymentReferenceError("runtime_endpoint must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DeploymentReferenceError("runtime_endpoint must not contain credentials or query data")
    if parsed.path not in {"", "/"}:
        raise DeploymentReferenceError("runtime_endpoint must not contain a path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise DeploymentReferenceError("runtime_endpoint has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise DeploymentReferenceError("runtime_endpoint port is out of range")
    return value.rstrip("/")


def _secret_free_reference(value: Any, field: str) -> str:
    value = _text(value, field)
    if value.lower().startswith(_SECRET_PREFIXES):
        raise DeploymentReferenceError(f"{field} must be a reference, not a secret")
    return value


def _target(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise DeploymentReferenceError(f"{field} must be a non-empty object")
    try:
        return json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError) as exc:
        raise DeploymentReferenceError(f"{field} must be JSON-compatible") from exc


def _object_id(value: Any, field: str) -> str:
    match = _OBJECT_ID.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise DeploymentReferenceError(f"{field} must be a sha256 object ID")
    return "sha256:" + match.group(1)


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdmissionIdentity:
    """The immutable identity Runtime admitted for one task/run."""

    task_id: str
    run_id: str
    project_id: str | None
    idempotency_key: str
    admission_digest: str
    spec_digest: str
    request_digest: str

    def __post_init__(self) -> None:
        for field in ("task_id", "run_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), f"admission.{field}"))
        idempotency_key = _text(self.idempotency_key, "admission.idempotency_key")
        if _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise DeploymentReferenceError("admission.idempotency_key is not a valid Runtime key")
        object.__setattr__(self, "idempotency_key", idempotency_key)
        if self.project_id is not None:
            object.__setattr__(self, "project_id", _identifier(self.project_id, "admission.project_id"))
        for field in ("admission_digest", "spec_digest", "request_digest"):
            object.__setattr__(self, field, _digest(getattr(self, field), f"admission.{field}"))


@dataclass(frozen=True)
class CapabilityIdentity:
    """Runtime's capability id and registered definition digest."""

    capability_id: str
    capability_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "capability_id", _identifier(self.capability_id, "capability.id"))
        object.__setattr__(self, "capability_digest", _digest(self.capability_digest, "capability.digest"))


@dataclass(frozen=True)
class InputBinding:
    """One ordered Runtime input binding.

    Runtime's canonical input identity is the ordered ``input_object_ids``
    mirror of ``execution_request.inputs``.  The digest is therefore a
    repeated, explicit witness of the same immutable object identity.
    """

    name: str
    object_id: str
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, "input.name"))
        object_id = _object_id(self.object_id, "input.object_id")
        digest = _object_id(self.digest, "input.digest")
        if object_id != digest:
            raise DeploymentReferenceError("input digest conflicts with object_id")
        object.__setattr__(self, "object_id", object_id)
        object.__setattr__(self, "digest", digest)


@dataclass(frozen=True)
class PlacementIdentity:
    """Runtime-authorized placement, retaining the immutable original target."""

    original_target: Mapping[str, Any]
    effective_target: Mapping[str, Any]
    placement_version: int = 0
    recovery_decision_digest: str | None = None

    def __post_init__(self) -> None:
        original = _target(self.original_target, "placement.original_target")
        effective = _target(self.effective_target, "placement.effective_target")
        object.__setattr__(self, "original_target", original)
        object.__setattr__(self, "effective_target", effective)
        if isinstance(self.placement_version, bool) or not isinstance(self.placement_version, int) or self.placement_version < 0:
            raise DeploymentReferenceError("placement.placement_version must be a non-negative integer")
        digest = None if self.recovery_decision_digest in (None, "") else _digest(self.recovery_decision_digest, "placement.recovery_decision_digest")
        if self.placement_version == 0 and digest is not None:
            raise DeploymentReferenceError("initial placement cannot carry a recovery decision digest")
        if self.placement_version > 0 and digest is None:
            raise DeploymentReferenceError("recovered placement requires a recovery decision digest")
        object.__setattr__(self, "recovery_decision_digest", digest)


@dataclass(frozen=True)
class DeploymentBinding:
    """The small Runtime-owned contract consumed by Astrid freshness checks."""

    admission_identity: AdmissionIdentity
    capability_identity: CapabilityIdentity
    input_bindings: tuple[InputBinding, ...]
    placement: PlacementIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.admission_identity, AdmissionIdentity):
            raise DeploymentReferenceError("deployment admission identity is required")
        if not isinstance(self.capability_identity, CapabilityIdentity):
            raise DeploymentReferenceError("deployment capability identity is required")
        inputs = tuple(self.input_bindings)
        if any(not isinstance(item, InputBinding) for item in inputs):
            raise DeploymentReferenceError("deployment input bindings are invalid")
        if len({item.name for item in inputs}) != len(inputs) or len({item.object_id for item in inputs}) != len(inputs):
            raise DeploymentReferenceError("deployment input bindings must be unique")
        if not isinstance(self.placement, PlacementIdentity):
            raise DeploymentReferenceError("deployment placement identity is required")
        object.__setattr__(self, "input_bindings", inputs)

    def as_dict(self) -> dict[str, Any]:
        return {
            "admission": {
                "task_id": self.admission_identity.task_id,
                "run_id": self.admission_identity.run_id,
                "project_id": self.admission_identity.project_id,
                "idempotency_key": self.admission_identity.idempotency_key,
                "admission_digest": self.admission_identity.admission_digest,
                "spec_digest": self.admission_identity.spec_digest,
                "request_digest": self.admission_identity.request_digest,
            },
            "capability": {
                "capability_id": self.capability_identity.capability_id,
                "capability_digest": self.capability_identity.capability_digest,
            },
            "inputs": [
                {"name": item.name, "object_id": item.object_id, "digest": item.digest}
                for item in self.input_bindings
            ],
            "placement": {
                "original_target": self.placement.original_target,
                "effective_target": self.placement.effective_target,
                "placement_version": self.placement.placement_version,
                "recovery_decision_digest": self.placement.recovery_decision_digest,
            },
        }

    def digest(self) -> str:
        return _sha256(self.as_dict())


@dataclass(frozen=True)
class ArtifactReference:
    """One executable/dependency artifact, identified without its contents."""

    name: str
    path: Path
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _identifier(self.name, "artifact.name"))
        object.__setattr__(self, "path", _absolute_path(self.path, f"artifact[{self.name}].path"))
        object.__setattr__(self, "digest", _digest(self.digest, f"artifact[{self.name}].digest"))


@dataclass(frozen=True)
class DeploymentReference:
    """The complete immutable input to a remote worker launch projection."""

    deployment_id: str
    revision: str
    task_id: str
    run_id: str
    target_ref: str
    effective_target_ref: str
    executable: ArtifactReference
    dependency_closure: tuple[ArtifactReference, ...]
    source_closure_digest: str
    data_root: Path
    support_root: Path
    runtime_endpoint: str
    runtime_instance_id: str
    runtime_epoch: int
    runtime_schema_digest: str
    model_root: Path
    capacity: int
    session_ref: str
    session_config_digest: str
    output_root: Path
    credential_ref: str
    executor_id: str
    boot_manifest_path: Path
    boot_manifest_hash: str
    readiness_profile_path: Path
    readiness_profile_hash: str
    source_checkout: Path | None = None
    source_checkout_digest: str | None = None
    pack_roots: tuple[Path, ...] = ()
    source_inventory_identity: str = ""
    capability_matrix: Path | None = None
    ready_file: Path | None = None
    execution_target: Mapping[str, Any] | None = None
    register: bool = True
    admission_identity: AdmissionIdentity | None = None
    capability_identity: CapabilityIdentity | None = None
    input_bindings: tuple[InputBinding, ...] = ()
    original_target: Mapping[str, Any] | None = None
    effective_target: Mapping[str, Any] | None = None
    placement_version: int = 0
    recovery_decision_digest: str | None = None

    def __post_init__(self) -> None:
        for field in ("deployment_id", "revision", "task_id", "run_id", "target_ref", "effective_target_ref", "runtime_instance_id", "session_ref", "executor_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        if not isinstance(self.admission_identity, AdmissionIdentity):
            raise DeploymentReferenceError("admission identity is required")
        if not isinstance(self.capability_identity, CapabilityIdentity):
            raise DeploymentReferenceError("capability identity is required")
        if self.admission_identity.task_id != self.task_id or self.admission_identity.run_id != self.run_id:
            raise DeploymentReferenceError("admission identity conflicts with deployment task/run")
        input_bindings = tuple(self.input_bindings)
        if any(not isinstance(item, InputBinding) for item in input_bindings):
            raise DeploymentReferenceError("input_bindings entries must be InputBinding values")
        if len({item.name for item in input_bindings}) != len(input_bindings) or len({item.object_id for item in input_bindings}) != len(input_bindings):
            raise DeploymentReferenceError("input_bindings must contain unique ordered inputs")
        object.__setattr__(self, "input_bindings", input_bindings)
        if self.original_target is None or self.effective_target is None:
            raise DeploymentReferenceError("original_target and effective_target are required")
        original_target = _target(self.original_target, "original_target")
        effective_target = _target(self.effective_target, "effective_target")
        if self.target_ref != self.effective_target_ref and original_target == effective_target:
            raise DeploymentReferenceError("effective_target_ref conflicts with the unchanged original target")
        if self.execution_target is not None and _target(self.execution_target, "execution_target") != effective_target:
            raise DeploymentReferenceError("execution_target must equal the authorized effective target")
        object.__setattr__(self, "original_target", original_target)
        object.__setattr__(self, "effective_target", effective_target)
        object.__setattr__(self, "execution_target", effective_target)
        placement = PlacementIdentity(
            original_target=original_target,
            effective_target=effective_target,
            placement_version=self.placement_version,
            recovery_decision_digest=self.recovery_decision_digest,
        )
        object.__setattr__(self, "placement_version", placement.placement_version)
        object.__setattr__(self, "recovery_decision_digest", placement.recovery_decision_digest)
        if not isinstance(self.executable, ArtifactReference):
            raise DeploymentReferenceError("executable must be an ArtifactReference")
        closure = tuple(self.dependency_closure)
        if not closure:
            raise DeploymentReferenceError("dependency_closure is required")
        if any(not isinstance(item, ArtifactReference) for item in closure):
            raise DeploymentReferenceError("dependency_closure entries must be ArtifactReference values")
        names = [item.name for item in closure]
        if names != sorted(names) or len(names) != len(set(names)):
            raise DeploymentReferenceError("dependency_closure must be unique and deterministically sorted")
        matching = [item for item in closure if item.name == self.executable.name]
        if matching != [self.executable]:
            raise DeploymentReferenceError("executable must appear identically in dependency_closure")
        object.__setattr__(self, "dependency_closure", closure)
        object.__setattr__(self, "source_closure_digest", _digest(self.source_closure_digest, "source_closure_digest"))
        for field in ("data_root", "support_root", "model_root", "output_root", "boot_manifest_path", "readiness_profile_path"):
            object.__setattr__(self, field, _absolute_path(getattr(self, field), field))
        if self.support_root != self.data_root / "runtime":
            raise DeploymentReferenceError("support_root must be data_root/runtime")
        object.__setattr__(self, "runtime_endpoint", _endpoint(self.runtime_endpoint))
        if isinstance(self.runtime_epoch, bool) or not isinstance(self.runtime_epoch, int) or self.runtime_epoch <= 0:
            raise DeploymentReferenceError("runtime_epoch must be a positive integer")
        object.__setattr__(self, "runtime_schema_digest", _digest(self.runtime_schema_digest, "runtime_schema_digest"))
        if isinstance(self.capacity, bool) or not isinstance(self.capacity, int) or self.capacity != 2:
            raise DeploymentReferenceError("capacity must be the canonical two-lane value 2")
        object.__setattr__(self, "session_config_digest", _digest(self.session_config_digest, "session_config_digest"))
        object.__setattr__(self, "credential_ref", _secret_free_reference(self.credential_ref, "credential_ref"))
        object.__setattr__(self, "boot_manifest_hash", _digest(self.boot_manifest_hash, "boot_manifest_hash"))
        object.__setattr__(self, "readiness_profile_hash", _digest(self.readiness_profile_hash, "readiness_profile_hash"))
        source_checkout = _optional_absolute_path(self.source_checkout, "source_checkout")
        source_digest = _bare_digest(self.source_checkout_digest, "source_checkout_digest")
        if (source_checkout is None) != (source_digest is None):
            raise DeploymentReferenceError("source_checkout and source_checkout_digest must be supplied together")
        object.__setattr__(self, "source_checkout", source_checkout)
        object.__setattr__(self, "source_checkout_digest", source_digest)
        object.__setattr__(self, "pack_roots", tuple(_absolute_path(item, "pack root") for item in self.pack_roots))
        object.__setattr__(self, "source_inventory_identity", str(self.source_inventory_identity or ""))
        object.__setattr__(self, "capability_matrix", _optional_absolute_path(self.capability_matrix, "capability_matrix"))
        object.__setattr__(self, "ready_file", _optional_absolute_path(self.ready_file, "ready_file"))
        if self.execution_target is not None:
            if not isinstance(self.execution_target, Mapping) or not self.execution_target:
                raise DeploymentReferenceError("execution_target must be a non-empty object")
            try:
                normalized_target = json.loads(json.dumps(dict(self.execution_target), sort_keys=True, separators=(",", ":"), allow_nan=False))
            except (TypeError, ValueError) as exc:
                raise DeploymentReferenceError("execution_target must be JSON-compatible") from exc
            object.__setattr__(self, "execution_target", normalized_target)

    @classmethod
    def from_local_worker_profile(
        cls,
        profile: LocalWorkerProfile,
        *,
        deployment_id: str,
        revision: str,
        task_id: str,
        run_id: str,
        target_ref: str,
        effective_target_ref: str | None = None,
        runtime_endpoint: str,
        runtime_instance_id: str,
        runtime_epoch: int,
        runtime_schema_digest: str,
        model_root: Path,
        session_ref: str,
        output_root: Path,
        session_config_digest: str | None = None,
        credential_ref: str,
        boot_manifest_path: Path,
        boot_manifest_hash: str,
        readiness_profile_path: Path,
        readiness_profile_hash: str,
        source_closure_digest: str | None = None,
        executor_id: str = "astrid-pack-host",
        capacity: int = 2,
        source_checkout: Path | None = None,
        source_checkout_digest: str | None = None,
        pack_roots: tuple[Path, ...] = (),
        source_inventory_identity: str = "",
        capability_matrix: Path | None = None,
        ready_file: Path | None = None,
        execution_target: Mapping[str, Any] | None = None,
        register: bool = True,
        admission_identity: AdmissionIdentity | None = None,
        capability_identity: CapabilityIdentity | None = None,
        input_bindings: tuple[InputBinding, ...] = (),
        original_target: Mapping[str, Any] | None = None,
        effective_target: Mapping[str, Any] | None = None,
        placement_version: int = 0,
        recovery_decision_digest: str | None = None,
    ) -> "DeploymentReference":
        """Lift the existing profile into the shared immutable handoff."""
        artifacts = (
            ArtifactReference("engine", profile.engine_executable, profile.engine_artifact_digest),
            ArtifactReference("engine_listener", profile.engine_listener_executable, profile.engine_listener_artifact_digest),
            ArtifactReference("host", profile.host_executable, profile.host_artifact_digest),
            ArtifactReference("worker", profile.worker_executable, profile.worker_artifact_digest),
        )
        closure_digest = source_closure_digest or _computed_digest(
            {"release": profile.release_digest, "profile": profile.profile_digest, "artifacts": [item.digest for item in artifacts]},
        )
        return cls(
            deployment_id=deployment_id,
            revision=revision,
            task_id=task_id,
            run_id=run_id,
            target_ref=target_ref,
            effective_target_ref=effective_target_ref or target_ref,
            executable=next(item for item in artifacts if item.name == "host"),
            dependency_closure=artifacts,
            source_closure_digest=closure_digest,
            data_root=profile.support_root.parent,
            support_root=profile.support_root,
            runtime_endpoint=runtime_endpoint,
            runtime_instance_id=runtime_instance_id,
            runtime_epoch=runtime_epoch,
            runtime_schema_digest=runtime_schema_digest,
            model_root=model_root,
            capacity=capacity,
            session_ref=session_ref,
            session_config_digest=session_config_digest or profile.session_config_digest,
            output_root=output_root,
            credential_ref=credential_ref,
            executor_id=executor_id,
            boot_manifest_path=boot_manifest_path,
            boot_manifest_hash=boot_manifest_hash,
            readiness_profile_path=readiness_profile_path,
            readiness_profile_hash=readiness_profile_hash,
            source_checkout=source_checkout,
            source_checkout_digest=source_checkout_digest,
            pack_roots=pack_roots,
            source_inventory_identity=source_inventory_identity,
            capability_matrix=capability_matrix,
            ready_file=ready_file,
            execution_target=execution_target,
            register=register,
            admission_identity=admission_identity,
            capability_identity=capability_identity,
            input_bindings=input_bindings,
            original_target=original_target,
            effective_target=effective_target or original_target,
            placement_version=placement_version,
            recovery_decision_digest=recovery_decision_digest,
        )

    def digest(self) -> str:
        """Return the stable identity of this reference, excluding no fields."""
        payload = {
            key: _json_safe(value)
            for key, value in self.__dict__.items()
            if key not in {"dependency_closure", "executable"}
        }
        payload["executable"] = _json_safe(self.executable)
        payload["dependency_closure"] = [_json_safe(item) for item in self.dependency_closure]
        return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def deployment_binding(self) -> DeploymentBinding:
        return DeploymentBinding(
            admission_identity=self.admission_identity,
            capability_identity=self.capability_identity,
            input_bindings=self.input_bindings,
            placement=PlacementIdentity(
                original_target=self.original_target,
                effective_target=self.effective_target,
                placement_version=self.placement_version,
                recovery_decision_digest=self.recovery_decision_digest,
            ),
        )


@dataclass(frozen=True)
class ProjectedLaunch:
    """Deterministic, secret-free process inputs derived from a reference."""

    argv: tuple[str, ...]
    env_items: tuple[tuple[str, str], ...]
    deployment_digest: str
    cwd: Path

    def env(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.env_items))


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, ArtifactReference):
        return {"name": value.name, "path": str(value.path), "digest": value.digest}
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, (AdmissionIdentity, CapabilityIdentity, InputBinding, PlacementIdentity, DeploymentBinding)):
        return _json_safe(value.as_dict() if hasattr(value, "as_dict") else value.__dict__)
    return value


def _conflicting_value(value: Mapping[str, Any], names: tuple[str, ...], field: str) -> Any:
    present = [value[name] for name in names if name in value]
    if not present:
        raise DeploymentReferenceError(f"{field} is required")
    if any(item != present[0] for item in present[1:]):
        raise DeploymentReferenceError(f"{field} has conflicting identity values")
    return present[0]


def _recovery_digest(decision: Mapping[str, Any]) -> str:
    material = dict(decision)
    supplied = material.pop("decision_digest", None)
    if supplied is None:
        raise DeploymentReferenceError("placement recovery decision_digest is required")
    expected = _sha256(material)
    if _digest(supplied, "placement recovery decision_digest") != expected:
        raise DeploymentReferenceError("placement recovery decision_digest is stale or foreign")
    return expected


def deployment_binding_from_task(value: Mapping[str, Any]) -> DeploymentBinding:
    """Project a Runtime task read into the shared immutable deployment binding.

    This is intentionally read-only.  It consumes Runtime's task and recovery
    projections and never authorizes or performs placement recovery.
    """
    if not isinstance(value, Mapping):
        raise DeploymentReferenceError("Runtime task projection must be an object")
    task = value.get("task") if isinstance(value.get("task"), Mapping) else value
    run = value.get("run") if isinstance(value.get("run"), Mapping) else {}
    if not isinstance(task, Mapping):
        raise DeploymentReferenceError("Runtime task projection is missing task identity")

    task_id = _conflicting_value(task, ("task_id", "id"), "task_id")
    run_id = _conflicting_value(task, ("run_id",), "run_id")
    if run.get("id") is not None and run["id"] != run_id:
        raise DeploymentReferenceError("task/run identity conflict")
    project_values = [item for item in (task.get("project_id"), run.get("project_id")) if item is not None]
    if len(project_values) > 1 and project_values[0] != project_values[1]:
        raise DeploymentReferenceError("project identity conflict")
    project_id = project_values[0] if project_values else None
    idempotency_key = task.get("idempotency_key") or run.get("idempotency_key")
    if task.get("idempotency_key") is not None and run.get("idempotency_key") is not None and task["idempotency_key"] != run["idempotency_key"]:
        raise DeploymentReferenceError("idempotency identity conflict")
    idempotency_key = _text(idempotency_key, "idempotency_key")
    capability_id = _conflicting_value(task, ("capability_id", "capability"), "capability_id")
    capability_digest = task.get("capability_digest")
    if capability_digest is None:
        raise DeploymentReferenceError("capability_digest is required")
    spec = task.get("spec")
    if not isinstance(spec, Mapping):
        raise DeploymentReferenceError("admitted spec is required")
    if spec.get("capability_digest") is not None and spec.get("capability_digest") != capability_digest:
        raise DeploymentReferenceError("capability identity has conflicting digests")
    request = task.get("execution_request")
    nested_request = spec.get("execution_request")
    if request is None and nested_request is not None:
        request = nested_request
    elif request is not None and nested_request is not None and request != nested_request:
        raise DeploymentReferenceError("execution_request has conflicting identity values")
    if not isinstance(request, Mapping):
        raise DeploymentReferenceError("admitted execution_request is required")
    request = json.loads(canonical_json(dict(request)))
    original_target = _target(request.get("target"), "execution_request.target")
    if task.get("target") is not None and _target(task["target"], "task.target") != original_target:
        raise DeploymentReferenceError("task target drifted from immutable admission")

    input_ids = task.get("input_object_ids")
    spec_input_ids = spec.get("input_object_ids")
    if not isinstance(input_ids, list):
        raise DeploymentReferenceError("input_object_ids is required")
    if spec_input_ids is not None and list(spec_input_ids) != input_ids:
        raise DeploymentReferenceError("input_object_ids has conflicting identity values")
    inputs = request.get("inputs", [])
    if not isinstance(inputs, list):
        raise DeploymentReferenceError("execution_request.inputs must be a list")
    if len(inputs) != len(input_ids):
        raise DeploymentReferenceError("input_object_ids does not mirror execution_request.inputs")
    bindings: list[InputBinding] = []
    normalized_ids: list[str] = []
    for index, item in enumerate(inputs):
        if not isinstance(item, Mapping):
            raise DeploymentReferenceError(f"execution_request.inputs[{index}] is invalid")
        object_id = _object_id(item.get("object_id"), f"execution_request.inputs[{index}].object_id")
        normalized_ids.append(object_id)
        digest = item.get("digest", object_id)
        bindings.append(InputBinding(name=item.get("name"), object_id=object_id, digest=digest))
    supplied_ids = [_object_id(item, f"input_object_ids[{index}]") for index, item in enumerate(input_ids)]
    if supplied_ids != normalized_ids:
        raise DeploymentReferenceError("input_object_ids does not exactly mirror execution_request.inputs in order")
    if len(set(supplied_ids)) != len(supplied_ids):
        raise DeploymentReferenceError("input_object_ids contains duplicate object IDs")

    binding_projection = value.get("execution_binding")
    if not isinstance(binding_projection, Mapping):
        binding_projection = task.get("execution_binding")
    if not isinstance(binding_projection, Mapping):
        raise DeploymentReferenceError("Runtime execution binding is required")
    recovery = binding_projection.get("placement_recovery") or value.get("placement_recovery")
    if recovery is not None and not isinstance(recovery, Mapping):
        raise DeploymentReferenceError("placement recovery projection is invalid")
    if recovery:
        recovery = dict(recovery)
        if recovery.get("task_id") != task_id or recovery.get("run_id") != run_id:
            raise DeploymentReferenceError("placement recovery is foreign to the admitted task")
        if _target(recovery.get("original_target"), "placement recovery original_target") != original_target:
            raise DeploymentReferenceError("placement recovery changes the immutable original target")
        effective_target = _target(recovery.get("replacement_target"), "placement recovery replacement_target")
        placement_version = recovery.get("placement_version")
        if isinstance(placement_version, bool) or not isinstance(placement_version, int) or placement_version <= 0:
            raise DeploymentReferenceError("placement recovery has a stale or invalid placement version")
        if effective_target == original_target:
            raise DeploymentReferenceError("placement recovery does not authorize a replacement target")
        decision_digest = _recovery_digest(recovery)
    else:
        effective_target = _target(
            binding_projection.get("effective_target", binding_projection.get("resolved_target", original_target)),
            "effective_target",
        )
        placement_version = 0
        decision_digest = None
    if _target(binding_projection.get("original_target", original_target), "binding.original_target") != original_target:
        raise DeploymentReferenceError("execution binding changes the immutable original target")
    binding_effective = binding_projection.get("effective_target", binding_projection.get("resolved_target"))
    if binding_effective is not None and _target(binding_effective, "binding.effective_target") != effective_target:
        raise DeploymentReferenceError("execution binding effective target drifted from Runtime recovery")
    binding_version = binding_projection.get("placement_version")
    if binding_version is not None:
        if isinstance(binding_version, bool) or not isinstance(binding_version, int) or binding_version < 0:
            raise DeploymentReferenceError("placement version is stale or conflicting")
        if binding_version != placement_version:
            raise DeploymentReferenceError("placement version is stale or conflicting")
    if binding_projection.get("recovery_decision_digest") is not None and binding_projection["recovery_decision_digest"] != decision_digest:
        raise DeploymentReferenceError("recovery decision digest is stale or conflicting")

    expected_effect = task.get("expected_effect")
    spec_for_hash = task_spec_for_request_hash(dict(spec))
    spec_digest = _sha256(spec_for_hash)
    request_digest = _sha256(request)
    admission_material = {
        "capability": capability_id,
        "spec": spec_for_hash,
        "execution_request": request,
        "project_id": project_id,
        "expected_effect": expected_effect,
        "capability_digest": capability_digest,
    }
    admission_digest = _sha256(admission_material)
    supplied_digests = {
        "admission_digest": task.get("admission_digest"),
        "spec_digest": task.get("spec_digest"),
        "request_digest": task.get("request_digest"),
    }
    for field, supplied in supplied_digests.items():
        if supplied is not None and _digest(supplied, field) != {"admission_digest": admission_digest, "spec_digest": spec_digest, "request_digest": request_digest}[field]:
            raise DeploymentReferenceError(f"{field} is stale or conflicting")
    admission = AdmissionIdentity(
        task_id=task_id,
        run_id=run_id,
        project_id=project_id,
        idempotency_key=idempotency_key,
        admission_digest=admission_digest,
        spec_digest=spec_digest,
        request_digest=request_digest,
    )
    return DeploymentBinding(
        admission_identity=admission,
        capability_identity=CapabilityIdentity(capability_id, capability_digest),
        input_bindings=tuple(bindings),
        placement=PlacementIdentity(original_target, effective_target, placement_version, decision_digest),
    )


def deployment_binding_digest(value: Mapping[str, Any]) -> str:
    return deployment_binding_from_task(value).digest()


def project_launch(reference: DeploymentReference) -> ProjectedLaunch:
    """Project one validated reference into stable argv and non-secret env."""
    if not isinstance(reference, DeploymentReference):
        raise DeploymentReferenceError("project_launch requires a DeploymentReference")
    credential_path = _credential_path(reference.credential_ref)
    cwd = reference.source_checkout or reference.executable.path.parent
    ready_file = reference.ready_file or reference.support_root / "generic-host.ready.json"
    argv_list = [
        str(reference.executable.path),
        "-m",
        "astrid.core.execution.generic_host",
        "run",
    ]
    for root in reference.pack_roots:
        argv_list.extend(("--pack-root", str(root)))
    argv_list.extend((
        "--runtime-endpoint", reference.runtime_endpoint,
        "--credential-file", str(credential_path),
        "--executor-id", reference.executor_id,
        "--max-concurrency", str(reference.capacity),
        "--ready-file", str(ready_file),
        "--support-root", str(reference.support_root),
    ))
    if reference.source_checkout is not None:
        argv_list.extend((
            "--source-checkout", str(reference.source_checkout),
            "--source-checkout-digest", str(reference.source_checkout_digest),
        ))
    argv_list.extend((
        "--runtime-instance-id", reference.runtime_instance_id,
        "--source-inventory-identity", reference.source_inventory_identity,
        "--boot-manifest-path", str(reference.boot_manifest_path),
        "--boot-manifest-hash", reference.boot_manifest_hash,
    ))
    if reference.register:
        argv_list.append("--register")
    if reference.capability_matrix is not None:
        argv_list.extend(("--capability-matrix", str(reference.capability_matrix)))
    argv_list.extend((
        "--readiness-profile-path", str(reference.readiness_profile_path),
        "--readiness-profile-hash", reference.readiness_profile_hash,
    ))
    env = {
        "ASTRID_DEPLOYMENT_ID": reference.deployment_id,
        "ASTRID_DEPLOYMENT_REVISION": reference.revision,
        "ASTRID_DEPLOYMENT_DIGEST": reference.digest(),
        "ASTRID_TASK_ID": reference.task_id,
        "ASTRID_RUN_ID": reference.run_id,
        "ASTRID_PROJECT_ID": reference.admission_identity.project_id or "",
        "ASTRID_IDEMPOTENCY_KEY": reference.admission_identity.idempotency_key,
        "ASTRID_ADMISSION_DIGEST": reference.admission_identity.admission_digest,
        "ASTRID_SPEC_DIGEST": reference.admission_identity.spec_digest,
        "ASTRID_REQUEST_DIGEST": reference.admission_identity.request_digest,
        "ASTRID_CAPABILITY_ID": reference.capability_identity.capability_id,
        "ASTRID_CAPABILITY_DIGEST": reference.capability_identity.capability_digest,
        "ASTRID_TARGET_REF": reference.effective_target_ref,
        "ASTRID_ORIGINAL_TARGET_JSON": json.dumps(reference.original_target, sort_keys=True, separators=(",", ":")),
        "ASTRID_EFFECTIVE_TARGET_JSON": json.dumps(reference.effective_target, sort_keys=True, separators=(",", ":")),
        "ASTRID_PLACEMENT_VERSION": str(reference.placement_version),
        "ASTRID_RUNTIME_ENDPOINT": reference.runtime_endpoint,
        "ASTRID_RUNTIME_INSTANCE_ID": reference.runtime_instance_id,
        "ASTRID_RUNTIME_EPOCH": str(reference.runtime_epoch),
        "ASTRID_RUNTIME_SCHEMA_DIGEST": reference.runtime_schema_digest,
        "ASTRID_VIBECOMFY_MODELS_ROOT": str(reference.model_root),
        "ASTRID_SESSION_REF": reference.session_ref,
        "ASTRID_SESSION_CONFIG_DIGEST": reference.session_config_digest,
        "ASTRID_OUTPUT_ROOT": str(reference.output_root),
        "ASTRID_CREDENTIAL_REF": reference.credential_ref,
        "ASTRID_SOURCE_CLOSURE_DIGEST": reference.source_closure_digest,
        "BANODOCO_LOCAL_DATA_ROOT": str(reference.data_root),
    }
    if reference.execution_target is not None:
        env["ASTRID_EXECUTION_TARGET_JSON"] = json.dumps(
            reference.execution_target, sort_keys=True, separators=(",", ":")
        )
    if reference.recovery_decision_digest is not None:
        env["ASTRID_RECOVERY_DECISION_DIGEST"] = reference.recovery_decision_digest
    env["ASTRID_INPUT_BINDINGS_JSON"] = json.dumps(
        [
            {"name": item.name, "object_id": item.object_id, "digest": item.digest}
            for item in reference.input_bindings
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return ProjectedLaunch(
        argv=tuple(argv_list),
        env_items=tuple(sorted(env.items())),
        deployment_digest=reference.digest(),
        cwd=cwd,
    )


__all__ = [
    "ArtifactReference",
    "AdmissionIdentity",
    "CapabilityIdentity",
    "DeploymentBinding",
    "DeploymentReference",
    "DeploymentReferenceError",
    "InputBinding",
    "PlacementIdentity",
    "ProjectedLaunch",
    "PROJECTION_VERSION",
    "SCHEMA_VERSION",
    "project_launch",
    "deployment_binding_digest",
    "deployment_binding_from_task",
]
