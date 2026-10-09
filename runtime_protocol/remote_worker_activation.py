"""Owner-only qualified activation for an already admitted remote worker.

The preparer parks the host. The inspector is an independent provider/process
observer supplied by the Runtime owner, never the worker's own readiness JSON.
No task is admitted or retried by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping, Protocol

from .auth import CredentialStore
from .errors import ConflictError, ValidationError
from .remote_worker_deployment import (
    DeploymentReference,
    ProjectedLaunch,
    deployment_binding_from_task,
    project_launch,
)
from .service import RuntimeService
from .util import canonical_json


OWNER = {"actor": "owner", "scopes": ["admin"]}


@dataclass(frozen=True)
class RemotePreparationLaunch:
    """Exact provider/host selection and its deterministic non-secret launch."""

    reference: DeploymentReference
    launch: ProjectedLaunch


class RemotePreparer(Protocol):
    def prepare(self, launch: RemotePreparationLaunch) -> object: ...
    def restore(self, reference: DeploymentReference) -> RemotePreparationCheckpoint:
        """Optional read of the exact durable parked process and observation."""
        ...
    def checkpoint(self, parked: ParkedRemoteHost, stage: str, details: Mapping[str, Any]) -> None:
        """Optional durable, exact-generation checkpoint; never readiness evidence.

        Implementations persist the opaque owned handle and ``parked`` proof
        at ``parked``, then advance only the same process/generation through
        ``qualification``, ``credential``, ``acknowledged``, ``enabled``,
        ``ready``, and ``committed``. Repeated stages must be idempotent.
        """
        ...
    def acknowledge(self, handle: object, grant: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def await_ready(self, handle: object) -> None:
        """Wait for host startup; this response is never readiness evidence."""
        ...
    def abort(self, handle: object) -> None: ...


class RemoteInspector(Protocol):
    def observe(self, handle: object) -> Mapping[str, Any]: ...
    def observe_ready(self, handle: object) -> Mapping[str, Any]:
        """Independently confirm initialized host and authenticated registration.

        Return the same exact process/provider/Runtime/source/model/session/
        output-root observation as ``observe`` only after independently
        measuring host initialization, authenticated executor registration,
        installed source/dependencies, model inventory, session configuration,
        and writable output root for this owned process. The
        preparer's ready-file/wait response alone is never this evidence.
        """
        ...


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True)
class ParkedRemoteHost:
    handle: object
    target: Mapping[str, Any]
    observation: Mapping[str, Any]
    evidence_digest: str
    executor_incarnation: str

    def recovery_qualification(self) -> dict[str, Any]:
        """The existing T12 transition's unclaimable replacement proof."""
        return {
            "target": dict(self.target), "verified": True,
            "evidence_digest": self.evidence_digest,
            "executor_incarnation": self.executor_incarnation,
        }


@dataclass(frozen=True)
class RemotePreparationCheckpoint:
    """Persisted owner handle and independent parked-process evidence."""

    handle: object
    target: Mapping[str, Any]
    observation: Mapping[str, Any]
    evidence_digest: str
    executor_incarnation: str


class QualifiedRemoteWorkerLauncher:
    """Compose parked launch, independent observation, private ack and Runtime commit."""

    def __init__(self, *, runtime: RuntimeService, credentials: CredentialStore | None,
                 preparer: RemotePreparer, inspector: RemoteInspector,
                 credential_control: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
                 scopes: tuple[str, ...] = ("worker:execute",),
                 ttl_seconds: int = 300):
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ValidationError("remote activation TTL is out of range")
        self.runtime = runtime
        self.credentials = credentials
        self.credential_control = credential_control
        if (credentials is None) == (credential_control is None):
            raise ValidationError("exactly one resident credential control is required")
        self.preparer = preparer
        self.inspector = inspector
        self.scopes = scopes
        self.ttl_seconds = ttl_seconds
        self.activation_state = "inactive"
        # Retain the exact generation and process handle even if the final
        # commit reply is lost. Callers can retry reconciliation without
        # reprovisioning a credential or preparing a different host.
        self.activation_qualification: dict[str, Any] | None = None
        self.activation_host: ParkedRemoteHost | None = None
        self.activation_credential_digest: str | None = None
        self.preparation_handle: object | None = None

    @staticmethod
    def _validate_observation(value: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ConflictError("independent remote observation is missing")
        required = {
            "target", "provider_identity", "process", "runtime_instance_id",
            "runtime_epoch", "runtime_session_id", "source_closure_digest",
            "dependency_closure_digest", "model_root", "session_ref", "data_root",
            "support_root", "output_root", "capacity", "model_inventory_digest", "session_config_digest",
        }
        if set(value) != required or value["target"] != target:
            raise ConflictError("remote provider or host observation is incomplete or misplaced")
        process = value["process"]
        if (not isinstance(process, Mapping) or isinstance(process.get("pid"), bool)
                or not isinstance(process.get("pid"), int)
                or process["pid"] <= 0 or not process.get("birth_id")
                or process.get("pgid") != process["pid"] or process.get("sid") != process["pid"]):
            raise ConflictError("remote parked host has no owned process incarnation")
        if not isinstance(value["provider_identity"], Mapping) or not value["provider_identity"].get("account_ref"):
            raise ConflictError("independent provider identity is missing")
        provider = value["provider_identity"]
        if (provider["account_ref"] != target.get("provider_account_ref")
                or (target.get("kind") == "runpod" and provider.get("pod_id") != target.get("pod_id"))):
            raise ConflictError("remote provider identity differs from effective placement")
        for field in ("source_closure_digest", "dependency_closure_digest",
                      "model_inventory_digest", "session_config_digest"):
            if not isinstance(value[field], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]):
                raise ConflictError("remote observation has an invalid readiness digest")
        for field in ("model_root", "data_root", "support_root", "output_root"):
            path = value[field]
            if (not isinstance(path, str) or not PurePosixPath(path).is_absolute()
                    or ".." in PurePosixPath(path).parts):
                raise ConflictError("remote observation has an invalid readiness root")
        for field in ("runtime_instance_id", "runtime_session_id", "session_ref"):
            if not isinstance(value[field], str) or not value[field].strip():
                raise ConflictError("remote observation has an invalid Runtime or session identity")
        if (type(value["capacity"]) is not int or value["capacity"] != 1
                or type(value["runtime_epoch"]) is not int or value["runtime_epoch"] <= 0
                or not isinstance(process["birth_id"], str)):
            raise ConflictError("remote observation has an invalid host incarnation or capacity")
        try:
            return json.loads(canonical_json(dict(value)))
        except (TypeError, ValueError) as exc:
            raise ConflictError("remote observation is not canonical") from exc

    def park(self, reference: DeploymentReference, *, target: Mapping[str, Any]) -> ParkedRemoteHost:
        """Prepare replacement while unclaimable; return proof for T12 recovery."""
        if self.activation_state == "unknown":
            raise ConflictError("remote process custody is unresolved")
        if not isinstance(reference, DeploymentReference):
            raise ValidationError("typed deployment reference is required for preparation")
        if reference.effective_target != target:
            raise ConflictError("preparation target differs from the exact deployment reference")
        handle = self.preparer.prepare(RemotePreparationLaunch(reference, project_launch(reference)))
        self.preparation_handle = handle
        try:
            first = self._validate_observation(self.inspector.observe(handle), target)
            second = self._validate_observation(self.inspector.observe(handle), target)
            if first != second:
                raise ConflictError("remote identity changed before qualification")
            incarnation = getattr(handle, "incarnation", None)
            if incarnation is not None and (not isinstance(incarnation, str)
                                             or not incarnation.strip() or len(incarnation) > 256):
                raise ConflictError("prepared process incarnation is invalid")
            parked = ParkedRemoteHost(
                handle, dict(target), second, _digest(second), incarnation or uuid.uuid4().hex,
            )
            self._checkpoint(parked, "parked")
            self.preparation_handle = None
            return parked
        except BaseException:
            try:
                self.preparer.abort(handle)
            except BaseException:
                self.activation_state = "unknown"
            else:
                self.preparation_handle = None
            raise

    def _checkpoint(self, parked: ParkedRemoteHost, stage: str,
                    qualification: Mapping[str, Any] | None = None, **details: Any) -> None:
        checkpoint = getattr(self.preparer, "checkpoint", None)
        if callable(checkpoint):
            payload = {"schema_version": 1}
            if qualification is not None:
                payload["qualification"] = dict(qualification)
            payload.update(details)
            checkpoint(parked, stage, json.loads(canonical_json(payload)))

    def activate(self, task: Mapping[str, Any], reference: DeploymentReference,
                 parked: ParkedRemoteHost) -> dict[str, Any]:
        """Bootstrap one exact host, independently verify readiness, commit last."""
        if self.activation_state == "unknown":
            raise ConflictError("remote activation is unresolved; reconcile the exact retained generation")
        if not isinstance(reference, DeploymentReference):
            raise ValidationError("typed deployment reference is required")
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or binding.placement.effective_target != parked.target):
            raise ConflictError("parked host is foreign to Runtime's effective placement")
        observation = parked.observation
        self._assert_reference_observation(reference, parked)
        if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != observation:
            raise ConflictError("remote identity changed before credential issuance")
        activation_id = uuid.uuid4().hex
        credential_actor = reference.executor_id
        qualification = {
            "activation_id": activation_id,
            "task_id": binding.admission_identity.task_id,
            "run_id": binding.admission_identity.run_id,
            "credential_actor": credential_actor,
            "binding_digest": binding.digest(),
            "deployment_digest": reference.digest(),
            "evidence_digest": parked.evidence_digest,
            "effective_target": dict(parked.target),
            "executor_incarnation": parked.executor_incarnation,
            "runtime_session_id": self.runtime.runtime_session_id,
            "runtime_epoch": self.runtime.store._current_runtime_epoch(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)).isoformat(),
            "observation_digest": _digest(observation),
            "authorized_child_lineage": {
                "parent_task_id": binding.admission_identity.task_id,
                "parent_run_id": binding.admission_identity.run_id,
                "max_depth": 1,
                "placement_version": binding.placement.placement_version,
                "effective_target": dict(parked.target),
            },
        }
        placement = {
            "actual": dict(parked.target),
            "verification": {"method": "credential_claim", "verified": True,
                             "evidence_digest": parked.evidence_digest},
            "executor_incarnation": parked.executor_incarnation,
        }
        provision_started = False
        commit_started = False
        self.activation_state = "inactive"
        self.activation_qualification = json.loads(canonical_json(qualification))
        self.activation_host = parked
        self.activation_credential_digest = None
        try:
            self._checkpoint(parked, "qualification", qualification)
            provision_started = True
            self.activation_state = "unknown"
            if self.credential_control is None:
                token, path = self.credentials.provision(
                    credential_actor, list(self.scopes), rotate=True, enabled=False,
                    metadata={"execution_binding": placement, "qualified_activation": qualification},
                )
                self.activation_credential_digest = hashlib.sha256(token.encode()).hexdigest()
            else:
                response = self.credential_control(binding.admission_identity.task_id, {
                    "action": "provision", "qualification": qualification, "placement": placement,
                })
                if (not isinstance(response, Mapping)
                        or response.get("credential_actor") != credential_actor
                        or not isinstance(response.get("credential_file"), str)):
                    raise ConflictError("resident Runtime did not provision the disabled credential")
                path = response["credential_file"]
            self._checkpoint(parked, "credential", qualification, credential_file=str(path))
            grant = {
                "activation_id": activation_id,
                "credential_file": str(path),
                "executor_incarnation": parked.executor_incarnation,
                "evidence_digest": parked.evidence_digest,
            }
            acknowledgement = self.preparer.acknowledge(parked.handle, grant)
            if acknowledgement != {"activation_id": activation_id,
                                   "executor_incarnation": parked.executor_incarnation,
                                   "evidence_digest": parked.evidence_digest}:
                raise ConflictError("private remote activation acknowledgement is invalid")
            self._checkpoint(parked, "acknowledged", qualification,
                             credential_file=str(path), acknowledgement=dict(acknowledgement))
            if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != observation:
                raise ConflictError("remote identity changed after private acknowledgement")
            if self.credential_control is None:
                with self.runtime.store._mutex, self.credentials._lock:
                    self._assert_exact_credential(credential_actor, qualification, placement)
                    if (self.runtime._latest_remote_activation(binding.admission_identity.task_id) is not None
                            or self.runtime._remote_activation_history(binding.admission_identity.task_id, activation_id)):
                        raise ConflictError("remote credential generation is no longer unrecorded")
                    self.credentials.enable_actor(credential_actor)
            elif self.credential_control(binding.admission_identity.task_id, {
                "action": "enable", "activation_id": activation_id,
            }) != {"enabled": True}:
                raise ConflictError("resident Runtime did not enable the remote credential")
            self._checkpoint(parked, "enabled", qualification, credential_file=str(path))
            await_ready = getattr(self.preparer, "await_ready", None)
            if callable(await_ready):
                await_ready(parked.handle)
            ready_observation = self._assert_ready(reference, parked)
            self._checkpoint(parked, "ready", qualification, credential_file=str(path),
                             ready_observation=ready_observation)
            # The request can commit and lose its reply, or admit a claim
            # before returning. From this point no exception authorizes abort.
            commit_started = True
            self.activation_state = "unknown"
            recorded = self.runtime.record_remote_activation(
                binding.admission_identity.task_id, qualification, identity=OWNER
            )
            if recorded != qualification:
                raise ConflictError("Runtime activation commit response is not exact")
            self._checkpoint(parked, "committed", qualification)
            self.activation_state = "active"
            return qualification
        except BaseException as error:
            if commit_started:
                try:
                    reconciled = self.reconcile_activation(task, reference, parked, qualification)
                except BaseException:
                    self.activation_state = "unknown"
                else:
                    if isinstance(error, Exception):
                        return reconciled
                    raise
                # Preserve exact authority/process custody. A failed exact
                # replay cannot prove that the first request did not commit.
                raise
            try:
                self._cleanup_uncommitted(binding.admission_identity.task_id,
                                          credential_actor, qualification, placement,
                                          provision_started)
            except BaseException:
                self.activation_state = "unknown"
                raise
            self.activation_state = "inactive"
            try:
                self.preparer.abort(parked.handle)
            except BaseException:
                self.activation_state = "unknown"
                raise
            raise

    def _assert_reference_observation(self, reference: DeploymentReference,
                                      parked: ParkedRemoteHost) -> None:
        observation = parked.observation
        expected = {
            "runtime_instance_id": reference.runtime_instance_id,
            "runtime_epoch": reference.runtime_epoch,
            "runtime_session_id": self.runtime.runtime_session_id,
            "source_closure_digest": reference.source_closure_digest,
            "dependency_closure_digest": _digest([
                {"name": item.name, "path": str(item.path), "digest": item.digest}
                for item in reference.dependency_closure
            ]),
            "model_root": str(reference.model_root),
            "session_ref": reference.session_ref,
            "data_root": str(reference.data_root),
            "support_root": str(reference.support_root),
            "output_root": str(reference.output_root),
            "capacity": reference.capacity,
            "session_config_digest": reference.session_config_digest,
        }
        if any(observation.get(key) != value for key, value in expected.items()):
            raise ConflictError("remote release, Runtime, model, session, root or capacity evidence changed")
        if observation["provider_identity"].get("account_ref") != parked.target.get("provider_account_ref"):
            raise ConflictError("remote provider account differs from effective placement")

    def _assert_exact_credential(self, actor, qualification, placement):
        if self.activation_credential_digest is None:
            raise ConflictError("remote credential generation is unresolved")
        token, metadata = self.credentials._read_actor(actor)
        if (hashlib.sha256(token.encode()).hexdigest() != self.activation_credential_digest
                or metadata.get("qualified_activation") != qualification
                or metadata.get("execution_binding") != placement):
            raise ConflictError("remote credential generation changed")

    def _cleanup_uncommitted(self, task_id, actor, qualification, placement, provision_started):
        """Retire only a generation proven never committed, before stopping."""
        if self.credential_control is not None:
            # The resident Runtime owns the event history, credential token,
            # and their transaction boundary.  The HTTP owner cannot inspect
            # private store tables; Runtime's exact revoke operation performs
            # the same uncommitted-generation check and writes the tombstone
            # before removing the token.
            if not provision_started:
                return
            result = self.credential_control(task_id, {
                "action": "revoke-uncommitted", "qualification": qualification,
                "placement": placement,
            })
            if result != {"revoked": True}:
                raise ConflictError("resident Runtime did not confirm exact credential revocation")
            return
        with self.runtime.store._mutex:
            history = self.runtime._remote_activation_history(task_id, qualification["activation_id"])
            if (self.runtime._latest_remote_activation(task_id) is not None
                    or any(kind == "task.remote_activation_qualified" for kind, _ in history)):
                raise ConflictError("remote activation may have admitted work; reconcile before cleanup")
            if not provision_started:
                return
            with self.credentials._lock:
                self._assert_exact_credential(actor, qualification, placement)
                # Existing revocation history prevents a delayed attempt
                # from recording this retired, unqualified generation.
                if not any(kind == "task.remote_activation_revoked" for kind, _ in history):
                    task = self.runtime.store.get_task(task_id)
                    with self.runtime.store._transaction():
                        self.runtime.store._append_event(task["run"]["id"], task_id,
                            "task.remote_activation_revoked", {
                                "activation_id": qualification["activation_id"], "unqualified": True,
                            })
                self.credentials.revoke(actor)

    def _assert_ready(self, reference, parked):
        observe_ready = getattr(self.inspector, "observe_ready", None)
        if not callable(observe_ready):
            raise ConflictError("independent remote readiness observation is required")
        self._assert_reference_observation(reference, parked)
        current = self._validate_observation(observe_ready(parked.handle), parked.target)
        if current != parked.observation:
            raise ConflictError("remote identity or independently measured readiness changed")
        return current

    def restore_activation(self, task: Mapping[str, Any], reference: DeploymentReference,
                           parked: ParkedRemoteHost, qualification: Mapping[str, Any]) -> None:
        """Recover exact process/credential custody before replaying a lost commit.

        The caller supplies the preparer's rehydrated handle and persisted
        qualification. This method never provisions, enables, or commits.
        """
        if (self.activation_state != "inactive" or self.activation_host is not None
                or self.activation_qualification is not None):
            raise ConflictError("launcher already owns a remote activation generation")
        if not isinstance(reference, DeploymentReference) or not isinstance(parked, ParkedRemoteHost):
            raise ValidationError("typed deployment reference and parked host are required")
        if not isinstance(qualification, Mapping):
            raise ValidationError("persisted remote activation qualification is required")
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or binding.placement.effective_target != parked.target
                or parked.target != reference.effective_target
                or self._validate_observation(parked.observation, parked.target) != parked.observation
                or parked.evidence_digest != _digest(parked.observation)):
            raise ConflictError("persisted remote host is foreign to the admitted task")
        incarnation = getattr(parked.handle, "incarnation", None)
        if incarnation is not None and incarnation != parked.executor_incarnation:
            raise ConflictError("rehydrated process incarnation changed")
        expected = {
            "task_id": binding.admission_identity.task_id,
            "run_id": binding.admission_identity.run_id,
            "credential_actor": reference.executor_id,
            "binding_digest": binding.digest(),
            "deployment_digest": reference.digest(),
            "evidence_digest": parked.evidence_digest,
            "effective_target": dict(parked.target),
            "executor_incarnation": parked.executor_incarnation,
            "runtime_session_id": self.runtime.runtime_session_id,
            "runtime_epoch": self.runtime.store._current_runtime_epoch(),
            "observation_digest": _digest(parked.observation),
            "authorized_child_lineage": {
                "parent_task_id": binding.admission_identity.task_id,
                "parent_run_id": binding.admission_identity.run_id,
                "max_depth": 1,
                "placement_version": binding.placement.placement_version,
                "effective_target": dict(parked.target),
            },
        }
        if (set(qualification) != set(expected) | {"activation_id", "expires_at"}
                or any(qualification.get(field) != value for field, value in expected.items())
                or not isinstance(qualification.get("activation_id"), str)
                or not qualification["activation_id"]
                or not isinstance(qualification.get("expires_at"), str)):
            raise ConflictError("persisted remote activation generation is foreign or incomplete")
        self._assert_reference_observation(reference, parked)
        if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != parked.observation:
            raise ConflictError("rehydrated remote process observation changed")
        self._assert_ready(reference, parked)
        placement = {
            "actual": dict(parked.target),
            "verification": {"method": "credential_claim", "verified": True,
                             "evidence_digest": parked.evidence_digest},
            "executor_incarnation": parked.executor_incarnation,
        }
        digest = None
        if self.credential_control is None:
            with self.credentials._lock:
                token, metadata = self.credentials._read_actor(reference.executor_id)
                if (metadata.get("qualified_activation") != qualification
                        or metadata.get("execution_binding") != placement
                        or self.credentials.load(token) != metadata):
                    raise ConflictError("persisted remote credential generation changed")
                digest = hashlib.sha256(token.encode()).hexdigest()
        elif self.credential_control(binding.admission_identity.task_id, {
                "action": "verify", "activation_id": qualification["activation_id"],
        }) not in ({"fresh": False}, {"fresh": True}):
            raise ConflictError("resident Runtime cannot verify the persisted credential generation")
        self.activation_qualification = json.loads(canonical_json(dict(qualification)))
        self.activation_host = parked
        self.activation_credential_digest = digest
        self.activation_state = "unknown"

    def restore_prepared_activation(self, task: Mapping[str, Any], reference: DeploymentReference,
                                    qualification: Mapping[str, Any]) -> ParkedRemoteHost:
        """Rehydrate a parked host from the preparer's durable checkpoint."""
        if not isinstance(reference, DeploymentReference):
            raise ValidationError("typed deployment reference is required for restoration")
        restore = getattr(self.preparer, "restore", None)
        if not callable(restore):
            raise ConflictError("remote preparer has no durable restore callback")
        checkpoint = restore(reference)
        if not isinstance(checkpoint, RemotePreparationCheckpoint):
            raise ConflictError("remote preparer returned no exact parked checkpoint")
        parked = ParkedRemoteHost(
            checkpoint.handle, checkpoint.target, checkpoint.observation,
            checkpoint.evidence_digest, checkpoint.executor_incarnation,
        )
        current = self._validate_observation(self.inspector.observe(parked.handle), parked.target)
        if current != parked.observation:
            raise ConflictError("rehydrated remote process observation changed")
        self.restore_activation(task, reference, parked, qualification)
        return parked

    def reconcile_activation(self, task: Mapping[str, Any], reference: DeploymentReference,
                             parked: ParkedRemoteHost, qualification: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve uncertain commit with the identical idempotent owner request.

        Failure leaves custody unknown and never revokes credentials or stops
        the host. The owner must retain this exact qualification for retry.
        """
        self.activation_state = "unknown"
        if (self.activation_qualification != qualification or self.activation_host is not parked):
            raise ConflictError("remote activation reconciliation requires the retained generation")
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or binding.admission_identity.task_id != qualification.get("task_id")
                or qualification.get("binding_digest") != binding.digest()
                or qualification.get("deployment_digest") != reference.digest()
                or qualification.get("evidence_digest") != parked.evidence_digest
                or qualification.get("observation_digest") != _digest(parked.observation)
                or qualification.get("executor_incarnation") != parked.executor_incarnation):
            raise ConflictError("remote activation generation changed before reconciliation")
        if self.credential_control is None:
            with self.credentials._lock:
                self._assert_exact_credential(reference.executor_id, qualification, {
                    "actual": dict(parked.target),
                    "verification": {"method": "credential_claim", "verified": True,
                                     "evidence_digest": parked.evidence_digest},
                    "executor_incarnation": parked.executor_incarnation,
                })
        self._assert_ready(reference, parked)
        recorded = self.runtime.record_remote_activation(
            binding.admission_identity.task_id, dict(qualification), identity=OWNER
        )
        if recorded != qualification:
            raise ConflictError("Runtime activation replay response is not exact")
        self._checkpoint(parked, "committed", qualification)
        self.activation_state = "active"
        return dict(qualification)

    def assert_fresh(self, task: Mapping[str, Any], reference: DeploymentReference,
                     parked: ParkedRemoteHost, qualification: Mapping[str, Any]) -> None:
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or qualification.get("binding_digest") != binding.digest()
                or qualification.get("deployment_digest") != reference.digest()
                or qualification.get("evidence_digest") != parked.evidence_digest
                or qualification.get("observation_digest") != _digest(parked.observation)
                or qualification.get("executor_incarnation") != parked.executor_incarnation):
            raise ConflictError("remote activation is stale before queue")
        if self.credential_control is None:
            metadata = self.credentials.actor_metadata(reference.executor_id)
            if metadata is None or not self.runtime._remote_activation_matches(
                    binding.admission_identity.task_id,
                    {"actor": reference.executor_id, "qualified_activation": dict(qualification)},
                    metadata["execution_binding"]):
                raise ConflictError("remote activation is revoked or expired before queue")
            token, _metadata = self.credentials._read_actor(reference.executor_id)
            if self.credentials.load(token) != metadata:
                raise ConflictError("remote credential changed before queue")
        elif self.credential_control(binding.admission_identity.task_id, {
                "action": "verify", "activation_id": qualification["activation_id"],
        }) != {"fresh": True}:
            raise ConflictError("remote activation is revoked or expired before queue")
        self._assert_ready(reference, parked)
