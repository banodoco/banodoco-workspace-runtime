"""Owner-only qualified activation for an already admitted remote worker.

The preparer parks the host. The inspector is an independent provider/process
observer supplied by the Runtime owner, never the worker's own readiness JSON.
No task is admitted or retried by this module.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Protocol

from .auth import CredentialStore
from .errors import ConflictError, ValidationError
from .remote_worker_deployment import DeploymentReference, deployment_binding_from_task
from .service import RuntimeService
from .util import canonical_json


OWNER = {"actor": "owner", "scopes": ["admin"]}


class RemotePreparer(Protocol):
    def prepare(self, launch: Any) -> object: ...
    def acknowledge(self, handle: object, grant: Mapping[str, Any], *,
                    accept: Callable[[Mapping[str, Any], Mapping[str, Any]], None]) -> Mapping[str, Any]: ...
    def abort(self, handle: object) -> None: ...


class RemoteInspector(Protocol):
    def observe(self, handle: object) -> Mapping[str, Any]: ...


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

    @staticmethod
    def _validate_observation(value: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ConflictError("independent remote observation is missing")
        required = {
            "target", "process", "runtime_instance_id",
            "runtime_epoch", "runtime_session_id", "source_closure_digest",
            "dependency_closure_digest", "model_root", "session_ref", "data_root",
            "support_root", "capacity", "model_inventory_digest", "session_config_digest",
        }
        if target.get("kind") == "runpod":
            required |= {"provider_identity", "child"}
        elif target.get("kind") == "machine" and isinstance(target.get("id"), str) and target["id"]:
            required.add("machine_identity")
        else:
            raise ConflictError("remote placement is unsupported or incomplete")
        if set(value) != required or value["target"] != target:
            raise ConflictError("remote provider or host observation is incomplete or misplaced")
        process = value["process"]
        if (not isinstance(process, Mapping) or type(process.get("pid")) is not int
                or process["pid"] <= 0 or not process.get("birth_id")
                or process.get("pgid") != process["pid"] or process.get("sid") != process["pid"]):
            raise ConflictError("remote parked host has no owned process incarnation")
        if target["kind"] == "runpod":
            child = value["child"]
            if (not isinstance(child, Mapping) or child.get("attached") is not True
                    or child.get("lanes") != ["orchestration", "executor"]
                    or not child.get("birth_id")):
                raise ConflictError("remote child attachment or two-lane proof is missing")
            provider = value["provider_identity"]
            if (not isinstance(provider, Mapping) or not target.get("provider_account_ref")
                    or not target.get("pod_id")
                    or provider.get("account_ref") != target["provider_account_ref"]
                    or provider.get("pod_id") != target["pod_id"]):
                raise ConflictError("independent provider identity differs from effective placement")
        else:
            machine = value["machine_identity"]
            if (not isinstance(machine, Mapping) or machine.get("id") != target["id"]
                    or type(machine.get("uid")) is not int or machine["uid"] < 0
                    or type(process.get("uid")) is not int
                    or process.get("uid") != machine["uid"]
                    or not process.get("executable") or not process.get("artifact_digest")):
                raise ConflictError("independent machine identity is missing or misplaced")
        try:
            return json.loads(canonical_json(dict(value)))
        except (TypeError, ValueError) as exc:
            raise ConflictError("remote observation is not canonical") from exc

    def park(self, launch: Any, *, target: Mapping[str, Any]) -> ParkedRemoteHost:
        """Prepare replacement while unclaimable; return proof for T12 recovery."""
        handle = self.preparer.prepare(launch)
        try:
            first = self._validate_observation(self.inspector.observe(handle), target)
            second = self._validate_observation(self.inspector.observe(handle), target)
            if first != second:
                raise ConflictError("remote identity changed before qualification")
            return ParkedRemoteHost(
                handle, dict(target), second, _digest(second), uuid.uuid4().hex,
            )
        except Exception:
            try:
                self.preparer.abort(handle)
            except Exception:
                pass
            raise

    def activate(self, task: Mapping[str, Any], reference: DeploymentReference,
                 parked: ParkedRemoteHost) -> dict[str, Any]:
        """Disabled grant -> owner acceptance commit -> final ACK -> enable.

        The callback uses the existing owner record RPC. Its resident transaction
        commits qualification and acceptance before the preparer sends a receipt.
        A lost final ACK never authorizes a second grant delivery.
        """
        if self.activation_state != "inactive":
            raise ConflictError("remote activation is already active or requires reconciliation")
        if not isinstance(reference, DeploymentReference):
            raise ValidationError("typed deployment reference is required")
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or binding.placement.effective_target != parked.target):
            raise ConflictError("parked host is foreign to Runtime's effective placement")
        latest = getattr(self.runtime, "_latest_remote_activation", None)
        if callable(latest) and latest(binding.admission_identity.task_id) is not None:
            raise ConflictError("another remote activation is already qualified")
        if self.credential_control is None:
            metadata = self.credentials.actor_metadata(reference.executor_id)
            existing = metadata.get("qualified_activation") if isinstance(metadata, dict) else None
            if isinstance(existing, dict) and not any(
                    kind == "task.remote_activation_revoked"
                    for kind, _ in self.runtime._remote_activation_history(
                        existing.get("task_id"), existing.get("activation_id"))):
                raise ConflictError("another remote credential generation remains unfenced")
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
            "capacity": reference.capacity,
            "session_config_digest": reference.session_config_digest,
        }
        if any(observation.get(key) != value for key, value in expected.items()):
            raise ConflictError("remote release, Runtime, model, session, root or capacity evidence changed")
        if (parked.target["kind"] == "machine"
                and (observation["process"]["executable"] != str(reference.executable.path)
                     or observation["process"]["artifact_digest"] != reference.executable.digest)):
            raise ConflictError("machine executable differs from the deployment artifact")
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
        self.runtime.assert_remote_activation_admissible(binding.admission_identity.task_id, qualification)
        issued = False
        self.activation_state = "inactive"
        try:
            issued = True  # A lost provision response may already have rotated the token.
            if self.credential_control is None:
                _token, path = self.credentials.provision(
                    credential_actor, list(self.scopes), rotate=True, enabled=False,
                    metadata={"execution_binding": placement, "qualified_activation": qualification},
                )
            else:
                response = self.credential_control(binding.admission_identity.task_id, {
                    "action": "provision", "qualification": qualification, "placement": placement,
                })
                if (not isinstance(response, Mapping)
                        or response.get("credential_actor") != credential_actor
                        or not isinstance(response.get("credential_file"), str)):
                    raise ConflictError("resident Runtime did not provision the disabled credential")
                path = response["credential_file"]
            self.activation_state = "unknown"
            grant = {
                "activation_id": activation_id,
                "credential_file": str(path),
                "executor_incarnation": parked.executor_incarnation,
                "evidence_digest": parked.evidence_digest,
            }
            expected_ack = {key: grant[key] for key in (
                "activation_id", "executor_incarnation", "evidence_digest",
            )}
            frozen_grant = dict(grant)
            accepted = False

            def accept(received: Mapping[str, Any], process: Mapping[str, Any]) -> None:
                nonlocal accepted
                if (accepted or received != frozen_grant or process != {
                        "pid": observation["process"]["pid"],
                        "birth_id": observation["process"]["birth_id"],
                }):
                    raise ConflictError("private remote acceptance is foreign or duplicated")
                if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != observation:
                    raise ConflictError("remote identity changed before resident acceptance")
                if self.runtime.record_remote_activation(
                        binding.admission_identity.task_id, qualification, identity=OWNER) != qualification:
                    raise ConflictError("resident Runtime did not commit the exact acceptance")
                accepted = True

            try:
                acknowledgement = self.preparer.acknowledge(parked.handle, grant, accept=accept)
            except (OSError, EOFError):
                if not accepted:
                    raise
                # Reconcile the committed generation by observation and resident
                # enablement below. Never resend the private grant.
                acknowledgement = expected_ack
            if not accepted or acknowledgement != expected_ack:
                raise ConflictError("private remote activation acknowledgement is invalid")
            if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != observation:
                raise ConflictError("remote identity changed after private acknowledgement")
            if self.credential_control is None:
                if not self.runtime._remote_activation_matches(
                        binding.admission_identity.task_id,
                        {"actor": credential_actor, "qualified_activation": qualification}, placement):
                    raise ConflictError("resident acceptance changed before credential release")
                self.credentials.enable_actor(credential_actor)
            elif self.credential_control(binding.admission_identity.task_id, {
                "action": "enable", "activation_id": activation_id,
            }) != {"enabled": True}:
                raise ConflictError("resident Runtime did not enable the remote credential")
            await_ready = getattr(self.preparer, "await_ready", None)
            if callable(await_ready):
                await_ready(parked.handle)
            self.activation_state = "active"
            return qualification
        except Exception:
            credential_revoked = not issued
            try:
                if issued:
                    if self.credential_control is None:
                        self.credentials.revoke(credential_actor)
                    else:
                        revoked = self.credential_control(binding.admission_identity.task_id, {
                            "action": "revoke", "activation_id": activation_id,
                        })
                        if revoked != {"revoked": True}:
                            raise ConflictError("resident Runtime did not confirm credential revocation")
                    credential_revoked = True
            except Exception:
                pass
            activation_revoked = False
            try:
                self.runtime.revoke_remote_activation(
                    binding.admission_identity.task_id, activation_id, identity=OWNER,
                    **({"qualification": qualification} if self.credential_control is None else {}),
                )
                activation_revoked = True
            except Exception:
                latest = getattr(self.runtime, "_latest_remote_activation", None)
                if callable(latest):
                    try:
                        activation_revoked = latest(binding.admission_identity.task_id) is None
                    except Exception:
                        pass
            host_aborted = False
            try:
                self.preparer.abort(parked.handle)
                host_aborted = True
            except Exception:
                pass
            self.activation_state = "inactive" if credential_revoked and activation_revoked and host_aborted else "unknown"
            raise

    def assert_fresh(self, task: Mapping[str, Any], reference: DeploymentReference,
                     parked: ParkedRemoteHost, qualification: Mapping[str, Any]) -> None:
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or qualification.get("binding_digest") != binding.digest()
                or qualification.get("deployment_digest") != reference.digest()):
            raise ConflictError("remote activation is stale before queue")
        if self.credential_control is None:
            metadata = self.credentials.actor_metadata(reference.executor_id)
            if metadata is None or not self.runtime._remote_activation_matches(
                    binding.admission_identity.task_id,
                    {"actor": reference.executor_id, "qualified_activation": dict(qualification)},
                    metadata["execution_binding"]):
                raise ConflictError("remote activation is revoked or expired before queue")
        elif self.credential_control(binding.admission_identity.task_id, {
                "action": "verify", "activation_id": qualification["activation_id"],
        }) != {"fresh": True}:
            raise ConflictError("remote activation is revoked or expired before queue")
        if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != parked.observation:
            raise ConflictError("remote provider, process, child, model or session changed before queue")
