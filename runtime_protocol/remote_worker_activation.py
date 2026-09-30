"""Owner-only qualified activation for an already admitted remote worker.

The preparer parks the host. The inspector is an independent provider/process
observer supplied by the Runtime owner, never the worker's own readiness JSON.
No task is admitted or retried by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .auth import CredentialStore
from .errors import AuthorizationError, ConflictError, ValidationError
from .remote_worker_deployment import DeploymentReference, ProjectedLaunch, deployment_binding_from_task
from .service import RuntimeService
from .util import canonical_json


OWNER = {"actor": "owner", "scopes": ["admin"]}


class RemotePreparer(Protocol):
    def prepare(self, launch: Any) -> object: ...
    # The receiver calls accept(grant, actual_pid_birth) after consuming the
    # grant and before sending its private ACK. This is an owner-bound internal
    # callback, never a worker bearer operation or a second launch/ACK message.
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
    deployment_digest: str

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
                 scopes: tuple[str, ...] = ("handshake", "worker:execute"),
                 ttl_seconds: int = 300):
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ValidationError("remote activation TTL is out of range")
        if not {"handshake", "worker:execute"}.issubset(scopes):
            raise ValidationError("activation requires handshake and execution scopes")
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

    def _authenticate_credential(self, reference: DeploymentReference, path: Path) -> None:
        """Prove bearer enablement with the existing authenticated handshake."""
        token = path.read_text(encoding="utf-8").strip()
        if self.credential_control is None:
            identity = self.credentials.require(token, "handshake")
            response = self.runtime.handshake({
                "authenticated_actor": identity["actor"],
                "authenticated_scopes": identity["scopes"],
                "requested_scopes": ["worker:execute"],
            })
        else:
            request = Request(reference.runtime_endpoint + "/v1/handshake",
                              data=b'{"requested_scopes":["worker:execute"]}',
                              headers={"Authorization": "Bearer " + token,
                                       "Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=5) as reply:
                response = json.load(reply)
        if (response.get("actor_id") != reference.executor_id
                or response.get("realm_id") != self.runtime.realm["id"]
                or response.get("scopes") != ["worker:execute"]):
            raise ConflictError("authenticated credential readiness is foreign or incomplete")

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
        machine = target.get("kind") == "machine"
        required |= {"machine_identity"} if machine else {"provider_identity", "child"}
        if set(value) != required or value["target"] != target:
            raise ConflictError("remote provider or host observation is incomplete or misplaced")
        for key in ("source_closure_digest", "dependency_closure_digest", "model_inventory_digest", "session_config_digest"):
            try:
                RuntimeService._placement_evidence_digest(value[key], key)
            except ValidationError as exc:
                raise ConflictError("independent host digest evidence is missing or invalid") from exc
        process = value["process"]
        if (not isinstance(process, Mapping) or type(process.get("pid")) is not int
                or process["pid"] <= 0 or not process.get("birth_id")
                or process.get("pgid") != process["pid"] or process.get("sid") != process["pid"]):
            raise ConflictError("remote parked host has no owned process incarnation")
        if machine:
            identity = value["machine_identity"]
            if (not isinstance(identity, Mapping) or identity.get("id") != target.get("id")
                    or type(identity.get("uid")) is not int or identity["uid"] != os.getuid()
                    or process.get("uid") != identity["uid"]
                    or not process.get("executable") or not process.get("artifact_digest")):
                raise ConflictError("independent local machine or executable identity is missing")
        else:
            child = value["child"]
            if (not isinstance(child, Mapping) or child.get("attached") is not True
                    or child.get("lanes") != ["orchestration", "executor"]
                    or not child.get("birth_id")):
                raise ConflictError("remote child attachment or two-lane proof is missing")
            if not isinstance(value["provider_identity"], Mapping) or not value["provider_identity"].get("account_ref"):
                raise ConflictError("independent provider identity is missing")
        try:
            return json.loads(canonical_json(dict(value)))
        except (TypeError, ValueError) as exc:
            raise ConflictError("remote observation is not canonical") from exc

    def park(self, launch: Any, *, target: Mapping[str, Any]) -> ParkedRemoteHost:
        """Prepare replacement while unclaimable; return proof for T12 recovery."""
        if isinstance(launch, DeploymentReference):
            deployment_digest = launch.digest()
        elif isinstance(launch, ProjectedLaunch):
            deployment_digest = launch.deployment_digest
        else:
            raise ValidationError("a Runtime deployment reference or projected launch is required")
        handle = self.preparer.prepare(launch)
        try:
            first = self._validate_observation(self.inspector.observe(handle), target)
            second = self._validate_observation(self.inspector.observe(handle), target)
            if first != second:
                raise ConflictError("remote identity changed before qualification")
            return ParkedRemoteHost(
                handle, dict(target), second, _digest(second), uuid.uuid4().hex, deployment_digest,
            )
        except Exception:
            try:
                self.preparer.abort(handle)
            except Exception:
                self.activation_state = "unknown"
            raise

    def activate(self, task: Mapping[str, Any], reference: DeploymentReference,
                 parked: ParkedRemoteHost) -> dict[str, Any]:
        try:
            return self._activate(task, reference, parked)
        except Exception:
            # A rejected duplicate belongs to the already consumed generation.
            # Clean up only a fresh parked launch rejected before reservation;
            # the reserved path below owns its own exact cleanup.
            try:
                used = any(kind == "task.remote_activation_granted"
                           and record["qualification"]["executor_incarnation"] == parked.executor_incarnation
                           for kind, record in self.runtime._remote_grant_events())
            except Exception:
                used = True
                self.activation_state = "unknown"
            if not used:
                try:
                    self.preparer.abort(parked.handle)
                    self.activation_state = "inactive"
                except Exception:
                    self.activation_state = "unknown"
            raise

    def _activate(self, task: Mapping[str, Any], reference: DeploymentReference,
                  parked: ParkedRemoteHost) -> dict[str, Any]:
        """Issue disabled credential, privately acknowledge, reobserve, then enable."""
        if not isinstance(reference, DeploymentReference):
            raise ValidationError("typed deployment reference is required")
        binding = deployment_binding_from_task(task)
        if (binding != reference.deployment_binding
                or binding.placement.effective_target != parked.target
                or _digest(parked.observation) != parked.evidence_digest):
            raise ConflictError("parked host is foreign to Runtime's effective placement")
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
        if parked.target.get("kind") == "machine":
            if (observation["process"]["executable"] != str(reference.executable.path)
                    or observation["process"]["artifact_digest"] != reference.executable.digest):
                raise ConflictError("local host executable differs from the qualified launch")
        elif observation["provider_identity"].get("account_ref") != parked.target.get("provider_account_ref"):
            raise ConflictError("remote provider account differs from effective placement")
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
        # Reserve before credential rotation or delivery. Retrying this parked
        # incarnation must not rotate/revoke the generation already using it.
        path = (self.credentials.path_for(credential_actor) if self.credential_control is None
                else Path(reference.credential_ref.removeprefix("file:")))
        grant = {
            "activation_id": activation_id,
            "credential_file": str(path),
            "executor_incarnation": parked.executor_incarnation,
            "evidence_digest": parked.evidence_digest,
        }
        process = {key: observation["process"][key] for key in ("pid", "birth_id")}
        # T12 may authorize a new placement version after parking. Preserve the
        # actual launch identity separately from the current admission binding.
        record = {"qualification": qualification, "grant_digest": _digest(grant),
                  "launch_digest": parked.deployment_digest, "process": process}
        self.runtime._begin_remote_grant(binding.admission_identity.task_id, record, identity=OWNER)
        issued = False
        self.activation_state = "unknown"
        try:
            # Mark issuance as uncertain before an RPC which can lose its reply.
            issued = True
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
                        or response.get("credential_file") != str(path)):
                    raise ConflictError("resident Runtime did not provision the disabled credential")
                path = response["credential_file"]
            try:
                self._authenticate_credential(reference, Path(path))
            except AuthorizationError:
                pass
            except HTTPError as exc:
                if exc.code != 401:
                    raise
            else:
                raise ConflictError("disabled execution credential authenticated before acceptance")

            acceptance_failed = False

            def accept(accepted_grant: Mapping[str, Any], accepted_process: Mapping[str, Any]) -> None:
                nonlocal acceptance_failed
                try:
                    if _digest(accepted_grant) != record["grant_digest"] or accepted_process != process:
                        raise ConflictError("private activation acceptance differs from the exact grant or process")
                    self.runtime._accept_remote_grant(binding.admission_identity.task_id, record, identity=OWNER)
                except Exception:
                    acceptance_failed = True
                    raise

            try:
                acknowledgement = self.preparer.acknowledge(parked.handle, grant, accept=accept)
            except Exception:
                # A lost reply is uncertainty, not acceptance. Only the already
                # committed receiver receipt can resolve it; never resend.
                if acceptance_failed:
                    raise
                acknowledgement = None
            if acceptance_failed:
                raise ConflictError("private activation receiver rejected acceptance")
            if acknowledgement is not None and acknowledgement != {
                    "activation_id": activation_id,
                    "executor_incarnation": parked.executor_incarnation,
                    "evidence_digest": parked.evidence_digest}:
                raise ConflictError("private remote activation acknowledgement is invalid")
            if self._validate_observation(self.inspector.observe(parked.handle), parked.target) != observation:
                raise ConflictError("remote identity changed after private acknowledgement")
            self.runtime._recover_remote_grant(binding.admission_identity.task_id, record, identity=OWNER)
            self.runtime.record_remote_activation(
                binding.admission_identity.task_id, qualification, identity=OWNER
            )
            if self.credential_control is None:
                with self.runtime.store._mutex, self.credentials._lock:
                    metadata = self.credentials.actor_metadata(credential_actor)
                    if (metadata is None or metadata.get("qualified_activation") != qualification
                            or metadata.get("execution_binding") != placement
                            or not self.runtime._remote_activation_matches(
                                binding.admission_identity.task_id, metadata, placement)):
                        raise ConflictError("execution credential generation changed before enablement")
                    self.credentials.enable_actor(credential_actor)
            elif self.credential_control(binding.admission_identity.task_id, {
                "action": "enable", "activation_id": activation_id,
            }) != {"enabled": True}:
                raise ConflictError("resident Runtime did not enable the remote credential")
            self._authenticate_credential(reference, Path(path))
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
                        with self.credentials._lock:
                            metadata = self.credentials.actor_metadata(credential_actor)
                            if metadata is not None and metadata.get("qualified_activation") != qualification:
                                raise ConflictError("execution credential generation changed before cleanup")
                            self.credentials.disable_actor(credential_actor)
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
                self.runtime._revoke_remote_grant(
                    binding.admission_identity.task_id, activation_id, identity=OWNER
                )
                activation_revoked = True
            except Exception:
                pass
            process_cleaned = False
            try:
                self.preparer.abort(parked.handle)
                process_cleaned = True
            except Exception:
                pass
            self.activation_state = "inactive" if credential_revoked and activation_revoked and process_cleaned else "unknown"
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
