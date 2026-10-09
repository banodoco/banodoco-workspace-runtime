"""Bounded Runtime-owned local execution relay and private host boundary.

GenericHost owns engines and listeners. This module never imports Astrid,
Worker, VibeComfy, provider SDKs or model code, and issues no task credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
from typing import Any, Mapping
from urllib.parse import urlsplit
from .errors import ValidationError

HOST_PREPARATION_VERSION = "runtime.local-execution-host/v1"
ENGINE_CONTROL_VERSION = "runtime.local-execution-engine-control/v1"
CONTROL_VERSION = "runtime.local-execution-control/v1"
PREPARATION_VERSION = "runtime.local-worker-preparation/v3"
FRAME_LIMIT = 1024 * 1024
HOST_ROLES = frozenset({"engine", "engine_listener"})
PROCESS_ROLES = frozenset({"host", "engine", "engine_listener"})
RUNTIME_OWNER_FIELDS = frozenset({"pid", "uid", "birth_id", "runtime_instance_id", "coordinator_epoch"})
ROLE_REFERENCE_VERSION = "runtime.role-custody-reference/v1"
TARGET_FIELDS = frozenset({"pid", "uid", "birth_id", "audit_token_sha256", "audit_token_pidversion"})
PROFILE_FIELDS = frozenset({"profile_id", "workspace_uuid", "realm_root", "support_root", "machine_id",
                            "worker_executable", "host_executable", "engine_executable", "engine_listener_executable",
                            "engine_endpoint", "worker_artifact_digest", "host_artifact_digest", "engine_artifact_digest",
                            "engine_listener_artifact_digest", "session_config_digest", "profile_revision", "profile_digest",
                            "release_digest", "engine_launch"})
ADAPTER_PIN_FIELDS = frozenset({"session_source_sha256", "spawn_sha256", "cleanup_sha256", "stop_sha256", "adapter_source_sha256"})


class RelayError(RuntimeError):
    """A bounded delegated transition lacks exact identity or custody."""


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RelayError("local execution control payload is not canonical JSON") from exc


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def send_frame(channel: socket.socket, value: Mapping[str, Any]) -> None:
    encoded = canonical_json(dict(value))
    if len(encoded) > FRAME_LIMIT:
        raise RelayError("local execution control frame exceeds its bound")
    channel.sendall(encoded + b"\n")


def receive_frame(channel: socket.socket) -> dict[str, Any]:
    frame = bytearray()
    while b"\n" not in frame:
        chunk = channel.recv(min(4096, FRAME_LIMIT + 1 - len(frame)))
        if not chunk:
            raise RelayError("local execution control channel closed")
        frame.extend(chunk)
        if len(frame) > FRAME_LIMIT:
            raise RelayError("local execution control frame exceeds its bound")
    encoded, extra = bytes(frame).split(b"\n", 1)
    if extra:
        raise RelayError("local execution control channel has an unsolicited frame")
    try:
        from .local_execution_handoff import decode
        value = decode(encoded)
    except (ValueError, UnicodeDecodeError, ValidationError) as exc:
        raise RelayError("local execution control frame is malformed") from exc
    if not isinstance(value, dict):
        raise RelayError("local execution control frame is not an object")
    # Re-encoding rejects NaN accepted by Python's decoder and unbounded values.
    canonical_json(value)
    return value


def host_prepare_request(*, operation_id: str, channel_id: str, owner_epoch: str,
                         runtime_owner: Mapping[str, Any], profile: Mapping[str, Any],
                         custody_scope: str) -> dict[str, Any]:
    if not all(isinstance(x, str) and x and len(x) <= 256 for x in (operation_id, channel_id, owner_epoch)):
        raise RelayError("host preparation private identities are invalid")
    if runtime_owner.get("runtime_instance_id") != owner_epoch or runtime_owner.get("coordinator_epoch") != owner_epoch:
        raise RelayError("host preparation epoch differs from Runtime-issued ownership")
    if set(runtime_owner) != RUNTIME_OWNER_FIELDS or isinstance(runtime_owner.get("pid"), bool) or not isinstance(runtime_owner.get("pid"), int) or runtime_owner["pid"] <= 0 or isinstance(runtime_owner.get("uid"), bool) or not isinstance(runtime_owner.get("uid"), int) or runtime_owner["uid"] < 0 or not isinstance(runtime_owner.get("birth_id"), str) or not runtime_owner["birth_id"]:
        raise RelayError("host preparation lacks exact Runtime owner incarnation")
    if not Path(custody_scope).is_absolute():
        raise RelayError("host preparation custody scope must be absolute")
    validate_selected_profile(profile)
    request = {
        "version": HOST_PREPARATION_VERSION, "command": "prepare_local_execution",
        "operation_id": operation_id, "channel_id": channel_id,
        "owner_epoch": owner_epoch, "runtime_owner": dict(runtime_owner),
        "profile": dict(profile), "custody_scope": custody_scope,
    }
    return json.loads(canonical_json(request))


def validate_selected_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Bound the selected private launch contract before forwarding it.

    This checks declarations. Installed artifact origins and live observations
    must independently prove the same pins before activation or real enablement.
    """
    optional = {"host_os_executable", "host_os_artifact_digest"}
    if not isinstance(profile, Mapping) or not PROFILE_FIELDS.issubset(profile) or set(profile) - PROFILE_FIELDS - optional:
        raise RelayError("local execution selected profile shape is invalid")
    if ("host_os_executable" in profile) != ("host_os_artifact_digest" in profile):
        raise RelayError("selected host lexical/kernel pin pair is incomplete")
    if "host_os_executable" in profile and (not isinstance(profile["host_os_executable"], str) or not Path(profile["host_os_executable"]).is_absolute() or ".." in Path(profile["host_os_executable"]).parts or not isinstance(profile["host_os_artifact_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", profile["host_os_artifact_digest"])):
        raise RelayError("selected host kernel executable/artifact pin is invalid")
    for name in PROFILE_FIELDS - {"engine_launch"}:
        if not isinstance(profile[name], str) or not profile[name] or len(profile[name]) > 4096:
            raise RelayError("local execution selected profile has an invalid identity")
        if name.endswith("digest") and not re.fullmatch(r"sha256:[0-9a-f]{64}", profile[name]):
            raise RelayError("local execution selected profile digest is invalid")
    for name in ("realm_root", "support_root", "worker_executable", "host_executable", "engine_executable", "engine_listener_executable"):
        if not Path(profile[name]).is_absolute() or ".." in Path(profile[name]).parts:
            raise RelayError("local execution selected path is not an absolute pin")
    launch = profile["engine_launch"]
    if not isinstance(launch, Mapping) or set(launch) != {"module", "session_root", "config", "source_revision", "source_content_digest", "listener_argv", "adapter_pins"} or launch["module"] != "vibecomfy.commands.session":
        raise RelayError("selected engine launch shape or module is invalid")
    root = Path(str(launch["session_root"]))
    if not root.is_absolute() or ".." in root.parts or root.parent.name != "sessions" or root.parent.parent.name != "out":
        raise RelayError("selected engine session root does not have the fresh-session layout")
    config = launch["config"]
    if not isinstance(config, Mapping) or config.get("runtime_root") != str(root.parents[2]) or config.get("cwd") != str(root.parents[2]) or config.get("server_log_path") != str(root / "comfy.log") or config.get("locality") != "managed_local_server" or config.get("warm_policy") != "auto":
        raise RelayError("selected engine configuration has inconsistent owner paths or locality")
    endpoint = urlsplit(profile["engine_endpoint"])
    try:
        port = endpoint.port
    except ValueError as exc:
        raise RelayError("selected engine endpoint is invalid") from exc
    if endpoint.scheme != "http" or endpoint.hostname not in {"127.0.0.1", "::1"} or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in {"", "/"} or isinstance(config.get("port"), bool) or not isinstance(config.get("port"), int) or config["port"] != port or not 1 <= config["port"] <= 65535:
        raise RelayError("selected engine configuration has a different loopback endpoint")
    timeout = config.get("ready_timeout_sec")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 900:
        raise RelayError("selected engine readiness timeout is invalid")
    canonical_json(config)
    emitted = json.dumps(dict(config), indent=2, sort_keys=True).encode("utf-8")
    if "sha256:" + hashlib.sha256(emitted).hexdigest() != profile["session_config_digest"]:
        raise RelayError("selected engine configuration differs from the pinned emitted file digest")
    if not isinstance(launch["source_revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", launch["source_revision"]) or not isinstance(launch["source_content_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", launch["source_content_digest"]):
        raise RelayError("selected engine package source pins are invalid")
    argv = launch["listener_argv"]
    if not isinstance(argv, list) or not argv or len(argv) > 256 or any(not isinstance(x, str) or "\0" in x or len(x) > 4096 for x in argv) or not Path(argv[0]).is_absolute():
        raise RelayError("selected engine listener argv is invalid")
    pins = launch["adapter_pins"]
    if not isinstance(pins, Mapping) or set(pins) != ADAPTER_PIN_FIELDS or any(not isinstance(x, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in pins.values()):
        raise RelayError("selected engine adapter source/seam pins are invalid")
    return json.loads(canonical_json(dict(profile)))


def validate_host_prepared(value: Mapping[str, Any], *, request: Mapping[str, Any],
                           host_pid: int, host_birth_id: str) -> dict[str, Any]:
    required = {"version", "status", "operation_id", "channel_id", "owner_epoch",
                "processes", "engine_binding", "session_config_digest", "custody_capabilities"}
    if set(value) != required or value.get("version") != HOST_PREPARATION_VERSION or value.get("status") != "prepared":
        raise RelayError("host preparation reply shape/version is invalid")
    if any(value.get(k) != request.get(k) for k in ("operation_id", "channel_id", "owner_epoch")):
        raise RelayError("host preparation reply has a stale channel or owner epoch")
    processes = value.get("processes")
    if not isinstance(processes, Mapping) or set(processes) != PROCESS_ROLES:
        raise RelayError("host preparation reply lacks required process roles")
    pids = set()
    for role, identity in processes.items():
        if not isinstance(identity, Mapping) or set(identity) != {"pid", "birth_id"}:
            raise RelayError("host preparation process identity is invalid")
        pid = identity.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or not isinstance(identity.get("birth_id"), str) or not identity.get("birth_id"):
            raise RelayError("host preparation process identity is invalid")
        pids.add(pid)
    if len(pids) != len(PROCESS_ROLES) or processes["host"] != {"pid": host_pid, "birth_id": host_birth_id}:
        raise RelayError("host preparation reply does not identify the retained host")
    binding = value.get("engine_binding")
    expected = {"supervisor_pid": processes["engine"]["pid"], "listener_pid": processes["engine_listener"]["pid"],
                "listener_parent_pid": processes["engine"]["pid"], "socket_owner_pid": processes["engine_listener"]["pid"]}
    if not isinstance(binding, Mapping) or dict(binding) != expected:
        raise RelayError("host preparation reply has inconsistent listener ownership")
    profile = request["profile"]
    if value.get("session_config_digest") != profile.get("session_config_digest"):
        raise RelayError("host preparation reply has a different session configuration")
    capabilities = value.get("custody_capabilities")
    if not isinstance(capabilities, Mapping) or set(capabilities) != HOST_ROLES:
        raise RelayError("host preparation reply lacks per-role retained custody")
    for role, reference in capabilities.items():
        validate_role_reference(reference, role=role, scope_root=request["custody_scope"], process=processes[role])
    return json.loads(canonical_json(dict(value)))


def validate_role_reference(value: object, *, role: str, scope_root: str, process: Mapping[str, Any]) -> dict[str, Any]:
    """Validate serialization only; independent kernel/ledger checks follow.

    A valid reference never authenticates a claimant or grants it signaling
    authority. The protected designation and private peer supply that proof.
    """
    if not isinstance(value, Mapping) or set(value) != {"version", "scope_root", "role", "generation", "target"} or value.get("version") != ROLE_REFERENCE_VERSION or value.get("scope_root") != scope_root or value.get("role") != role:
        raise RelayError("host custody reference has a different role, scope or version")
    generation, target = value.get("generation"), value.get("target")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1 or not isinstance(target, Mapping) or set(target) != TARGET_FIELDS:
        raise RelayError("host custody reference generation or incarnation is invalid")
    if any(target.get(k) != process.get(k) for k in ("pid", "birth_id")) or isinstance(target.get("uid"), bool) or not isinstance(target.get("uid"), int) or target["uid"] < 0 or isinstance(target.get("audit_token_pidversion"), bool) or not isinstance(target.get("audit_token_pidversion"), int) or target["audit_token_pidversion"] < 1 or not isinstance(target.get("audit_token_sha256"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", target["audit_token_sha256"]):
        raise RelayError("host custody reference differs from its process or kernel token")
    return json.loads(canonical_json(dict(value)))


def engine_listener_signal_request(*, preparation: Mapping[str, Any], reference: Mapping[str, Any], signum: int) -> dict[str, Any]:
    if isinstance(signum, bool) or signum not in {9, 15} or reference.get("role") != "engine_listener":
        raise RelayError("engine signal request is outside the admitted listener signals")
    return {"version": ENGINE_CONTROL_VERSION, "command": "signal_owned_listener",
            **{k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch")},
            "role": "engine_listener", "generation": reference["generation"],
            "target": json.loads(canonical_json(reference["target"])), "signal": signum}


def validate_engine_listener_signal(value: Mapping[str, Any], *, preparation: Mapping[str, Any],
                                    reference: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != {"version", "command", "operation_id", "channel_id", "owner_epoch", "role", "generation", "target", "signal"}:
        raise RelayError("engine listener signal request shape is invalid")
    expected = engine_listener_signal_request(preparation=preparation, reference=reference, signum=value.get("signal"))
    if dict(value) != expected:
        raise RelayError("engine listener signal has stale channel, role, target or generation")
    return json.loads(canonical_json(expected))


def engine_listener_signal_ack(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return only after the host's fenced kernel call; never attest exit."""
    return {"status": "signaled", **{k: v for k, v in request.items() if k != "command"}}


def host_report_request(preparation: Mapping[str, Any]) -> dict[str, Any]:
    return {"version": HOST_PREPARATION_VERSION, "command": "report_local_execution",
            **{k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch")}}


def host_abort_request(preparation: Mapping[str, Any], capabilities: Mapping[str, Any]) -> dict[str, Any]:
    if set(capabilities) - HOST_ROLES:
        raise RelayError("abort contains an unsupported custody role")
    return {"version": HOST_PREPARATION_VERSION, "command": "abort_local_execution",
            **{k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch")},
            "profile_digest": preparation["profile"]["profile_digest"],
            "profile_binding_digest": digest(preparation["profile"]),
            "custody_scope": preparation["custody_scope"],
            "custody_capabilities": json.loads(canonical_json(dict(capabilities)))}


def validate_host_unresolved(value: Mapping[str, Any], *, request: Mapping[str, Any]) -> dict[str, Any]:
    command = request.get("command")
    expected_code = {"prepare_local_execution": "preparation_unresolved",
                     "report_local_execution": "report_unresolved"}.get(command)
    if expected_code is None or set(value) != {"version", "status", "operation_id", "channel_id", "owner_epoch", "error_code", "custody_capabilities"}:
        raise RelayError("host failure envelope shape is invalid")
    if value.get("version") != HOST_PREPARATION_VERSION or value.get("status") != "unresolved" or value.get("error_code") != expected_code or any(value.get(k) != request.get(k) for k in ("operation_id", "channel_id", "owner_epoch")):
        raise RelayError("host failure envelope has stale or invalid binders")
    capabilities = value.get("custody_capabilities")
    if not isinstance(capabilities, Mapping) or set(capabilities) - HOST_ROLES:
        raise RelayError("host failure envelope has unsupported custody roles")
    # Pending obligations may not yet have an executable incarnation. These
    # references are retained evidence only; they never authorize a signal.
    for role, ref in capabilities.items():
        if not isinstance(ref, Mapping) or set(ref) != {"version", "scope_root", "role", "generation", "target"} or ref.get("version") != ROLE_REFERENCE_VERSION or ref.get("role") != role or not isinstance(ref.get("scope_root"), str) or not Path(ref["scope_root"]).is_absolute() or isinstance(ref.get("generation"), bool) or not isinstance(ref.get("generation"), int) or ref["generation"] < 1:
            raise RelayError("host unresolved custody reference is invalid")
        target = ref.get("target")
        if isinstance(target, Mapping) and set(target) == {"admission_id"}:
            if not isinstance(target["admission_id"], str) or not target["admission_id"]:
                raise RelayError("host pending admission identity is invalid")
        elif isinstance(target, Mapping):
            validate_role_reference(ref, role=role, scope_root=ref["scope_root"], process=target)
        else:
            raise RelayError("host unresolved target is invalid")
    return json.loads(canonical_json(dict(value)))


def validate_host_abort(value: Mapping[str, Any], *, request: Mapping[str, Any]) -> dict[str, Any]:
    bound = {k: v for k, v in request.items() if k != "command"}
    extra = {"status", "cleanup"} if value.get("status") == "cleaned" else {"status", "error_code"}
    if set(value) != set(bound) | extra or any(value.get(k) != v for k, v in bound.items()):
        raise RelayError("host abort reply differs from retained cleanup binding")
    if value.get("status") == "unresolved":
        if value.get("error_code") != "cleanup_unresolved":
            raise RelayError("host abort failure code is invalid")
    elif value.get("status") == "cleaned":
        cleanup = value.get("cleanup")
        if not isinstance(cleanup, Mapping) or set(cleanup) != HOST_ROLES:
            raise RelayError("host cleaned reply lacks the required graph")
        for role, proof in cleanup.items():
            if not isinstance(proof, Mapping) or set(proof) != {"generation", "target", "exit_code", "proof_kind"}:
                raise RelayError("host cleanup proof shape is invalid")
            ref = request["custody_capabilities"].get(role)
            if ref is not None and (proof["generation"] != ref["generation"] or proof["target"] != ref["target"]):
                raise RelayError("host cleanup proof changed the retained incarnation")
            if isinstance(proof["generation"], bool) or not isinstance(proof["generation"], int) or proof["generation"] < 1:
                raise RelayError("host cleanup generation is invalid")
            target = proof["target"]
            if proof["proof_kind"] == "never-spawned":
                if proof["exit_code"] is not None or not isinstance(target, Mapping) or set(target) != {"admission_id"} or not isinstance(target["admission_id"], str) or not target["admission_id"]:
                    raise RelayError("host never-spawned proof is not an authoritative pending obligation")
            else:
                kinds = {"retained-child-exit"} if role == "engine" else {"retained-child-exit", "authenticated-retained-child-exit"}
                if proof["proof_kind"] not in kinds or isinstance(proof["exit_code"], bool) or not isinstance(proof["exit_code"], int) or not isinstance(target, Mapping) or set(target) != TARGET_FIELDS:
                    raise RelayError("host cleanup lacks retained child exit proof")
                validate_role_reference({"version": ROLE_REFERENCE_VERSION, "scope_root": request["custody_scope"], "role": role, "generation": proof["generation"], "target": target}, role=role, scope_root=request["custody_scope"], process=target)
    else:
        raise RelayError("host abort returned an unknown outcome")
    return json.loads(canonical_json(dict(value)))


class LocalExecutionRelay:
    """One retained host's protocol bridge, without engine or task authority.

    The launcher publishes the child obligation before constructing this bridge.
    `verify_host` must check the retained child/kernel incarnation, and `exchange`
    uses that launch's private persistent descriptor. An inherited descriptor's
    creator credentials are deliberately not consulted as child authentication.
    """

    def __init__(self, *, host_pid: int, host_birth_id: str, exchange, verify_host):
        self.host_pid = host_pid
        self.host_birth_id = host_birth_id
        self._exchange = exchange
        self._verify_host = verify_host
        self._preparation: dict[str, Any] | None = None
        self._prepared: dict[str, Any] | None = None
        self._capabilities: dict[str, Any] = {}
        self._abort_input: bytes | None = None
        self._cleaned: dict[str, Any] | None = None

    def _call(self, request):
        self._verify_host()
        reply = self._exchange(request)
        self._verify_host()
        if not isinstance(reply, Mapping):
            raise RelayError("host reply is not an object")
        return reply

    def _accept_report(self, reply, request):
        if reply.get("status") == "unresolved":
            value = validate_host_unresolved(reply, request=request)
            # Retain all previously known obligations. A disappearing reference
            # cannot erase a child, even if the host's latest report is partial.
            for role, ref in value["custody_capabilities"].items():
                if ref["scope_root"] != self._preparation["custody_scope"]:
                    raise RelayError("host failure custody scope differs from selected scope")
                if role in self._capabilities and self._capabilities[role] != ref:
                    raise RelayError("host failure replaced retained custody")
                self._capabilities[role] = ref
            return value
        value = validate_host_prepared(reply, request=self._preparation,
                                       host_pid=self.host_pid, host_birth_id=self.host_birth_id)
        if self._prepared is not None and value != self._prepared:
            raise RelayError("host report changed its retained prepared graph")
        for role, ref in self._capabilities.items():
            if value["custody_capabilities"].get(role) != ref:
                raise RelayError("host prepared reply replaced retained custody")
        self._capabilities = value["custody_capabilities"]
        self._prepared = value
        return value

    def prepare(self, request):
        selected = host_prepare_request(**{k: request[k] for k in ("operation_id", "channel_id", "owner_epoch", "runtime_owner", "profile", "custody_scope")})
        if dict(request) != selected:
            raise RelayError("relay preparation shape is invalid")
        if self._preparation is not None and self._preparation != selected:
            raise RelayError("relay preparation replay changed input")
        if self._abort_input is not None:
            raise RelayError("relay preparation is already aborting")
        self._preparation = selected
        if self._prepared is not None:
            self._verify_host()
            return json.loads(canonical_json(self._prepared))
        return self._accept_report(self._call(selected), selected)

    def report(self):
        if self._preparation is None or self._abort_input is not None:
            raise RelayError("relay has no reportable preparation")
        request = host_report_request(self._preparation)
        return self._accept_report(self._call(request), request)

    def abort(self):
        if self._preparation is None:
            raise RelayError("relay has no retained cleanup binding")
        request = host_abort_request(self._preparation, self._capabilities)
        encoded = canonical_json(request)
        if self._abort_input is not None and self._abort_input != encoded:
            raise RelayError("relay abort replay changed input")
        self._abort_input = encoded
        if self._cleaned is not None:
            return json.loads(canonical_json(self._cleaned))
        value = validate_host_abort(self._call(request), request=request)
        if value["status"] == "cleaned":
            self._cleaned = value
        return value


class RelayHandoffEndpoint:
    """Authenticated original-owner forwarding, with no successor adoption.

    The journal authority and fence verifier come from retained local owners,
    never from serialized actor fields. No lock spans the host exchange.
    """
    def __init__(self, bridge, journal, *, verify_binding, verify_fence, verify_active_owner=None, verify_successor=None, transfer_successor=None, on_export=None):
        self.bridge = bridge; self.journal = journal
        self.verify_binding = verify_binding; self.verify_fence = verify_fence
        self._phase = "owned"
        self.verify_active_owner = verify_active_owner
        self.verify_successor = verify_successor
        self.transfer_successor = transfer_successor
        self.on_export = on_export
        self.successor_listener = None

    def handoff(self, request, *, successor_peer=None):
        from .local_execution_handoff import validate_request, digest, VERSION, COUNTERS
        from .errors import ConflictError
        validate_request(request)
        try:
            return self._handoff(request, successor_peer=successor_peer)
        except Exception as exc:
            b = request["binding"]
            conflict = isinstance(exc, ConflictError) and any(word in str(exc) for word in ("changed input", "binding changed", "phase conflict", "stale"))
            return {"version": VERSION, "command": request["command"], "binding_digest": digest(b), "request_digest": digest(request), "status": "conflict" if conflict else "unresolved", "phase": self._phase,
                    "host": {k: b["current_roles"]["host"]["target"][k] for k in ("pid", "birth_id", "uid")}, "registered_state": None,
                    "quiescence": {"claim_gate_closed": None, **{k: None for k in COUNTERS}, "observation_status": "unknown"},
                    "custody_capabilities": b["current_roles"], "error_code": "binding_conflict" if conflict else "custody_unresolved"}

    def _handoff(self, request, *, successor_peer=None):
        from .local_execution_handoff import validate_request, validate_reply, digest, VERSION, COUNTERS
        validate_request(request)
        b = request["binding"]
        if successor_peer is None:
            self.verify_binding(b)
        else:
            successor_peer.verify_binding(b)
            if self.verify_successor is None:
                raise RelayError("fresh successor authority is unavailable")
            self.verify_successor(b, successor_peer)
        with self.journal.locked() as state:
            phase = state["phase"]
            self._phase = phase
        # This retained A descriptor is not fresh B authentication. Even a
        # correctly hashed claimant-supplied proof must not unlock adoption.
        if successor_peer is None and request["command"] in ("handoff_adopt", "handoff_commit", "resume_prepare", "resume_commit", "handoff_finalize"):
            return {"version": VERSION, "command": request["command"], "binding_digest": digest(b), "request_digest": digest(request), "status": "unresolved", "phase": phase,
                    "host": {k: b["current_roles"]["host"]["target"][k] for k in ("pid", "birth_id", "uid")}, "registered_state": None,
                    "quiescence": {"claim_gate_closed": None, **{k: None for k in COUNTERS}, "observation_status": "unknown"},
                    "custody_capabilities": b["current_roles"], "error_code": "identity_unresolved"}
        if request["command"] == "handoff_report":
            return validate_reply(dict(self.bridge._call(request)), request)
        prior = self.journal.replay(request)
        if prior is not None:
            if request["command"] == "handoff_export_sealed" and prior["status"] == "ok" and self.on_export is not None:
                self.on_export(request)
            return prior
        if successor_peer is None and self.verify_active_owner is not None:
            self.verify_active_owner(b)
        if successor_peer is not None:
            if request["command"] == "handoff_adopt":
                if self.transfer_successor is None:
                    raise RelayError("successor transfer adapter is unavailable")
                self.transfer_successor(request, successor_peer)
            elif request["command"] not in ("handoff_report", "handoff_commit", "resume_prepare", "resume_commit", "handoff_finalize"):
                raise RelayError("successor cannot mutate source preparation")
        if request["command"] != "handoff_prepare":
            self.verify_fence(request)
        prior = self.journal.begin(request)
        if prior is not None:
            return prior
        reply = validate_reply(dict(self.bridge._call(request)), request)
        if successor_peer is None:
            self.verify_binding(b)
        else:
            self.verify_successor(b, successor_peer)
        if request["command"] != "handoff_prepare":
            self.verify_fence(request)
        expected_host = {k: b["current_roles"]["host"]["target"][k] for k in ("pid", "birth_id", "uid")}
        if reply["host"] != expected_host:
            raise RelayError("handoff reply replaced retained host")
        result = self.journal.finish(request, reply)
        self._phase = result["phase"]
        if request["command"] == "handoff_export_sealed" and result["status"] == "ok" and self.on_export is not None:
            self.on_export(request)
        return result


def _native_handoff_endpoint(channel, session, preparation, binding):
    from banodoco_local.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority, _read_owner_file
    from .local_execution_handoff import HandoffJournal, decode, read_protected, validate_fence, digest
    peer = AuthenticatedCleanupActor.private_peer(channel)
    relay_actor = AuthenticatedCleanupActor.current()
    scope = Path(preparation["custody_scope"])
    def verify_binding(b, *, participant=True):
        if (b["custody_scope"] != str(scope) or b["operation_id"] != preparation["operation_id"] or b["channel_id"] != preparation["channel_id"]
                or b["workspace_uuid"] != preparation["profile"]["workspace_uuid"] or b["profile_binding_digest"] != digest(preparation["profile"])
                or b["original_owner_epoch"] != preparation["owner_epoch"] or (participant and peer.verify() != b["source_owner"])):
            raise RelayError("handoff source is not the retained authenticated Runtime")
        raw, _ = _read_owner_file(scope / "activation-record.json")
        record = decode(raw)
        if ("sha256:" + hashlib.sha256(raw).hexdigest() != b["activation_record_digest"]
                or record.get("evidence_digest") != b["launch_evidence_digest"] or record.get("executor_incarnation") != b["executor_incarnation"]
                or record.get("custody_capabilities") != b["original_roles"] or record.get("credential_generation") != b["credential_generation_digest"]):
            raise RelayError("handoff immutable launch record differs")
        current = b["current_roles"]
        owners = {"host": relay_actor.verify(), "engine": current["host"]["target"], "engine_listener": current["host"]["target"]}
        if current["relay"]["target"] != relay_actor.verify():
            raise RelayError("handoff relay incarnation differs")
        for role, owner in owners.items():
            RoleCustodyAuthority(scope, role).verify_reference(current[role], expected_actor=owner, owner_epoch=b["original_owner_epoch"])
    def verify_source_active(b):
        verify_binding(b)
        RoleCustodyAuthority(scope, "relay").verify_reference(b["source_relay_reference"], expected_actor=peer.verify(), owner_epoch=b["source_owner_epoch"])
    def verify_fence(request):
        b = request["binding"]
        fence = validate_fence(read_protected(Path(preparation["profile"]["support_root"]) / "local-execution-claim-fence.json"))
        if fence["state"] != "held" or any(fence[k] != b[k] for k in ("workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest", "source_owner_epoch")) or fence["target_owner_epoch"] != b["new_owner_epoch"]:
            raise RelayError("handoff canonical claim fence differs")
        if "task_fence_digest" in request["payload"] and request["payload"]["task_fence_digest"] != digest(fence):
            raise RelayError("handoff fence digest differs")
        if request["command"] == "handoff_export_sealed" and request["payload"]["export_metadata"]["task_fence_digest"] != digest(fence):
            raise RelayError("handoff export fence digest differs")
        record = read_protected(scope / "activation-record.json")
        commit_path = Path(record["request"]["grant"]["credential_file"]).with_suffix(".commit")
        if "sha256:" + hashlib.sha256(_read_owner_file(commit_path)[0]).hexdigest() != b["credential_generation_digest"]:
            raise RelayError("handoff protected credential commit changed")
    verify_source_active(binding)
    # Relay remains its own endpoint writer after Runtime ownership changes.
    def relay_writer_authority():
        relay_actor.verify()
        RoleCustodyAuthority(scope, "host").verify_reference(binding["current_roles"]["host"], expected_actor=relay_actor.verify(), owner_epoch=binding["original_owner_epoch"])
    journal = HandoffJournal(scope / "relay-handoff-state.json", writer=relay_actor.verify(), owner_epoch=preparation["owner_epoch"], authority=relay_writer_authority)
    runtime_journal = HandoffJournal(scope / "runtime-handoff-state.json", writer=binding["source_owner"], owner_epoch=binding["source_owner_epoch"], authority=lambda: verify_source_active(binding))
    def verify_successor(b, fresh_peer):
        verify_binding(b, participant=False)
        fresh_peer.verify_binding(b)
        authority = RoleCustodyAuthority(scope, "relay")
        current = authority.reference()
        if current == b["source_relay_reference"]:
            verify_source_active(b)
        else:
            from .local_worker_handoff import committed_relay_transfer
            committed_relay_transfer(b, successor_actor=fresh_peer.actor, authority=authority)
    def transfer_successor(request, fresh_peer):
        from .local_worker_handoff import transfer_relay_to_successor
        return transfer_relay_to_successor(request, peer=fresh_peer, source_actor=peer, runtime_journal=runtime_journal, authority=RoleCustodyAuthority(scope, "relay"), verify_fence=verify_fence)
    endpoint = RelayHandoffEndpoint(session.bridge, journal, verify_binding=verify_binding, verify_fence=verify_fence, verify_active_owner=verify_source_active, verify_successor=verify_successor, transfer_successor=transfer_successor)
    def on_export(request):
        from .local_worker_handoff import HandoffSuccessorListener
        if endpoint.successor_listener is None:
            endpoint.successor_listener = HandoffSuccessorListener(request["binding"], request["payload"]["sealed_record_digest"], timeout=min(session.timeout, 10.0))
        elif endpoint.successor_listener.binding != request["binding"] or endpoint.successor_listener.sealed_record_digest != request["payload"]["sealed_record_digest"]:
            raise RelayError("successor transport replay changed binding")
    endpoint.on_export = on_export
    def verify_control_requester(control):
        requester = AuthenticatedCleanupActor.private_peer(control)
        authority = RoleCustodyAuthority(scope, "relay")
        record = read_protected(authority.path)
        authority.verify_reference(authority.reference(), expected_actor=requester.verify(), owner_epoch=record["owner_epoch"])
    endpoint.verify_control_requester = verify_control_requester
    return endpoint


def preparation_report(preparation, prepared, *, relay_process, relay_reference, host_reference):
    """Compose the legacy worker alias from exact retained relay evidence."""
    value = validate_host_prepared(prepared, request=preparation,
                                   host_pid=prepared["processes"]["host"]["pid"],
                                   host_birth_id=prepared["processes"]["host"]["birth_id"])
    validate_role_reference(relay_reference, role="relay", scope_root=preparation["custody_scope"], process=relay_process)
    validate_role_reference(host_reference, role="host", scope_root=preparation["custody_scope"], process=value["processes"]["host"])
    return {"version": PREPARATION_VERSION,
            **{k: preparation[k] for k in ("operation_id", "channel_id", "owner_epoch", "custody_scope")},
            "profile_binding_digest": digest(preparation["profile"]),
            "processes": {"worker": dict(relay_process), **value["processes"]},
            "engine_binding": value["engine_binding"],
            "session_config_digest": value["session_config_digest"],
            "custody_capabilities": {"relay": relay_reference, "host": host_reference, **value["custody_capabilities"]}}


class RetainedProcess:
    """Sole waiter for a direct child, with no ECHILD-as-zero convention."""

    def __init__(self, child):
        import threading
        self.child = child
        self.guard = threading.RLock()
        self.exit_code = None
        self.actor = None

    def bind_actor(self):
        from banodoco_local.custody_broker import AuthenticatedCleanupActor
        with self.guard:
            self.actor = AuthenticatedCleanupActor.retained_child(self.child, reap_guard=self.guard)
        return self.actor

    def poll(self):
        with self.guard, self.child._waitpid_lock:
            if self.exit_code is not None:
                return self.exit_code
            if self.child.returncode is not None:
                raise RelayError("child was reaped outside retained launch ownership")
            try:
                pid, status = os.waitpid(self.child.pid, os.WNOHANG)
            except ChildProcessError as exc:
                raise RelayError("retained child wait ownership is unknown") from exc
            if pid == 0:
                return None
            if pid != self.child.pid:
                raise RelayError("wait result differs from retained launch")
            self.child._handle_exitstatus(status)
            self.exit_code = self.child.returncode
            return self.exit_code

    def verify(self):
        with self.guard:
            if self.poll() is not None or self.actor is None:
                raise RelayError("retained launch is not a verified live child")
            return self.actor.verify()

    def wait(self, timeout):
        import time
        deadline = time.monotonic() + timeout
        while True:
            result = self.poll()
            if result is not None:
                return result
            if time.monotonic() >= deadline:
                raise RelayError("retained child exit remains unresolved")
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def selected_host_argv(config, preparation, *, activation_fd, host_control_fd, timeout):
    """Preserve the admitted GenericHost two-descriptor launch projection."""
    required = {"host_python", "source_checkout", "pack_root", "runtime_endpoint", "credential_file", "support_root", "runtime_instance_id", "ready_file", "state_file", "boot_manifest_path", "boot_manifest_hash", "capability_matrix", "readiness_profile_path", "readiness_profile_hash"}
    if set(config) != required or config["host_python"] != preparation["profile"]["host_executable"] or config["support_root"] != preparation["profile"]["support_root"] or config["runtime_instance_id"] != preparation["owner_epoch"]:
        raise RelayError("selected host launch configuration is not the retained Runtime binding")
    argv = [config["host_python"], "-m", "astrid.core.execution.generic_host", "run"]
    for key in ("pack_root", "runtime_endpoint", "credential_file", "ready_file", "support_root", "runtime_instance_id", "boot_manifest_path", "boot_manifest_hash"):
        if not isinstance(config[key], str) or not config[key]:
            raise RelayError("selected host launch configuration is incomplete")
        argv.extend(("--" + key.replace("_", "-"), config[key]))
    argv.extend(("--executor-id", "astrid-pack-host", "--register"))
    for key in ("source_checkout", "capability_matrix"):
        if config[key] is not None:
            argv.extend(("--" + key.replace("_", "-"), config[key]))
    if (config["readiness_profile_path"] is None) != (config["readiness_profile_hash"] is None):
        raise RelayError("selected host readiness binding is incomplete")
    if config["readiness_profile_path"] is not None:
        for key in ("readiness_profile_path", "readiness_profile_hash"):
            argv.extend(("--" + key.replace("_", "-"), config[key]))
    argv.extend(("--activation-fd", str(activation_fd), "--activation-operation-id", preparation["operation_id"], "--activation-channel-id", preparation["channel_id"], "--activation-timeout-seconds", str(float(timeout)), "--host-control-fd", str(host_control_fd)))
    return argv


class NativeHostSession:
    """Park one GenericHost and retain its capability before any RPC."""

    def __init__(self, preparation, config, *, timeout=120.0):
        import subprocess
        from banodoco_local.custody_broker import RoleBoundCustodyBroker, default_process_identity, custody_wrapper_argv
        self.timeout = timeout
        self.preparation = preparation
        self.config = dict(config)
        self.retained = None
        self.control, control_child = socket.socketpair()
        self.activation, activation_child = socket.socketpair()
        self.control.settimeout(timeout)
        self.activation.settimeout(timeout)
        self.broker = RoleBoundCustodyBroker(role="host", identity_provider=default_process_identity,
            ledger_root=Path(preparation["custody_scope"]) / "host-admission",
            authority_scope_root=Path(preparation["custody_scope"]),
            authority_journal=Path(preparation["custody_scope"]) / "admissions.jsonl",
            owner_epoch=preparation["owner_epoch"], timeout=min(timeout, 60.0))
        try:
            argv = selected_host_argv(config, preparation, activation_fd=activation_child.fileno(), host_control_fd=control_child.fileno(), timeout=timeout)
            environment = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "XDG_RUNTIME_DIR", "CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "ASTRID_EXECUTION_TARGET_JSON"}}
            if config["source_checkout"] is not None:
                environment["PYTHONPATH"] = config["source_checkout"]
            environment["PYTHONUNBUFFERED"] = "1"
            environment.update(self.broker.child_environment(argv, start_new_session=True))
            child = subprocess.Popen(custody_wrapper_argv(preparation["profile"]["worker_executable"]), env=environment,
                cwd=config["support_root"], stdin=subprocess.DEVNULL, close_fds=True,
                pass_fds=(control_child.fileno(), activation_child.fileno()))
            # Publish the exact owned child before fallible sealing/binding.
            self.retained = RetainedProcess(child)
            control_child.close()
            activation_child.close()
            self.broker.wait_until_sealed()
            self.retained.bind_actor()
            identity = self.retained.verify()
            self.bridge = LocalExecutionRelay(host_pid=child.pid, host_birth_id=identity["birth_id"],
                                              exchange=self.exchange, verify_host=self.retained.verify)
        except BaseException:
            control_child.close()
            activation_child.close()
            # The caller retains this session before initialization through
            # create(); its launch obligation survives every setup exception.
            if self.retained is None:
                self.broker.abort_before_spawn()
            raise

    @classmethod
    def create(cls, preparation, config, *, retain, timeout=120.0):
        session = cls.__new__(cls)
        retain(session)
        session.__init__(preparation, config, timeout=timeout)
        return session

    def exchange(self, request):
        send_frame(self.control, request)
        return receive_frame(self.control)

    def begin_activation(self, grant):
        required = {"version", "operation_id", "channel_id", "credential_file", "executor_incarnation", "evidence_digest", "acceptance_mode", "activation_id"}
        if not isinstance(grant, Mapping) or set(grant) != required or grant.get("version") != "runtime.local-worker-activation/v1" or grant.get("acceptance_mode") != "runtime-owner-receipt/v1" or any(grant.get(k) != self.preparation[k] for k in ("operation_id", "channel_id")):
            raise RelayError("local activation lacks exact identified Runtime grant")
        if not isinstance(grant["activation_id"], str) or not grant["activation_id"] or len(grant["activation_id"]) > 256 or not isinstance(grant["executor_incarnation"], str) or not grant["executor_incarnation"] or not isinstance(grant["evidence_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", grant["evidence_digest"]):
            raise RelayError("local activation identity/evidence digest is invalid")
        if Path(grant["credential_file"]) != Path(self.config["credential_file"]):
            raise RelayError("local activation credential reference differs from selected binding")
        self.retained.verify()
        frame = {**grant, "host": {"pid": self.retained.child.pid, "birth_id": self.bridge.host_birth_id}}
        if getattr(self, "activation_frame", None) is not None:
            if self.activation_frame != frame:
                raise RelayError("local activation replay changed grant or host")
            return json.loads(canonical_json(self.activation_request))
        self.activation_frame = json.loads(canonical_json(frame))
        send_frame(self.activation, frame)
        request = receive_frame(self.activation)
        expected = {"version": "astrid.local-worker-activation-request/v1", "operation_id": grant["operation_id"], "channel_id": grant["channel_id"],
            "grant": {k: grant[k] for k in ("activation_id", "credential_file", "executor_incarnation", "evidence_digest")}, "host": frame["host"]}
        if request != expected:
            raise RelayError("host activation request differs from retained grant/incarnation")
        self.retained.verify()
        self.activation_request = expected
        return json.loads(canonical_json(expected))

    def finish_activation(self, receipt):
        expected = {**self.activation_request, "version": "runtime.local-worker-activation-recorded/v1"}
        if dict(receipt) != expected:
            raise RelayError("Runtime activation receipt differs from exact host request")
        self.retained.verify()
        if getattr(self, "activation_accepted", None) is not None:
            return json.loads(canonical_json(self.activation_accepted))
        send_frame(self.activation, expected)
        self.activation.shutdown(socket.SHUT_WR)
        # EOF applies only to this dedicated activation FD. The separate
        # persistent host-control channel remains retained after activation.
        accepted = receive_frame(self.activation)
        frame = self.activation_frame
        expected_ack = {"version": "astrid.local-worker-activation-accepted/v1", **{k: frame[k] for k in ("operation_id", "channel_id", "executor_incarnation", "evidence_digest", "host", "activation_id")}}
        if accepted != expected_ack:
            raise RelayError("host final activation ACK differs from recorded grant")
        self.retained.verify()
        self.activation_accepted = expected_ack
        self.activation.close()
        return json.loads(canonical_json(expected_ack))

    def reap_host(self):
        import signal
        if self.retained is None:
            return None
        result = self.retained.poll()
        if result is None:
            self.broker.signal(signal.SIGTERM, expected_pid=self.retained.child.pid)
            try:
                result = self.retained.wait(min(self.timeout, 5.0))
            except RelayError:
                self.broker.signal(signal.SIGKILL, expected_pid=self.retained.child.pid)
                result = self.retained.wait(min(self.timeout, 5.0))
        self.control.close()
        self.activation.close()
        return result


class _RelaySupervisionFailure(RelayError):
    def __init__(self, reason, *, cleanup_verified=False):
        self.reason = reason
        self.cleanup_verified = cleanup_verified
        disposition = "cleanup verified" if cleanup_verified else "cleanup remains unresolved"
        label = "Runtime control channel closed" if reason == "runtime_control_closed" else reason
        super().__init__(label + "; " + disposition)


class _DeadlineExpired(TimeoutError):
    """The single retained monotonic budget is exhausted."""


class _HostExchangeFailure(RelayError):
    def __init__(self, original):
        self.original = original
        super().__init__("host exchange remains unresolved")


class _HostStreamState:
    def __init__(self):
        self.state = "idle"
        self.operations = 0
        self.original_failure = None


class _CleanupBudget:
    def __init__(self, seconds):
        import time
        self.monotonic = time.monotonic
        self.deadline = self.monotonic() + seconds

    def current_deadline(self):
        return self.deadline

    def check(self):
        if self.monotonic() >= self.deadline:
            raise _DeadlineExpired("delegated cleanup deadline expired")


class _DeadlineIO:
    """Keep the existing parser on its raw socket, with one absolute budget."""
    def __init__(self, channel, monitor, stream=None):
        self.channel = channel
        self.monitor = monitor
        self.stream = stream

    def __getattr__(self, name):
        return getattr(self.channel, name)

    def _call(self, name, *args):
        deadline = self.monitor.current_deadline()
        remaining = None if deadline is None else deadline - self.monitor.monotonic()
        if remaining is not None and remaining <= 0:
            raise _DeadlineExpired("absolute handoff deadline expired")
        previous = self.channel.gettimeout()
        timeout = previous if remaining is None else remaining if previous is None else min(previous, remaining)
        if self.stream is not None:
            self.stream.state = "outstanding"
            self.stream.operations += 1
        try:
            self.channel.settimeout(timeout)
            return getattr(self.channel, name)(*args)
        except Exception:
            if self.stream is not None:
                self.stream.state = "failed"
            raise
        finally:
            # A successful recvmsg must reach the existing ancillary parser,
            # even if another owner has closed the socket in the meantime.
            try:
                if self.channel.fileno() >= 0:
                    self.channel.settimeout(previous)
            except OSError:
                pass

    def recv(self, *args):
        return self._call("recv", *args)

    def recvmsg(self, *args):
        return self._call("recvmsg", *args)

    def sendall(self, *args):
        return self._call("sendall", *args)

    def accept(self):
        return self._call("accept")


class _RelayFailureMonitor:
    """Observe an accepted handoff; observation never confers authority."""
    def __init__(self, *, monotonic=None, wall_time=None):
        import time
        self.monotonic = monotonic or time.monotonic
        self.wall_time = wall_time or time.time
        self.binding_digest = None
        self.deadline = None
        self.dispatch_deadline = None

    def accepted(self, request, reply, *, current_phase=None):
        if reply["status"] != "ok" or request["command"] == "handoff_report":
            return
        binding_digest = digest(request["binding"])
        if self.binding_digest is None:
            self.binding_digest = binding_digest
            remaining = request["binding"]["deadline_unix_ms"] / 1000 - self.wall_time()
            self.deadline = self.dispatch_deadline if self.dispatch_deadline is not None else self.monotonic() + max(0.0, remaining)
        if binding_digest != self.binding_digest:
            # Even an unexpected accepted reply cannot extend a retained timer.
            return
        phase = current_phase or reply["phase"]
        if phase in ("owned", "finalized"):
            self.deadline = None
            if phase == "owned":
                self.binding_digest = None

    def expired(self):
        deadline = self.current_deadline()
        return deadline is not None and self.monotonic() >= deadline

    def accepted_expired(self):
        return self.deadline is not None and self.monotonic() >= self.deadline

    def current_deadline(self):
        deadlines = [d for d in (self.deadline, self.dispatch_deadline) if d is not None]
        return min(deadlines) if deadlines else None

    def check(self):
        if self.expired():
            raise _DeadlineExpired("absolute handoff deadline expired")

    def timeout(self):
        deadline = self.current_deadline()
        if deadline is None:
            return 10.0
        return min(10.0, max(0.0, deadline - self.monotonic()))


def _host_stream_usable(session, stream):
    import select
    if session is None or stream.state != "idle":
        return False
    control = getattr(session, "control", None)
    if not isinstance(control, socket.socket) or control.fileno() < 0:
        return False
    try:
        # Any queued bytes, EOF or observer error disqualifies cleanup RPC.
        readable, _, _ = select.select([control], [], [], 0)
        if readable:
            control.recv(1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0))
            return False
        return True
    except (OSError, ValueError):
        return False


def _host_call(session, monitor, stream, callback, *, endpoint_call=False, replay_only=False):
    originals = {}
    before = stream.operations
    if stream.state != "idle" and not replay_only:
        raise _HostExchangeFailure(stream.original_failure) from stream.original_failure
    original_exchange = getattr(session.bridge, "_exchange", None)
    if original_exchange is not None:
        def observed_exchange(request):
            exchange_before = stream.operations
            try:
                if replay_only:
                    raise RelayError("terminal durable replay cannot start a host exchange")
                monitor.check()
                reply = original_exchange(request)
                # The complete existing parser returned. Check before the
                # endpoint can validate/finish its journal or transfer phase.
                monitor.check()
                return reply
            except Exception as exc:
                if stream.operations != exchange_before:
                    stream.state = "failed"
                    if stream.original_failure is None:
                        stream.original_failure = exc
                raise
        session.bridge._exchange = observed_exchange
    for name in ("control", "activation"):
        channel = getattr(session, name, None)
        if isinstance(channel, socket.socket):
            originals[name] = channel
            setattr(session, name, _DeadlineIO(channel, monitor, stream))
    try:
        monitor.check()
        result = callback()
        if stream.original_failure is not None and not replay_only:
            raise _HostExchangeFailure(stream.original_failure) from stream.original_failure
        if not endpoint_call:
            monitor.check()
        if stream.operations != before:
            # The endpoint catches failed exchanges in this bounded outcome.
            if stream.state == "failed" or (isinstance(result, Mapping) and result.get("error_code") == "custody_unresolved"):
                stream.state = "failed"
            else:
                stream.state = "idle"
        return result
    except Exception as exc:
        if stream.operations != before:
            stream.state = "failed"
            if stream.original_failure is None:
                stream.original_failure = exc
        raise
    finally:
        if original_exchange is not None:
            session.bridge._exchange = original_exchange
        for name, channel in originals.items():
            setattr(session, name, channel)


def _control_failure_reason(exc, monitor):
    if isinstance(exc, _DeadlineExpired) or (isinstance(exc, TimeoutError) and monitor.expired()):
        return "deadline_expired"
    if isinstance(exc, TimeoutError):
        return "runtime_control_timeout"
    if isinstance(exc, RelayError):
        return "runtime_control_closed" if str(exc) == "local execution control channel closed" else "runtime_control_malformed"
    return "runtime_control_failed"


def _fail_supervision(channels, session, reason, *, stream, cause=None, host_control_usable=True, cleanup_allowed=True):
    """Publish failure before bounded delegated cleanup; retain uncertainty."""
    if stream.original_failure is not None:
        cause = stream.original_failure
    for channel in channels:
        previous_timeout = channel.gettimeout()
        try:
            channel.settimeout(1.0 if previous_timeout is None else min(previous_timeout, 1.0))
            send_frame(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": reason})
        except Exception:
            pass
        finally:
            if channel.fileno() >= 0:
                channel.settimeout(previous_timeout)
    cleanup_verified = False
    if cleanup_allowed and host_control_usable and _host_stream_usable(session, stream) and hasattr(session, "bridge"):
        # Only the already retained relay/host owner protocol may clean up.
        # Broken/unsolicited host channels cannot supply a trustworthy reply.
        control = getattr(session, "control", None)
        previous_timeout = control.gettimeout() if isinstance(control, socket.socket) else None
        try:
            # Cleanup has its own finite budget after the failed handoff.
            # It cannot reset or resume the expired handoff's authority.
            cleanup_monitor = _CleanupBudget(min(getattr(session, "timeout", 5.0), 5.0))
            result = _host_call(session, cleanup_monitor, stream, session.bridge.abort)
            if result.get("status") == "cleaned":
                exit_code = session.reap_host()
                cleanup_verified = isinstance(exit_code, int) and not isinstance(exit_code, bool)
        except Exception:
            pass
        finally:
            if isinstance(control, socket.socket) and control.fileno() >= 0:
                control.settimeout(previous_timeout)
    raise _RelaySupervisionFailure(reason, cleanup_verified=cleanup_verified) from cause


def serve_control(channel, *, session_factory=NativeHostSession.create, reference_reader=None, relay_identity=None):
    """Serve one Runtime-owned launch over its retained private descriptor.

    Host cleanup success is distinct from relay exit, which the Runtime sole
    waiter must prove. Capability recovery/handoff are intentionally rejected
    until their separate continuation is implemented.
    """
    from banodoco_local.custody_broker import RoleCustodyAuthority, default_process_identity
    preparation = None
    session = None
    prepare_input = None
    terminal_abort = None
    handoff_endpoint = None
    monitor = _RelayFailureMonitor()
    host_stream = _HostStreamState()
    channels = {channel: None}
    def retain(value):
        nonlocal session
        session = value
    if reference_reader is None:
        reference_reader = lambda scope, role: RoleCustodyAuthority(Path(scope), role).reference()
    if relay_identity is None:
        relay_identity = lambda: default_process_identity(os.getpid())
    def report(value):
        identity = relay_identity()
        if identity is None:
            raise RelayError("relay own incarnation is unavailable")
        return preparation_report(preparation, value,
            relay_process={"pid": identity["pid"], "birth_id": identity["birth_id"]},
            relay_reference=reference_reader(preparation["custody_scope"], "relay"),
            host_reference=reference_reader(preparation["custody_scope"], "host"))
    def lose_control(control, exc):
        channels.pop(control, None)
        control.close()
        listener = handoff_endpoint.successor_listener if handoff_endpoint is not None else None
        reason = _control_failure_reason(exc, monitor)
        if reason == "deadline_expired":
            _fail_supervision(channels, session, reason, stream=host_stream, cause=exc)
        if channels or (listener is not None and not listener.closed):
            return True
        if terminal_abort is not None and reason == "runtime_control_closed":
            return False
        _fail_supervision(channels, session, reason, stream=host_stream, cause=exc,
            cleanup_allowed=reason not in ("runtime_control_malformed", "runtime_control_timeout"))
    def respond(control, response, *, refusal=False):
        previous_timeout = control.gettimeout()
        try:
            if refusal:
                control.settimeout(1.0 if previous_timeout is None else min(previous_timeout, 1.0))
            send_frame(_DeadlineIO(control, monitor), response)
            return True
        except Exception as exc:
            return lose_control(control, exc)
        finally:
            if refusal and control.fileno() >= 0:
                control.settimeout(previous_timeout)
    while True:
        import select
        listener = handoff_endpoint.successor_listener if handoff_endpoint is not None else None
        if listener is not None:
            listener._frame_io = lambda control: _DeadlineIO(control, monitor)
        surfaces = list(channels) + ([listener.socket] if listener is not None and not listener.closed else [])
        host_control = getattr(session, "control", None) if terminal_abort is None else None
        if isinstance(host_control, socket.socket) and host_control.fileno() >= 0:
            surfaces.append(host_control)
        else:
            host_control = None
        if monitor.expired():
            _fail_supervision(channels, session, "deadline_expired", stream=host_stream)
        if not surfaces:
            _fail_supervision(channels, session, "runtime_control_closed", stream=host_stream)
        ready, _, _ = select.select(surfaces, [], [], monitor.timeout())
        if monitor.expired():
            _fail_supervision(channels, session, "deadline_expired", stream=host_stream)
        if not ready:
            continue
        if host_control is not None and host_control in ready:
            try:
                pending = host_control.recv(1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0))
            except BlockingIOError:
                continue
            except OSError as exc:
                _fail_supervision(channels, session, "host_control_failed", stream=host_stream, cause=exc, host_control_usable=False)
            _fail_supervision(channels, session, "host_control_unsolicited" if pending else "host_control_closed", stream=host_stream, host_control_usable=False)
        if listener is not None and listener.socket in ready:
            try:
                successor_peer, request = listener.accept()
            except Exception as exc:
                # Rejected peers/frames own no role. accept() closes that FD;
                # keep the selected listener and all retained obligations.
                if monitor.expired():
                    _fail_supervision(channels, session, "deadline_expired", stream=host_stream, cause=exc)
                continue
            channel = successor_peer.channel
            channels[channel] = successor_peer
        else:
            channel = next(control for control in channels if control in ready)
            successor_peer = channels[channel]
            try:
                request = receive_frame(_DeadlineIO(channel, monitor))
            except Exception as exc:
                if lose_control(channel, exc):
                    continue
                return
        try:
            monitor.check()
            if request.get("version") != CONTROL_VERSION:
                raise RelayError("relay control version is invalid")
            command = request.get("command")
            if handoff_endpoint is not None and command not in ("handoff", "report"):
                handoff_endpoint.verify_control_requester(channel)
                if successor_peer is None and command in ("activate", "abort") and handoff_endpoint._phase not in ("owned", "host_paused"):
                    raise RelayError("source descriptor relinquished mutation authority at export")
            if command == "prepare":
                if set(request) != {"version", "command", "preparation", "config"}:
                    raise RelayError("relay prepare request shape is invalid")
                selected = request["preparation"]
                encoded = canonical_json(request)
                if prepare_input is not None and encoded != prepare_input:
                    raise RelayError("relay prepare replay changed selected launch input")
                if terminal_abort is not None:
                    raise RelayError("relay preparation is already cleaned")
                if prepare_input is None:
                    # Validate before launch; preserve exact original selection.
                    selected = host_prepare_request(**{k: selected[k] for k in ("operation_id", "channel_id", "owner_epoch", "runtime_owner", "profile", "custody_scope")})
                    if selected != request["preparation"]:
                        raise RelayError("relay host prepare shape is invalid")
                    preparation, prepare_input = selected, encoded
                    session_factory(preparation, request["config"], retain=retain)
                if not hasattr(session, "bridge"):
                    raise RelayError("host sealing remains unresolved")
                reply = _host_call(session, monitor, host_stream, lambda: session.bridge.prepare(preparation))
                if reply["status"] != "prepared":
                    if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "preparation_unresolved", "host_result": reply}):
                        return
                    continue
                response = {"version": CONTROL_VERSION, "status": "ok", "report": report(reply)}
            elif command == "report":
                if set(request) != {"version", "command"} or session is None or terminal_abort is not None:
                    raise RelayError("relay has no reportable retained host")
                reply = _host_call(session, monitor, host_stream, session.bridge.report)
                if reply["status"] != "prepared":
                    if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "report_unresolved", "host_result": reply}):
                        return
                    continue
                response = {"version": CONTROL_VERSION, "status": "ok", "report": report(reply)}
            elif command == "activate":
                if set(request) != {"version", "command", "grant"} or session is None or terminal_abort is not None or session.bridge._prepared is None:
                    raise RelayError("relay activation lacks a retained prepared graph")
                activation_request = _host_call(session, monitor, host_stream, lambda: session.begin_activation(request["grant"]))
                if not respond(channel, {"version": CONTROL_VERSION, "status": "activation_requested", "request": activation_request}):
                    return
                if channel not in channels:
                    continue
                try:
                    confirmation = receive_frame(_DeadlineIO(channel, monitor))
                except Exception as exc:
                    if lose_control(channel, exc):
                        continue
                    return
                monitor.check()
                if set(confirmation) != {"version", "command", "receipt"} or confirmation.get("version") != CONTROL_VERSION or confirmation.get("command") != "record_activation_receipt":
                    raise RelayError("relay activation receipt forwarding frame is invalid")
                accepted = _host_call(session, monitor, host_stream, lambda: session.finish_activation(confirmation["receipt"]))
                response = {"version": CONTROL_VERSION, "status": "ok", "accepted": accepted}
            elif command == "abort":
                if set(request) != {"version", "command"} or session is None:
                    raise RelayError("relay abort has no retained launch")
                if terminal_abort is None:
                    if not hasattr(session, "bridge"):
                        raise RelayError("host setup failed with retained unresolved launch")
                    if host_stream.state != "idle" or (isinstance(getattr(session, "control", None), socket.socket) and not _host_stream_usable(session, host_stream)):
                        raise RelayError("host cleanup stream is unresolved")
                    result = _host_call(session, monitor, host_stream, session.bridge.abort)
                    if result["status"] != "cleaned":
                        if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "cleanup_unresolved", "host_result": result}):
                            return
                        continue
                    host_exit = session.reap_host()
                    if isinstance(host_exit, bool) or not isinstance(host_exit, int):
                        raise RelayError("relay host child exit is unresolved")
                    terminal_abort = {"version": CONTROL_VERSION, "status": "ok", "host_result": result, "host_exit_code": host_exit}
                    monitor.deadline = None
                response = terminal_abort
            elif command == "handoff":
                if set(request) != {"version", "command", "request"} or session is None or terminal_abort is not None:
                    raise RelayError("handoff lacks retained host control")
                from .local_execution_handoff import validate_request
                validate_request(request["request"])
                if handoff_endpoint is None:
                    handoff_endpoint = _native_handoff_endpoint(channel, session, preparation, request["request"]["binding"])
                phase = getattr(handoff_endpoint, "_phase", None)
                owned_committed_replay = False
                if hasattr(handoff_endpoint, "journal"):
                    with handoff_endpoint.journal.locked() as state:
                        phase = state["phase"]
                        received = request["request"]
                        key = received["binding"]["handoff_id"] + ":" + received["command"]
                        entry = state["entries"].get(key)
                        prior = entry.get("reply") if entry is not None else None
                        # This is only an I/O-budget hint. The unchanged
                        # endpoint must authenticate and return durable replay;
                        # no success is composed from journal metadata here.
                        owned_committed_replay = phase == "owned" and prior is not None
                if monitor.binding_digest is None and phase != "finalized" and not owned_committed_replay:
                    remaining = request["request"]["binding"]["deadline_unix_ms"] / 1000 - monitor.wall_time()
                    if remaining <= 0:
                        if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "deadline_expired"}, refusal=True):
                            return
                        continue
                    monitor.dispatch_deadline = monitor.monotonic() + max(0.0, remaining)
                try:
                    monitor.check()
                    outcome = _host_call(session, monitor, host_stream,
                        lambda: handoff_endpoint.handoff(request["request"], successor_peer=successor_peer),
                        endpoint_call=True, replay_only=owned_committed_replay)
                    if not owned_committed_replay:
                        monitor.accepted(request["request"], outcome, current_phase=getattr(handoff_endpoint, "_phase", None))
                except (_HostExchangeFailure, TimeoutError) as exc:
                    original = exc.original if isinstance(exc, _HostExchangeFailure) else exc
                    reason = "deadline_expired" if isinstance(original, _DeadlineExpired) else "host_exchange_timeout" if isinstance(original, TimeoutError) else "host_exchange_failed"
                    if monitor.accepted_expired():
                        _fail_supervision(channels, session, "deadline_expired", stream=host_stream, cause=original, cleanup_allowed=False)
                    # Provisional expiry or failed exchange is refusal only.
                    # The endpoint may have swallowed the original exception;
                    # retain it without another host RPC or journal advance.
                    # A provisional request has been refused. Its I/O budget
                    # must not turn the refusal send into lifecycle expiry.
                    monitor.dispatch_deadline = None
                    if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": reason}, refusal=True):
                        return
                    continue
                finally:
                    monitor.dispatch_deadline = None
                response = {"version": CONTROL_VERSION, "status": "ok", "handoff": outcome}
            else:
                raise RelayError("relay command is outside this checkpoint")
            if not respond(channel, response):
                return
        except _RelaySupervisionFailure:
            raise
        except Exception as exc:
            # Bounded error only. Retained session/child obligations remain
            # available for retry; EOF, failed seal and timeout never clean them.
            if monitor.accepted_expired():
                _fail_supervision(channels, session, "deadline_expired", stream=host_stream, cause=exc)
            if not respond(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "cleanup_unresolved" if request.get("command") == "abort" else "operation_unresolved"}):
                return


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Runtime-owned local execution relay")
    parser.add_argument("--prepared-control-fd", type=int, required=True)
    args = parser.parse_args(argv)
    if args.prepared_control_fd < 0:
        raise RelayError("relay private descriptor is invalid")
    channel = socket.socket(fileno=args.prepared_control_fd)
    os.set_inheritable(channel.fileno(), False)
    try:
        serve_control(channel)
    except _RelaySupervisionFailure as exc:
        # Failure is never an authority transfer or a clean shutdown receipt.
        # Existing protected custody remains authoritative after this exit.
        os.write(2, ("local execution supervision failed: " + str(exc) + "\n").encode("utf-8"))
        return 78
    finally:
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
