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
        value = json.loads(encoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
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
    while True:
        request = receive_frame(channel)
        try:
            if request.get("version") != CONTROL_VERSION:
                raise RelayError("relay control version is invalid")
            command = request.get("command")
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
                reply = session.bridge.prepare(preparation)
                if reply["status"] != "prepared":
                    send_frame(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "preparation_unresolved", "host_result": reply})
                    continue
                response = {"version": CONTROL_VERSION, "status": "ok", "report": report(reply)}
            elif command == "report":
                if set(request) != {"version", "command"} or session is None or terminal_abort is not None:
                    raise RelayError("relay has no reportable retained host")
                reply = session.bridge.report()
                if reply["status"] != "prepared":
                    send_frame(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "report_unresolved", "host_result": reply})
                    continue
                response = {"version": CONTROL_VERSION, "status": "ok", "report": report(reply)}
            elif command == "activate":
                if set(request) != {"version", "command", "grant"} or session is None or terminal_abort is not None or session.bridge._prepared is None:
                    raise RelayError("relay activation lacks a retained prepared graph")
                activation_request = session.begin_activation(request["grant"])
                send_frame(channel, {"version": CONTROL_VERSION, "status": "activation_requested", "request": activation_request})
                confirmation = receive_frame(channel)
                if set(confirmation) != {"version", "command", "receipt"} or confirmation.get("version") != CONTROL_VERSION or confirmation.get("command") != "record_activation_receipt":
                    raise RelayError("relay activation receipt forwarding frame is invalid")
                accepted = session.finish_activation(confirmation["receipt"])
                response = {"version": CONTROL_VERSION, "status": "ok", "accepted": accepted}
            elif command == "abort":
                if set(request) != {"version", "command"} or session is None:
                    raise RelayError("relay abort has no retained launch")
                if terminal_abort is None:
                    if not hasattr(session, "bridge"):
                        raise RelayError("host setup failed with retained unresolved launch")
                    result = session.bridge.abort()
                    if result["status"] != "cleaned":
                        send_frame(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "cleanup_unresolved", "host_result": result})
                        continue
                    host_exit = session.reap_host()
                    if isinstance(host_exit, bool) or not isinstance(host_exit, int):
                        raise RelayError("relay host child exit is unresolved")
                    terminal_abort = {"version": CONTROL_VERSION, "status": "ok", "host_result": result, "host_exit_code": host_exit}
                response = terminal_abort
            else:
                raise RelayError("relay command is outside this checkpoint")
            send_frame(channel, response)
        except Exception:
            # Bounded error only. Retained session/child obligations remain
            # available for retry; EOF, failed seal and timeout never clean them.
            send_frame(channel, {"version": CONTROL_VERSION, "status": "unresolved", "error_code": "cleanup_unresolved" if request.get("command") == "abort" else "operation_unresolved"})


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
    finally:
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
