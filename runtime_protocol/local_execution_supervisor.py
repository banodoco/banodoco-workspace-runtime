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
