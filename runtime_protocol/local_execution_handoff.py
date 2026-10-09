"""Bounded handoff wire and durable observations; these confer no custody.

Authentication and role designation stay with the retained transport/broker.
The journal never turns descriptor possession, a deadline or an unknown reply
into authority. A pending entry cannot be blindly reexecuted after a crash.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from .errors import ConflictError, ValidationError

VERSION = "runtime.local-execution-handoff/v1"
FENCE_VERSION = "runtime.local-execution-claim-fence/v1"
LIMIT = 1_048_576
ROLES = frozenset(("relay", "host", "engine", "engine_listener"))
ACTOR_FIELDS = frozenset(("pid", "uid", "birth_id", "audit_token_sha256", "audit_token_pidversion"))
BINDING_FIELDS = frozenset(("operation_id", "channel_id", "handoff_id", "nonce_digest", "deadline_unix_ms", "workspace_uuid", "profile_binding_digest", "launch_evidence_digest", "activation_record_digest", "executor_incarnation", "custody_scope", "original_owner_epoch", "new_owner_epoch", "new_owner", "credential_generation_digest", "original_roles", "intent_digest", "source_owner", "source_owner_epoch", "source_relay_reference", "current_roles"))
COUNTERS = ("claim_rpc_in_flight", "active_attempts", "pending_settlements", "registration_rpc_in_flight")
PHASES = {"handoff_prepare": ("owned", "host_paused"), "handoff_export_sealed": ("host_paused", "export_sealed"), "handoff_adopt": ("export_sealed", "adopt_prepared"), "handoff_commit": ("adopt_prepared", "rebind_committed"), "resume_prepare": ("rebind_committed", "resume_armed"), "resume_commit": ("resume_armed", "resumed"), "handoff_finalize": ("resumed", "finalized"), "handoff_abort": ("host_paused", "owned")}
PAYLOAD_FIELDS = {"handoff_prepare": set(), "handoff_report": set(), "handoff_export_sealed": {"export_metadata", "seal_record", "sealed_record_digest"}, "handoff_adopt": {"export_digest", "sealed_record_digest", "task_fence_digest", "relay_transfer_ack", "successor_authentication_digest"}, "handoff_commit": {"new_runtime", "task_fence_digest", "relay_reference"}, "resume_prepare": {"new_runtime", "task_fence_digest", "registered_state_digest"}, "resume_commit": {"new_runtime", "task_fence_digest", "registered_state_digest"}, "handoff_finalize": {"registered_state_digest", "task_fence_digest"}, "handoff_abort": {"reason_code"}}
REPLY_FIELDS = frozenset(("version", "command", "binding_digest", "request_digest", "status", "phase", "host", "registered_state", "quiescence", "custody_capabilities", "error_code"))
FENCE_FIELDS = frozenset(("version", "state", "workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest", "source_owner_epoch", "target_owner_epoch", "fence_generation", "release_ack_digest"))


def canonical(value):
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ValidationError("handoff value is not finite JSON") from exc
    if len(data) > LIMIT:
        raise ValidationError("handoff value exceeds frame bound")
    return data


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def decode(data):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValidationError("duplicate handoff JSON key")
            result[key] = value
        return result
    if len(data) > LIMIT:
        raise ValidationError("handoff JSON exceeds bound")
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("nonfinite handoff number")))
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("malformed handoff JSON") from exc
    canonical(value)
    return value


def exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValidationError("handoff object has unexpected fields")


def integer(value, minimum=1):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError("invalid handoff integer")


def string(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValidationError("invalid bounded handoff string")


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValidationError("invalid handoff digest")


def actor(value):
    exact(value, ACTOR_FIELDS)
    integer(value["pid"]); integer(value["uid"], 0); integer(value["audit_token_pidversion"])
    string(value["birth_id"]); sha(value["audit_token_sha256"])


def reference(value, role=None, scope=None):
    exact(value, ("version", "scope_root", "role", "generation", "target"))
    if value["version"] != "runtime.role-custody-reference/v1" or value["role"] not in ROLES or (role is not None and value["role"] != role):
        raise ValidationError("invalid handoff role reference")
    string(value["scope_root"])
    if not Path(value["scope_root"]).is_absolute() or (scope is not None and value["scope_root"] != scope):
        raise ValidationError("handoff role scope differs")
    integer(value["generation"]); actor(value["target"])


def roles(value, scope):
    exact(value, ROLES)
    for role, ref in value.items():
        reference(ref, role, scope)


def runtime_binding(value):
    exact(value, ("endpoint", "protocol", "schema_digest", "runtime_epoch", "runtime_session_id", "runtime_instance_id", "coordinator_epoch"))
    integer(value["runtime_epoch"]); sha(value["schema_digest"])
    for key in ("endpoint", "protocol", "runtime_session_id", "runtime_instance_id", "coordinator_epoch"):
        string(value[key])
    from urllib.parse import urlsplit
    import ipaddress
    parsed = urlsplit(value["endpoint"])
    try:
        valid = parsed.scheme == "http" and parsed.port is not None and (parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback)
    except (ValueError, TypeError):
        valid = False
    if not valid or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValidationError("handoff Runtime endpoint is not selected loopback")


def registered_state(value):
    exact(value, ("executor_incarnation", "source_epoch", "capabilities", "runtime"))
    string(value["executor_incarnation"]); string(value["source_epoch"]); runtime_binding(value["runtime"])
    if not isinstance(value["capabilities"], dict):
        raise ValidationError("handoff registration capabilities are unknown")
    for key, item in value["capabilities"].items():
        string(key); exact(item, ("capability_digest", "source_digest", "dependency_digest"))
        for pin in item.values():
            sha(pin)


def validate_request(value):
    exact(value, ("version", "command", "binding", "payload"))
    if value["version"] != VERSION or value["command"] not in PAYLOAD_FIELDS:
        raise ValidationError("unknown handoff command/version")
    b = value["binding"]; exact(b, BINDING_FIELDS)
    for key in ("new_owner", "source_owner"):
        actor(b[key])
    for key in ("original_roles", "current_roles"):
        roles(b[key], b["custody_scope"])
    reference(b["source_relay_reference"], "relay", b["custody_scope"])
    if b["current_roles"]["relay"] != b["source_relay_reference"] or b["source_owner_epoch"] == b["new_owner_epoch"] or b["source_owner"] == b["new_owner"]:
        raise ValidationError("handoff current source or successor conflicts")
    integer(b["deadline_unix_ms"])
    for key in BINDING_FIELDS - {"new_owner", "source_owner", "original_roles", "current_roles", "source_relay_reference", "deadline_unix_ms"}:
        (sha if key.endswith("digest") else string)(b[key])
    if b["intent_digest"] != digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}}):
        raise ValidationError("handoff intent digest differs")
    payload = value["payload"]; exact(payload, PAYLOAD_FIELDS[value["command"]])
    for key, item in payload.items():
        if key.endswith("digest"):
            sha(item)
    if value["command"] == "handoff_abort":
        string(payload["reason_code"])
    if "new_runtime" in payload:
        runtime_binding(payload["new_runtime"])
        if payload["new_runtime"]["coordinator_epoch"] != b["new_owner_epoch"]:
            raise ValidationError("handoff Runtime epoch differs from successor")
    if "relay_reference" in payload:
        reference(payload["relay_reference"], "relay", b["custody_scope"])
    if value["command"] == "handoff_export_sealed":
        export = payload["export_metadata"]; seal = payload["seal_record"]
        exact(export, ("version", "handoff_id", "intent_digest", "nonce_digest", "host_pause_ack_digest", "task_fence_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference", "descriptor_identity_digest", "launch_evidence_digest"))
        exact(seal, ("version", "handoff_id", "intent_digest", "nonce_digest", "export_digest", "host_pause_ack_digest", "task_fence_digest", "credential_generation_digest", "source_owner_epoch", "target_owner_epoch", "source_relay_reference", "successor_incarnation"))
        for record in (export, seal):
            for key, item in record.items():
                if key.endswith("digest"):
                    sha(item)
        if export["version"] != "runtime.local-execution-handoff-export/v1" or seal["version"] != "runtime.local-execution-handoff-seal/v1" or seal["export_digest"] != digest(export) or payload["sealed_record_digest"] != digest(seal):
            raise ValidationError("handoff noncircular seal chain differs")
        for key in ("handoff_id", "intent_digest", "nonce_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference"):
            if export[key] != b[key] or seal[key] != b[key]:
                raise ValidationError("handoff seal binding differs")
        if export["launch_evidence_digest"] != b["launch_evidence_digest"] or seal["target_owner_epoch"] != b["new_owner_epoch"] or seal["successor_incarnation"] != b["new_owner"] or any(seal[k] != export[k] for k in ("host_pause_ack_digest", "task_fence_digest")):
            raise ValidationError("handoff seal evidence differs")
    canonical(value)
    return value


def validate_reply(value, request):
    exact(value, REPLY_FIELDS)
    if value["version"] != VERSION or value["command"] != request["command"] or value["binding_digest"] != digest(request["binding"]) or value["request_digest"] != digest(request):
        raise ValidationError("handoff reply binding differs")
    if value["status"] not in ("ok", "active_work", "unresolved", "conflict") or value["phase"] not in {"owned", *[p for _, p in PHASES.values()]}:
        raise ValidationError("invalid handoff outcome")
    exact(value["host"], ("pid", "uid", "birth_id")); integer(value["host"]["pid"]); integer(value["host"]["uid"], 0); string(value["host"]["birth_id"])
    q = value["quiescence"]; exact(q, ("claim_gate_closed", *COUNTERS, "observation_status"))
    if q["observation_status"] not in ("known", "unknown") or (q["claim_gate_closed"] is not None and type(q["claim_gate_closed"]) is not bool):
        raise ValidationError("invalid handoff quiescence")
    for key in COUNTERS:
        if q[key] is not None:
            integer(q[key], 0)
    if q["observation_status"] == "known" and any(q[k] is None for k in ("claim_gate_closed", *COUNTERS)):
        raise ValidationError("unknown quiescence cannot be known")
    if value["status"] == "ok" and request["command"] != "handoff_report" and (q["observation_status"] != "known" or any(q[k] != 0 for k in COUNTERS)):
        raise ValidationError("handoff success lacks measured quiescence")
    if value["status"] == "ok" and value["error_code"] is not None:
        raise ValidationError("handoff success includes error")
    errors = {"active_work", "binding_conflict", "phase_conflict", "identity_unresolved", "quiescence_unresolved", "fence_unresolved", "registration_unresolved", "custody_unresolved", "cleanup_unresolved", "deadline_expired"}
    if value["status"] != "ok" and value["error_code"] not in errors:
        raise ValidationError("handoff failure lacks bounded error")
    if value["registered_state"] is not None:
        registered_state(value["registered_state"])
        if value["registered_state"]["executor_incarnation"] != request["binding"]["executor_incarnation"]:
            raise ValidationError("handoff registration incarnation changed")
    if value["status"] == "ok" and request["command"] not in ("handoff_report", "handoff_abort"):
        expected_phase = PHASES[request["command"]][1]
        if value["phase"] != expected_phase:
            raise ValidationError("handoff success phase differs")
        expected_closed = request["command"] != "handoff_finalize"
        if q["claim_gate_closed"] is not expected_closed:
            raise ValidationError("handoff claim gate differs from committed phase")
    if value["status"] == "ok" and request["command"] not in ("handoff_report", "handoff_abort") and value["registered_state"] is None:
        raise ValidationError("handoff success lacks actual registration")
    if value["status"] == "ok" and value["registered_state"] is not None:
        if ("registered_state_digest" in request["payload"]
                and digest(value["registered_state"]) != request["payload"]["registered_state_digest"]):
            raise ValidationError("handoff accepted registration digest changed")
        if ("new_runtime" in request["payload"]
                and value["registered_state"]["runtime"] != request["payload"]["new_runtime"]):
            raise ValidationError("handoff accepted Runtime binding changed")
    roles(value["custody_capabilities"], request["binding"]["custody_scope"])
    for role in ROLES - {"relay"}:
        if value["custody_capabilities"][role] != request["binding"]["current_roles"][role]:
            raise ValidationError("handoff changed delegated custody")
    return value


def validate_fence(value):
    exact(value, FENCE_FIELDS)
    if value["version"] != FENCE_VERSION or value["state"] not in ("held", "released"):
        raise ValidationError("invalid canonical claim fence")
    integer(value["fence_generation"])
    for key in FENCE_FIELDS - {"version", "state", "fence_generation", "release_ack_digest"}:
        (sha if key.endswith("digest") else string)(value[key])
    if value["state"] == "held":
        if value["release_ack_digest"] is not None:
            raise ValidationError("held fence cannot have release ACK")
    else:
        sha(value["release_ack_digest"])
    return value


def read_protected(path):
    from banodoco_local.custody_broker import _read_owner_file
    return decode(_read_owner_file(Path(path))[0])


def write_protected(path, value):
    from banodoco_local.custody_broker import _atomic_owner_json
    _atomic_owner_json(Path(path), decode(canonical(value)))


class HandoffJournal:
    """Exclusive endpoint writer with authenticated replay outside deadlines.

    ``authority`` must reread current protected designation and authenticate
    the actual transport actor. It is called under the journal lock on every
    access. This object does not implement role transfer or fresh B transport.
    """
    def __init__(self, path, *, writer, owner_epoch, authority, timeout=0.25):
        self.path = Path(path); self.writer = dict(writer); self.owner_epoch = owner_epoch
        actor(self.writer); string(owner_epoch)
        self.authority = authority; self.timeout = timeout
        self.writer_generation = None

    @contextlib.contextmanager
    def locked(self, *, transition_authority=None):
        parent = self.path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or self.path.parent.is_symlink() or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ConflictError("handoff journal scope is unprotected")
        fd = os.open(self.path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            observed = os.fstat(fd)
            if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600:
                raise ConflictError("handoff journal lock is unprotected")
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ConflictError("handoff journal lock is unresolved")
                    time.sleep(0.002)
            (transition_authority or self.authority)()
            if self.path.exists() or self.path.is_symlink():
                state = read_protected(self.path)
                base = {"version", "writer_incarnation", "writer_owner_epoch", "writer_generation", "phase", "binding_digest", "binding", "entries"}
                if not isinstance(state, dict) or set(state) - base - {"writer_transfer", "ownership", "sealed_export"} or not base.issubset(state):
                    raise ConflictError("handoff journal fields differ")
                if state["version"] != VERSION or (transition_authority is None and (state["writer_incarnation"] != self.writer or state["writer_owner_epoch"] != self.owner_epoch)):
                    raise ConflictError("stale handoff journal writer")
                integer(state["writer_generation"])
                if transition_authority is None:
                    if self.writer_generation is None:
                        self.writer_generation = state["writer_generation"]
                    elif state["writer_generation"] != self.writer_generation:
                        raise ConflictError("stale handoff journal writer generation")
                if state["binding"] is not None and state["binding_digest"] != digest(state["binding"]):
                    raise ConflictError("handoff current ownership projection changed")
            else:
                state = {"version": VERSION, "writer_incarnation": self.writer, "writer_owner_epoch": self.owner_epoch, "writer_generation": 1, "phase": "owned", "binding_digest": None, "binding": None, "entries": {}}
                if transition_authority is not None:
                    raise ConflictError("writer transfer lacks a prepared journal")
                self.writer_generation = 1
            yield state
        finally:
            os.close(fd)

    def begin(self, request):
        validate_request(request)
        with self.locked() as state:
            binding = digest(request["binding"]); key = request["binding"]["handoff_id"] + ":" + request["command"]
            prior = state["entries"].get(key)
            if prior is not None:
                if prior["request_digest"] != digest(request) or prior["binding_digest"] != binding:
                    raise ConflictError("handoff replay changed input")
                if prior["reply"] is None:
                    raise ConflictError("handoff pending outcome requires reconciliation")
                return prior["reply"]
            if state["binding_digest"] not in (None, binding):
                current = [e for e in state["entries"].values() if e["binding_digest"] == state["binding_digest"]]
                terminal = all(e["reply"] is not None for e in current) and any(e["reply"]["status"] == "active_work" or (e["reply"]["command"] == "handoff_abort" and e["reply"]["status"] == "ok") for e in current)
                if state["phase"] != "owned" or not terminal:
                    raise ConflictError("handoff binding changed")
            if time.time_ns() // 1_000_000 > request["binding"]["deadline_unix_ms"]:
                raise ConflictError("handoff deadline expired")
            if request["command"] != "handoff_report" and PHASES[request["command"]][0] != state["phase"]:
                raise ConflictError("handoff phase conflict")
            state["binding_digest"] = binding
            state["binding"] = request["binding"]
            state["entries"][key] = {"request_digest": digest(request), "binding_digest": binding, "reply": None}
            write_protected(self.path, state)
        return None

    def replay(self, request):
        """Authenticated read-only outcome retrieval, including after deadline."""
        validate_request(request)
        with self.locked() as state:
            entry = state["entries"].get(request["binding"]["handoff_id"] + ":" + request["command"])
            if entry is None:
                return None
            if entry["request_digest"] != digest(request) or entry["binding_digest"] != digest(request["binding"]):
                raise ConflictError("handoff replay changed input")
            if entry["reply"] is None:
                raise ConflictError("handoff pending outcome requires reconciliation")
            return entry["reply"]

    def finish(self, request, reply):
        validate_reply(reply, request)
        with self.locked() as state:
            key = request["binding"]["handoff_id"] + ":" + request["command"]
            entry = state["entries"].get(key)
            if entry is None or entry["request_digest"] != digest(request):
                raise ConflictError("handoff outcome has no matching pending intent")
            if entry["reply"] is not None and entry["reply"] != reply:
                raise ConflictError("handoff outcome conflicts with committed receipt")
            if reply["status"] == "ok":
                expected = state["phase"] if request["command"] == "handoff_report" else PHASES[request["command"]][1]
                if reply["phase"] != expected:
                    raise ConflictError("handoff reply phase differs")
                state["phase"] = expected
                if request["command"] == "handoff_export_sealed":
                    pause = state["entries"].get(request["binding"]["handoff_id"] + ":handoff_prepare")
                    if pause is None or pause["reply"] is None or pause["reply"]["status"] != "ok" or request["payload"]["export_metadata"]["host_pause_ack_digest"] != digest(pause["reply"]):
                        raise ConflictError("sealed export differs from durable host pause ACK")
                    state["sealed_export"] = request["payload"]
            entry["reply"] = reply
            write_protected(self.path, state)
        return reply

    def prepare_writer_transfer(self, binding, *, transition_id, source_actor, successor_actor):
        """Fsync exact A intent before relay ownership can change.

        Actor objects are retained kernel proofs, never reconstructed from
        payloads. No role lock/RPC/wait is held inside this journal operation.
        """
        source, successor = source_actor.verify(), successor_actor.verify()
        if source != binding["source_owner"] or successor != binding["new_owner"]:
            raise ConflictError("writer transfer incarnation differs")
        with self.locked() as state:
            if state["phase"] != "export_sealed" or state["binding_digest"] != digest(binding):
                raise ConflictError("writer transfer lacks durable sealed export")
            intent = {"transition_id": transition_id, "binding_digest": digest(binding), "from_writer": source, "from_epoch": binding["source_owner_epoch"], "from_generation": state["writer_generation"], "to_writer": successor, "to_epoch": binding["new_owner_epoch"], "source_relay_reference": binding["source_relay_reference"]}
            prior = state.get("writer_transfer")
            if prior is not None:
                if prior["intent"] != intent:
                    raise ConflictError("writer transfer replay changed transition")
                return prior
            state["writer_transfer"] = {"state": "prepared", "intent": intent, "relay_ack": None}
            write_protected(self.path, state)
            return state["writer_transfer"]

    def reconcile_writer_transfer(self, binding, *, transition_id, successor_actor, authoritative_ack):
        """Fresh B closes the split commit using the protected relay ledger.

        The callback reads/verifies the current ledger and its exact committed
        transition, not a supplied ACK. A missing ledger transition never
        permits journal takeover. It performs no RPC/wait under the lock.
        """
        def authenticate():
            if successor_actor.verify() != binding["new_owner"]:
                raise ConflictError("journal successor incarnation differs")
        with self.locked(transition_authority=authenticate) as state:
            prepared = state.get("writer_transfer")
            if prepared is None:
                raise ConflictError("writer transfer has no durable prepared intent")
            intent = prepared["intent"]
            if (intent["transition_id"] != transition_id or intent["binding_digest"] != digest(binding)
                    or intent["from_writer"] != binding["source_owner"] or intent["from_epoch"] != binding["source_owner_epoch"]
                    or intent["to_writer"] != binding["new_owner"] or intent["to_epoch"] != binding["new_owner_epoch"]
                    or intent["source_relay_reference"] != binding["source_relay_reference"]):
                raise ConflictError("writer transfer prepared intent conflicts")
            ack = authoritative_ack()
            expected = {"version": "runtime.role-custody-designation/v1", "transition_id": transition_id, "role": "relay", "generation": binding["source_relay_reference"]["generation"] + 1, "owner_epoch": binding["new_owner_epoch"], "actor": binding["new_owner"], "target": binding["source_relay_reference"]["target"]}
            if ack != expected:
                raise ConflictError("writer transfer authoritative relay ACK differs")
            if prepared["state"] == "committed":
                if (prepared["relay_ack"] != ack or state["writer_incarnation"] != intent["to_writer"] or state["writer_owner_epoch"] != intent["to_epoch"] or state["writer_generation"] != intent["from_generation"] + 1):
                    raise ConflictError("committed writer transfer conflicts")
                return prepared
            if (prepared["state"] != "prepared" or state["writer_incarnation"] != intent["from_writer"] or state["writer_owner_epoch"] != intent["from_epoch"] or state["writer_generation"] != intent["from_generation"]):
                raise ConflictError("writer transfer lost exclusive source ownership")
            relay_ref = {"version": "runtime.role-custody-reference/v1", "scope_root": binding["custody_scope"], "role": "relay", "generation": ack["generation"], "target": ack["target"]}
            state["ownership"] = {"owner": ack["actor"], "owner_epoch": ack["owner_epoch"], "relay_reference": relay_ref, "current_roles": {**binding["current_roles"], "relay": relay_ref}, "previous_projection_digest": digest(state.get("ownership") or {"owner": binding["source_owner"], "owner_epoch": binding["source_owner_epoch"], "relay_reference": binding["source_relay_reference"]})}
            state.update(writer_incarnation=intent["to_writer"], writer_owner_epoch=intent["to_epoch"], writer_generation=intent["from_generation"] + 1)
            state["writer_transfer"] = {"state": "committed", "intent": intent, "relay_ack": ack}
            write_protected(self.path, state)
            return state["writer_transfer"]
