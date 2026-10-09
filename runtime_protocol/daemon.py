from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .auth import CredentialStore
from .catalog import LiveDiscovery, RealmCatalog, process_birth_identity
from .backup import restore_backup, verify_backup, verify_restore_candidate
from .dirfd import capture_parent, close_pinned, validate_parent
from .errors import ConflictError, NotFoundError, ProtocolError
from .server import RuntimeHTTPServer, RuntimeHandler
from .service import RuntimeService
from .util import atomic_json_write, now

try:
    import fcntl
except ImportError:  # pragma: no cover - supported beta host is POSIX
    fcntl = None


WORKER_ACTOR = "astrid-pack-host"
WORKER_SCOPES = (
    "handshake",
    "worker:register",
    "worker:execute",
    "tasks:read",
    "objects:read",
    "objects:write",
)


def _authority_path(value, label):
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
            raise ValueError(f"{label} must not traverse a symlink")
    return path


class RuntimeDaemon:
    """Loopback-only daemon owning one realm and its storage."""

    def __init__(self, root, *, support_root=None, export_root=None, display_name="Workspace", host="127.0.0.1", port=0, realm_id=None, owner_lock=None, bootstrap_token_file=None, reboot_executor=None, reboot_allowlist=None, production_worker_credentials=False, admission_timeout=None, local_worker_profiles=None, local_worker_preparer=None, local_worker_inspector=None):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("runtime daemon only binds to loopback")
        self.root = _authority_path(root, "realm root").resolve()
        self.support_root = (_authority_path(support_root, "support root").resolve() if support_root else self.root / "support")
        self.export_root = _authority_path(export_root, "managed-output export root").resolve() if export_root else None
        self.host, self.port, self.display_name = host, port, display_name
        self.realm_id = realm_id
        self.owner_lock = _authority_path(owner_lock, "owner lock").resolve() if owner_lock else None
        self.bootstrap_token_file = _authority_path(bootstrap_token_file, "bootstrap token file").resolve() if bootstrap_token_file else None
        # Reboot is deliberately disabled unless a host supplies an executor.
        # The service additionally validates that any configured command is in
        # its small, explicit allowlist.
        self.reboot_executor = reboot_executor
        self.reboot_allowlist = reboot_allowlist
        # In-process RuntimeDaemon fixtures historically use ``worker_token``
        # as an administrator convenience for arbitrary fake executor IDs.
        # The installed CLI passes production_worker_credentials=True, which
        # switches the real process to the bound least-privilege pack-host
        # credential below.  Keeping the fixture mode explicit avoids granting
        # that administrator credential to the production host.
        self.production_worker_credentials = bool(production_worker_credentials)
        self.admission_timeout = admission_timeout
        self.instance_id = uuid.uuid4().hex
        self.service = None
        self.httpd = None
        self.thread = None
        self.catalog = RealmCatalog(self.support_root / "catalog.json")
        self.discovery = LiveDiscovery(self.support_root / "discovery.json")
        # CredentialStore creates its directory. Defer that side effect until
        # the realm has passed RuntimeService's fenced startup admission.
        self.credentials = None
        self.token = None
        self.worker_token = None
        self.credential_path = None
        self.worker_credential_path = None
        self.local_worker_profiles = dict(local_worker_profiles or {})
        self.local_worker_preparer = local_worker_preparer
        self.local_worker_inspector = local_worker_inspector
        self.local_worker_launcher = None
        self._local_worker_deferred = False
        # Local launch and remote credential control share one actor. Keep
        # their ownership transitions mutually exclusive without adding a
        # second actor or credential ledger.
        self._worker_actor_lock = threading.RLock()
        if bool(self.local_worker_profiles) != bool(local_worker_preparer) or bool(self.local_worker_profiles) != bool(local_worker_inspector):
            raise ValueError("local worker profiles, preparer, and inspector must be configured together")

    @property
    def endpoint(self):
        if not self.httpd:
            return None
        host = "127.0.0.1" if self.host == "localhost" else self.host
        return f"http://{host}:{self.httpd.server_port}"

    def start(self):
        if self.httpd:
            return self
        self._start(rotate_credentials=False)
        self._cleanup_completed_replacement()
        return self

    def _catalog_owner_valid(self, proof):
        return self.service is not None and self.service.validate_catalog_admission(proof)

    def _provision_credentials(self, *, rotate=False):
        self.credentials = CredentialStore(_authority_path(self.support_root / "credentials", "credential root"))
        self._local_worker_deferred = False
        owner_scopes = ["admin", "handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write", "worker:execute", "worker:register", "credentials:provision"]
        self.token, self.credential_path = self.credentials.provision("owner", owner_scopes, rotate=rotate)
        if self.local_worker_profiles:
            if self._remote_worker_custody_unresolved() or self._local_relinquish_pending():
                # Keep the owner and exact remote cleanup route available. Do
                # not construct LocalWorkerLauncher here: its restart recovery
                # intentionally reconciles local receipts and could otherwise
                # revoke an exact remote generation as an invalid local one.
                self.credentials.disable_actor(WORKER_ACTOR)
                self._local_worker_deferred = True
            # The two-phase local path issues this shared actor only after
            # independent process verification.
            self.worker_token = None
            self.worker_credential_path = self.credentials.path_for(WORKER_ACTOR)
        else:
            # A new production owner must never inherit a receipt-less legacy
            # Worker bearer. Rotate the single CredentialStore generation
            # before HTTP starts; fixture-mode credentials retain their
            # historical behavior for in-process tests.
            existing_worker = self.credentials.actor_metadata(WORKER_ACTOR)
            if isinstance(existing_worker, dict) and isinstance(existing_worker.get("qualified_activation"), dict):
                # Preserve exact remote custody across daemon restart. The old
                # session/epoch cannot execute; only exact owner cleanup may
                # retire it before a freshly observed generation is installed.
                self.credentials.disable_actor(WORKER_ACTOR)
                self.worker_token = None
                self.worker_credential_path = self.credentials.path_for(WORKER_ACTOR)
            else:
                legacy = self.credentials._legacy_pair(WORKER_ACTOR)
                if (existing_worker is None and any(path.exists() or path.is_symlink() for path in self.credentials._paths(WORKER_ACTOR))
                        and (legacy is None or isinstance(legacy[1].get("qualified_activation"), dict))):
                    # Keep owner reconciliation reachable after interrupted
                    # credential cleanup; never rotate unresolved file bytes.
                    self.credentials.disable_actor(WORKER_ACTOR)
                    self.worker_token = None
                    self.worker_credential_path = self.credentials.path_for(WORKER_ACTOR)
                else:
                    rotate_worker = (
                        rotate
                        or bool(self.production_worker_credentials and existing_worker)
                        or self.credentials.has_legacy_generation(WORKER_ACTOR)
                    )
                    self.worker_token, self.worker_credential_path = self.credentials.provision(
                        WORKER_ACTOR, list(WORKER_SCOPES), rotate=rotate_worker
                    )
        if not self.production_worker_credentials and not self.local_worker_profiles:
            # Test-only in-process convenience.  The production CLI never
            # selects this branch; its pack host receives WORKER_ACTOR's
            # scoped token and cannot call admin/project routes.
            self.worker_token = self.token
        if self.bootstrap_token_file and self.bootstrap_token_file.exists():
            bootstrap_token = self.bootstrap_token_file.read_text(encoding="utf-8").strip()
            self.credentials.provision_static("bootstrap", bootstrap_token, ["admin", "credentials:provision"])
            self.bootstrap_token_file.unlink(missing_ok=True)

    def _shutdown_http(self):
        if self.httpd:
            # HTTPServer.shutdown() waits for serve_forever() to be running.
            # Replacement startup can fail after constructing the server but
            # before its serving thread starts; calling shutdown in that state
            # hangs cleanup indefinitely.
            if self.thread is not None and self.thread.is_alive():
                self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        self.thread = None

    def _revoke_readiness(self, report):
        if self.service is None:
            return
        try:
            realm_id = self.service.realm["id"]
        except Exception:
            return
        self.catalog.revoke_readiness(realm_id, instance_id=self.instance_id, reason="runtime_admission_failed")
        self.discovery.clear(self.instance_id)

    def _epoch_floor_path(self):
        return self.support_root / "runtime-epoch-floor.json"

    def _read_epoch_floor(self):
        path = self._epoch_floor_path()
        if not path.exists():
            return 0
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            floor = int(value["runtime_epoch_floor"])
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ConflictError("runtime epoch floor is invalid; refuse startup") from exc
        if floor < 0:
            raise ConflictError("runtime epoch floor is invalid; refuse startup")
        return floor

    def _write_epoch_floor(self, epoch):
        floor = int(epoch)
        if floor < 0:
            raise ConflictError("runtime epoch floor is invalid")
        atomic_json_write(self._epoch_floor_path(), {"format_version": 1, "runtime_epoch_floor": floor})

    def _start(self, *, rotate_credentials=False):
        epoch_floor = self._read_epoch_floor()
        self.service = RuntimeService(self.root, display_name=self.display_name, realm_id=self.realm_id, support_root=self.support_root, export_root=self.export_root, reboot_executor=self.reboot_executor, reboot_allowlist=self.reboot_allowlist, runtime_epoch_floor=epoch_floor, admission_timeout=self.admission_timeout)
        self.service.set_readiness_callback(self._revoke_readiness)
        self.service.set_local_claim_generation_verifier(self._verify_local_claim_generation, actor=WORKER_ACTOR)
        self.catalog.bind_owner(self._catalog_owner_valid)
        self._provision_credentials(rotate=rotate_credentials)
        if self.local_worker_profiles and not self._local_worker_deferred:
            self._create_local_worker_launcher()
        self.httpd = RuntimeHTTPServer((self.host, self.port), RuntimeHandler)
        self.httpd.runtime = self.service
        self.httpd.daemon_runtime = self
        self.httpd.credentials = self.credentials
        owner = self.service.catalog_admission(self.instance_id)
        # Persist the observed epoch before readiness publication.  A restored
        # older database can therefore never reuse an epoch from its snapshot.
        self._write_epoch_floor(owner["runtime_epoch"])
        self.catalog.register(realm_id=self.service.realm["id"], display_name=self.service.realm["display_name"], data_root=str(self.root), owner=owner, runtime_epoch=owner["runtime_epoch"], runtime_instance_id=self.instance_id, readiness="ready")
        birth_id = process_birth_identity()
        if self.owner_lock:
            atomic_json_write(self.owner_lock, {"pid": os.getpid(), "process_birth_id": birth_id, "runtime_instance_id": self.instance_id, "realm_id": self.service.realm["id"], "realm_root": str(self.root)})
        self.discovery.publish(version=1, endpoint=self.endpoint, pid=os.getpid(), process_birth_id=birth_id, runtime_instance_id=self.instance_id, active_realm=self.service.realm["id"], realm_root=str(self.root), protocol_version="workspace.v1", schema_version="workspace-schema-v1", coordinator_epoch=self.instance_id, credential_file=str(self.credential_path), worker_credential_file=str(self.worker_credential_path), worker_credential_pending=bool(self.local_worker_profiles), worker_actor=WORKER_ACTOR, worker_scopes=list(WORKER_SCOPES))
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="banodoco-runtime", daemon=True)
        self.thread.start()
        return self

    def _create_local_worker_launcher(self):
        from .local_worker import LocalWorkerLauncher

        self.local_worker_launcher = LocalWorkerLauncher(
            credentials=self.credentials,
            profiles=self.local_worker_profiles,
            preparer=self.local_worker_preparer,
            inspector=self.local_worker_inspector,
            workspace_uuid=self.service.realm["id"],
            realm_root=self.root,
            support_root=self.support_root,
            runtime_pid=os.getpid(),
            actor=WORKER_ACTOR,
            scopes=WORKER_SCOPES,
        )
        self._local_worker_deferred = False
        return self.local_worker_launcher

    def _has_unrevoked_remote_activation(self):
        rows = self.service.store.conn.execute(
            "SELECT task_id, kind, payload_json FROM events "
            "WHERE kind IN ('task.remote_activation_qualified', 'task.remote_activation_revoked') "
            "ORDER BY id"
        ).fetchall()
        active = set()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                # Corrupt identity history cannot prove the shared actor free.
                return True
            activation_id = payload.get("activation_id") if isinstance(payload, dict) else None
            if not isinstance(activation_id, str):
                return True
            key = (str(row["task_id"]), activation_id)
            if row["kind"] == "task.remote_activation_qualified":
                active.add(key)
            else:
                active.discard(key)
        return bool(active)

    def _remote_worker_custody_unresolved(self):
        """Whether the shared actor still has remote or ambiguous custody."""
        metadata = self.credentials.actor_metadata(WORKER_ACTOR)
        paths = self.credentials._paths(WORKER_ACTOR)
        files_exist = any(path.exists() or path.is_symlink() for path in paths)
        if self._has_unrevoked_remote_activation():
            return True
        if isinstance(metadata, dict) and isinstance(metadata.get("qualified_activation"), dict):
            return True
        if files_exist and not (
            isinstance(metadata, dict)
            and isinstance(metadata.get("local_launch_receipt"), dict)
        ):
            # Partial, corrupt, legacy, or otherwise unclassified bytes are
            # not evidence that a local process may take over the actor.
            return True
        return False

    def _local_relinquish_path(self):
        return self.support_root / "local-worker-relinquish.json"

    def _local_relinquish_state(self):
        path = self._local_relinquish_path()
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConflictError("local Worker relinquish checkpoint is unreadable") from exc
        if (not isinstance(value, dict) or value.get("version") != 1
                or value.get("state") not in {"fencing", "fenced", "stop_unknown", "stopped", "complete"}
                or not isinstance(value.get("receipt"), dict)):
            raise ConflictError("local Worker relinquish checkpoint is invalid")
        return value

    def _local_relinquish_pending(self):
        state = self._local_relinquish_state()
        return state is not None and state["state"] != "complete"

    def _write_local_relinquish(self, state):
        atomic_json_write(self._local_relinquish_path(), state)

    def _assert_worker_actor_has_no_work(self):
        """Called under the claim/store mutex before disabling the bearer."""
        queries = (
            ("tasks", "SELECT 1 FROM tasks WHERE executor_id=? AND status IN ('running', 'cancel_requested') LIMIT 1"),
            ("attempts", "SELECT 1 FROM attempts WHERE executor_id=? AND settled=0 LIMIT 1"),
            ("reservations", "SELECT 1 FROM reservations WHERE executor_id=? AND released_at IS NULL LIMIT 1"),
            ("execution bindings", "SELECT 1 FROM execution_bindings WHERE executor_id=? AND status='claimed' LIMIT 1"),
        )
        for label, query in queries:
            if self.service.store.conn.execute(query, (WORKER_ACTOR,)).fetchone():
                raise ConflictError(f"local Worker has outstanding {label}")

    def _verify_local_claim_generation(self, fence, identity):
        from .local_worker import _credential_commit_generation
        with self.credentials._lock:
            generation = _credential_commit_generation(self.credentials, WORKER_ACTOR)
            metadata = self.credentials.actor_metadata(WORKER_ACTOR)
            receipt = metadata.get("local_launch_receipt") if isinstance(metadata, dict) else None
            if (not isinstance(receipt, dict) or receipt.get("workspace_uuid") != fence["workspace_uuid"]
                    or receipt.get("executor_incarnation") != fence["executor_incarnation"]):
                raise ConflictError("claim fence differs from protected launch generation")
            if identity is not None and (not isinstance(identity, dict)
                    or identity.get("actor") != WORKER_ACTOR
                    or identity.get("execution_binding") != metadata.get("execution_binding")):
                raise ConflictError("claim fence caller differs from selected credential binding")
            return generation

    def hold_local_execution_claims(self, binding):
        """Publish a generation fence after the host's durable pause.

        This is a composed owner method, not an HTTP authority grant. It never
        holds the claim mutex across relay/host RPC or credential rotation.
        """
        from .local_execution_handoff import FENCE_VERSION, validate_request
        validate_request({"version": "runtime.local-execution-handoff/v1", "command": "handoff_prepare", "binding": binding, "payload": {}})
        launcher = self.local_worker_launcher
        if launcher is None:
            raise ConflictError("handoff has no retained launch owner")
        launcher.verify_retained_handoff_binding(binding)
        with self._worker_actor_lock:
            prior = self.service._local_claim_fence
            same = prior is not None and prior["handoff_id"] == binding["handoff_id"] and prior["intent_digest"] == binding["intent_digest"]
            if same and prior["state"] == "released":
                # Exact old pause receipt retrieval must not rehold or rotate
                # a finalized/rolled-back fence. Export still requires held.
                return dict(prior)
            generation = prior["fence_generation"] if same else (prior["fence_generation"] + 1 if prior else 1)
            value = {"version": FENCE_VERSION, "state": "held", **{k: binding[k] for k in ("workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest", "source_owner_epoch")}, "target_owner_epoch": binding["new_owner_epoch"], "fence_generation": generation, "release_ack_digest": None}
            return self.service.hold_local_claim_fence(value, assert_no_work=self._assert_worker_actor_has_no_work)

    def forward_local_execution_handoff(self, request):
        from .local_execution_handoff import digest, read_protected, validate_request
        validate_request(request)
        final_fence = None
        if request["command"] == "handoff_finalize":
            final_fence = self._local_finalization_fence(request)
            # Recheck the actual registration before asking the host to open.
            # This reads durable state; no store lock spans the host RPC.
            state = read_protected(Path(request["binding"]["custody_scope"]) / "runtime-handoff-state.json")
            command = "handoff_finalize" if state.get("phase") == "finalized" else "resume_commit"
            entry = state.get("entries", {}).get(request["binding"]["handoff_id"] + ":" + command)
            if entry is None or entry.get("reply") is None or entry["reply"].get("status") != "ok":
                raise ConflictError("finalization lacks durable resumed registration")
            registered = entry["reply"].get("registered_state")
            if digest(registered) != request["payload"]["registered_state_digest"]:
                raise ConflictError("finalization registration changed before host opening")
            self._verify_local_finalization_registration(request["binding"], registered)
        # No canonical store/credential/role lock spans this RPC.
        reply = self.local_worker_launcher.retained_handoff_command(request)
        if request["command"] == "handoff_prepare" and reply["status"] == "ok":
            # Pause is durable first. The no-work check and fence publication
            # then exclude any stale concurrent claim before export. A failed
            # fence keeps the host paused and denies further transitions.
            self.hold_local_execution_claims(request["binding"])
        if request["command"] == "handoff_abort" and reply["status"] == "ok":
            def verify_ack(ack):
                state = read_protected(Path(request["binding"]["custody_scope"]) / "relay-handoff-state.json")
                entry = state["entries"].get(request["binding"]["handoff_id"] + ":handoff_abort")
                if (state["phase"] != "owned" or state["binding_digest"] != digest(request["binding"])
                        or entry is None or entry["request_digest"] != digest(request) or entry["reply"] != ack):
                    raise ConflictError("rollback lacks exact durable relay ACK")
            held = self.service._local_claim_fence
            if held is None:
                raise ConflictError("rollback has no retained canonical claim fence")
            if held["state"] == "released":
                verify_ack(reply)
                if held["release_ack_digest"] != digest(reply):
                    raise ConflictError("rollback replay differs from released fence ACK")
            else:
                self.service.release_local_claim_fence(held, durable_ack=reply, verify_ack=verify_ack)
        if request["command"] == "handoff_finalize":
            from .local_execution_handoff import validate_reply
            validate_reply(reply, request)
            if reply["status"] != "ok":
                return reply  # Unknown outcomes never release canonical claims.
            def verify_final(ack):
                self._verify_local_finalization_outcome(request, ack)
            # Reload even after an exception/lost persistence ACK: the file,
            # not an old in-memory flag, determines whether release committed.
            with self.service.store._mutex:
                self.service._load_local_claim_fence()
                current = self.service._local_claim_fence
                if self.service._local_claim_fence_unknown or current is None:
                    raise ConflictError("finalization claim fence is unresolved")
                if current["state"] == "released":
                    if {k: v for k, v in current.items() if k not in ("state", "release_ack_digest")} != {k: v for k, v in final_fence.items() if k not in ("state", "release_ack_digest")}:
                        raise ConflictError("finalization released generation changed")
                    verify_final(reply)
                    if current["release_ack_digest"] != digest(reply):
                        raise ConflictError("finalization replay changed terminal ACK")
                else:
                    if current != final_fence:
                        raise ConflictError("finalization held generation changed")
                    self.service.release_local_claim_fence(current, durable_ack=reply, verify_ack=verify_final)
        return reply

    def _local_finalization_fence(self, request):
        """Bind finalization to the actual B and existing canonical generation."""
        from .local_execution_handoff import digest
        b = request["binding"]
        if self.service is None or self.local_worker_launcher is None:
            raise ConflictError("finalization has no admitted successor owner")
        self.local_worker_launcher._verify_adopted_handoff(b)
        with self.service.store._mutex:
            self.service._assert_mutation_admitted()
            self.service._load_local_claim_fence()
            fence = self.service._local_claim_fence
            if (self.service._local_claim_fence_unknown or fence is None
                    or any(fence[k] != b[k] for k in ("workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest", "source_owner_epoch"))
                    or fence["target_owner_epoch"] != b["new_owner_epoch"]
                    or self._verify_local_claim_generation(fence, None) != b["credential_generation_digest"]):
                raise ConflictError("finalization canonical generation differs")
            held_projection = {**fence, "state": "held", "release_ack_digest": None}
            if request["payload"]["task_fence_digest"] != digest(held_projection):
                raise ConflictError("finalization exact held fence digest differs")
            return dict(fence)

    def _verify_local_finalization_registration(self, binding, registered):
        """Observe the canonical executor, without changing registration/metadata."""
        from .local_execution_handoff import digest, registered_state
        registered_state(registered)
        with self.service.store._mutex:
            health = self.service.health()
            expected_runtime = {"endpoint": self.endpoint, "protocol": health["protocol"], "schema_digest": health["schema_digest"], "runtime_epoch": health["runtime_epoch"], "runtime_session_id": self.service.runtime_session_id, "runtime_instance_id": self.instance_id, "coordinator_epoch": self.instance_id}
            row = self.service.store.conn.execute("SELECT * FROM executors WHERE id=?", (WORKER_ACTOR,)).fetchone()
            if (registered["executor_incarnation"] != binding["executor_incarnation"]
                    or self.instance_id != binding["new_owner_epoch"]
                    or registered["runtime"] != expected_runtime or row is None
                    or row["protocol"] != expected_runtime["protocol"] or row["runtime_epoch"] != expected_runtime["runtime_epoch"]
                    or row["source_epoch"] != registered["source_epoch"]):
                raise ConflictError("finalization actual executor registration differs")
            observed = self.service.store._executor_result(row)
            capabilities = registered["capabilities"]
            if ({c["capability_id"]: c["definition_digest"] for c in observed["capabilities"]}
                    != {k: c["capability_digest"] for k, c in capabilities.items()}
                    or row["source_digest"] != digest({k: c["source_digest"].removeprefix("sha256:") for k, c in capabilities.items()}).removeprefix("sha256:")
                    or row["dependency_digest"] != digest({k: c["dependency_digest"].removeprefix("sha256:") for k, c in capabilities.items()}).removeprefix("sha256:")):
                raise ConflictError("finalization capability/source registration changed")

    def _verify_local_finalization_outcome(self, request, ack):
        """Exact host/relay/B journal proof, current custody, and real registration."""
        import hashlib
        from banodoco_local.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority, _read_owner_file
        from .local_execution_handoff import digest, exact, read_protected, validate_reply
        from .local_worker_handoff import committed_relay_transfer, relay_transition_id
        b = request["binding"]; scope = Path(b["custody_scope"])
        validate_reply(ack, request)
        self._local_finalization_fence(request)
        actual = AuthenticatedCleanupActor.current()
        if actual.verify() != b["new_owner"]:
            raise ConflictError("finalization actual B incarnation differs")
        relay_ref = {**b["source_relay_reference"], "generation": b["source_relay_reference"]["generation"] + 1}
        roles = {**b["current_roles"], "relay": relay_ref}
        if ack["custody_capabilities"] != roles or ack["host"] != {k: roles["host"]["target"][k] for k in ("pid", "uid", "birth_id")}:
            raise ConflictError("finalization current host/custody projection differs")
        owners = {"relay": b["new_owner"], "host": relay_ref["target"], "engine": roles["host"]["target"], "engine_listener": roles["host"]["target"]}
        for role, ref in roles.items():
            RoleCustodyAuthority(scope, role).verify_reference(ref, expected_actor=owners[role], owner_epoch=b["new_owner_epoch"] if role == "relay" else b["original_owner_epoch"])
        transfer_ack = committed_relay_transfer(b, successor_actor=actual, authority=RoleCustodyAuthority(scope, "relay"))
        activation, _ = _read_owner_file(scope / "activation-record.json")
        if "sha256:" + hashlib.sha256(activation).hexdigest() != b["activation_record_digest"]:
            raise ConflictError("finalization immutable activation bytes changed")
        host = read_protected(scope / "host-handoff-state.json")
        exact(host, ("version", "writer_incarnation", "writer_owner_epoch", "handoff_id", "command", "request_digest", "reply"))
        if (host["version"] != "runtime.local-execution-handoff-journal/v1"
                or host["writer_incarnation"] != f"{ack['host']['pid']}:{ack['host']['birth_id']}"
                or host["writer_owner_epoch"] != b["original_owner_epoch"] or host["handoff_id"] != b["handoff_id"]
                or host["command"] != "handoff_finalize" or host["request_digest"] != digest(request) or host["reply"] != ack):
            raise ConflictError("finalization lacks exact durable host outcome")
        for name in ("relay", "runtime"):
            state = read_protected(scope / (name + "-handoff-state.json"))
            entry = state.get("entries", {}).get(b["handoff_id"] + ":handoff_finalize")
            expected_writer = relay_ref["target"] if name == "relay" else b["new_owner"]
            expected_epoch = b["original_owner_epoch"] if name == "relay" else b["new_owner_epoch"]
            if (state.get("phase") != "finalized" or state.get("binding_digest") != digest(b) or state.get("binding") != b
                    or state.get("writer_incarnation") != expected_writer or state.get("writer_owner_epoch") != expected_epoch
                    or entry != {"request_digest": digest(request), "binding_digest": digest(b), "reply": ack}):
                raise ConflictError("finalization lacks exact durable " + name + " outcome")
            if name == "runtime":
                transition = state.get("writer_transfer", {})
                intent = transition.get("intent", {})
                ownership = state.get("ownership", {})
                if (transition.get("state") != "committed" or transition.get("relay_ack") != transfer_ack
                        or intent.get("transition_id") != relay_transition_id(b) or intent.get("binding_digest") != digest(b)
                        or intent.get("from_writer") != b["source_owner"] or intent.get("to_writer") != b["new_owner"]
                        or intent.get("from_epoch") != b["source_owner_epoch"] or intent.get("to_epoch") != b["new_owner_epoch"]
                        or intent.get("source_relay_reference") != b["source_relay_reference"]
                        or type(intent.get("from_generation")) is not int or state.get("writer_generation") != intent["from_generation"] + 1
                        or ownership.get("owner") != b["new_owner"] or ownership.get("owner_epoch") != b["new_owner_epoch"]
                        or ownership.get("relay_reference") != relay_ref or ownership.get("current_roles") != roles):
                    raise ConflictError("finalization current Runtime writer transfer differs")
        self._verify_local_finalization_registration(b, ack["registered_state"])
        self._assert_worker_actor_has_no_work()

    def adopt_local_execution_handoff(self, request, receipt):
        """Fresh B custody/control adoption remains behind the held task fence."""
        from .local_execution_handoff import validate_request
        validate_request(request)
        if self.service is None or self.local_worker_launcher is None:
            raise ConflictError("successor requires its admitted canonical Runtime owner")
        with self.service.store._mutex:
            self.service._load_local_claim_fence()
            fence = self.service._local_claim_fence
            if (self.service._local_claim_fence_unknown or fence is None or fence["state"] != "held"
                    or any(fence[k] != request["binding"][k] for k in ("workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest"))
                    or self._verify_local_claim_generation(fence, None) != fence["credential_generation_digest"]):
                raise ConflictError("successor canonical claim fence is unresolved")
        # No store lock spans the fresh accept/role transfer/host exchange.
        result = self.local_worker_launcher.adopt_retained_handoff(request, receipt)
        with self.service.store._mutex:
            self.service._load_local_claim_fence()
            if self.service._local_claim_fence != fence:
                raise ConflictError("successor claim fence changed during adoption")
        # No activation, credential enablement, registration or fence release.
        return result

    def _assert_local_relinquish_receipt(self, receipt, metadata):
        from .local_worker import RECEIPT_VERSION

        profile = self.local_worker_profiles.get(receipt.get("profile_id")) if isinstance(receipt, dict) else None
        if (profile is None or receipt.get("version") != RECEIPT_VERSION
                or receipt.get("workspace_uuid") != self.service.realm["id"]
                or not isinstance(receipt.get("executor_incarnation"), str)
                or not receipt["executor_incarnation"]
                or not isinstance(receipt.get("evidence_digest"), str)
                or not receipt["evidence_digest"]
                or receipt.get("profile_digest") != profile.profile_digest
                or receipt.get("release_digest") != profile.release_digest
                or receipt.get("machine_id") != profile.machine_id):
            raise ConflictError("local Worker relinquish receipt does not match this Runtime")
        for name in ("worker", "host", "engine", "engine_listener"):
            process = receipt.get(name)
            if (not isinstance(process, dict) or not isinstance(process.get("pid"), int)
                    or process["pid"] <= 0 or not isinstance(process.get("birth_id"), str)
                    or not process["birth_id"]):
                raise ConflictError("local Worker relinquish process receipt is invalid")
        if metadata is not None:
            binding = metadata.get("execution_binding")
            verification = binding.get("verification") if isinstance(binding, dict) else None
            if (metadata.get("local_launch_receipt") != receipt
                    or not isinstance(binding, dict)
                    or binding.get("executor_incarnation") != receipt.get("executor_incarnation")
                    or not isinstance(verification, dict)
                    or verification.get("verified") is not True
                    or verification.get("evidence_digest") != receipt.get("evidence_digest")):
                raise ConflictError("local Worker relinquish credential binding changed")

    def relinquish_local_worker(self, executor_incarnation, evidence_digest, *, identity):
        """Fence, stop, and retire one exact local shared-actor generation.

        The checkpoint is intentionally kept through process and credential
        cleanup so an interrupted owner can replay this exact request. No
        process wait runs while the SQLite claim mutex is held.
        """
        if not isinstance(executor_incarnation, str) or not executor_incarnation or not isinstance(evidence_digest, str) or not evidence_digest:
            raise ProtocolError("exact local Worker generation is required")
        if not self.local_worker_profiles or self.service is None:
            raise ConflictError("local Worker relinquish requires a configured Runtime owner")
        with self._worker_actor_lock:
            with self.service.store._mutex:
                self.service._assert_mutation_admitted()
                if self.service._require_placement_recovery_owner(identity) != "owner":
                    raise ConflictError("local Worker relinquish requires the Runtime owner")
                self._assert_worker_actor_has_no_work()
                checkpoint = self._local_relinquish_state()
                metadata = self.credentials.actor_metadata(WORKER_ACTOR)
                receipt = metadata.get("local_launch_receipt") if isinstance(metadata, dict) else None
                if checkpoint is not None and checkpoint["state"] != "complete":
                    saved = checkpoint["receipt"]
                    if (saved.get("executor_incarnation") != executor_incarnation
                            or saved.get("evidence_digest") != evidence_digest):
                        raise ConflictError("another local Worker generation is pending relinquish")
                    if receipt is not None and receipt != saved:
                        raise ConflictError("local Worker credential generation changed")
                    receipt = saved
                    self._assert_local_relinquish_receipt(receipt, metadata)
                else:
                    if (not isinstance(receipt, dict)
                            or receipt.get("executor_incarnation") != executor_incarnation
                            or receipt.get("evidence_digest") != evidence_digest):
                        if checkpoint is not None and checkpoint["state"] == "complete" and (
                            checkpoint["receipt"].get("executor_incarnation") == executor_incarnation
                            and checkpoint["receipt"].get("evidence_digest") == evidence_digest
                        ):
                            return {"state": "relinquished", "executor_incarnation": executor_incarnation}
                        raise ConflictError("local Worker credential generation changed")
                    if self.local_worker_launcher is not None and self.local_worker_launcher._operation_lock.locked():
                        raise ConflictError("local Worker launch is in progress")
                    self._assert_local_relinquish_receipt(receipt, metadata)
                    self.credentials._read_actor(WORKER_ACTOR)
                    file_digests = {
                        path.name: self.credentials._sha256(path.read_bytes())
                        for path in self.credentials._paths(WORKER_ACTOR)
                    }
                    checkpoint = {"version": 1, "state": "fencing", "receipt": dict(receipt), "file_digests": file_digests}
                    self._write_local_relinquish(checkpoint)
                self.credentials.disable_actor(WORKER_ACTOR)
                if (not isinstance(checkpoint.get("file_digests"), dict)
                        or set(checkpoint["file_digests"]) != {path.name for path in self.credentials._paths(WORKER_ACTOR)}):
                    raise ConflictError("local Worker relinquish file proof is incomplete")
                checkpoint["state"] = "fenced" if checkpoint["state"] == "fencing" else checkpoint["state"]
                self._write_local_relinquish(checkpoint)

            # The actor lock excludes local start and remote provision. The
            # SQLite mutex is free while the OS stop may wait or be retried.
            handle = None
            if self.local_worker_launcher is not None:
                handle = self.local_worker_launcher.relinquish_handle(receipt)
            stop_owned = getattr(self.local_worker_preparer, "stop_owned", None)
            if not callable(stop_owned):
                checkpoint["state"] = "stop_unknown"
                self._write_local_relinquish(checkpoint)
                raise ConflictError("local Worker preparer cannot attest exact process stop")
            try:
                if stop_owned(receipt, handle=handle) is not True:
                    raise ConflictError("receipt-owned local Worker stop is unconfirmed")
            except BaseException:
                checkpoint["state"] = "stop_unknown"
                self._write_local_relinquish(checkpoint)
                raise
            checkpoint["state"] = "stopped"
            self._write_local_relinquish(checkpoint)
            with self.service.store._mutex:
                self._assert_worker_actor_has_no_work()
                current = self.credentials.actor_metadata(WORKER_ACTOR)
                if current is not None and current.get("local_launch_receipt") != receipt:
                    raise ConflictError("local Worker credential generation changed during cleanup")
                for path in self.credentials._paths(WORKER_ACTOR):
                    if path.exists():
                        self.credentials._safe_file(path, "local Worker relinquish file")
                        if self.credentials._sha256(path.read_bytes()) != checkpoint["file_digests"].get(path.name):
                            raise ConflictError("local Worker credential bytes changed during cleanup")
                self.credentials.revoke(WORKER_ACTOR)
                checkpoint["state"] = "complete"
                self._write_local_relinquish(checkpoint)
                self.local_worker_launcher = None
                self._local_worker_deferred = False
            return {"state": "relinquished", "executor_incarnation": executor_incarnation}

    def local_worker_generation(self, *, identity):
        """Read the exact local generation held by this owner, including a pending stop."""
        with self._worker_actor_lock:
            with self.service.store._mutex:
                if self.service._require_placement_recovery_owner(identity) != "owner":
                    raise ConflictError("local Worker generation requires the Runtime owner")
                checkpoint = self._local_relinquish_state()
                if checkpoint is not None and checkpoint["state"] != "complete":
                    receipt = checkpoint["receipt"]
                    state = checkpoint["state"]
                else:
                    metadata = self.credentials.actor_metadata(WORKER_ACTOR)
                    receipt = metadata.get("local_launch_receipt") if isinstance(metadata, dict) else None
                    state = "active"
                if not isinstance(receipt, dict):
                    raise NotFoundError("local Worker generation is unavailable")
                self._assert_local_relinquish_receipt(receipt, None)
                return {
                    "executor_incarnation": receipt["executor_incarnation"],
                    "evidence_digest": receipt["evidence_digest"],
                    "profile_id": receipt["profile_id"],
                    "workspace_uuid": receipt["workspace_uuid"],
                    "state": state,
                }

    def start_local_worker(self, profile_id, expected_workspace_uuid):
        if not self.local_worker_profiles:
            raise ConflictError(
                "No local Worker profile is configured; set worker_profile in the Astrid source profile and restart the Runtime"
            )
        if self.service is None or self.httpd is None:
            raise ConflictError("local Worker start requires a running Runtime owner")
        with self._worker_actor_lock:
            with self.service.store._mutex:
                self.service._assert_local_claim_admission(WORKER_ACTOR)
            if self._remote_worker_custody_unresolved() or self._local_relinquish_pending():
                raise ConflictError(
                    "remote or unresolved Worker credential custody must be reconciled before local launch"
                )
            if self.local_worker_launcher is None:
                self._create_local_worker_launcher()
            bind_runtime = getattr(self.local_worker_preparer, "bind_runtime", None)
            if bind_runtime is not None:
                bind_runtime(
                    endpoint=self.endpoint,
                    runtime_instance_id=self.instance_id,
                    credential_file=self.worker_credential_path,
                )
            return self.local_worker_launcher.start(profile_id, expected_workspace_uuid)

    def _cleanup_exact_remote_credential(self, task_id, activation_id):
        """Reconcile interrupted file deletion using committed, secret-free hashes.

        Called only inside the Runtime owner mutex after exact revocation.
        A foreign or changed byte is unresolved, never an orphan we may erase.
        """
        actor = WORKER_ACTOR
        paths = self.credentials._paths(actor)
        existing = [path for path in paths if path.exists() or path.is_symlink()]
        if not existing:
            return
        rows = self.service.store.conn.execute(
            "SELECT payload_json FROM events WHERE task_id=? "
            "AND kind='task.remote_credential_cleanup_started' ORDER BY id DESC",
            (str(task_id),),
        ).fetchall()
        intent = next((value for row in rows if (value := json.loads(row["payload_json"]))
                       .get("activation_id") == activation_id), None)
        if intent is None:
            metadata = self.credentials.actor_metadata(actor)
            qualification = metadata.get("qualified_activation") if isinstance(metadata, dict) else None
            if (not isinstance(qualification, dict) or qualification.get("task_id") != task_id
                    or qualification.get("activation_id") != activation_id):
                raise ConflictError("exact remote credential cleanup is unresolved")
            self.credentials._read_actor(actor)
            intent = {"activation_id": activation_id, "credential_actor": actor,
                      "file_digests": {path.name: self.credentials._sha256(path.read_bytes()) for path in paths}}
            task = self.service.store.get_task(task_id)
            with self.service.store._transaction():
                self.service.store._append_event(task["run"]["id"], str(task_id),
                                                "task.remote_credential_cleanup_started", intent)
        if intent.get("credential_actor") != actor:
            raise ConflictError("remote credential cleanup actor changed")
        for path in existing:
            self.credentials._safe_file(path, "remote credential cleanup file")
            if self.credentials._sha256(path.read_bytes()) != intent["file_digests"].get(path.name):
                raise ConflictError("remote credential cleanup bytes changed")
        self.credentials.revoke(actor)

    def remote_credential_control(self, task_id, body, *, identity):
        # Metadata compare and every token side effect share claim/admission's
        # owner mutex. Credential files retain their own durable generation
        # commit; a failed Runtime commit leaves exact metadata to reconcile.
        with self._worker_actor_lock:
            with self.service.store._mutex:
                self.service._assert_mutation_admitted()
                if self.service._require_placement_recovery_owner(identity) != "owner":
                    raise ConflictError("remote credential control requires the Runtime owner")
                if self.local_worker_launcher is not None and not self.local_worker_launcher.is_idle():
                    raise ConflictError("the local Worker owns the shared executor actor")
                if isinstance(body, dict) and body.get("action") in {"provision", "enable"} and self._local_relinquish_pending():
                    raise ConflictError("local Worker relinquish is unresolved")
                return self._remote_credential_control(task_id, body, identity=identity)

    def _remote_credential_binding_matches(self, task_id, binding, qualification, placement):
        """Validate provision/startup against the same resident task binding."""
        return bool(
            isinstance(qualification, dict) and isinstance(placement, dict)
            and qualification.get("task_id") == task_id
            and qualification.get("run_id") == binding.admission_identity.run_id
            and qualification.get("credential_actor") == WORKER_ACTOR
            and qualification.get("binding_digest") == binding.digest()
            and qualification.get("effective_target") == binding.placement.effective_target
            and qualification.get("runtime_session_id") == self.service.runtime_session_id
            and qualification.get("runtime_epoch") == self.service.store._current_runtime_epoch()
            and placement.get("actual") == binding.placement.effective_target
            and placement.get("executor_incarnation") == qualification.get("executor_incarnation")
            and isinstance(placement.get("verification"), dict)
            and placement["verification"].get("method") == "credential_claim"
            and placement["verification"].get("verified") is True
            and placement["verification"].get("evidence_digest") == qualification.get("evidence_digest")
        )

    def _remote_credential_control(self, task_id, body, *, identity):
        """Keep the remote Worker's credential generation in the resident owner.

        The caller must already have authenticated as the exact daemon owner.
        No arbitrary actor, scope, task, or placement can be supplied here.
        """
        from .remote_worker_deployment import deployment_binding_from_task

        if not isinstance(body, dict) or body.get("action") not in {"provision", "enable", "verify", "revoke", "revoke-uncommitted", "begin-drain", "finish-drain"}:
            raise ProtocolError("remote credential action is invalid")
        task = self.service._task_resource(self.service.store.get_task(task_id))
        binding = deployment_binding_from_task(task)
        actor = WORKER_ACTOR
        if body["action"] == "revoke-uncommitted":
            if set(body) != {"action", "qualification", "placement"}:
                raise ProtocolError("uncommitted remote cleanup requires exact qualification and placement")
            qualification, placement = body["qualification"], body["placement"]
            if not self._remote_credential_binding_matches(task_id, binding, qualification, placement):
                raise ConflictError("uncommitted remote cleanup does not match Runtime task binding")
            activation_id = qualification.get("activation_id")
            if not isinstance(activation_id, str) or not activation_id:
                raise ProtocolError("uncommitted remote cleanup activation_id is required")
            history = self.service._remote_activation_history(task_id, activation_id)
            if (self.service._latest_remote_activation(task_id) is not None
                    or any(kind == "task.remote_activation_qualified" for kind, _ in history)
                    or any(kind == "task.remote_activation_revoked" and payload.get("unqualified") is not True
                           for kind, payload in history)):
                raise ConflictError("remote activation may have admitted work; reconcile before cleanup")
            metadata = self.credentials.actor_metadata(actor)
            if metadata is not None and (
                    metadata.get("qualified_activation") != qualification
                    or metadata.get("execution_binding") != placement):
                raise ConflictError("remote credential generation changed before uncommitted cleanup")
            if not any(kind == "task.remote_activation_revoked" for kind, _ in history):
                with self.service.store._transaction():
                    self.service.store._append_event(
                        binding.admission_identity.run_id, task_id,
                        "task.remote_activation_revoked",
                        {"activation_id": activation_id, "unqualified": True},
                    )
            self._cleanup_exact_remote_credential(task_id, activation_id)
            return {"revoked": True}
        if body["action"] in {"begin-drain", "finish-drain"}:
            if set(body) != {"action", "qualification"}:
                raise ProtocolError("remote drain requires exact qualification")
            metadata = self.credentials.actor_metadata(actor)
            qualification = body["qualification"]
            if metadata is not None and metadata.get("qualified_activation") != qualification:
                if body["action"] == "finish-drain":
                    # An old successful finish may lose its reply before a new
                    # generation is installed. Reconcile only its Runtime
                    # marker/tombstone; never touch the current actor token.
                    return self.service.finish_remote_drain(task_id, qualification, identity=identity)
                raise ConflictError("remote drain credential generation changed")
            if body["action"] == "begin-drain":
                if metadata is None:
                    raise ConflictError("remote drain credential generation is unavailable")
                return self.service.begin_remote_drain(task_id, qualification, identity=identity)
            result = self.service.finish_remote_drain(task_id, qualification, identity=identity)
            if result["state"] == "drained":
                self._cleanup_exact_remote_credential(task_id, qualification["activation_id"])
            return result
        if body["action"] == "provision":
            if set(body) != {"action", "qualification", "placement"}:
                raise ProtocolError("remote credential provision has invalid fields")
            qualification, placement = body["qualification"], body["placement"]
            if not isinstance(qualification, dict) or not isinstance(placement, dict):
                raise ProtocolError("remote credential proof is missing")
            if not self._remote_credential_binding_matches(task_id, binding, qualification, placement):
                raise ConflictError("remote credential proof does not match Runtime task binding")
            history = self.service._remote_activation_history(task_id, qualification.get("activation_id"))
            if any(kind == "task.remote_activation_revoked" for kind, _ in history):
                raise ConflictError("remote credential generation is permanently revoked")
            existing = self.credentials.actor_metadata(actor)
            previous = existing.get("qualified_activation") if isinstance(existing, dict) else None
            if existing is None and any(path.exists() for path in self.credentials._paths(actor)):
                raise ConflictError("remote credential generation is unresolved")
            if previous is not None:
                if previous != qualification or existing.get("execution_binding") != placement:
                    raise ConflictError("another remote credential generation is live or unresolved")
                # A lost provision response must not rotate or disable a token
                # already enabled for this exact activation.
                return {"credential_file": str(self.credentials.path_for(actor)), "credential_actor": actor}
            _, path = self.credentials.provision(
                actor, list(WORKER_SCOPES), rotate=True, enabled=False,
                metadata={"execution_binding": placement, "qualified_activation": qualification},
            )
            return {"credential_file": str(path), "credential_actor": actor}
        if set(body) != {"action", "activation_id"} or not isinstance(body["activation_id"], str):
            raise ProtocolError("remote credential activation_id is required")
        metadata = self.credentials.actor_metadata(actor)
        qualification = metadata.get("qualified_activation") if isinstance(metadata, dict) else None
        if body["action"] == "revoke" and qualification is None:
            history = self.service._remote_activation_history(task_id, body["activation_id"])
            if any(kind == "task.remote_activation_revoked" for kind, _ in history):
                self._cleanup_exact_remote_credential(task_id, body["activation_id"])
                return {"revoked": True}
            raise ConflictError("remote credential generation is unavailable")
        if (not isinstance(qualification, dict) or qualification.get("task_id") != task_id
                or qualification.get("activation_id") != body["activation_id"]):
            raise ConflictError("remote credential generation changed")
        placement = metadata.get("execution_binding")
        matched = self.service._remote_activation_matches(
            task_id, {"actor": actor, "qualified_activation": qualification}, placement
        )
        if body["action"] == "enable":
            # Startup authentication precedes the final activation commit.
            # Only the exact current provision may bootstrap; claim/admission
            # still require _remote_activation_matches and verify stays false.
            startup = False
            if not matched and self._remote_credential_binding_matches(task_id, binding, qualification, placement):
                try:
                    expiry = datetime.fromisoformat(qualification["expires_at"].replace("Z", "+00:00"))
                    startup = bool(
                        expiry.tzinfo is not None and expiry > datetime.now(timezone.utc)
                        and all(isinstance(qualification.get(field), str) and qualification[field]
                                for field in ("activation_id", "executor_incarnation"))
                        and metadata.get("actor") == actor
                        and metadata.get("scopes") == sorted(WORKER_SCOPES)
                        and self.service._latest_remote_activation(task_id) is None
                        and not self.service._remote_activation_history(task_id, qualification["activation_id"])
                    )
                except (KeyError, TypeError, ValueError, AttributeError):
                    pass
            if not matched and not startup:
                raise ConflictError("remote credential generation is not current for startup or activation")
            self.credentials.enable_actor(actor)
            return {"enabled": True}
        if body["action"] == "verify":
            return {"fresh": bool(matched)}
        if body["action"] == "revoke":
            latest = self.service._latest_remote_activation(task_id)
            if latest is not None and latest != qualification:
                raise ConflictError("remote activation generation changed before revocation")
            if latest == qualification:
                self.service.revoke_remote_activation(task_id, body["activation_id"], identity=identity)
            elif not any(kind == "task.remote_activation_revoked" for kind, _ in
                         self.service._remote_activation_history(task_id, body["activation_id"])):
                # A startup generation can fail before activation commits.
                # Tombstone its exact identity before deleting files so a lost
                # cleanup reply is reconcilable without blind reprovision.
                with self.service.store._transaction():
                    self.service.store._append_event(
                        binding.admission_identity.run_id, task_id,
                        "task.remote_activation_revoked", {"activation_id": body["activation_id"], "unqualified": True},
                    )
        self._cleanup_exact_remote_credential(task_id, body["activation_id"])
        return {"revoked": True}

    def _replacement_state_path(self):
        return self.support_root / "replacement-state.json"

    def _require_replacement_support_layout(self):
        """Require support custody to remain outside the movable realm tree."""
        try:
            self.support_root.relative_to(self.root)
        except ValueError:
            return
        raise ConflictError(
            "replacement requires support_root outside the active realm root; "
            "pass an explicit sibling support_root so epoch, credentials, and catalog state survive the move"
        )

    def _write_replacement_state(self, *, state, candidate, superseded=None, error=None, retain_superseded=False):
        value = {
            "format_version": 1,
            "state": state,
            "active_root": str(self.root),
            "candidate_root": str(candidate),
            "superseded_root": str(superseded) if superseded else None,
            "retain_superseded": bool(retain_superseded),
            "updated_at": now(),
        }
        if error:
            value["error"] = str(error)
        atomic_json_write(self._replacement_state_path(), value)

    def _cleanup_completed_replacement(self):
        """Remove an unretained old realm left by a completed prior cutover."""
        try:
            state = json.loads(self._replacement_state_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        # Require an explicit no-retention receipt from this version. Older
        # journals predate the field and may refer to intentionally retained
        # recovery data, so they are never auto-cleaned.
        if state.get("state") not in {"complete", "cleanup_pending"} or state.get("retain_superseded") is not False:
            return
        raw_path = state.get("superseded_root")
        if not isinstance(raw_path, str) or not raw_path:
            return
        superseded = Path(raw_path)
        if (
            superseded.parent != self.root.parent
            or not superseded.name.startswith(f".{self.root.name}.superseded-")
            or superseded.is_symlink()
            or not superseded.is_dir()
        ):
            return
        try:
            shutil.rmtree(superseded)
        except OSError:
            return
        state["state"] = "complete"
        state["superseded_root"] = None
        state["updated_at"] = now()
        try:
            atomic_json_write(self._replacement_state_path(), state)
        except OSError:
            pass

    def activate_candidate(self, candidate_root, *, retain_superseded=False):
        """Atomically activate a verified inactive candidate under one owner."""
        if not isinstance(retain_superseded, bool):
            raise ConflictError("retain_superseded must be a boolean")
        if self.service is None or self.httpd is None:
            raise ConflictError("replacement requires a running runtime owner")
        self._require_replacement_support_layout()
        candidate = _authority_path(candidate_root, "restore candidate").resolve()
        if candidate == self.root or candidate.parent != self.root.parent:
            raise ConflictError("replacement candidate must be an inactive sibling of the active realm")
        if candidate.is_symlink() or not candidate.is_dir():
            raise ConflictError("replacement candidate must be an ordinary directory")
        active_identity = capture_parent(self.root)
        candidate_identity = capture_parent(candidate)
        superseded = self.root.parent / f".{self.root.name}.superseded-{uuid.uuid4().hex}"
        moved_old = False
        moved_candidate = False
        replacement_committed = False
        try:
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            first = verify_restore_candidate(candidate, directory_identity=candidate_identity)
            if self.service.realm["id"] != first["manifest"].get("realm", {}).get("id"):
                raise ConflictError("replacement realm identity does not match the live realm")
            self._write_replacement_state(state="verified", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            self.stop()
            self._write_replacement_state(state="owner_stopped", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            second = verify_restore_candidate(candidate, directory_identity=candidate_identity)
            if second["database_sha256"] != first["database_sha256"]:
                raise ConflictError("replacement candidate changed during preparation")
            parent_fd = int(active_identity["_parent_fd"])
            os.rename(self.root.name, superseded.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_old = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="old_quarantined", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            os.rename(candidate.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_candidate = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="candidate_published", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            self.instance_id = uuid.uuid4().hex
            self._start(rotate_credentials=True)
            # The candidate is now serving requests. From this point onward
            # failures may affect bookkeeping or cleanup, never rollback.
            replacement_committed = True
            completion_receipt_pending = False
            try:
                self._write_replacement_state(
                    state="complete",
                    candidate=candidate,
                    superseded=superseded,
                    retain_superseded=retain_superseded,
                )
            except OSError:
                completion_receipt_pending = True
            if retain_superseded:
                pass
            else:
                try:
                    shutil.rmtree(superseded)
                except OSError as cleanup_error:
                    try:
                        self._write_replacement_state(
                            state="cleanup_pending",
                            candidate=candidate,
                            superseded=superseded,
                            error=cleanup_error,
                            retain_superseded=False,
                        )
                    except OSError:
                        # The published candidate is already committed. The
                        # earlier explicit no-retention receipt remains the
                        # startup cleanup instruction if this update hits ENOSPC.
                        pass
                    return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded), "retained": False, "cleanup_pending": True, "cleanup_error": str(cleanup_error)}
                try:
                    self._write_replacement_state(state="complete", candidate=candidate, retain_superseded=False)
                except OSError:
                    # The active realm is committed and the old tree is gone;
                    # never attempt rollback after this point.
                    pass
            return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded) if retain_superseded else None, "retained": bool(retain_superseded), "completion_receipt_pending": completion_receipt_pending}
        except Exception as exc:
            if replacement_committed:
                raise ConflictError(
                    "replacement is active but its completion receipt or cleanup failed; "
                    f"inspect recovery path {superseded}: {exc}"
                ) from exc
            try:
                self.stop()
            except Exception:
                pass
            try:
                parent_fd = int(active_identity["_parent_fd"])
                def present(name):
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        return False
                    return True
                if moved_candidate and not present(candidate.name) and present(self.root.name):
                    os.rename(self.root.name, candidate.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                if moved_old and not present(self.root.name) and present(superseded.name):
                    os.rename(superseded.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
                self._write_replacement_state(state="rolled_back", candidate=candidate, superseded=superseded if present(superseded.name) else None, error=exc, retain_superseded=False)
            except Exception as rollback_exc:
                try:
                    self._write_replacement_state(
                        state="rollback_failed",
                        candidate=candidate,
                        superseded=superseded,
                        error=rollback_exc,
                        retain_superseded=False,
                    )
                except Exception:
                    pass
                raise ConflictError(
                    "replacement failed and rollback failed; recovery roots are "
                    f"candidate={candidate}, superseded={superseded}; cause={rollback_exc}"
                ) from exc
            self.instance_id = uuid.uuid4().hex
            try:
                self._start(rotate_credentials=True)
            except Exception:
                pass
            raise
        finally:
            close_pinned(candidate_identity)
            close_pinned(active_identity)

    def _acquire_offline_custody(self):
        """Fence an active path without admitting or opening its database."""
        if self.root.is_symlink() or not self.root.is_dir():
            raise ConflictError("damaged active root must be an ordinary directory")
        lock_path = self.root / "owner.lock"
        if lock_path.is_symlink():
            raise ConflictError("damaged active owner lock must not be a symlink")
        handle = lock_path.open("a+")
        try:
            os.fchmod(handle.fileno(), 0o600)
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except Exception:
            handle.close()
            raise ConflictError("active realm is already owned; offline replacement refused")

    @staticmethod
    def _release_offline_custody(handle):
        if handle is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def replace_from_backup(self, backup_root, *, retain_superseded=False):
        """Replace an unadmittable active root through an offline fence.

        The backup is verified first and the active database is never opened.
        The active tree remains available until the materialized candidate has
        started successfully. After success it is removed unless explicitly
        retained; failed rollback keeps the recovery roots and reports paths.
        """
        if self.service is not None or self.httpd is not None:
            raise ConflictError("offline replacement requires a stopped runtime")
        if not isinstance(retain_superseded, bool):
            raise ConflictError("retain_superseded must be a boolean")
        self._require_replacement_support_layout()
        backup = _authority_path(backup_root, "backup").resolve()
        # This is deliberately independent of active-root admission.
        verify_backup(backup)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ConflictError("damaged active root must be retained as an ordinary directory")
        candidate = self.root.parent / f".{self.root.name}.candidate-{os.getpid()}-{time.time_ns()}"
        try:
            restore_backup(backup, candidate)
        except Exception:
            if candidate.exists() and not candidate.is_symlink():
                shutil.rmtree(candidate, ignore_errors=True)
            raise
        candidate_identity = capture_parent(candidate)
        active_identity = capture_parent(self.root)
        custody = None
        superseded = self.root.parent / f".{self.root.name}.superseded-{uuid.uuid4().hex}"
        moved_old = False
        moved_candidate = False
        replacement_committed = False
        try:
            verify_restore_candidate(candidate, directory_identity=candidate_identity)
            custody = self._acquire_offline_custody()
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            self._write_replacement_state(state="offline_verified", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            parent_fd = int(active_identity["_parent_fd"])
            os.rename(self.root.name, superseded.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_old = True
            os.fsync(parent_fd)
            os.rename(candidate.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_candidate = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="offline_candidate_published", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            self._release_offline_custody(custody)
            custody = None
            self.instance_id = uuid.uuid4().hex
            self._start(rotate_credentials=True)
            # The candidate is now serving requests. From this point onward
            # failures may affect bookkeeping or cleanup, never rollback.
            replacement_committed = True
            completion_receipt_pending = False
            try:
                self._write_replacement_state(state="complete", candidate=candidate, superseded=superseded, retain_superseded=retain_superseded)
            except OSError:
                completion_receipt_pending = True
            if not retain_superseded:
                try:
                    shutil.rmtree(superseded)
                except OSError as cleanup_error:
                    try:
                        self._write_replacement_state(
                            state="cleanup_pending",
                            candidate=candidate,
                            superseded=superseded,
                            error=cleanup_error,
                            retain_superseded=False,
                        )
                    except OSError:
                        # The published candidate is already committed. The
                        # earlier explicit no-retention receipt remains the
                        # startup cleanup instruction if this update hits ENOSPC.
                        pass
                    return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded), "retained": False, "cleanup_pending": True, "cleanup_error": str(cleanup_error), "offline": True}
                try:
                    self._write_replacement_state(state="complete", candidate=candidate, retain_superseded=False)
                except OSError:
                    pass
            return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded) if retain_superseded else None, "retained": bool(retain_superseded), "completion_receipt_pending": completion_receipt_pending, "offline": True}
        except Exception as exc:
            if replacement_committed:
                raise ConflictError(
                    "replacement is active but its completion receipt or cleanup failed; "
                    f"inspect recovery path {superseded}: {exc}"
                ) from exc
            try:
                self.stop()
            except Exception:
                pass
            rollback_error = None
            try:
                parent_fd = int(active_identity["_parent_fd"])
                def present(name):
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        return False
                    return True
                if moved_candidate and not present(candidate.name) and present(self.root.name):
                    os.rename(self.root.name, candidate.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                if moved_old and not present(self.root.name) and present(superseded.name):
                    os.rename(superseded.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
                self._write_replacement_state(state="rolled_back", candidate=candidate, superseded=None, error=exc, retain_superseded=False)
            except Exception as rollback_exc:
                rollback_error = rollback_exc
            finally:
                self._release_offline_custody(custody)
                custody = None
            if rollback_error is None:
                if candidate.exists() and not candidate.is_symlink():
                    try:
                        shutil.rmtree(candidate)
                    except OSError as cleanup_error:
                        raise ConflictError(
                            f"replacement was rolled back; temporary candidate cleanup failed at {candidate}: {cleanup_error}"
                        ) from exc
            else:
                try:
                    self._write_replacement_state(
                        state="rollback_failed",
                        candidate=candidate,
                        superseded=superseded,
                        error=rollback_error,
                        retain_superseded=False,
                    )
                except Exception:
                    pass
                raise ConflictError(
                    "replacement failed and rollback failed; recovery roots are "
                    f"candidate={candidate}, superseded={superseded}; cause={rollback_error}"
                ) from exc
            raise
        finally:
            if custody is not None:
                self._release_offline_custody(custody)
            close_pinned(candidate_identity)
            close_pinned(active_identity)

    def stop(self):
        # Fence bearer authority and authenticated acceptance before any
        # potentially blocking child cleanup. The launcher's abort wrapper is
        # bounded independently of the Worker's configured RPC timeout.
        worker_handles = []
        if self.httpd is not None:
            self.httpd.accepting_authenticated_requests = False
        if self.local_worker_launcher is not None:
            worker_handles = self.local_worker_launcher.begin_shutdown()
        if self.service is not None:
            try:
                self.catalog.revoke_readiness(self.service.realm["id"], instance_id=self.instance_id, reason="runtime_stopped")
            except Exception:
                pass
        self.discovery.clear(self.instance_id)
        self._shutdown_http()
        if self.local_worker_launcher is not None:
            self.local_worker_launcher.finish_shutdown(worker_handles)
            self.local_worker_launcher = None
        if self.service:
            self.service.close()
            self.service = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
