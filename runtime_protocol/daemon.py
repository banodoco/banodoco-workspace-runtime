from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from .auth import CredentialStore
from .catalog import LiveDiscovery, RealmCatalog, process_birth_identity
from .backup import restore_backup, verify_backup, verify_restore_candidate
from .dirfd import capture_parent, close_pinned, validate_parent
from .errors import ConflictError, RuntimeErrorBase
from .handoff_recovery import (
    recover_aborted_predecessor_resolution,
    validate_pending_adopter_request,
)
from .lifecycle import inspect_interruption_state, interruption_fence
from .orderly_handoff import HandoffRecord, digest
from .server import RuntimeHTTPServer, RuntimeHandler, registration_body_digest
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
_HANDOFF_REGISTRATION_PATHS = ("/v1/capabilities", "/v1/executors")

_BOUNDED_RUNTIME_HANDOFF_ERRORS = {
    "cannot establish runtime interruption safety: task/attempt tables are missing":
        "interruption_schema_missing",
    "credential generation is unreadable": "credential_generation_unreadable",
    "credential generation marker is invalid": "credential_generation_marker_invalid",
    "credential generation is inconsistent": "credential_generation_inconsistent",
    "handoff_id is required": "handoff_id_missing",
}


def _handoff_stage_error(exc: RuntimeErrorBase, stage: str) -> RuntimeErrorBase:
    """Add one credential-safe phase/code without exposing refusal details."""

    details = dict(exc.details) if isinstance(exc.details, Mapping) else {}
    details.setdefault(
        "handoff_error_code",
        _BOUNDED_RUNTIME_HANDOFF_ERRORS.get(str(exc), exc.code),
    )
    details.setdefault("handoff_stage", stage)
    return type(exc)(exc.message, details=details)


def handoff_registration_admission(registered_state: Mapping[str, object]):
    """Validate Astrid's exact deliberate-registration preview.

    Runtime rederives every canonical body digest.  The allowlist is evidence,
    never trusted input, and an empty route list means deny that route.
    """

    actor = registered_state.get("registration_actor")
    bodies = registered_state.get("registration_bodies")
    allowlist = registered_state.get("registration_allowlist")
    if actor != WORKER_ACTOR or not isinstance(bodies, Mapping) or not isinstance(allowlist, list):
        raise ConflictError("handoff registered state lacks exact registration admission")
    if set(bodies) != set(_HANDOFF_REGISTRATION_PATHS):
        raise ConflictError("handoff registration body routes are invalid")
    normalized: dict[str, list[object]] = {}
    expected = []
    for path in _HANDOFF_REGISTRATION_PATHS:
        values = bodies[path]
        if not isinstance(values, list):
            raise ConflictError("handoff registration bodies must be arrays")
        normalized[path] = list(values)
        expected.append({
            "method": "POST",
            "path": path,
            "actor": actor,
            "body_sha256": sorted(registration_body_digest(item) for item in values),
        })
    expected.sort(key=lambda item: (item["path"], item["actor"]))
    if allowlist != expected:
        raise ConflictError("handoff registration allowlist disagrees with canonical bodies")
    return str(actor), normalized


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

    def __init__(self, root, *, support_root=None, export_root=None, display_name="Workspace", host="127.0.0.1", port=0, realm_id=None, owner_lock=None, bootstrap_token_file=None, reboot_executor=None, reboot_allowlist=None, production_worker_credentials=False, admission_timeout=None, local_worker_profiles=None, local_worker_preparer=None, local_worker_inspector=None, inherited_listener_fd=None, handoff_registration_actor=None, handoff_registration_bodies=None, handoff_predecessor_active_ref_digest=None, handoff_predecessor_old_owner=None, handoff_predecessor_old_runtime=None, handoff_id=None, handoff_record_path=None, handoff_record_path_raw=None, handoff_record_digest=None, handoff_expected_listener=None):
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
        # Retain the exact caller-supplied adopter tuple.  `_start` classifies
        # raw presence, type and lexical form before locks or support mutation.
        self.inherited_listener_fd = inherited_listener_fd
        self.handoff_registration_actor = (
            str(handoff_registration_actor) if handoff_registration_actor else None
        )
        self.handoff_registration_bodies = dict(handoff_registration_bodies or {})
        self.handoff_pending = self.inherited_listener_fd is not None
        self.handoff_predecessor_active_ref_digest = handoff_predecessor_active_ref_digest
        self.handoff_predecessor_old_owner = handoff_predecessor_old_owner
        self.handoff_predecessor_old_runtime = handoff_predecessor_old_runtime
        self.handoff_id = handoff_id
        self.handoff_record_path = handoff_record_path
        self.handoff_record_path_raw = handoff_record_path_raw
        self.handoff_record_digest = handoff_record_digest
        self.handoff_expected_listener = handoff_expected_listener
        self._handoff_finalized_id: str | None = None
        self._handoff_final_ack: dict[str, object] | None = None
        self._handoff_ready_surface_id: str | None = None
        self._handoff_claim_arm: dict[str, object] | None = None
        self._handoff_claims_id: str | None = None
        self._last_handoff_cleanup_proof: dict[str, object] | None = None
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
        return self._start(rotate_credentials=False)

    def _catalog_owner_valid(self, proof):
        return self.service is not None and self.service.validate_catalog_admission(proof)

    def _provision_credentials(self, *, rotate=False):
        self.credentials = CredentialStore(_authority_path(self.support_root / "credentials", "credential root"))
        owner_scopes = ["admin", "handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write", "worker:execute", "worker:register", "credentials:provision"]
        self.token, self.credential_path = self.credentials.provision("owner", owner_scopes, rotate=rotate)
        if self.local_worker_profiles:
            # The two-phase owner path issues this actor only after independent
            # process verification. I-06b supplies the parked Worker adapter.
            self.worker_token = None
            self.worker_credential_path = self.credentials.path_for(WORKER_ACTOR)
        else:
            # A new production owner must never inherit a receipt-less legacy
            # Worker bearer. Rotate the single CredentialStore generation
            # before HTTP starts; fixture-mode credentials retain their
            # historical behavior for in-process tests.
            existing_worker = self.credentials.actor_metadata(WORKER_ACTOR)
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

    def _http_server(self):
        if self.inherited_listener_fd is None:
            return RuntimeHTTPServer((self.host, self.port), RuntimeHandler)
        descriptor = self.inherited_listener_fd
        self.inherited_listener_fd = None
        os.set_inheritable(descriptor, False)
        if os.get_inheritable(descriptor):
            raise ConflictError("inherited Runtime listener is not close-on-exec")
        inherited = socket.socket(fileno=descriptor)
        try:
            address = inherited.getsockname()
            if not isinstance(address, tuple) or len(address) < 2:
                raise ConflictError("inherited Runtime listener address is invalid")
            observed_host = str(address[0])
            if observed_host not in {"127.0.0.1", "::1"}:
                raise ConflictError("inherited Runtime listener is not loopback")
            server = RuntimeHTTPServer((self.host, self.port), RuntimeHandler, bind_and_activate=False)
            server.socket.close()
            server.socket = inherited
            server.server_address = address
            server.server_name = observed_host
            server.server_port = int(address[1])
            return server
        except BaseException:
            inherited.close()
            raise

    def _publish_discovery(self, *, worker_pending: bool) -> None:
        birth_id = process_birth_identity()
        self.discovery.publish(
            version=1,
            endpoint=self.endpoint,
            pid=os.getpid(),
            process_birth_id=birth_id,
            runtime_instance_id=self.instance_id,
            active_realm=self.service.realm["id"],
            realm_root=str(self.root),
            protocol_version="workspace.v1",
            schema_version="workspace-schema-v1",
            coordinator_epoch=self.instance_id,
            credential_file=str(self.credential_path),
            worker_credential_file=str(self.worker_credential_path),
            worker_credential_pending=bool(worker_pending),
            worker_actor=WORKER_ACTOR,
            worker_scopes=list(WORKER_SCOPES),
        )

    def runtime_identity(self) -> dict[str, object]:
        if self.service is None or self.httpd is None:
            raise ConflictError("Runtime owner is not active")
        health = self.service.health()
        return {
            "endpoint": self.endpoint,
            "protocol": health["protocol"],
            "schema_digest": health["schema_digest"],
            "runtime_epoch": health["runtime_epoch"],
            "runtime_instance_id": self.instance_id,
            "runtime_session_id": health["runtime_session_id"],
        }

    def _start(self, *, rotate_credentials=False):
        # Direct starts use the same bootstrap -> coordinator recovery order as
        # the installed launcher, before active-owner or request-pointer checks.
        required_pending_binding = (
            self.inherited_listener_fd,
            self.handoff_id,
            self.handoff_record_path,
            self.handoff_record_path_raw,
            self.handoff_record_digest,
            self.handoff_predecessor_old_owner,
            self.handoff_predecessor_old_runtime,
            self.handoff_expected_listener,
        )
        required_present = tuple(value is not None for value in required_pending_binding)
        predecessor = self.handoff_predecessor_active_ref_digest
        if (
            any(required_present) and not all(required_present)
        ) or (
            predecessor is not None and not all(required_present)
        ):
            raise ConflictError("pending adopter binding tuple is incomplete")
        if all(required_present):
            (
                fd, handoff_id, record_path, record_path_raw, record_digest,
                old_owner, old_runtime, expected_listener,
            ) = required_pending_binding
            expected_record_path = (
                self.support_root / f"orderly-handoff-record-{handoff_id}.json"
                if isinstance(handoff_id, str) else None
            )
            if (
                isinstance(fd, bool)
                or not isinstance(fd, int)
                or fd <= 2
                or not isinstance(handoff_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", handoff_id)
                is None
                or not isinstance(record_path, Path)
                or not isinstance(record_path_raw, str)
                or not record_path_raw
                or not os.path.isabs(record_path_raw)
                or os.path.normpath(record_path_raw) != record_path_raw
                or str(record_path) != record_path_raw
                or not record_path.is_absolute()
                or record_path != expected_record_path
                or any(part in {".", ".."} for part in record_path.parts)
                or not isinstance(record_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", record_digest) is None
                or (
                    predecessor is not None
                    and (
                        not isinstance(predecessor, str)
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", predecessor) is None
                    )
                )
                or type(old_owner) is not dict
                or set(old_owner) != {"pid", "birth_id"}
                or isinstance(old_owner.get("pid"), bool)
                or not isinstance(old_owner.get("pid"), int)
                or old_owner["pid"] <= 0
                or not isinstance(old_owner.get("birth_id"), str)
                or not old_owner["birth_id"]
                or old_owner["birth_id"] != old_owner["birth_id"].strip()
                or type(old_runtime) is not dict
                or type(expected_listener) is not tuple
                or len(expected_listener) != 2
                or expected_listener[0] not in {"127.0.0.1", "::1"}
                or isinstance(expected_listener[1], bool)
                or not isinstance(expected_listener[1], int)
                or not (1 <= expected_listener[1] <= 65535)
            ):
                raise ConflictError("pending adopter binding tuple is invalid")
            try:
                observed_fd = os.fstat(fd)
                duplicated = os.dup(fd)
            except OSError as exc:
                raise ConflictError("pending adopter listener descriptor is invalid") from exc
            if (
                not stat.S_ISSOCK(observed_fd.st_mode)
                or observed_fd.st_uid != os.getuid()
            ):
                os.close(duplicated)
                raise ConflictError("pending adopter listener authority is invalid")
            listener = socket.socket(fileno=duplicated)
            try:
                address = listener.getsockname()
                try:
                    accepting = listener.getsockopt(
                        socket.SOL_SOCKET, socket.SO_ACCEPTCONN
                    ) == 1
                except OSError:
                    # Darwin's Python exposes SO_ACCEPTCONN but the kernel may
                    # reject that query.  A bounded nonblocking accept probe
                    # distinguishes a listener (EAGAIN) from an unconnected or
                    # connected non-listener (EINVAL/ENOTSUP).  Restore the
                    # shared file-description flags immediately afterwards.
                    if fcntl is None:
                        accepting = False
                    else:
                        flags = fcntl.fcntl(duplicated, fcntl.F_GETFL)
                        try:
                            fcntl.fcntl(duplicated, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                            try:
                                accepted, _peer = listener.accept()
                            except BlockingIOError:
                                accepting = True
                            except OSError:
                                accepting = False
                            else:
                                accepted.close()
                                accepting = True
                        finally:
                            fcntl.fcntl(duplicated, fcntl.F_SETFL, flags)
                if (
                    listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                    != socket.SOCK_STREAM
                    or not accepting
                    or not isinstance(address, tuple)
                    or len(address) < 2
                    or (str(address[0]), int(address[1])) != expected_listener
                ):
                    raise ConflictError("pending adopter listener authority is invalid")
            except OSError as exc:
                raise ConflictError("pending adopter listener authority is invalid") from exc
            finally:
                listener.close()
            validate_pending_adopter_request(
                self.support_root,
                handoff_id=self.handoff_id,
                record_path=self.handoff_record_path,
                record_digest=self.handoff_record_digest,
                predecessor_active_ref_digest=(
                    self.handoff_predecessor_active_ref_digest
                ),
                old_owner=self.handoff_predecessor_old_owner,
                old_runtime=self.handoff_predecessor_old_runtime,
            )
            self._assert_active_adoption_start_allowed()
        else:
            try:
                recover_aborted_predecessor_resolution(self.support_root)
            except ConflictError as exc:
                raise ConflictError(
                    "an orderly Runtime handoff is pending audit; "
                    "operator recovery is required"
                ) from exc
            self._assert_active_adoption_start_allowed()
        cleanup_uncertain = self.support_root / "orderly-handoff-cleanup-uncertain.json"
        if cleanup_uncertain.exists() or cleanup_uncertain.is_symlink():
            raise ConflictError(
                "previous orderly Worker cleanup is uncertain; operator recovery is required"
            )
        pending_handoff = self.support_root / "orderly-handoff-request.json"
        if not self.handoff_pending and (
            pending_handoff.exists() or pending_handoff.is_symlink()
        ):
            raise ConflictError(
                "an orderly Runtime handoff is pending audit; operator recovery is required"
            )
        epoch_floor = self._read_epoch_floor()
        self.service = RuntimeService(self.root, display_name=self.display_name, realm_id=self.realm_id, support_root=self.support_root, export_root=self.export_root, reboot_executor=self.reboot_executor, reboot_allowlist=self.reboot_allowlist, runtime_epoch_floor=epoch_floor, admission_timeout=self.admission_timeout)
        self.service.set_readiness_callback(self._revoke_readiness)
        self.catalog.bind_owner(self._catalog_owner_valid)
        self._provision_credentials(rotate=rotate_credentials)
        if self.local_worker_profiles:
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
        self.httpd = self._http_server()
        self.httpd.runtime = self.service
        self.httpd.daemon_runtime = self
        self.httpd.credentials = self.credentials
        if self.handoff_pending:
            self.httpd.set_admission_mode(
                "handoff_pending",
                registration_actor=self.handoff_registration_actor or WORKER_ACTOR,
                registration_bodies=self.handoff_registration_bodies,
            )
        owner = self.service.catalog_admission(self.instance_id)
        # Persist the observed epoch before readiness publication.  A restored
        # older database can therefore never reuse an epoch from its snapshot.
        self._write_epoch_floor(owner["runtime_epoch"])
        self.catalog.register(
            realm_id=self.service.realm["id"],
            display_name=self.service.realm["display_name"],
            data_root=str(self.root),
            owner=owner,
            runtime_epoch=owner["runtime_epoch"],
            runtime_instance_id=self.instance_id,
            readiness="not_ready" if self.handoff_pending else "ready",
            readiness_reason="worker_handoff_pending" if self.handoff_pending else None,
        )
        birth_id = process_birth_identity()
        if self.owner_lock:
            atomic_json_write(self.owner_lock, {"pid": os.getpid(), "process_birth_id": birth_id, "runtime_instance_id": self.instance_id, "realm_id": self.service.realm["id"], "realm_root": str(self.root)})
        self._publish_discovery(
            worker_pending=bool(self.local_worker_profiles) or self.handoff_pending
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="banodoco-runtime", daemon=True)
        self.thread.start()
        return self

    def _strict_owner_json(self, path: Path) -> dict[str, object] | None:
        if not path.exists() and not path.is_symlink():
            return None
        try:
            observed = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(observed.st_mode):
                raise ConflictError("orderly handoff authority file is invalid")
            if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600:
                raise ConflictError("orderly handoff authority file is not owner-only")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConflictError("orderly handoff authority file is unavailable") from exc
        if not isinstance(value, dict):
            raise ConflictError("orderly handoff authority file is invalid")
        return value

    def _assert_active_adoption_start_allowed(self) -> None:
        """Defend direct daemon starts before any support-state mutation."""

        path = self.support_root / "orderly-handoff-adopted-owner.json"
        active = self._strict_owner_json(path)
        if active is None:
            if self.handoff_pending and self.handoff_predecessor_active_ref_digest is not None:
                raise ConflictError("handoff predecessor owner reference is unavailable")
            return
        required = {
            "version", "state", "handoff_id", "record_path", "record_digest",
            "pid", "birth_id", "runtime_instance_id", "reference_digest",
        }
        unsigned = {key: item for key, item in active.items() if key != "reference_digest"}
        try:
            record_path = Path(str(active["record_path"]))
            pid = int(active["pid"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ConflictError("active adopted owner reference is invalid") from exc
        if (
            set(active) != required
            or active.get("version") != 1
            or active.get("state") != "ADOPTED"
            or active.get("reference_digest") != digest(unsigned)
            or not record_path.is_absolute()
            or record_path.parent != self.support_root
            or record_path.name != f"orderly-handoff-record-{active.get('handoff_id')}.json"
        ):
            raise ConflictError("active adopted owner reference is invalid")
        record = HandoffRecord(record_path).read()
        if (
            record.get("state") != "ADOPTED"
            or record.get("handoff_id") != active.get("handoff_id")
            or record.get("record_digest") != active.get("record_digest")
        ):
            raise ConflictError("active adopted owner tombstone is invalid")
        if self.handoff_pending:
            old_owner = self.handoff_predecessor_old_owner
            if (
                active.get("reference_digest")
                != self.handoff_predecessor_active_ref_digest
                or not isinstance(old_owner, Mapping)
                or old_owner.get("pid") != pid
                or old_owner.get("birth_id") != active.get("birth_id")
            ):
                raise ConflictError("handoff predecessor owner binding is invalid")
            return
        observed_birth = process_birth_identity(pid)
        if observed_birth == active.get("birth_id"):
            raise ConflictError("the adopted Runtime owner is already active")
        atomic_json_write(
            self.support_root / "orderly-handoff-cleanup-uncertain.json",
            {
                "version": 1,
                "state": "operator_audit_required",
                "reason": "unexpected_post_adopted_owner_loss",
                "handoff_id": active.get("handoff_id"),
                "record_path": str(record_path),
                "record_digest": active.get("record_digest"),
                "active_reference_digest": active.get("reference_digest"),
                "owner_b_pid": pid,
                "owner_b_birth_id": active.get("birth_id"),
                "runtime_instance_id": active.get("runtime_instance_id"),
            },
        )
        raise ConflictError(
            "the adopted Runtime owner was lost; operator recovery is required"
        )

    def begin_orderly_worker_handoff(self, common: Mapping[str, object]) -> dict[str, object]:
        """Pause, fence and export A's Worker and bound HTTP listener."""

        if self.local_worker_launcher is None or self.httpd is None or self.service is None:
            raise ConflictError("orderly Worker handoff requires an active local Worker Runtime")
        try:
            first_audit = inspect_interruption_state(self.root)
        except RuntimeErrorBase as exc:
            raise _handoff_stage_error(exc, "interruption_audit") from exc
        if not first_audit["safe"]:
            # This is the expected, non-mutating refusal path.  Return the
            # typed result before reading Worker source facts or preparing,
            # fencing, and exporting the live graph so the owner-side CLI can
            # send its authenticated ``refused_active_work`` frame.  Raising
            # here closes that private channel and makes the coordinator see
            # only a misleading transfer EOF.
            return {"state": "active_work", "audit": first_audit}
        try:
            facts = self.local_worker_launcher.orderly_handoff_source_facts()
        except RuntimeErrorBase as exc:
            raise _handoff_stage_error(exc, "handoff_source_facts") from exc
        request = {
            **dict(common),
            "command": "handoff_prepare",
            "old_runtime": self.runtime_identity(),
            "receipt_evidence_digest": facts["receipt"]["evidence_digest"],
            "credential_generation": facts["credential_generation"],
        }
        try:
            prepared = self.local_worker_launcher.prepare_orderly_handoff(request)
        except RuntimeErrorBase as exc:
            raise _handoff_stage_error(exc, "handoff_prepare") from exc
        if prepared["state"] == "active_work":
            return {"state": "active_work", "audit": first_audit, **prepared}
        handoff_id = str(common["handoff_id"])
        failure_stage = "handoff_fence"
        try:
            with interruption_fence(self.root) as fenced_audit:
                fenced = self.local_worker_launcher.fence_orderly_handoff(handoff_id)
                self.httpd.set_admission_mode("closed")
            failure_stage = "handoff_export"
            worker_fd, export = self.local_worker_launcher.export_orderly_handoff(handoff_id)
            listener_fd = os.dup(self.httpd.socket.fileno())
            os.set_inheritable(listener_fd, False)
            if os.get_inheritable(listener_fd):
                os.close(worker_fd)
                os.close(listener_fd)
                raise ConflictError("exported Runtime listener is inheritable")
            return {
                "state": "PREPARED",
                "handoff_id": handoff_id,
                "first_audit": first_audit,
                "fenced_audit": fenced_audit,
                "fenced": fenced,
                "export": export,
                "worker_control_fd": worker_fd,
                "listener_fd": listener_fd,
                "old_runtime": request["old_runtime"],
            }
        except RuntimeErrorBase as exc:
            self.local_worker_launcher.cancel_orderly_handoff(
                handoff_id, reason_code="runtime_prepare_failed"
            )
            if self.httpd is not None:
                self.httpd.set_admission_mode("ready")
            raise _handoff_stage_error(exc, failure_stage) from exc
        except BaseException:
            self.local_worker_launcher.cancel_orderly_handoff(
                handoff_id, reason_code="runtime_prepare_failed"
            )
            if self.httpd is not None:
                self.httpd.set_admission_mode("ready")
            raise

    def release_orderly_worker_handoff(self, handoff_id: str) -> None:
        """Close A authority after the coordinator has accepted both FDs."""

        if self.local_worker_launcher is None:
            raise ConflictError("orderly Worker handoff launcher is unavailable")
        self.local_worker_launcher.release_exported_handoff(handoff_id)
        self.local_worker_launcher = None
        if self.service is not None:
            try:
                self.catalog.revoke_readiness(
                    self.service.realm["id"],
                    instance_id=self.instance_id,
                    reason="worker_handoff_exported",
                )
            except Exception:
                pass
        self.discovery.clear(self.instance_id)
        self._shutdown_http()
        if self.service is not None:
            self.service.close()
            self.service = None

    def seal_orderly_worker_handoff(
        self, handoff_id: str, request: Mapping[str, object]
    ) -> dict[str, object]:
        """Require Worker verification of the durable export seal before release."""

        if self.local_worker_launcher is None:
            raise ConflictError("orderly Worker handoff launcher is unavailable")
        return self.local_worker_launcher.seal_orderly_handoff(handoff_id, request)

    def cancel_orderly_worker_handoff(self, handoff_id: str, *, reason_code: str) -> None:
        """Restore A only while it still owns every original descriptor."""

        if self.local_worker_launcher is None or self.httpd is None:
            raise ConflictError("owner A can no longer roll back the orderly handoff")
        self.local_worker_launcher.cancel_orderly_handoff(
            handoff_id, reason_code=reason_code
        )
        self.httpd.set_admission_mode("ready")

    def finalize_orderly_handoff(self, handoff_id: str) -> dict[str, object]:
        """Obtain the terminal Worker/host acknowledgement while claims stay closed."""

        if not self.handoff_pending or self.local_worker_launcher is None:
            raise ConflictError("Runtime is not awaiting an orderly Worker handoff")
        if self._handoff_finalized_id not in (None, handoff_id):
            raise ConflictError("Runtime finalized a different orderly handoff")
        if self._handoff_finalized_id == handoff_id:
            if not isinstance(self._handoff_final_ack, dict):
                raise ConflictError("Runtime final acknowledgement cache is unavailable")
            return dict(self._handoff_final_ack)
        acknowledgement = self.local_worker_launcher.finalize_orderly_handoff(handoff_id)
        if not isinstance(acknowledgement, dict):
            raise ConflictError("Runtime final acknowledgement is invalid")
        self._handoff_finalized_id = handoff_id
        self._handoff_final_ack = dict(acknowledgement)
        return dict(acknowledgement)

    def publish_orderly_handoff_surfaces(self, handoff_id: str) -> None:
        """Publish B's ready catalog/discovery surfaces with HTTP claims still closed."""

        if (
            not self.handoff_pending
            or self.httpd is None
            or self.service is None
            or self._handoff_finalized_id != handoff_id
        ):
            raise ConflictError("Runtime handoff is not final-acknowledged")
        if self._handoff_ready_surface_id not in (None, handoff_id):
            raise ConflictError("Runtime published a different orderly handoff")
        owner = self.service.catalog_admission(self.instance_id)
        self.catalog.register(
            realm_id=self.service.realm["id"],
            display_name=self.service.realm["display_name"],
            data_root=str(self.root),
            owner=owner,
            runtime_epoch=owner["runtime_epoch"],
            runtime_instance_id=self.instance_id,
            readiness="ready",
        )
        self._publish_discovery(worker_pending=False)
        # Registration-only admission remains in force.  The durable record
        # must reach ADOPTED before the final claim gate can open.
        if self.httpd.admission_snapshot()[0] != "handoff_pending":
            raise ConflictError("Runtime claim admission opened before durable adoption")
        self._handoff_ready_surface_id = handoff_id

    def arm_orderly_handoff_claims(
        self, handoff_id: str, finalizing_record: Mapping[str, object]
    ) -> dict[str, object]:
        """Validate ready surfaces and bind the exact pre-ADOPTED generation."""

        existing_arm = self._handoff_claim_arm
        if isinstance(existing_arm, Mapping):
            if (
                existing_arm.get("handoff_id") == handoff_id
                and existing_arm.get("finalizing_record_digest")
                == finalizing_record.get("record_digest")
                and existing_arm.get("runtime_instance_id") == self.instance_id
                and existing_arm.get("pid") == os.getpid()
                and existing_arm.get("birth_id") == process_birth_identity()
            ):
                return dict(existing_arm)
            raise ConflictError("Runtime claim gate is armed for a different generation")
        if (
            not self.handoff_pending
            or self.httpd is None
            or self.service is None
            or self._handoff_finalized_id != handoff_id
            or self._handoff_ready_surface_id != handoff_id
        ):
            raise ConflictError("Runtime handoff publication is incomplete")
        finalization = finalizing_record.get("finalization")
        final_ack = (
            finalization.get("final_ack") if isinstance(finalization, Mapping) else None
        )
        adopter = finalizing_record.get("adopter")
        new_owner = finalizing_record.get("new_owner")
        expected_birth = process_birth_identity()
        if (
            finalizing_record.get("state") != "FINALIZING"
            or finalizing_record.get("handoff_id") != handoff_id
            or not isinstance(finalization, Mapping)
            or set(finalization) != {"final_ack", "ready_surfaces"}
            or finalization.get("ready_surfaces") is not True
            or not isinstance(final_ack, Mapping)
            or set(final_ack) != {
                "request_digest", "worker_ack_digest", "host_ack_digest",
            }
            or any(
                not isinstance(value, str)
                or not value.startswith("sha256:")
                or len(value) != 71
                or any(character not in "0123456789abcdef" for character in value[7:])
                for value in final_ack.values()
            )
            or not isinstance(adopter, Mapping)
            or not isinstance(new_owner, Mapping)
            or adopter.get("pid") != os.getpid()
            or adopter.get("birth_id") != expected_birth
            or adopter.get("runtime_instance_id") != self.instance_id
            or new_owner.get("pid") != os.getpid()
            or new_owner.get("birth_id") != expected_birth
            or new_owner.get("runtime_instance_id") != self.instance_id
            or new_owner.get("runtime") != self.runtime_identity()
        ):
            raise ConflictError("finalizing owner does not match Runtime B")
        catalog = self.catalog.read()
        selected = next(
            (
                row for row in catalog.get("realms", [])
                if row.get("realm_id") == self.service.realm["id"]
            ),
            None,
        )
        try:
            discovery = self.discovery.read()
        except Exception as exc:
            raise ConflictError("Runtime handoff discovery is unavailable") from exc
        if (
            not isinstance(selected, Mapping)
            or selected.get("readiness") != "ready"
            or selected.get("runtime_instance_id") != self.instance_id
            or discovery.get("runtime_instance_id") != self.instance_id
            or discovery.get("pid") != os.getpid()
            or discovery.get("process_birth_id") != expected_birth
            or discovery.get("worker_credential_pending") is not False
        ):
            raise ConflictError("Runtime handoff ready surfaces do not match owner B")
        arm = {
            "handoff_id": handoff_id,
            "finalizing_record_digest": finalizing_record.get("record_digest"),
            "runtime_instance_id": self.instance_id,
            "pid": os.getpid(),
            "birth_id": expected_birth,
        }
        self._handoff_claim_arm = arm
        return dict(arm)

    def open_orderly_handoff_claims(
        self, handoff_id: str, adopted_record: Mapping[str, object]
    ) -> None:
        """Open claims only after durable ADOPTED matches the armed generation."""

        arm = self._handoff_claim_arm
        if (
            not self.handoff_pending
            or self.httpd is None
            or self._handoff_claims_id not in (None, handoff_id)
            or not isinstance(arm, Mapping)
            or adopted_record.get("state") != "ADOPTED"
            or adopted_record.get("handoff_id") != handoff_id
            or adopted_record.get("publication_predecessor_digest")
            != arm.get("finalizing_record_digest")
            or arm.get("handoff_id") != handoff_id
            or arm.get("runtime_instance_id") != self.instance_id
            or arm.get("pid") != os.getpid()
            or arm.get("birth_id") != process_birth_identity()
        ):
            raise ConflictError("durable ADOPTED record does not match the armed claim gate")
        self.httpd.set_admission_mode("ready")
        self.handoff_pending = False
        self._handoff_claims_id = handoff_id
        self._handoff_claim_arm = None

    def latch_orderly_handoff_operator_audit(
        self, *, record_path: str, record: Mapping[str, object], reason: str
    ) -> dict[str, object]:
        """Persist a support-root gate before cleaning a terminal invariant failure."""

        value = {
            "version": 1,
            "state": "operator_audit_required",
            "reason": str(reason),
            "handoff_id": record.get("handoff_id"),
            "handoff_state": record.get("state"),
            "record_path": str(record_path),
            "record_digest": record.get("record_digest"),
            "runtime_instance_id": self.instance_id,
            "pid": os.getpid(),
            "process_birth_id": process_birth_identity(),
        }
        atomic_json_write(
            self.support_root / "orderly-handoff-cleanup-uncertain.json", value
        )
        return value

    def last_handoff_cleanup_proof(self) -> dict[str, object] | None:
        return (
            dict(self._last_handoff_cleanup_proof)
            if isinstance(self._last_handoff_cleanup_proof, dict)
            else None
        )

    def adopt_orderly_worker_handoff(self, frame: Mapping[str, object]) -> dict[str, object]:
        """Complete B adoption while publication remains registration-only."""

        if self.local_worker_launcher is None or self.service is None or self.httpd is None:
            raise ConflictError("owner B local Worker handoff is unavailable")
        export = frame.get("export")
        if not isinstance(export, Mapping):
            raise ConflictError("owner B handoff export is invalid")
        receipt = export.get("receipt")
        generation = export.get("credential_generation")
        registered_state = export.get("registered_state")
        old_runtime = frame.get("old_runtime")
        if not all(isinstance(item, Mapping) for item in (receipt, generation, registered_state, old_runtime)):
            raise ConflictError("owner B handoff facts are incomplete")
        new_runtime = self.runtime_identity()
        common = {
            "version": "reigh.local-worker-control/v2",
            "handoff_id": frame["handoff_id"],
            "nonce_digest": frame["nonce_digest"],
            "sealed_record_digest": frame["sealed_record_digest"],
            "deadline_monotonic": frame["deadline_monotonic"],
            "deadline_unix_ms": frame["deadline_unix_ms"],
        }
        request = {
            **common,
            "command": "handoff_adopt",
            "nonce": frame["nonce"],
            "request_id": frame["handoff_id"],
            "old_owner": dict(frame["old_owner"]),
            "new_owner": dict(frame["new_owner"]),
            "export_sealed_digest": frame["export_sealed_digest"],
            "export_record_digest": frame["export_record_digest"],
            "adopter_record_digest": frame["adopter_record_digest"],
            "old_runtime": dict(old_runtime),
            "new_runtime": new_runtime,
            "endpoint": old_runtime["endpoint"],
            "credential_file": str(self.worker_credential_path),
            "credential_generation": dict(generation),
            "receipt_evidence_digest": receipt["evidence_digest"],
            "executor_incarnation": receipt["executor_incarnation"],
            "registered_state": dict(registered_state),
        }
        adopted = self.local_worker_launcher.adopt_orderly_handoff(
            descriptor=int(frame["worker_control_fd"]),
            profile_id=str(receipt["profile_id"]),
            receipt=receipt,
            request=request,
        )
        prospective_state = adopted.get("registered_state")
        if not isinstance(prospective_state, Mapping):
            raise ConflictError("owner B host preview is unavailable")
        actor, bodies = handoff_registration_admission(prospective_state)
        self.httpd.set_admission_mode(
            "handoff_pending",
            registration_actor=actor,
            registration_bodies=bodies,
        )
        committed = self.local_worker_launcher.commit_orderly_handoff(
            str(frame["handoff_id"]), new_runtime=new_runtime
        )
        armed = self.local_worker_launcher.resume_orderly_handoff(
            str(frame["handoff_id"]), new_runtime=new_runtime, commit=False
        )
        resumed = self.local_worker_launcher.resume_orderly_handoff(
            str(frame["handoff_id"]), new_runtime=new_runtime, commit=True
        )
        return {
            "state": "resume_committed",
            "old_runtime": dict(old_runtime),
            "new_runtime": new_runtime,
            "adopt_ack": adopted["ack"],
            "registration_preview": dict(prospective_state),
            "commit_ack": committed,
            "resume_prepare_ack": armed,
            "resume_commit_ack": resumed,
        }

    def start_local_worker(self, profile_id, expected_workspace_uuid):
        if self.local_worker_launcher is None:
            raise ConflictError(
                "No local Worker profile is configured; set worker_profile in the Astrid source profile and restart the Runtime"
            )
        bind_runtime = getattr(self.local_worker_preparer, "bind_runtime", None)
        if bind_runtime is not None:
            bind_runtime(
                endpoint=self.endpoint,
                runtime_instance_id=self.instance_id,
                credential_file=self.worker_credential_path,
            )
        return self.local_worker_launcher.start(profile_id, expected_workspace_uuid)

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

    def _write_replacement_state(self, *, state, candidate, superseded=None, error=None):
        value = {
            "format_version": 1,
            "state": state,
            "active_root": str(self.root),
            "candidate_root": str(candidate),
            "superseded_root": str(superseded) if superseded else None,
            "updated_at": now(),
        }
        if error:
            value["error"] = str(error)
        atomic_json_write(self._replacement_state_path(), value)

    def activate_candidate(self, candidate_root, *, retain_superseded=True):
        """Atomically activate a verified inactive candidate under one owner."""
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
        try:
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            first = verify_restore_candidate(candidate, directory_identity=candidate_identity)
            if self.service.realm["id"] != first["manifest"].get("realm", {}).get("id"):
                raise ConflictError("replacement realm identity does not match the live realm")
            self._write_replacement_state(state="verified", candidate=candidate, superseded=superseded)
            self.stop()
            self._write_replacement_state(state="owner_stopped", candidate=candidate, superseded=superseded)
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
            self._write_replacement_state(state="old_quarantined", candidate=candidate, superseded=superseded)
            os.rename(candidate.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_candidate = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="candidate_published", candidate=candidate, superseded=superseded)
            self.instance_id = uuid.uuid4().hex
            self._start(rotate_credentials=True)
            self._write_replacement_state(state="complete", candidate=candidate, superseded=superseded)
            return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded), "retained": bool(retain_superseded)}
        except Exception as exc:
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
                self._write_replacement_state(state="rolled_back", candidate=candidate, superseded=superseded, error=exc)
            except Exception:
                pass
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

    def replace_from_backup(self, backup_root, *, retain_superseded=True):
        """Replace an unadmittable active root through an offline fence.

        The backup is verified first and the active database is never opened.
        The active tree is retained under a quarantine sibling, while the
        materialized candidate is the only tree admitted after publication.
        """
        if self.service is not None or self.httpd is not None:
            raise ConflictError("offline replacement requires a stopped runtime")
        self._require_replacement_support_layout()
        backup = _authority_path(backup_root, "backup").resolve()
        # This is deliberately independent of active-root admission.
        verify_backup(backup)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ConflictError("damaged active root must be retained as an ordinary directory")
        candidate = self.root.parent / f".{self.root.name}.candidate-{os.getpid()}-{time.time_ns()}"
        restore_backup(backup, candidate)
        candidate_identity = capture_parent(candidate)
        active_identity = capture_parent(self.root)
        custody = None
        superseded = self.root.parent / f".{self.root.name}.superseded-{uuid.uuid4().hex}"
        moved_old = False
        moved_candidate = False
        try:
            verify_restore_candidate(candidate, directory_identity=candidate_identity)
            custody = self._acquire_offline_custody()
            validate_parent(self.root, active_identity)
            validate_parent(candidate, candidate_identity)
            self._write_replacement_state(state="offline_verified", candidate=candidate, superseded=superseded)
            parent_fd = int(active_identity["_parent_fd"])
            os.rename(self.root.name, superseded.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_old = True
            os.fsync(parent_fd)
            os.rename(candidate.name, self.root.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved_candidate = True
            os.fsync(parent_fd)
            validate_parent(self.root, active_identity)
            self._write_replacement_state(state="offline_candidate_published", candidate=candidate, superseded=superseded)
            self._release_offline_custody(custody)
            custody = None
            self.instance_id = uuid.uuid4().hex
            self._start(rotate_credentials=True)
            self._write_replacement_state(state="complete", candidate=candidate, superseded=superseded)
            return {"state": "complete", "realm_id": self.service.realm["id"], "runtime_epoch": self.service.health()["runtime_epoch"], "runtime_instance_id": self.instance_id, "superseded_root": str(superseded), "retained": bool(retain_superseded), "offline": True}
        except Exception as exc:
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
                self._write_replacement_state(state="rolled_back", candidate=candidate, superseded=superseded, error=exc)
            finally:
                self._release_offline_custody(custody)
                custody = None
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
        realm_id = None
        graph_cleanup_verified = self.local_worker_launcher is None
        cleanup_source_receipt = (
            self.local_worker_launcher.cleanup_receipt_snapshot()
            if self.local_worker_launcher is not None else None
        )
        self._last_handoff_cleanup_proof = None
        if self.httpd is not None:
            set_admission_mode = getattr(self.httpd, "set_admission_mode", None)
            if callable(set_admission_mode):
                set_admission_mode("closed")
            else:
                self.httpd.accepting_authenticated_requests = False
        if self.local_worker_launcher is not None:
            worker_handles = self.local_worker_launcher.begin_shutdown()
        if self.service is not None:
            try:
                realm_id = self.service.realm["id"]
                self.catalog.revoke_readiness(realm_id, instance_id=self.instance_id, reason="runtime_stopped")
            except Exception:
                pass
        self.discovery.clear(self.instance_id)
        self._shutdown_http()
        cleanup_failure = None
        if self.local_worker_launcher is not None:
            try:
                self.local_worker_launcher.finish_shutdown(worker_handles)
                graph_cleanup_verified = True
            except BaseException as exc:
                cleanup_failure = exc
                atomic_json_write(
                    self.support_root / "orderly-handoff-cleanup-uncertain.json",
                    {
                        "version": 1,
                        "state": "cleanup_uncertain",
                        "runtime_instance_id": self.instance_id,
                        "reason": " ".join(str(exc).split())[:768],
                    },
                )
            self.local_worker_launcher = None
        if self.service:
            self.service.close()
            self.service = None
        if cleanup_failure is not None:
            raise ConflictError(str(cleanup_failure)) from cleanup_failure
        catalog_neutral = True
        if realm_id is not None:
            try:
                row = next(
                    (
                        item for item in self.catalog.read().get("realms", [])
                        if item.get("realm_id") == realm_id
                        and item.get("runtime_instance_id") == self.instance_id
                    ),
                    None,
                )
                catalog_neutral = row is None or row.get("readiness") != "ready"
            except Exception:
                catalog_neutral = False
        discovery_absent = not self.discovery.path.exists() and not self.discovery.path.is_symlink()
        credential_revoked = (
            self.credentials is None
            or not self.local_worker_profiles
            or not self.credentials.actor_enabled(WORKER_ACTOR)
        )
        expected_processes = []
        process_rows = []
        uncertainties = []
        listener = None
        if isinstance(cleanup_source_receipt, Mapping):
            for role in ("worker", "host", "engine", "engine_listener"):
                identity = cleanup_source_receipt.get(role)
                if not isinstance(identity, Mapping):
                    uncertainties.append(f"missing_identity:{role}")
                    continue
                identity_value = dict(identity)
                identity_digest = digest(identity_value)
                expected_processes.append({
                    "role": role,
                    "identity": identity_value,
                    "identity_digest": identity_digest,
                })
                expected_pid = int(identity_value["pid"])
                try:
                    os.kill(expected_pid, 0)
                    pid_alive = True
                except ProcessLookupError:
                    pid_alive = False
                except PermissionError:
                    pid_alive = True
                observed_birth = process_birth_identity(expected_pid) if pid_alive else None
                if pid_alive and observed_birth is None:
                    uncertainties.append(f"birth_identity_unavailable:{role}")
                associated_alive = observed_birth == identity_value.get("birth_id")
                process_rows.append({
                    "role": role,
                    "pid": expected_pid,
                    "expected_birth_id": identity_value.get("birth_id"),
                    "identity_digest": identity_digest,
                    "observed_birth_id": observed_birth,
                    "associated_alive": associated_alive,
                    "absent": not pid_alive,
                })
            binding = cleanup_source_receipt.get("engine_binding")
            endpoint = binding.get("endpoint") if isinstance(binding, Mapping) else None
            parsed = urlsplit(str(endpoint or ""))
            listener_identity = cleanup_source_receipt.get("engine_listener")
            if (
                parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.port is None
                or not isinstance(listener_identity, Mapping)
            ):
                uncertainties.append("listener_binding_unavailable")
            else:
                probe = socket.socket(
                    socket.AF_INET6 if parsed.hostname == "::1" else socket.AF_INET,
                    socket.SOCK_STREAM,
                )
                try:
                    try:
                        probe.bind((parsed.hostname, parsed.port))
                        port_free = True
                    except OSError:
                        port_free = False
                finally:
                    probe.close()
                listener = {
                    "host": parsed.hostname,
                    "port": parsed.port,
                    "expected_owner_pid": listener_identity.get("pid"),
                    "expected_owner_birth_id": listener_identity.get("birth_id"),
                    "observed_owner_pid": None if port_free else -1,
                    "owner_absent": port_free,
                    "port_free": port_free,
                }
                if not port_free:
                    uncertainties.append("listener_port_still_accepting")
        final_census = {
            "process_rows": process_rows,
            "listener": listener,
            "uncertainties": uncertainties,
        }
        final_census["census_digest"] = digest(final_census)
        graph_cleanup_verified = bool(
            graph_cleanup_verified
            and len(expected_processes) == 4
            and len(process_rows) == 4
            and all(row["absent"] for row in process_rows)
            and isinstance(listener, Mapping)
            and listener.get("owner_absent") is True
            and listener.get("port_free") is True
            and not uncertainties
        )
        proof = {
            "version": 1,
            "runtime_instance_id": self.instance_id,
            "receipt_evidence_digest": (
                cleanup_source_receipt.get("evidence_digest")
                if isinstance(cleanup_source_receipt, Mapping) else None
            ),
            "expected_processes": expected_processes,
            "graph_and_engine_listener_absent": bool(graph_cleanup_verified),
            "authority_descriptors_closed": self.httpd is None
            and self.local_worker_launcher is None
            and self.inherited_listener_fd is None,
            "worker_credential_revoked": credential_revoked,
            "catalog_neutral": catalog_neutral,
            "discovery_absent": discovery_absent,
            "replacement_graph_not_launched": True,
            "final_census": final_census,
        }
        proof["complete"] = all(
            proof[key] is True
            for key in (
                "graph_and_engine_listener_absent",
                "authority_descriptors_closed",
                "worker_credential_revoked",
                "catalog_neutral",
                "discovery_absent",
                "replacement_graph_not_launched",
            )
        )
        if not isinstance(cleanup_source_receipt, Mapping):
            proof = {
                "version": 1,
                "runtime_instance_id": self.instance_id,
                "graph_and_engine_listener_absent": True,
                "authority_descriptors_closed": self.httpd is None
                and self.local_worker_launcher is None
                and self.inherited_listener_fd is None,
                "worker_credential_revoked": credential_revoked,
                "catalog_neutral": catalog_neutral,
                "discovery_absent": discovery_absent,
                "replacement_graph_not_launched": True,
                "final_census": {
                    "http_server_present": self.httpd is not None,
                    "local_worker_launcher_present": self.local_worker_launcher is not None,
                    "inherited_listener_fd_present": self.inherited_listener_fd is not None,
                    "worker_credential_enabled": not credential_revoked,
                    "catalog_ready": not catalog_neutral,
                    "discovery_present": not discovery_absent,
                },
                "complete": True,
            }
        self._last_handoff_cleanup_proof = proof
        if isinstance(cleanup_source_receipt, Mapping) and proof["complete"] is not True:
            atomic_json_write(
                self.support_root / "orderly-handoff-cleanup-uncertain.json",
                {
                    "version": 1,
                    "state": "cleanup_uncertain",
                    "runtime_instance_id": self.instance_id,
                    "reason": "incomplete_cleanup_proof",
                    "cleanup_proof": proof,
                },
            )
            raise ConflictError("local Worker graph cleanup is uncertain")

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
