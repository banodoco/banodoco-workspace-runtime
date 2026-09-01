from __future__ import annotations

from .cas import ContentAddressedStore
from .backup import create_backup, restore_backup, structured_export
from .store import RealmStore
from .util import atomic_json_write
from .util import canonical_json, durable_json_bytes, new_id, now, sha256_bytes
import hashlib
import json
import sqlite3
import base64
import os
import re
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .errors import AuthorizationError, ConflictError, NotFoundError, ValidationError, LeaseError, InvalidRequestError
from .contract_metadata import PROTOCOL, SCHEMA_DIGEST
from .dirfd import close_pinned as _close_pinned, mkdir_chain_at as _mkdir_chain_at, pin_directory as _pin_directory, write_bytes_at as _write_bytes_at


CHECKPOINT_MAX_BYTES = 1024 * 1024
OBJECT_MAX_BYTES = 64 * 1024 * 1024
REBOOT_COMMAND_ALLOWLIST = frozenset({"reboot", "resume"})
PAGE_DEFAULT_LIMIT = 50
PAGE_MAX_LIMIT = 200
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$")


def validate_idempotency_key(value):
    """Validate the wire-level idempotency-key grammar in one place."""
    if not isinstance(value, str) or not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise InvalidRequestError(
            "Idempotency-Key must start with an alphanumeric character and contain at most 256 ASCII characters"
        )
    return value


def require_idempotency_key(value):
    """Require and validate the key for every durable state mutation."""
    if value is None:
        raise InvalidRequestError("Idempotency-Key is required for state mutations")
    return validate_idempotency_key(value)


def _page_args(cursor, limit):
    """Validate the public page arguments and decode an opaque keyset cursor."""
    if isinstance(limit, bool):
        raise InvalidRequestError("limit must be an integer between 1 and 200")
    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise InvalidRequestError("limit must be an integer between 1 and 200") from exc
    if limit < 1 or limit > PAGE_MAX_LIMIT:
        raise InvalidRequestError("limit must be an integer between 1 and 200")
    if cursor in (None, ""):
        return limit, None
    if not isinstance(cursor, str):
        raise InvalidRequestError("cursor must be a non-empty string")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRequestError("cursor is invalid") from exc
    if not isinstance(value, dict) or value.get("v") != 1 or not isinstance(value.get("k"), list) or not value["k"]:
        raise InvalidRequestError("cursor is invalid")
    return limit, value


def _page_cursor(scope, key):
    raw = json.dumps({"v": 1, "s": scope, "k": list(key)}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _page_rows(rows, *, scope, cursor, limit, key_fn, resource_fn):
    limit, decoded = _page_args(cursor, limit)
    if decoded is not None and decoded.get("s") != scope:
        raise InvalidRequestError("cursor does not belong to this collection")
    after = tuple(decoded["k"]) if decoded is not None else None
    selected = []
    for row in rows:
        key = tuple(key_fn(row))
        if after is not None:
            if len(key) != len(after):
                raise InvalidRequestError("cursor is invalid")
            try:
                before = key <= after
            except TypeError as exc:
                raise InvalidRequestError("cursor is invalid") from exc
            if before:
                continue
        selected.append((key, resource_fn(row)))
        if len(selected) > limit:
            break
    has_more = len(selected) > limit
    selected = selected[:limit]
    return {"items": [resource for _, resource in selected], "next_cursor": _page_cursor(scope, selected[-1][0]) if has_more else None}


def _durable_mutation(function):
    """Keep a B7 project mutation and its idempotency receipt atomic."""
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with self.store._mutex:
            try:
                with self.store._transaction():
                    result = function(self, *args, **kwargs)
            except Exception:
                # A CAS publication is journaled before its destination is
                # renamed.  Reconcile after SQLite has rolled back so a
                # failed commit cannot leave an unreferenced object behind.
                self._recover_cas_publication_journals()
                raise
            self._recover_cas_publication_journals()
            return result
    return wrapped


class RuntimeService:
    """Neutral application service composed by the daemon or an isolated test."""

    def __init__(self, root, *, display_name="Workspace", realm_id=None, support_root=None, reboot_executor=None, reboot_allowlist=None):
        self.store = RealmStore(root)
        self.cas = ContentAddressedStore(self.store.cas_root)
        self.realm = self.store.ensure_realm(display_name, realm_id=realm_id)
        self.runtime_session_id = new_id()
        self._runtime_state = self.store.begin_runtime_session(self.runtime_session_id)
        self.support_root = Path(support_root).expanduser().resolve() if support_root else None
        self.reboot_executor = reboot_executor
        configured_allowlist = frozenset(reboot_allowlist or REBOOT_COMMAND_ALLOWLIST)
        if not configured_allowlist or not configured_allowlist.issubset(REBOOT_COMMAND_ALLOWLIST):
            raise ValidationError("reboot allowlist contains an unsupported command", details={"allowlist": sorted(configured_allowlist), "supported": sorted(REBOOT_COMMAND_ALLOWLIST)})
        self.reboot_allowlist = configured_allowlist
        self._recover_cas_publication_journals()

    def close(self):
        self.store.close()

    def backup(self, destination, *, binding=None, destination_identity=None):
        key_path = (self.support_root / "backup-auth.key") if self.support_root else (self.store.root / ".operator-backup-key")
        return create_backup(self.store, destination, binding=binding, key_path=key_path, destination_identity=destination_identity)

    def restore(self, backup_dir, destination, *, destination_identity=None, source_identity=None):
        key_path = (self.support_root / "backup-auth.key") if self.support_root else (self.store.root / ".operator-backup-key")
        # A backup may have been created by a prior active root whose path is
        # now inactive. Let restore fall back to the manifest path in that
        # case; when this service owns a stable support key, bind verification
        # to it explicitly and retain the same HMAC key for the handoff.
        return restore_backup(backup_dir, destination, key_path=key_path if key_path.is_file() else None, destination_identity=destination_identity, source_identity=source_identity)

    def export_structured(self, destination=None):
        value = structured_export(self.store)
        if destination is not None:
            atomic_json_write(Path(destination).expanduser().resolve(), value)
        return value

    def doctor(self):
        return self.store.doctor(catalog_path=(self.support_root / "catalog.json") if self.support_root else None)

    def tombstone(self, body=None):
        body = body or {}
        return self.store.tombstone_realm(reason=body.get("reason"), expected_version=body.get("expected_version"))

    def recover_realm(self, body=None):
        body = body or {}
        # Recovery is a destructive lifecycle transition.  Require an
        # operator-scoped expectation before touching durable state, even when
        # the realm is already active (the no-op path must be fenced too).
        expected_realm_id = body.get("expected_realm_id")
        expected_version = body.get("expected_version")
        if not expected_realm_id or expected_version is None:
            raise ValidationError("recovery requires expected_realm_id and expected_version")
        if str(expected_realm_id) != str(self.realm["id"]):
            raise ConflictError("recovery realm identity mismatch", details={"expected": expected_realm_id, "actual": self.realm["id"]})
        noninteractive = body.get("noninteractive") is True
        confirmation = body.get("confirmation")
        required_confirmation = f"RECOVER {self.realm['id']}"
        if bool(noninteractive) == bool(confirmation):
            raise ValidationError(f"recovery requires exactly one of confirmation {required_confirmation!r} or noninteractive=true")
        if not noninteractive and confirmation != required_confirmation:
            raise ValidationError(f"recovery requires confirmation exactly {required_confirmation!r} or noninteractive=true")
        return self.store.restore_tombstone(expected_version=expected_version)

    def purge(self, body=None):
        """Return the explicit offline purge boundary; never purge online."""
        body = body or {}
        confirmation = body.get("confirmation")
        required = f"PURGE {self.realm['id']}"
        if confirmation != required:
            raise ValidationError(f"whole-realm purge requires confirmation exactly {required!r}")
        if self.store.realm_lifecycle()["state"] != "tombstoned":
            raise ConflictError("whole-realm purge requires a tombstoned realm")
        raise ConflictError("whole-realm purge is offline-only; stop the runtime and use the purge command", details={"next_action": "banodoco-runtime purge --root <realm> --confirm 'PURGE <realm_id>'"})

    def health(self):
        return {"status": "ok", "protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "runtime_epoch": self._runtime_state["runtime_epoch"]}

    def runtime_lifecycle(self):
        """Return current boot/session and recovery facts for diagnostics."""
        value = dict(self._runtime_state)
        value["runtime_session_id"] = self.runtime_session_id
        return value

    def realm_resource(self):
        row = self.store.realm
        lifecycle = self.store.realm_lifecycle()
        return {"realm_id": row["id"], "display_name": row["display_name"], "version": 1, "created_at": row["created_at"], "state": lifecycle["state"], "tombstoned_at": lifecycle["tombstoned_at"], "lifecycle_version": lifecycle["version"]}

    def handshake(self, body):
        requested = list(body.get("requested_scopes") or [])
        actor = body.get("authenticated_actor")
        if not actor:
            raise ValidationError("authenticated actor is required")
        if any(not isinstance(scope, str) or not scope for scope in requested) or len(set(requested)) != len(requested):
            raise ValidationError("requested_scopes must contain unique non-empty strings")
        authenticated = set(body.get("authenticated_scopes") or [])
        # ``admin`` authorizes endpoint access but is not a wildcard grant for
        # handshake negotiation.  The session is the exact authenticated
        # scope intersection, and asking for anything outside it fails closed.
        negotiated = authenticated - {"admin"}
        excess = sorted(set(requested) - negotiated)
        if excess:
            raise AuthorizationError("credential cannot negotiate requested scopes", details={"scopes": excess})
        return {"protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "session_id": new_id(), "actor_id": actor, "realm_id": self.realm["id"], "scopes": requested}

    @staticmethod
    def _assert_executor_identity(identity, executor_id):
        """Bind bearer worker credentials to the executor they operate.

        ``identity`` is supplied only by the HTTP boundary.  Direct service
        calls remain useful for in-process control-plane tests and have no
        bearer principal to bind.  HTTP worker credentials are accepted only
        when their actor is the executor itself or they carry the explicit
        administrator scope.
        """
        if identity is None:
            return
        if not executor_id:
            raise AuthorizationError("executor identity is required")
        actor = identity.get("actor")
        if actor == executor_id or "admin" in set(identity.get("scopes", [])):
            return
        raise AuthorizationError("worker credential is not bound to executor", details={"executor_id": executor_id, "actor_id": actor})

    def _assert_attempt_identity(self, row, identity):
        if not row:
            return
        self._assert_executor_identity(identity, row["executor_id"])

    def create_project(self, body, *, idempotency_key=None):
        name = str(body.get("name") or "")
        slug = str(body.get("slug") or "-".join(name.lower().split()))
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in slug).strip("-") or "project"
        return self.store.create_project(slug, name, body.get("metadata"), idempotency_key=idempotency_key)

    def get_project(self, selector):
        return self.store.get_project(selector)

    def list_projects(self, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        rows = self.store.conn.execute("SELECT id, created_at FROM projects ORDER BY created_at, id").fetchall()
        return _page_rows(rows, scope="projects", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._project_resource(self.store.get_project(row["id"])))

    def select_project(self, actor_id, selector, *, scope="workspace", idempotency_key=None):
        value = self.store.select_project(actor_id, selector, scope, idempotency_key=idempotency_key)
        return {
            "actor_id": value["actor_id"],
            "scope": value["scope"],
            "project": self._project_resource(value["project"]),
            "updated_at": value["updated_at"],
        }

    def current_project(self, actor_id):
        value = self.store.current_project(actor_id)
        return {
            "actor_id": value["actor_id"],
            "scope": value["scope"],
            "project": self._project_resource(value["project"]),
            "updated_at": value["updated_at"],
        }

    def update_project(self, selector, body, *, idempotency_key=None):
        return self.store.update_project(selector, name=body.get("name"), metadata=body.get("metadata"), expected_version=body.get("expected_version"), idempotency_key=idempotency_key)

    def _project_resource(self, value):
        return {"project_id": value["id"], "realm_id": value["realm_id"], "slug": value["slug"], "name": value["name"], "metadata": value.get("metadata", {}), "version": value["version"], "created_at": value["created_at"], "updated_at": value["updated_at"], "archived": False}

    def _timeline_resource(self, timeline_id):
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row: raise NotFoundError("timeline not found")
        shots = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
        refs = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
        result = {"timeline_id": row["id"], "project_id": row["project_id"], "version": row["version"], "archived": bool(row["archived_at"]), "shots": [{"shot_id": x["id"], "start_ms": x["start_ms"], "duration_ms": x["duration_ms"], "reference_ids": json.loads(x["reference_ids_json"])} for x in shots], "references": [{"reference_id": x["id"], "object_id": x["object_id"], **({"role": x["role"]} if x["role"] else {})} for x in refs]}
        document = self.store.conn.execute("SELECT content_json, version FROM project_documents WHERE id=? AND project_id=?", (f"timeline:{timeline_id}", row["project_id"])).fetchone()
        if document:
            content = json.loads(document["content_json"])
            if isinstance(content, dict):
                result.update({"slug": content.get("slug", timeline_id), "name": content.get("name", timeline_id), "config_version": int(document["version"]), "config": content.get("config", {}), "registry": content.get("registry", {})})
        return result

    def _record_timeline_revision(self, timeline_id, resource=None):
        resource = resource or self._timeline_resource(timeline_id)
        self.store.conn.execute(
            "INSERT OR IGNORE INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (timeline_id, resource["version"], canonical_json(resource["shots"]), canonical_json(resource["references"]), now()),
        )

    def _timeline_revision(self, timeline_id, version):
        row = self.store.conn.execute("SELECT * FROM timeline_revisions WHERE timeline_id=? AND version=?", (timeline_id, version)).fetchone()
        if row:
            return {"timeline_id": timeline_id, "version": int(row["version"]), "shots": json.loads(row["shots_json"]), "references": json.loads(row["references_json"]), "created_at": row["created_at"]}
        current = self._timeline_resource(timeline_id)
        if int(current["version"]) == int(version):
            return {"timeline_id": timeline_id, "version": current["version"], "shots": current["shots"], "references": current["references"], "created_at": now()}
        raise NotFoundError("timeline revision not found", details={"timeline_id": timeline_id, "version": version})

    @staticmethod
    def _expected_version(body):
        value = (body or {}).get("expected_version")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValidationError("expected_version must be a positive integer")
        return value

    @_durable_mutation
    def update_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row:
            raise NotFoundError("timeline not found")
        project_id = str(row["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body}).encode()).hexdigest()
        replay = self._command_replay("timeline.update", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if int(row["version"]) != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": int(row["version"])})
        shots = body.get("shots")
        refs = body.get("references")
        if shots is not None:
            if not isinstance(shots, list) or len({item.get("shot_id") for item in shots if isinstance(item, dict)}) != len(shots):
                raise ValidationError("shots must be a list with unique shot_id values")
            for shot in shots:
                if not isinstance(shot, dict) or not shot.get("shot_id") or int(shot.get("start_ms", -1)) < 0 or int(shot.get("duration_ms", 0)) < 1:
                    raise ValidationError("invalid shot timing")
        if refs is not None:
            if not isinstance(refs, list) or len({item.get("reference_id") for item in refs if isinstance(item, dict)}) != len(refs):
                raise ValidationError("references must be a list with unique reference_id values")
            for reference in refs:
                if not isinstance(reference, dict) or not reference.get("reference_id") or not reference.get("object_id"):
                    raise ValidationError("references require reference_id and object_id")
        if shots is None:
            shots = [dict(value) for value in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
            shots = [{"shot_id": value["id"], "start_ms": value["start_ms"], "duration_ms": value["duration_ms"], "reference_ids": json.loads(value["reference_ids_json"])} for value in shots]
        if refs is None:
            refs = [dict(value) for value in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
            refs = [{"reference_id": value["id"], "object_id": value["object_id"], **({"role": value["role"]} if value["role"] else {})} for value in refs]
        with self.store._transaction():
            self.store.conn.execute("DELETE FROM timeline_shot_state WHERE id IN (SELECT id FROM timeline_shots WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_reference_state WHERE id IN (SELECT id FROM timeline_references WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_shots WHERE timeline_id=?", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_references WHERE timeline_id=?", (timeline_id,))
            for shot in shots:
                self.store.conn.execute("INSERT INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (shot["shot_id"], timeline_id, int(shot["start_ms"]), int(shot["duration_ms"]), canonical_json(shot.get("reference_ids", []))))
                self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (shot["shot_id"],))
            for reference in refs:
                self.store.conn.execute("INSERT INTO timeline_references VALUES (?, ?, ?, ?)", (reference["reference_id"], timeline_id, reference["object_id"], reference.get("role")))
                self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (reference["reference_id"],))
            self.store.conn.execute("UPDATE timelines SET version=?, created_at=created_at WHERE id=?", (expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.updated", {"project_id": project_id, "version": resource["version"]})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.update", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def create_timeline(self, project_id, timeline_id, *, idempotency_key=None):
        if not isinstance(timeline_id, str) or not timeline_id:
            raise ValidationError("timeline_id is required")
        project = self.store.get_project(project_id)
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project["id"], "timeline_id": timeline_id,
        }).encode()).hexdigest()
        # A create request has no pre-existing aggregate, so keep its key in
        # one operation namespace and bind project/timeline identity in the
        # request hash. Reusing a key for any changed request is a conflict;
        # a retry gets the exact committed resource and receipt.
        replay = self._command_replay("timeline.create", "timelines", idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        if self.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (timeline_id,)).fetchone():
            raise ConflictError("timeline already exists", details={"timeline_id": timeline_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO timelines(id, project_id, version, created_at, archived_at) VALUES (?, ?, 1, ?, NULL)", (timeline_id, project["id"], timestamp))
        resource = self._timeline_resource(timeline_id)
        self._record_timeline_revision(timeline_id, resource)
        event_id = self.store._append_timeline_event(timeline_id, "timeline.created", {"project_id": project["id"]})
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        return self._command_record(
            "timeline.create", "timelines", idempotency_key, request_hash,
            resource, project_id=project["id"], event_ids=(event_id,),
            primary_stream_id=timeline_id, resulting_stream_seq=event_seq,
        )

    @_durable_mutation
    def create_timeline_document(self, project_id, body, *, idempotency_key=None):
        """Create the timeline and composition document in one transaction."""
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")
        project = self.store.get_project(project_id)
        timeline_id = str(body.get("timeline_id") or "")
        if not timeline_id:
            raise ValidationError("timeline_id is required")
        config, registry = body.get("config", {}), body.get("registry", {})
        if not isinstance(config, dict) or not isinstance(registry, dict):
            raise ValidationError("config and registry must be objects")
        slug, name = str(body.get("slug") or timeline_id), str(body.get("name") or body.get("slug") or timeline_id)
        content = {"slug": slug, "name": name, "config": config, "registry": registry}
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project["id"], "timeline_id": timeline_id,
            "slug": slug, "name": name, "config": config, "registry": registry,
        }).encode()).hexdigest()
        replay = self._command_replay("timeline_document.create", timeline_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        if self.store.conn.execute("SELECT 1 FROM timelines WHERE id=?", (timeline_id,)).fetchone():
            raise ConflictError("timeline already exists", details={"timeline_id": timeline_id})
        document_id = f"timeline:{timeline_id}"
        if self.store.conn.execute("SELECT 1 FROM project_documents WHERE id=?", (document_id,)).fetchone():
            raise ConflictError("timeline document already exists", details={"document_id": document_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO timelines(id, project_id, version, created_at, archived_at) VALUES (?, ?, 1, ?, NULL)", (timeline_id, project["id"], timestamp))
        self.store.conn.execute("INSERT INTO project_documents(id, project_id, kind, content_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)", (document_id, project["id"], "timeline.composition", canonical_json(content), timestamp, timestamp))
        resource = self._timeline_resource(timeline_id)
        self._record_timeline_revision(timeline_id, resource)
        event_id = self.store._append_timeline_event(timeline_id, "timeline.document.created", {"project_id": project["id"], "document_id": document_id, "config_version": resource["config_version"]})
        event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
        return self._command_record("timeline_document.create", timeline_id, idempotency_key, request_hash, resource, project_id=project["id"], event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    def list_timelines(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM timelines WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"timelines:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._timeline_resource(row["id"]))

    def _shot_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_shot_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"shot_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "start_ms": int(row["start_ms"]), "duration_ms": int(row["duration_ms"]), "reference_ids": json.loads(row["reference_ids_json"]), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def _reference_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_reference_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"reference_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "object_id": row["object_id"], **({"role": row["role"]} if row["role"] else {}), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def list_project_tasks(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM tasks WHERE run_id IN (SELECT id FROM runs WHERE project_id=?) ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"tasks:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self._task_resource(self.store.get_task(row["id"])))

    def list_project_runs(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id, created_at FROM runs WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"runs:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=lambda row: self.run(row["id"]))

    def list_project_shots(self, project_id, *, cursor=None, include_archived=False, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        query = "SELECT * FROM project_shots WHERE project_id=?"
        if not include_archived: query += " AND archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"project-shots:{project['id']}:{int(include_archived)}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._project_shot_resource)

    def list_project_references(self, project_id, *, cursor=None, include_archived=False, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        query = "SELECT * FROM project_references WHERE project_id=?"
        if not include_archived: query += " AND archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"project-references:{project['id']}:{int(include_archived)}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._project_reference_resource)

    @staticmethod
    def _require_object_body(body):
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")

    def _receipt_payload(self, row, *, project_id):
        """Expose the canonical receipt facts committed with the mutation."""
        if row is None or row["txn_id"] is None:
            return None
        result = json.loads(row["result_json"])
        return {
            "receipt_id": row["txn_id"],
            "command_kind": row["command_kind"],
            "idempotency_key": row["idempotency_key"],
            "request_hash": row["request_hash"],
            "project_id": project_id,
            "project_seq": [int(row["first_project_seq"]), int(row["last_project_seq"])],
            "event_ids": json.loads(row["event_ids_json"]),
            "result": result,
            "created_at": row["created_at"],
        }

    def committed_receipt(self, command_kind, aggregate_id, idempotency_key, *, project_id):
        """Return the receipt persisted with a successful mutation.

        This reads the command ledger; it never derives a receipt from client
        state or caches one in the service process.
        """
        if not idempotency_key:
            return None
        # HTTP handlers share the owner's SQLite connection. Serialize this
        # post-mutation read with the writer lock so another handler cannot
        # interleave a transaction on the same connection between the
        # mutation and receipt lookup, yielding a spurious null receipt.
        with self.store._mutex:
            row = self.store.conn.execute(
                "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
                "first_project_seq, last_project_seq, event_ids_json, created_at "
                "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                (command_kind, aggregate_id, idempotency_key),
            ).fetchone()
        return self._receipt_payload(row, project_id=project_id) if row else None

    def _command_replay(self, kind, aggregate_id, idempotency_key, request_hash, *, project_id=None, with_receipt=True):
        if idempotency_key is None:
            return None
        validate_idempotency_key(idempotency_key)
        prior = self.store.conn.execute(
            "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
            "first_project_seq, last_project_seq, event_ids_json, created_at "
            "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
            (kind, aggregate_id, idempotency_key),
        ).fetchone()
        if not prior:
            return None
        if prior["request_hash"] != request_hash:
            raise ConflictError("idempotency key was already used with different input")
        if project_id is not None and with_receipt:
            return {"data": json.loads(prior["result_json"]), "receipt": self._receipt_payload(prior, project_id=project_id)}
        return json.loads(prior["result_json"])

    def _command_record(self, kind, aggregate_id, idempotency_key, request_hash, result, *, project_id=None, event_ids=(), primary_stream_id=None, resulting_stream_seq=None, with_receipt=True):
        if idempotency_key is not None:
            validate_idempotency_key(idempotency_key)
            if project_id is not None:
                self.store._record_command_receipt(
                    kind, aggregate_id, idempotency_key, request_hash, result,
                    project_id=project_id, event_ids=event_ids,
                    primary_stream_id=primary_stream_id,
                    resulting_stream_seq=resulting_stream_seq,
                )
                row = self.store.conn.execute(
                    "SELECT txn_id, command_kind, idempotency_key, request_hash, result_json, "
                    "first_project_seq, last_project_seq, event_ids_json, created_at "
                    "FROM command_idempotency WHERE command_kind=? AND aggregate_id=? AND idempotency_key=?",
                    (kind, aggregate_id, idempotency_key),
                ).fetchone()
                if with_receipt:
                    return {"data": result, "receipt": self._receipt_payload(row, project_id=project_id)}
                return result
            self.store.conn.execute(
                "INSERT INTO command_idempotency(command_kind, aggregate_id, idempotency_key, request_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (kind, aggregate_id, idempotency_key, request_hash, canonical_json(result), now()),
            )
        return result

    def _publication_journal_root(self):
        root = self.store.staging_root / "publications"
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o700)
        return root

    def _begin_cas_publication_journal(self, kind, entries, *, project_id=None, task_id=None):
        """Durably describe CAS destinations before making them reachable.

        The journal is intentionally outside SQLite: a process crash can occur
        after ``rename`` and before the SQLite commit.  Startup then keeps a
        destination only when the durable metadata proves that this operation
        committed; otherwise it removes the exact content-addressed path.
        """
        if not entries:
            return None
        payload = {
            "version": 1,
            "kind": kind,
            "project_id": project_id,
            "task_id": task_id,
            "entries": [{"digest": str(entry["digest"])} for entry in entries],
        }
        path = self._publication_journal_root() / f"{new_id()}.json"
        atomic_json_write(path, payload)
        return path

    @staticmethod
    def _remove_publication_journal(path):
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError:
            return
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass

    def _publication_committed(self, journal):
        entries = journal.get("entries")
        if not isinstance(entries, list) or not entries:
            return False
        digests = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("digest"), str):
                return False
            digest = entry["digest"]
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                return False
            digests.append(digest)
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                return False
        project_id = journal.get("project_id")
        if project_id and project_id != "unscoped":
            for digest in digests:
                if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                    return False
        if journal.get("kind") == "settlement":
            task_id = journal.get("task_id")
            task = self.store.conn.execute("SELECT status, result_json FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task or task["status"] != "completed":
                return False
            try:
                result_digests = {
                    str(item.get("digest", "")).removeprefix("sha256:")
                    for item in (json.loads(task["result_json"] or "{}").get("outputs") or [])
                    if isinstance(item, dict)
                }
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            if not set(digests).issubset(result_digests):
                return False
        return True

    def _recover_cas_publication_journals(self):
        """Finish or roll back CAS publications left by a crashed mutation."""
        root = self.store.staging_root / "publications"
        if not root.exists() or root.is_symlink() or not root.is_dir():
            return
        for path in sorted(root.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                journal = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                # Leave malformed evidence for doctor/operator inspection; do
                # not guess at a path and risk deleting an unrelated object.
                continue
            if not isinstance(journal, dict) or journal.get("version") != 1:
                continue
            try:
                committed = self._publication_committed(journal)
            except (OSError, sqlite3.DatabaseError, TypeError, ValueError):
                continue
            if not committed:
                cleanup_failed = False
                for entry in journal.get("entries", []):
                    digest = entry.get("digest") if isinstance(entry, dict) else None
                    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                        continue
                    # If another operation has since durable-metadata-claimed
                    # this object, it owns the file and it must be retained.
                    if self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                        continue
                    destination = self.cas.path_for(digest)
                    try:
                        destination.unlink()
                    except FileNotFoundError:
                        continue
                    except OSError:
                        # Keep the durable evidence when cleanup fails so a
                        # later startup can retry the exact destination.
                        cleanup_failed = True
                        continue
                    try:
                        directory_fd = os.open(destination.parent, os.O_RDONLY)
                        try:
                            os.fsync(directory_fd)
                        finally:
                            os.close(directory_fd)
                    except OSError:
                        pass
                if cleanup_failed:
                    continue
            self._remove_publication_journal(path)

    def _project_shot_resource(self, row):
        value = dict(row)
        value["shot_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        value["archived"] = bool(value.pop("archived_at"))
        value["items"] = [self._shot_item_resource(item) for item in self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (value["shot_id"],))]
        return value

    @staticmethod
    def _shot_item_resource(row):
        value = dict(row)
        value["item_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    @_durable_mutation
    def create_project_shot(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        name = str(body.get("name") or "")
        if not name.strip():
            raise ValidationError("name is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("metadata must be an object")
        shot_id = str(body.get("shot_id") or new_id())
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.create", project["id"], idempotency_key, request_hash, project_id=project["id"])
            if replay is not None:
                return replay
            if self.store.conn.execute("SELECT 1 FROM project_shots WHERE id=?", (shot_id,)).fetchone():
                raise ConflictError("shot already exists", details={"shot_id": shot_id})
            timestamp = now()
            self.store.conn.execute("INSERT INTO project_shots(id, project_id, name, metadata_json, version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, 1, ?, ?, NULL)", (shot_id, project["id"], name, canonical_json(metadata), timestamp, timestamp))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record("shot.create", project["id"], idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def create_project_reference(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        kind, name = str(body.get("kind") or ""), str(body.get("name") or "")
        if kind not in {"character", "place", "object", "clothing", "other"}:
            raise ValidationError("invalid reference kind")
        if not name.strip():
            raise ValidationError("name is required")
        if "object_id" in body:
            raise ValidationError("object_id is not supported; use media_id")
        media_id = str(body.get("media_id") or "").removeprefix("sha256:")
        reference_id = str(body.get("reference_id") or "")
        if not media_id:
            raise ValidationError("media_id is required")
        if not reference_id:
            reference_id = new_id()
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("metadata must be an object")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.create", project["id"], idempotency_key, request_hash, project_id=project["id"])
            if replay is not None:
                return replay
            if self.store.conn.execute("SELECT 1 FROM project_references WHERE id=?", (reference_id,)).fetchone():
                raise ConflictError("reference already exists", details={"reference_id": reference_id})
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone():
                raise NotFoundError("media is not owned by project")
            timestamp = now()
            self.store.conn.execute("INSERT INTO project_references(id, project_id, kind, name, description, metadata_json, version, created_at, updated_at, archived_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)", (reference_id, project["id"], kind, name, str(body.get("description") or ""), canonical_json(metadata), timestamp, timestamp))
            self.store.conn.execute("INSERT INTO media_references(id, reference_id, media_id, role, ordinal, is_primary, metadata_json, created_at) VALUES (?, ?, ?, 'canonical', 0, 1, '{}', ?)", (new_id(), reference_id, media_id, timestamp))
            result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone())
            return self._command_record("reference.create", project["id"], idempotency_key, request_hash, result, project_id=project["id"])

    def get_project_shot(self, project_id, shot_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=? AND project_id=?", (shot_id, project["id"])).fetchone()
        if not row: raise NotFoundError("shot not found")
        return self._project_shot_resource(row)

    @_durable_mutation
    def update_project_shot(self, project_id, shot_id, body, *, idempotency_key=None, archived=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        expected = self._expected_version(body)
        action = "update" if archived is None else "archive" if archived else "recover"
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay(f"shot.{action}", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=? AND project_id=?", (shot_id, project["id"])).fetchone()
            if not row: raise NotFoundError("shot not found")
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            timestamp = now()
            name = str(body.get("name", row["name"]))
            metadata = body.get("metadata", json.loads(row["metadata_json"]))
            if not name.strip() or not isinstance(metadata, dict): raise ValidationError("invalid shot name or metadata")
            archived_at = (timestamp if archived is True else None if archived is False else row["archived_at"])
            self.store.conn.execute("UPDATE project_shots SET name=?, metadata_json=?, version=?, updated_at=?, archived_at=? WHERE id=?", (name, canonical_json(metadata), expected + 1, timestamp, archived_at, shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record(f"shot.{action}", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def add_shot_item(self, project_id, shot_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        media_id = str(body.get("media_id") or "").removeprefix("sha256:")
        if not media_id: raise ValidationError("media_id is required")
        if not isinstance(body.get("metadata", {}), dict): raise ValidationError("metadata must be an object")
        shot = self.get_project_shot(project["id"], shot_id)
        key = idempotency_key
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.add", shot_id, key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone(): raise NotFoundError("media is not owned by project")
            position = body.get("position")
            rows = self.store.conn.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,)).fetchall()
            if position is None: position = len(rows)
            if isinstance(position, bool) or not isinstance(position, int) or position < 0 or position > len(rows): raise ValidationError("position is out of range")
            item_id = str(body.get("item_id") or new_id())
            stamp = now()
            self.store.conn.execute("INSERT INTO shot_items(id, shot_id, media_id, sort_key, source_frame, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (item_id, shot_id, media_id, f"~{item_id}", body.get("source_frame"), canonical_json(body.get("metadata", {})), stamp))
            ordered_ids = [row["id"] for row in rows]; ordered_ids.insert(position, item_id)
            for index, ordered_id in enumerate(ordered_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"tmp-{index:08d}-{item_id}", ordered_id))
            for index, ordered_id in enumerate(ordered_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", ordered_id))
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (stamp, shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone())
            return self._command_record("shot.item.add", shot_id, key, request_hash, result, project_id=project["id"])

    def _renumber_shot_items(self, shot_id):
        rows = self.store.conn.execute("SELECT id FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,)).fetchall()
        for index, row in enumerate(rows): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", row["id"]))

    @_durable_mutation
    def remove_shot_item(self, project_id, shot_id, item_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        self.get_project_shot(project_id, shot_id)
        expected = self._expected_version(body)
        request_hash = hashlib.sha256(canonical_json({"item_id": item_id, **body}).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.remove", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            if not self.store.conn.execute("SELECT 1 FROM shot_items WHERE id=? AND shot_id=?", (item_id, shot_id)).fetchone(): raise NotFoundError("shot item not found")
            self.store.conn.execute("DELETE FROM shot_items WHERE id=?", (item_id,)); self._renumber_shot_items(shot_id)
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (now(), shot_id))
            result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()); return self._command_record("shot.item.remove", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def reorder_shot_items(self, project_id, shot_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        self.get_project_shot(project_id, shot_id); expected = self._expected_version(body)
        if "items" in body:
            raise ValidationError("items is not supported; use item_ids")
        item_ids = body.get("item_ids")
        if not isinstance(item_ids, list) or any(not isinstance(item_id, str) for item_id in item_ids) or len(item_ids) != len(set(item_ids)): raise ValidationError("items must be a unique complete permutation")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("shot.item.reorder", shot_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone(); current = [x["id"] for x in self.store.conn.execute("SELECT id FROM shot_items WHERE shot_id=?", (shot_id,))]
            if int(row["version"]) != expected: raise ConflictError("shot version conflict", details={"expected": expected, "actual": int(row["version"])})
            if set(map(str, item_ids)) != set(current): raise ValidationError("items must name the complete shot permutation")
            for index, item_id in enumerate(item_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"tmp-{index:08d}-{shot_id}", item_id))
            for index, item_id in enumerate(item_ids): self.store.conn.execute("UPDATE shot_items SET sort_key=? WHERE id=?", (f"{index:08d}", item_id))
            self.store.conn.execute("UPDATE project_shots SET version=version+1, updated_at=? WHERE id=?", (now(), shot_id)); result = self._project_shot_resource(self.store.conn.execute("SELECT * FROM project_shots WHERE id=?", (shot_id,)).fetchone()); return self._command_record("shot.item.reorder", shot_id, idempotency_key, request_hash, result, project_id=project["id"])

    def _project_reference_resource(self, row):
        value = dict(row); value["reference_id"] = value.pop("id"); value["metadata"] = json.loads(value.pop("metadata_json")); value["archived"] = bool(value.pop("archived_at")); value["media_references"] = []
        for assoc in self.store.conn.execute("SELECT * FROM media_references WHERE reference_id=? ORDER BY ordinal, id", (value["reference_id"],)):
            item = dict(assoc); item["association_id"] = item.pop("id"); item["metadata"] = json.loads(item.pop("metadata_json")); item["is_primary"] = bool(item["is_primary"]); item["media_id"] = "sha256:" + item["media_id"]; value["media_references"].append(item)
        value["links"] = [dict(x) for x in self.store.conn.execute("SELECT * FROM reference_links WHERE from_reference_id=? OR to_reference_id=?", (value["reference_id"], value["reference_id"]))]
        return value

    def get_project_reference(self, project_id, reference_id):
        project = self.store.get_project(project_id); row = self.store.conn.execute("SELECT * FROM project_references WHERE id=? AND project_id=?", (reference_id, project["id"])).fetchone()
        if not row: raise NotFoundError("reference not found")
        return self._project_reference_resource(row)

    @_durable_mutation
    def update_project_reference(self, project_id, reference_id, body, *, idempotency_key=None, archived=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id); expected = self._expected_version(body); action = "update" if archived is None else "archive" if archived else "recover"; request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay(f"reference.{action}", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_references WHERE id=? AND project_id=?", (reference_id, project["id"])).fetchone()
            if not row: raise NotFoundError("reference not found")
            if int(row["version"]) != expected: raise ConflictError("reference version conflict", details={"expected": expected, "actual": int(row["version"])})
            name = str(body.get("name", row["name"])); metadata = body.get("metadata", json.loads(row["metadata_json"]));
            if not name.strip() or not isinstance(metadata, dict): raise ValidationError("invalid reference name or metadata")
            self.store.conn.execute("UPDATE project_references SET name=?, description=?, metadata_json=?, version=version+1, updated_at=?, archived_at=? WHERE id=?", (name, str(body.get("description", row["description"])), canonical_json(metadata), now(), now() if archived is True else None if archived is False else row["archived_at"], reference_id))
            result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record(f"reference.{action}", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def associate_reference(self, project_id, reference_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); media_id = str(body.get("media_id") or "").removeprefix("sha256:"); role = body.get("role") or "depicts"
        if role not in {"canonical", "used_as_input", "depicts", "inspired_by"}: raise ValidationError("invalid reference role")
        self.get_project_reference(project["id"], reference_id)
        if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project["id"], media_id)).fetchone(): raise NotFoundError("media is not owned by project")
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.associate", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            if not isinstance(body.get("metadata", {}), dict): raise ValidationError("metadata must be an object")
            association_id = str(body.get("association_id") or new_id()); stamp = now()
            if role == "canonical": self.store.conn.execute("UPDATE media_references SET is_primary=0 WHERE reference_id=?", (reference_id,))
            self.store.conn.execute("INSERT INTO media_references(id, reference_id, media_id, role, ordinal, is_primary, metadata_json, created_at) VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(ordinal)+1,0) FROM media_references WHERE reference_id=?), ?, ?, ?)", (association_id, reference_id, media_id, role, reference_id, 1 if role == "canonical" else 0, canonical_json(body.get("metadata", {})), stamp))
            self.store.conn.execute("UPDATE project_references SET version=version+1, updated_at=? WHERE id=?", (stamp, reference_id)); result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record("reference.associate", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def link_references(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); source, target, kind = body.get("from_reference_id"), body.get("to_reference_id"), body.get("kind")
        if kind not in {"belongs_to", "wears", "located_in", "associated_with", "related_to"}: raise ValidationError("invalid reference link kind")
        self.get_project_reference(project["id"], source); self.get_project_reference(project["id"], target)
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.link", source, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            stamp = now(); metadata = canonical_json(body.get("metadata", {}))
            self.store.conn.execute("INSERT OR IGNORE INTO reference_links VALUES (?, ?, ?, ?, ?)", (source, target, kind, metadata, stamp))
            if kind == "related_to": self.store.conn.execute("INSERT OR IGNORE INTO reference_links VALUES (?, ?, ?, ?, ?)", (target, source, kind, metadata, stamp))
            result = {"from_reference_id": source, "to_reference_id": target, "kind": kind}; return self._command_record("reference.link", source, idempotency_key, request_hash, result, project_id=project["id"])

    @_durable_mutation
    def set_primary_reference(self, project_id, reference_id, association_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id); self.get_project_reference(project["id"], reference_id); expected = self._expected_version(body); request_hash = hashlib.sha256(canonical_json({"association_id": association_id, **body}).encode()).hexdigest()
        with self.store._mutex:
            replay = self._command_replay("reference.primary", reference_id, idempotency_key, request_hash, project_id=project["id"])
            if replay is not None: return replay
            row = self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()
            if int(row["version"]) != expected: raise ConflictError("reference version conflict", details={"expected": expected, "actual": int(row["version"])})
            assoc = self.store.conn.execute("SELECT * FROM media_references WHERE id=? AND reference_id=?", (association_id, reference_id)).fetchone()
            if not assoc: raise NotFoundError("media association not found")
            self.store.conn.execute("UPDATE media_references SET is_primary=0 WHERE reference_id=?", (reference_id,)); self.store.conn.execute("UPDATE media_references SET is_primary=1, role='canonical' WHERE id=?", (association_id,)); self.store.conn.execute("UPDATE project_references SET version=version+1, updated_at=? WHERE id=?", (now(), reference_id)); result = self._project_reference_resource(self.store.conn.execute("SELECT * FROM project_references WHERE id=?", (reference_id,)).fetchone()); return self._command_record("reference.primary", reference_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_timeline_history(self, timeline_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        self._timeline_resource(timeline_id)
        rows = self.store.conn.execute("SELECT * FROM timeline_revisions WHERE timeline_id=? ORDER BY version", (timeline_id,)).fetchall()
        if not rows:
            current = self._timeline_resource(timeline_id)
            rows = [{"version": current["version"], "shots_json": canonical_json(current["shots"]), "references_json": canonical_json(current["references"]), "created_at": now()}]
        page = _page_rows(rows, scope=f"timeline-history:{timeline_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (int(row["version"]),),
                          resource_fn=lambda row: {"timeline_id": timeline_id, "version": int(row["version"]), "shots": json.loads(row["shots_json"]), "references": json.loads(row["references_json"]), "created_at": row["created_at"]})
        return page

    @staticmethod
    def _diff_items(before, after, key):
        old = {str(item.get(key)): item for item in before}
        new = {str(item.get(key)): item for item in after}
        return {"added": [new[item_id] for item_id in sorted(new.keys() - old.keys())], "removed": [old[item_id] for item_id in sorted(old.keys() - new.keys())], "changed": [{"id": item_id, "before": old[item_id], "after": new[item_id]} for item_id in sorted(old.keys() & new.keys()) if old[item_id] != new[item_id]]}

    def diff_timeline(self, timeline_id, from_version, to_version):
        self._timeline_resource(timeline_id)
        before = self._timeline_revision(timeline_id, int(from_version))
        after = self._timeline_revision(timeline_id, int(to_version))
        return {"timeline_id": timeline_id, "from_version": int(from_version), "to_version": int(to_version), "changes": {"shots": self._diff_items(before["shots"], after["shots"], "shot_id"), "references": self._diff_items(before["references"], after["references"], "reference_id")}}

    @_durable_mutation
    def archive_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        current = self._timeline_resource(timeline_id)
        project_id = str(current["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body, "action": "archive"}).encode()).hexdigest()
        replay = self._command_replay("timeline.archive", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if current["version"] != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": current["version"]})
        with self.store._transaction():
            self.store.conn.execute("UPDATE timelines SET archived_at=?, version=? WHERE id=?", (now(), expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.archived", {"project_id": project_id, "version": resource["version"]})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.archive", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def recover_timeline(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        target = body.get("version")
        if isinstance(target, bool) or not isinstance(target, int) or target < 1:
            raise ValidationError("version must be a positive integer")
        current = self._timeline_resource(timeline_id)
        project_id = str(current["project_id"])
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body, "action": "recover"}).encode()).hexdigest()
        replay = self._command_replay("timeline.recover", timeline_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        if current["version"] != expected:
            raise ConflictError("timeline version conflict", details={"expected": expected, "actual": current["version"]})
        revision = self._timeline_revision(timeline_id, target)
        with self.store._transaction():
            self.store.conn.execute("DELETE FROM timeline_shot_state WHERE id IN (SELECT id FROM timeline_shots WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_reference_state WHERE id IN (SELECT id FROM timeline_references WHERE timeline_id=?)", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_shots WHERE timeline_id=?", (timeline_id,))
            self.store.conn.execute("DELETE FROM timeline_references WHERE timeline_id=?", (timeline_id,))
            for shot in revision["shots"]:
                self.store.conn.execute("INSERT INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (shot["shot_id"], timeline_id, int(shot["start_ms"]), int(shot["duration_ms"]), canonical_json(shot.get("reference_ids", []))))
                self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (shot["shot_id"],))
            for reference in revision["references"]:
                self.store.conn.execute("INSERT INTO timeline_references VALUES (?, ?, ?, ?)", (reference["reference_id"], timeline_id, reference["object_id"], reference.get("role")))
                self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (reference["reference_id"],))
            self.store.conn.execute("UPDATE timelines SET archived_at=NULL, version=? WHERE id=?", (expected + 1, timeline_id))
            resource = self._timeline_resource(timeline_id)
            self._record_timeline_revision(timeline_id, resource)
            event_id = self.store._append_timeline_event(timeline_id, "timeline.recovered", {"project_id": project_id, "version": resource["version"], "target_version": target})
            event_seq = self.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?", (timeline_id,)).fetchone()[0]
            return self._command_record("timeline.recover", timeline_id, idempotency_key, request_hash, resource, project_id=project_id, event_ids=(event_id,), primary_stream_id=timeline_id, resulting_stream_seq=event_seq)

    @_durable_mutation
    def create_shot(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        if not isinstance(body.get("shot_id"), str) or not body["shot_id"]:
            raise ValidationError("shot_id is required")
        if int(body.get("duration_ms", 0)) < 1 or int(body.get("start_ms", 0)) < 0:
            raise ValidationError("invalid shot timing")
        references = body.get("reference_ids", [])
        if not isinstance(references, list) or any(not isinstance(value, str) or not value for value in references):
            raise ValidationError("reference_ids must be a list of non-empty strings")
        self._timeline_resource(timeline_id)
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "shot": body}).encode()).hexdigest()
        # The key is scoped to the create-shot operation, while the request
        # hash binds both the timeline path and complete body.  This makes a
        # key reused for a different timeline or shot a deterministic
        # conflict rather than an unrelated successful mutation.
        aggregate_id = "timeline.shots"
        replay = self._command_replay("timeline.shot.create", aggregate_id, idempotency_key, request_hash)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute(
                "INSERT INTO timeline_shots(id, timeline_id, start_ms, duration_ms, reference_ids_json) VALUES (?, ?, ?, ?, ?)",
                (body["shot_id"], timeline_id, int(body["start_ms"]), int(body["duration_ms"]), canonical_json(references)),
            )
            self.store.conn.execute("INSERT INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["shot_id"],))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("shot already exists", details={"shot_id": body["shot_id"]}) from exc
        result = self._shot_resource(self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (body["shot_id"],)).fetchone())
        return self._command_record("timeline.shot.create", aggregate_id, idempotency_key, request_hash, result)

    def get_shot(self, shot_id):
        row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
        if not row: raise NotFoundError("shot not found")
        return self._shot_resource(row)

    @_durable_mutation
    def create_reference(self, timeline_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        if not isinstance(body.get("reference_id"), str) or not body["reference_id"]:
            raise ValidationError("reference_id is required")
        if not isinstance(body.get("object_id"), str) or not body["object_id"]:
            raise ValidationError("object_id is required")
        self._timeline_resource(timeline_id)
        request_hash = hashlib.sha256(canonical_json({"timeline_id": timeline_id, "reference": body}).encode()).hexdigest()
        aggregate_id = "timeline.references"
        replay = self._command_replay("timeline.reference.create", aggregate_id, idempotency_key, request_hash)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute(
                "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, ?, ?, ?)",
                (body["reference_id"], timeline_id, body["object_id"], body.get("role")),
            )
            self.store.conn.execute("INSERT INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["reference_id"],))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("reference already exists", details={"reference_id": body["reference_id"]}) from exc
        result = self._reference_resource(self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (body["reference_id"],)).fetchone())
        return self._command_record("timeline.reference.create", aggregate_id, idempotency_key, request_hash, result)

    def _document_resource(self, row):
        value = dict(row)
        value["document_id"] = value.pop("id")
        value["content"] = json.loads(value.pop("content_json"))
        return value

    @_durable_mutation
    def create_document(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        document_id = str(body.get("document_id") or "")
        kind = str(body.get("kind") or "")
        if not document_id or not kind or "content" not in body:
            raise ValidationError("document_id, kind, and content are required")
        content = body["content"]
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "document_id": document_id, "kind": kind, "content": content}).encode()).hexdigest()
        replay = self._command_replay("document.create", document_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        existing = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if existing:
            if existing["kind"] == kind and json.loads(existing["content_json"]) == content:
                return self._document_resource(existing)
            raise ConflictError("document already exists", details={"document_id": document_id})
        timestamp = now()
        self.store.conn.execute("INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)", (document_id, project["id"], kind, canonical_json(content), timestamp, timestamp))
        result = self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())
        return self._command_record("document.create", document_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_documents(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"documents:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._document_resource)

    def get_document(self, project_id, document_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if not row:
            raise NotFoundError("document not found")
        return self._document_resource(row)

    @_durable_mutation
    def update_document(self, project_id, document_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        expected = self._expected_version(body)
        project = self.store.get_project(project_id)
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "document_id": document_id, "body": body}).encode()).hexdigest()
        replay = self._command_replay("document.update", document_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        row = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if not row:
            raise NotFoundError("document not found")
        if int(row["version"]) != expected:
            raise ConflictError("document version conflict", details={"expected": expected, "actual": int(row["version"])})
        kind = str(body.get("kind", row["kind"]))
        content = body.get("content", json.loads(row["content_json"]))
        if not kind:
            raise ValidationError("document kind is required")
        timestamp = now()
        self.store.conn.execute("UPDATE project_documents SET kind=?, content_json=?, version=?, updated_at=? WHERE id=?", (kind, canonical_json(content), expected + 1, timestamp, document_id))
        result = self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())
        return self._command_record("document.update", document_id, idempotency_key, request_hash, result, project_id=project["id"])

    def _generation_resource(self, row):
        value = dict(row)
        value["generation_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    @_durable_mutation
    def create_generation(self, project_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        project = self.store.get_project(project_id)
        generation_id = str(body.get("generation_id") or "")
        if not generation_id:
            raise ValidationError("generation_id is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("generation metadata must be an object")
        generation_type = str(body.get("type", "generation"))
        status = str(body.get("status", "created"))
        source_task_id = body.get("source_task_id")
        request_hash = hashlib.sha256(canonical_json({"project_id": project["id"], "generation_id": generation_id, "source_task_id": source_task_id, "type": generation_type, "status": status, "metadata": metadata}).encode()).hexdigest()
        replay = self._command_replay("generation.create", generation_id, idempotency_key, request_hash, project_id=project["id"])
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)", (generation_id, project["id"], source_task_id, generation_type, status, canonical_json(metadata), now(), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("generation already exists", details={"generation_id": generation_id}) from exc
        result = self._generation_resource(self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone())
        return self._command_record("generation.create", generation_id, idempotency_key, request_hash, result, project_id=project["id"])

    def list_generations(self, project_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT * FROM generations WHERE project_id=? ORDER BY created_at, id", (project["id"],)).fetchall()
        return _page_rows(rows, scope=f"generations:{project['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._generation_resource)

    def get_generation(self, generation_id):
        row = self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
        if not row:
            raise NotFoundError("generation not found")
        return self._generation_resource(row)

    @_durable_mutation
    def create_variant(self, generation_id, body, *, idempotency_key=None):
        self._require_object_body(body)
        generation = self.get_generation(generation_id)
        variant_id = str(body.get("variant_id") or "")
        if not variant_id:
            raise ValidationError("variant_id is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("variant metadata must be an object")
        object_id = body.get("object_id")
        if object_id:
            object_id = str(object_id).removeprefix("sha256:")
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (object_id,)).fetchone():
                raise NotFoundError("object not found")
        variant_type = str(body.get("variant_type", "original"))
        request_hash = hashlib.sha256(canonical_json({"generation_id": generation_id, "variant_id": variant_id, "object_id": object_id, "variant_type": variant_type, "metadata": metadata}).encode()).hexdigest()
        replay = self._command_replay("variant.create", variant_id, idempotency_key, request_hash, project_id=generation["project_id"])
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO generation_variants VALUES (?, ?, ?, ?, ?, ?)", (variant_id, generation_id, object_id, variant_type, canonical_json(metadata), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("generation variant already exists", details={"variant_id": variant_id}) from exc
        result = self._variant_resource(self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone())
        return self._command_record("variant.create", variant_id, idempotency_key, request_hash, result, project_id=generation["project_id"])

    @staticmethod
    def _variant_resource(row):
        value = dict(row)
        value["variant_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        if value.get("object_id"):
            value["object_id"] = "sha256:" + value["object_id"]
        return value

    def list_variants(self, generation_id, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        self.get_generation(generation_id)
        rows = self.store.conn.execute("SELECT * FROM generation_variants WHERE generation_id=? ORDER BY created_at, id", (generation_id,)).fetchall()
        return _page_rows(rows, scope=f"variants:{generation_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["id"])),
                          resource_fn=self._variant_resource)

    def get_variant(self, variant_id):
        row = self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone()
        if not row:
            raise NotFoundError("generation variant not found")
        return self._variant_resource(row)

    def get_reference(self, reference_id):
        row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
        if not row: raise NotFoundError("reference not found")
        return self._reference_resource(row)

    def _update_shot_state(self, shot_id, body, *, archived=None, idempotency_key=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
            if not row: raise NotFoundError("shot not found")
            action = "update" if archived is None else "archive" if archived else "recover"
            request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            replay = self._command_replay(f"shot.{action}", shot_id, idempotency_key, request_hash)
            if replay is not None:
                return replay
            state = self.store.conn.execute("SELECT version, archived_at FROM timeline_shot_state WHERE id=?", (shot_id,)).fetchone()
            actual = int(state["version"] if state else 1)
            if expected != actual: raise ConflictError("shot version conflict", details={"expected": expected, "actual": actual})
            if archived is None:
                if state and state["archived_at"]: raise ConflictError("archived shot must be recovered before update")
                start = body.get("start_ms", row["start_ms"]); duration = body.get("duration_ms", row["duration_ms"]); refs = body.get("reference_ids", json.loads(row["reference_ids_json"]))
                if int(start) < 0 or int(duration) < 1 or not isinstance(refs, list): raise ValidationError("invalid shot timing or reference_ids")
            else:
                start, duration, refs = row["start_ms"], row["duration_ms"], json.loads(row["reference_ids_json"])
            with self.store._transaction():
                self.store.conn.execute("UPDATE timeline_shots SET start_ms=?, duration_ms=?, reference_ids_json=? WHERE id=?", (int(start), int(duration), canonical_json(refs), shot_id))
                self.store.conn.execute("INSERT OR REPLACE INTO timeline_shot_state(id, version, archived_at) VALUES (?, ?, ?)", (shot_id, actual + 1, now() if archived is True else None if archived is False else (state["archived_at"] if state else None)))
                result = self.get_shot(shot_id)
                self._command_record(f"shot.{action}", shot_id, idempotency_key, request_hash, result)
            return result

    def update_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, idempotency_key=idempotency_key)
    def archive_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, archived=True, idempotency_key=idempotency_key)
    def recover_shot(self, shot_id, body, *, idempotency_key=None): return self._update_shot_state(shot_id, body, archived=False, idempotency_key=idempotency_key)

    def _update_reference_state(self, reference_id, body, *, archived=None, idempotency_key=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
            if not row: raise NotFoundError("reference not found")
            action = "update" if archived is None else "archive" if archived else "recover"
            request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            replay = self._command_replay(f"reference.{action}", reference_id, idempotency_key, request_hash)
            if replay is not None:
                return replay
            state = self.store.conn.execute("SELECT version, archived_at FROM timeline_reference_state WHERE id=?", (reference_id,)).fetchone()
            actual = int(state["version"] if state else 1)
            if expected != actual: raise ConflictError("reference version conflict", details={"expected": expected, "actual": actual})
            if archived is None:
                if state and state["archived_at"]: raise ConflictError("archived reference must be recovered before update")
                object_id = body.get("object_id", row["object_id"]); role = body.get("role", row["role"])
                if not object_id: raise ValidationError("reference object_id is required")
            else: object_id, role = row["object_id"], row["role"]
            with self.store._transaction():
                self.store.conn.execute("UPDATE timeline_references SET object_id=?, role=? WHERE id=?", (object_id, role, reference_id))
                self.store.conn.execute("INSERT OR REPLACE INTO timeline_reference_state(id, version, archived_at) VALUES (?, ?, ?)", (reference_id, actual + 1, now() if archived is True else None if archived is False else (state["archived_at"] if state else None)))
                result = self.get_reference(reference_id)
                self._command_record(f"reference.{action}", reference_id, idempotency_key, request_hash, result)
            return result

    def update_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, idempotency_key=idempotency_key)
    def archive_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, archived=True, idempotency_key=idempotency_key)
    def recover_reference(self, reference_id, body, *, idempotency_key=None): return self._update_reference_state(reference_id, body, archived=False, idempotency_key=idempotency_key)

    @_durable_mutation
    def ingest(self, project, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise InvalidRequestError("object body must be bytes")
        if len(data) > OBJECT_MAX_BYTES:
            raise ValidationError("object exceeds 64 MiB limit")
        data = bytes(data)
        project_row = self.store.get_project(project)
        expected = (expected_digest or "").removeprefix("sha256:") or None
        request_hash = hashlib.sha256(canonical_json({
            "project_id": project_row["id"],
            "content_digest": sha256_bytes(data),
            "media_type": media_type,
            "original_name": original_name,
            "expected_digest": expected,
        }).encode()).hexdigest()
        aggregate_id = project_row["id"]
        replay = self._command_replay("object.ingest", aggregate_id, idempotency_key, request_hash, project_id=project_row["id"])
        if replay is not None:
            return replay
        destination = self.cas.path_for(sha256_bytes(data))
        if not destination.exists():
            self._begin_cas_publication_journal("ingest", [{"digest": sha256_bytes(data)}], project_id=project_row["id"])
        obj = self.cas.put(data, expected_digest=expected)
        try:
            timestamp = now()
            self.store.conn.execute(
                "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (obj["digest"], obj["size"], media_type, original_name, timestamp),
            )
            self.store.conn.execute(
                "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'managed', ?)",
                (project_row["id"], obj["digest"], timestamp),
            )
            row = dict(self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (obj["digest"],)).fetchone())
            result = self._object_resource(row) | {
                "project": project_row["id"],
                "relation": "managed",
                "deduplicated": obj["deduplicated"],
            }
            return self._command_record("object.ingest", aggregate_id, idempotency_key, request_hash, result, project_id=project_row["id"])
        except Exception:
            # The CAS write precedes the SQLite transaction.  If the durable
            # metadata/receipt transaction fails, remove only the file this
            # command introduced so a retry cannot observe a phantom object.
            if not obj["deduplicated"]:
                self._discard_published_digest(obj["digest"])
            raise

    @_durable_mutation
    def ingest_object(self, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise InvalidRequestError("object body must be bytes")
        if len(data) > OBJECT_MAX_BYTES:
            raise ValidationError("object exceeds 64 MiB limit")
        data = bytes(data)
        expected = (expected_digest or "").removeprefix("sha256:") or None
        request_hash = hashlib.sha256(canonical_json({
            "content_digest": sha256_bytes(data),
            "media_type": media_type,
            "original_name": original_name,
            "expected_digest": expected,
        }).encode()).hexdigest()
        aggregate_id = "objects"
        replay = self._command_replay("object.ingest", aggregate_id, idempotency_key, request_hash, project_id="unscoped")
        if replay is not None:
            return replay
        destination = self.cas.path_for(sha256_bytes(data))
        if not destination.exists():
            self._begin_cas_publication_journal("ingest", [{"digest": sha256_bytes(data)}], project_id="unscoped")
        obj = self.cas.put(data, expected_digest=expected)
        try:
            timestamp = now()
            self.store.conn.execute(
                "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (obj["digest"], obj["size"], media_type, original_name, timestamp),
            )
            result = self._object_resource(dict(self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (obj["digest"],)).fetchone()))
            return self._command_record("object.ingest", aggregate_id, idempotency_key, request_hash, result, project_id="unscoped")
        except Exception:
            if not obj["deduplicated"]:
                self._discard_published_digest(obj["digest"])
            raise

    def _discard_published_digest(self, digest):
        """Remove a newly published CAS file after a failed metadata commit."""
        path = self.cas.path_for(digest)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass

    def _object_resource(self, row):
        return {"object_id": "sha256:" + row["digest"], "digest": "sha256:" + row["digest"], "media_type": row["media_type"], "size": int(row["size"]), "version": 1, "created_at": row["created_at"], **({"filename": row["original_name"]} if row.get("original_name") else {})}

    def object(self, digest):
        digest = digest.removeprefix("sha256:")
        row = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if not row:
            from .errors import NotFoundError
            raise NotFoundError("object not found")
        return dict(row), self.cas.read(digest)

    def objects(self, project):
        return self.store.list_project_objects(project)

    def list_project_objects(self, project, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        rows = self.store.list_project_objects(project)
        return _page_rows(rows, scope=f"objects:{self.store.get_project(project)['id']}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["digest"])),
                          resource_fn=lambda row: self._object_resource(row) | {"relation": row["relation"]})

    @_durable_mutation
    def create_media_relation(self, project, body, *, idempotency_key=None):
        self._require_object_body(body)
        project_id = self.store.get_project(project)["id"]
        allowed = {"derived_from", "variant_of", "uses_as_input", "mask_for", "audio_for"}
        kind = str(body.get("kind") or "")
        if kind not in allowed: raise ValidationError("unsupported media relation kind")
        source = str(body.get("from_object_id") or "").removeprefix("sha256:")
        target = str(body.get("to_object_id") or "").removeprefix("sha256:")
        if not source or not target or source == target: raise ValidationError("media relation requires distinct from_object_id and to_object_id")
        for digest in (source, target):
            if not self.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone(): raise NotFoundError("object not found")
            if not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone(): raise NotFoundError("object is not in project")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict): raise ValidationError("media relation metadata must be an object")
        try:
            ordinal = int(body.get("ordinal", 0))
        except (TypeError, ValueError) as exc:
            raise ValidationError("media relation ordinal must be an integer") from exc
        if ordinal < 0: raise ValidationError("media relation ordinal must be non-negative")
        request_hash = hashlib.sha256(canonical_json({"project_id": project_id, "from_object_id": source, "to_object_id": target, "kind": kind, "ordinal": ordinal, "metadata": metadata}).encode()).hexdigest()
        aggregate_id = "media-relations"
        replay = self._command_replay("media_relation.create", aggregate_id, idempotency_key, request_hash, project_id=project_id)
        if replay is not None:
            return replay
        try:
            self.store.conn.execute("INSERT INTO media_relations VALUES (?, ?, ?, ?, ?, ?, ?)", (project_id, source, target, kind, ordinal, canonical_json(metadata), now()))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("media relation already exists") from exc
        created_at = self.store.conn.execute("SELECT created_at FROM media_relations WHERE project_id=? AND from_digest=? AND to_digest=? AND kind=? AND ordinal=?", (project_id, source, target, kind, ordinal)).fetchone()[0]
        result = {"project_id": project_id, "from_object_id": "sha256:" + source, "to_object_id": "sha256:" + target, "kind": kind, "ordinal": ordinal, "metadata": metadata, "created_at": created_at}
        return self._command_record("media_relation.create", aggregate_id, idempotency_key, request_hash, result, project_id=project_id)

    def list_media_relations(self, project, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        project_id = self.store.get_project(project)["id"]
        rows = self.store.conn.execute("SELECT * FROM media_relations WHERE project_id=? ORDER BY created_at, from_digest, to_digest, kind, ordinal", (project_id,)).fetchall()
        return _page_rows(rows, scope=f"media-relations:{project_id}", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["created_at"]), str(row["from_digest"]), str(row["to_digest"]), str(row["kind"]), int(row["ordinal"])),
                          resource_fn=lambda row: {"project_id": row["project_id"], "from_object_id": "sha256:" + row["from_digest"], "to_object_id": "sha256:" + row["to_digest"], "kind": row["kind"], "ordinal": int(row["ordinal"]), "metadata": json.loads(row["metadata_json"]), "created_at": row["created_at"]})

    def create_task(self, body, *, enforce_readiness=False):
        if "capability" in body or "expected_effect" in body:
            raise ValidationError("legacy task body aliases are not supported")
        capability = body.get("capability_id")
        digest = body.get("capability_digest", "sha256:" + hashlib.sha256(str(capability).encode()).hexdigest())
        value = self.store.create_task(capability, {"input_object_ids": body.get("input_object_ids", []), "schema_version": body.get("schema_version", "1"), "capability_digest": digest, "spec": body.get("spec", {})}, body.get("project"), body.get("idempotency_key"), body.get("settlement_effect"), digest, enforce_readiness=enforce_readiness)
        return value

    def task(self, task_id):
        return self.store.get_task(task_id)

    def run(self, run_id):
        row = self.store.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise NotFoundError("run not found")
        value = dict(row)
        value["spec"] = json.loads(value.pop("spec_json"))
        value["task_ids"] = [task["id"] for task in self.store.conn.execute("SELECT id FROM tasks WHERE run_id=? ORDER BY created_at, id", (run_id,))]
        return value

    def _task_resource(self, value):
        task, run = value["task"], value["run"]
        spec = task.get("spec", {})
        resource = {"task_id": task["id"], "run_id": run["id"], "project_id": run.get("project_id"), "state": "succeeded" if task["status"] == "completed" else ("cancelled" if task["status"] == "cancelled" else task["status"]), "version": int(task.get("attempt", 0)) + 1, "capability_id": task["capability"], "capability_digest": task.get("capability_digest") or spec.get("capability_digest", "sha256:" + hashlib.sha256(task["capability"].encode()).hexdigest()), "schema_version": spec.get("schema_version", "1"), "input_object_ids": spec.get("input_object_ids", []), "spec": spec, "idempotency_key": run.get("idempotency_key") or task["id"], "created_at": task["created_at"], "updated_at": task["updated_at"], "attempt_id": task.get("attempt_id"), "runtime_epoch": int(task.get("runtime_epoch") or self.store._current_runtime_epoch())}
        if task.get("waiting_reason"):
            resource["waiting_reason"] = task["waiting_reason"]
        if task.get("lease_fence"):
            resource["lease_fence"] = task["lease_fence"]
        if task.get("lease_expires_at"):
            resource["lease_expires_at"] = task["lease_expires_at"]
        if task.get("result") is not None:
            resource["result"] = task["result"]
        return resource

    def cancel(self, task_id):
        return self.store.cancel_task(task_id)

    def cancel_task_canonical(self, task_id, body=None, *, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        body = {} if body is None else body
        self._require_object_body(body)
        with self.store._mutex:
            current = self.store.get_task(task_id)
            project_id = current["run"].get("project_id") or "unscoped"
            request_hash = hashlib.sha256(canonical_json({"task_id": task_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("task.cancel", task_id, idempotency_key, request_hash, project_id=project_id)
            if replay is not None:
                return replay
            expected = body.get("expected_version")
            if expected is not None and int(expected) != int(current["task"].get("attempt", 0)) + 1:
                raise ConflictError("stale task version", details={"expected": expected, "actual": int(current["task"].get("attempt", 0)) + 1})
            with self.store._transaction():
                recorded = None
                def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                    nonlocal recorded
                    recorded = self._command_record("task.cancel", task_id, idempotency_key, request_hash, self._task_resource(value), project_id=project_id, event_ids=event_ids, primary_stream_id=primary_stream_id, resulting_stream_seq=resulting_stream_seq)
                self.store.cancel_task(task_id, record=record)
                return recorded

    def retry_task(self, task_id, body=None, *, idempotency_key=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        body = {} if body is None else body
        self._require_object_body(body)
        with self.store._mutex:
            current = self.store.get_task(task_id)
            project_id = current["run"].get("project_id") or "unscoped"
            request_hash = hashlib.sha256(canonical_json({"task_id": task_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("task.retry", task_id, idempotency_key, request_hash, project_id=project_id)
            if replay is not None:
                return replay
            status = current["task"]["status"]
            if status not in {"completed", "cancelled", "failed"}:
                raise ConflictError("task is not retryable", details={"status": status})
            expected = (body or {}).get("expected_version")
            version = int(current["task"].get("attempt", 0)) + 1
            if expected is not None and int(expected) != version:
                raise ConflictError("stale task version", details={"expected": expected, "actual": version})
            with self.store._transaction():
                timestamp = now()
                self.store._release_reservations(task_id, current["task"].get("lease_token"))
                self.store.conn.execute("UPDATE tasks SET status='queued', lease_token=NULL, executor_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, result_json=NULL, attempt_id=NULL, updated_at=? WHERE id=?", (timestamp, task_id))
                self.store.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=?", (timestamp, current["run"]["id"]))
                event_id = self.store._append_event(current["run"]["id"], task_id, "task.retried", {"from_status": status, "attempt": version})
                result = self._task_resource(self.store.get_task(task_id))
                event_seq = self.store.conn.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (current["run"]["id"],)).fetchone()[0]
                return self._command_record("task.retry", task_id, idempotency_key, request_hash, result, project_id=project_id, event_ids=(event_id,), primary_stream_id=current["run"]["id"], resulting_stream_seq=event_seq)

    def events(self, run_id):
        return self.store.list_events(run_id)

    def cancel_run(self, run_id, body=None, *, idempotency_key=None):
        return self._run_resource(self.store.cancel_run(run_id, idempotency_key=idempotency_key))

    def retry_run(self, run_id, body=None, *, idempotency_key=None):
        body = body or {}
        return self._run_resource(self.store.retry_run(run_id, selected_task_ids=body.get("selected_task_ids"), idempotency_key=idempotency_key))

    def _run_resource(self, value):
        result = dict(value)
        result["spec"] = json.loads(result.pop("spec_json"))
        result["task_ids"] = [task["id"] for task in self.store.conn.execute("SELECT id FROM tasks WHERE run_id=? ORDER BY created_at, id", (result["id"],))]
        return result

    def list_capabilities(self, *, cursor=None, limit=PAGE_DEFAULT_LIMIT):
        rows = self.store.conn.execute("SELECT * FROM capabilities ORDER BY id").fetchall()
        return _page_rows(rows, scope="capabilities", cursor=cursor, limit=limit,
                          key_fn=lambda row: (str(row["id"]),),
                          resource_fn=lambda r: self._capability_resource(r))

    def _capability_resource(self, row):
        status = row["status"]
        reason = row["unavailable_reason"]
        if status == "ready" and not self.store.matching_live_executor(row["id"], row["definition_digest"]):
            status, reason = "unavailable", "no_live_matching_executor"
        return {"capability_id": row["id"], "definition_digest": row["definition_digest"], "status": status, "required_resource_keys": json.loads(row["required_resource_keys_json"]), "estimated_scratch_bytes": row["estimated_scratch_bytes"], "estimated_output_bytes": row["estimated_output_bytes"], "unavailable_reason": reason}

    def register_capability(self, body):
        value = self.store.register_capability(body.get("capability_id", ""), body.get("definition_digest", ""), required_resource_keys=body.get("required_resource_keys", []), status=body.get("status", "ready"), unavailable_reason=body.get("unavailable_reason"), estimated_scratch_bytes=body.get("estimated_scratch_bytes", 0), estimated_output_bytes=body.get("estimated_output_bytes", 0))
        # Registration acknowledges the executor's declared state. Discovery
        # computes liveness-aware availability via ``_capability_resource``.
        return {"capability_id": value["id"], "definition_digest": value["definition_digest"], "status": value["status"], "required_resource_keys": value["required_resource_keys"], "estimated_scratch_bytes": value["estimated_scratch_bytes"], "estimated_output_bytes": value["estimated_output_bytes"], "unavailable_reason": value.get("unavailable_reason")}

    @_durable_mutation
    def register_executor(self, body, *, idempotency_key=None, identity=None):
        self._require_object_body(body)
        if not body.get("executor_id"):
            raise ValidationError("executor_id is required")
        self._assert_executor_identity(identity, body.get("executor_id"))
        max_concurrency = int(body.get("max_concurrency", 1))
        if max_concurrency < 1:
            raise ValidationError("max_concurrency must be positive")
        capabilities = body.get("capabilities", [])
        request_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        # Executor registration is an endpoint-scoped command.  The request
        # hash includes executor identity and all registration fields, so a
        # reused key can only replay the exact durable result.
        aggregate_id = "executors"
        existing = self.store.conn.execute("SELECT runtime_epoch FROM executors WHERE id=?", (body["executor_id"],)).fetchone()
        current_epoch = self.store._current_runtime_epoch()
        if body.get("runtime_epoch") is not None:
            self.store._validate_runtime_epoch(
                body.get("runtime_epoch"), identity="executor",
                identity_id=body.get("executor_id"), required=True,
            )
        prior = None
        if idempotency_key is not None:
            validate_idempotency_key(idempotency_key)
            prior = self.store.conn.execute(
                "SELECT request_hash, result_json FROM command_idempotency "
                "WHERE command_kind='executor.register' AND aggregate_id=? AND idempotency_key=?",
                (aggregate_id, idempotency_key),
            ).fetchone()
        if prior:
            if prior["request_hash"] != request_hash:
                raise ConflictError("idempotency key was already used with different input")
            replay = json.loads(prior["result_json"])
            # A replay is safe only in the same runtime session.  In
            # particular, do not let a pre-restart registration refresh a
            # dead executor lease merely because its key is known.
            if int(replay.get("runtime_epoch") or 0) != current_epoch:
                self.store._validate_runtime_epoch(
                    body.get("runtime_epoch"), identity="executor",
                    identity_id=body.get("executor_id"), required=True,
                )
            return replay
        # Re-registration is the canonical reconnect path after a runtime
        # restart or a deliberate capability/readiness refresh.  The bearer
        # fence above binds the caller to this executor (or an administrator),
        # while an existing identity must present the current runtime epoch.
        epoch = self.store._validate_runtime_epoch(
            body.get("runtime_epoch"), identity="executor",
            identity_id=body.get("executor_id"), required=existing is not None,
        )
        self.store.upsert_executor(body["executor_id"], capabilities, max_concurrency, body.get("resource_keys", []), protocol=body.get("protocol", "workspace.v1"), readiness=body.get("readiness", "ready"), readiness_reason=body.get("readiness_reason"), runtime_epoch=epoch)
        result = {"executor_id": body["executor_id"], "max_concurrency": max_concurrency, "resource_keys": body.get("resource_keys", []), "capabilities": capabilities, "protocol": body.get("protocol", "workspace.v1"), "readiness": body.get("readiness", "ready"), "runtime_epoch": epoch}
        return self._command_record("executor.register", aggregate_id, idempotency_key, request_hash, result, project_id="unscoped", with_receipt=False)

    @_durable_mutation
    def claim_next(self, body, *, idempotency_key=None, identity=None):
        """Atomically select, claim, fence, and record a canonical claim.

        A claim has no task path, so its command aggregate is the endpoint's
        claim namespace.  The request hash binds executor, capabilities, and
        runtime epoch; a replay can never consume a second queued task.
        """
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")
        executor_id = body.get("executor_id")
        capability_ids = body.get("capability_ids")
        runtime_epoch = body.get("runtime_epoch")
        if not isinstance(executor_id, str) or not executor_id:
            raise ValidationError("executor_id is required")
        self._assert_executor_identity(identity, executor_id)
        if not isinstance(capability_ids, list) or any(not isinstance(value, str) or not value for value in capability_ids) or len(set(capability_ids)) != len(capability_ids):
            raise ValidationError("capability_ids must be a list of unique non-empty strings")
        if runtime_epoch is not None and (isinstance(runtime_epoch, bool) or not isinstance(runtime_epoch, int) or runtime_epoch < 1):
            raise ValidationError("runtime_epoch must be a positive integer")
        request_hash = hashlib.sha256(canonical_json({
            "executor_id": executor_id, "capability_ids": capability_ids,
            "runtime_epoch": runtime_epoch,
        }).encode()).hexdigest()
        # Epoch validation intentionally precedes the idempotency lookup: a
        # stale worker must never turn an old claim receipt into a live lease.
        epoch = self.store._validate_runtime_epoch(runtime_epoch, identity="executor", identity_id=executor_id, required=True)
        replay = self._command_replay("task.claim", "claim", idempotency_key, request_hash, with_receipt=False)
        if replay is not None:
            return replay
        caps = set(capability_ids)
        rows = self.store.conn.execute("SELECT id, capability FROM tasks WHERE status='queued' ORDER BY created_at, id").fetchall()
        row = next((item for item in rows if not caps or item["capability"] in caps), None)
        if row is None:
            # Persist the empty outcome too.  Otherwise a retry after another
            # task is admitted would silently claim new work.
            return self._command_record("task.claim", "claim", idempotency_key, request_hash, None, project_id="unscoped", with_receipt=False)
        attempt_id, lease_id = new_id(), new_id()
        value = self.store._claim_task(row["id"], executor_id, lease_id, runtime_epoch=epoch, _transactional=False)
        if value["task"]["status"] != "running":
            result = {"task": self._task_resource(value), "waiting_reason": value["task"].get("waiting_reason") or "waiting_for_worker"}
        else:
            task = value["task"]
            fence = int(task.get("lease_fence") or task.get("attempt") or 1)
            expires = task.get("lease_expires_at") or now()
            self.store.conn.execute("INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", (attempt_id, row["id"], lease_id, fence, executor_id, expires, epoch))
            self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=?", (attempt_id, row["id"]))
            # Return the immutable admitted spec alongside the lease. Workers
            # must execute exactly what was claimed, without a racy second read.
            admitted_spec = dict(task.get("spec") or {})
            result = {"attempt_id": attempt_id, "task_id": row["id"], "project_id": value["run"].get("project_id"), "lease_id": lease_id, "fence": fence, "lease_expires_at": expires, "runtime_epoch": epoch, "input_object_ids": list(admitted_spec.get("input_object_ids") or []), "spec": admitted_spec}
        return self._command_record("task.claim", "claim", idempotency_key, request_hash, result, project_id="unscoped", with_receipt=False)

    @_durable_mutation
    def settle_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        # The identity/fence and effect preconditions must precede CAS writes.
        # Keep this entire sequence under the owner mutex so a concurrent
        # recovery cannot invalidate an attempt between validation and
        # publication.
        self._require_object_body(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current_epoch = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", identity_id=row["executor_id"] if row else None, required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone()
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.settle", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current_epoch)
            if not task or (task["runtime_epoch"] is not None and int(task["runtime_epoch"]) != current_epoch):
                raise LeaseError("attempt belongs to a stale runtime epoch")
            if task["status"] != "running" or task["attempt_id"] != attempt_id or task["lease_token"] != row["lease_id"] or int(task["lease_fence"] or 0) != int(row["fence"]):
                raise LeaseError("attempt lease is stale or already settled")
            declared = json.loads(task["expected_effect_json"]) if task["expected_effect_json"] else None
            effect = body.get("effect")
            if effect is not None and declared != effect:
                raise ValidationError("settlement effect was not predeclared", details={"declared": declared})
            if declared is not None and effect is None:
                raise ValidationError("declared settlement effect is required")
            if effect is not None:
                self.store._validate_settlement_effect(effect)
            staged = self._stage_outputs(attempt_id, body.get("outputs", []), project_id=project_id)
            try:
                result = {"outputs": staged["outputs"]}
                recorded = None
                def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                    nonlocal recorded
                    recorded = self._command_record(
                        "attempt.settle", attempt_id, idempotency_key, request_hash,
                        self._task_resource(value), project_id=project_id or "unscoped",
                        event_ids=event_ids, primary_stream_id=primary_stream_id,
                        resulting_stream_seq=resulting_stream_seq,
                    )
                value = self.store._settle_attempt(
                    row["task_id"], row["lease_id"], result,
                    effect=effect, fence=body.get("fence"), attempt_id=attempt_id,
                    publish=lambda: self._publish_staged_outputs(staged, project_id=project_id),
                    record=record,
                )
                staged["committed"] = True
                return recorded
            finally:
                self._discard_staged_outputs(staged)

    def _stage_outputs(self, attempt_id, outputs, *, project_id=None):
        """Validate and stage every output without making it globally reachable."""
        if not isinstance(outputs, list):
            raise ValidationError("outputs must be a list")
        stage_dir = self.store.staging_root / "settlements" / attempt_id
        stage_dir.mkdir(parents=True, exist_ok=True)
        stage_dir.chmod(0o700)
        staged = []
        seen = set()
        try:
            for index, output in enumerate(outputs):
                if not isinstance(output, dict):
                    raise ValidationError("each output must be an object")
                allowed = {"name", "kind", "digest", "media_type", "size", "data_base64"}
                unknown = sorted(set(output) - allowed)
                if unknown:
                    raise ValidationError("output contains unsupported fields", details={"fields": unknown})
                digest_value = output.get("digest")
                if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
                    raise ValidationError("each output requires a sha256 digest")
                digest = digest_value.removeprefix("sha256:")
                if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise ValidationError("each output requires a valid SHA-256 digest")
                if digest in seen:
                    raise ValidationError("outputs must not contain duplicate digests")
                seen.add(digest)
                kind = output.get("kind", "object")
                if not isinstance(kind, str) or kind not in {"object", "document", "value"}:
                    raise ValidationError("output kind is invalid")
                name = output.get("name", "output")
                if not isinstance(name, str) or not name or len(name) > 512:
                    raise ValidationError("output name must be a non-empty string")
                media_type = output.get("media_type", "application/octet-stream")
                if not isinstance(media_type, str) or not media_type or len(media_type) > 255 or any(ord(char) < 32 for char in media_type):
                    raise ValidationError("output media_type is invalid")
                declared_size = output.get("size")
                if declared_size is not None and (isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size < 0 or declared_size > OBJECT_MAX_BYTES):
                    raise ValidationError("output size must be an integer between 0 and 64 MiB")
                data_field = output.get("data_base64")
                stage_path = None
                if data_field is not None:
                    if not isinstance(data_field, str):
                        raise ValidationError("output data_base64 is invalid")
                    try:
                        data = base64.b64decode(data_field, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ValidationError("output data_base64 is invalid") from exc
                    if len(data) > OBJECT_MAX_BYTES:
                        raise ValidationError("output exceeds 64 MiB object limit")
                    actual_digest = sha256_bytes(data)
                    if actual_digest != digest:
                        raise ConflictError("output content hash does not match declared digest", details={"expected": digest_value, "actual": "sha256:" + actual_digest})
                    if declared_size is not None and declared_size != len(data):
                        raise ValidationError("output size does not match staged bytes")
                    stage_path = stage_dir / f"{index:08d}.stage"
                    with open(stage_path, "xb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    size = len(data)
                else:
                    path = self.cas.path_for(digest)
                    if not path.is_file() or path.is_symlink():
                        raise ConflictError("output must be staged or published to runtime CAS before settlement", details={"digest": digest_value})
                    size = path.stat().st_size
                    if size > OBJECT_MAX_BYTES:
                        raise ValidationError("output exceeds 64 MiB object limit")
                    self.cas.verify(digest)
                    if declared_size is not None and declared_size != size:
                        raise ValidationError("output size does not match CAS bytes")
                existing = self.store.conn.execute("SELECT size, media_type FROM objects WHERE digest=?", (digest,)).fetchone()
                if existing:
                    if int(existing["size"]) != size or existing["media_type"] != media_type:
                        raise ConflictError("output metadata does not match existing object", details={"digest": digest_value})
                    if project_id and not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                        raise ConflictError("output object is outside the task project", details={"project_id": project_id, "digest": digest_value})
                elif project_id and stage_path is None and not self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, digest)).fetchone():
                    raise ConflictError("output object is outside the task project", details={"project_id": project_id, "digest": digest_value})
                normalized = {"name": name, "kind": kind, "digest": digest_value, "media_type": media_type, "size": size}
                staged.append({"digest": digest, "path": stage_path, "size": size, "media_type": media_type, "name": name, "output": normalized})
            return {"stage_dir": stage_dir, "attempt_id": attempt_id, "items": staged, "outputs": [item["output"] for item in staged]}
        except Exception:
            self._discard_staged_outputs({"stage_dir": stage_dir, "items": staged})
            raise

    def _publish_staged_outputs(self, staged, *, project_id=None):
        """Publish already validated bytes as part of the settlement transaction."""
        staged.setdefault("published", [])
        candidate_entries = []
        task_id = None
        attempt_id = staged.get("attempt_id")
        if attempt_id:
            row = self.store.conn.execute("SELECT task_id FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            task_id = row["task_id"] if row else None
        for item in staged["items"]:
            destination = self.cas.path_for(item["digest"])
            if item["path"] is not None and not destination.exists():
                candidate_entries.append({"digest": item["digest"]})
        if candidate_entries:
            staged["journal_path"] = self._begin_cas_publication_journal(
                "settlement", candidate_entries, project_id=project_id or "unscoped", task_id=task_id,
            )
        for item in staged["items"]:
            digest = item["digest"]
            destination = self.cas.path_for(digest)
            if item["path"] is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    if destination.is_symlink() or self.cas.read(digest) != item["path"].read_bytes():
                        raise ConflictError("CAS collision or corrupt existing object")
                    item["path"].unlink(missing_ok=True)
                else:
                    os.replace(item["path"], destination)
                    staged["published"].append(destination)
                    # The destination directory is durable before SQLite can
                    # commit the corresponding object metadata.  The durable
                    # publication journal remains until recovery proves the
                    # commit, so a crash can remove only this exact destination.
                    directory_fd = os.open(destination.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            self.store.conn.execute(
                "INSERT OR IGNORE INTO objects(digest, size, media_type, original_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (digest, item["size"], item["media_type"], item["name"], now()),
            )
            if project_id:
                self.store.conn.execute(
                    "INSERT OR IGNORE INTO project_objects(project_id, digest, relation, created_at) VALUES (?, ?, 'managed', ?)",
                    (project_id, digest, now()),
                )

    @staticmethod
    def _discard_staged_outputs(staged):
        stage_dir = staged.get("stage_dir") if isinstance(staged, dict) else None
        committed = bool(staged.get("committed")) if isinstance(staged, dict) else False
        for item in (staged.get("items", []) if isinstance(staged, dict) else []):
            path = item.get("path")
            if path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        if stage_dir is not None:
            # Include a file whose validation failed immediately after its
            # fsync, before it could be appended to ``items``.
            try:
                for path in stage_dir.iterdir():
                    if path.is_file() or path.is_symlink():
                        path.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
            try:
                stage_dir.rmdir()
            except OSError:
                pass
        if not committed:
            for path in (staged.get("published", []) if isinstance(staged, dict) else []):
                try:
                    path.unlink()
                except FileNotFoundError:
                    continue
                except OSError:
                    continue
                try:
                    directory_fd = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass

    def _checkpoint_row(self, checkpoint_id=None, attempt_id=None):
        if checkpoint_id:
            row = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE id=?", (checkpoint_id,)).fetchone()
            if row and attempt_id is not None and row["attempt_id"] != attempt_id:
                raise LeaseError("checkpoint is bound to a different attempt")
        else:
            row = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE attempt_id=? ORDER BY created_at DESC LIMIT 1", (attempt_id,)).fetchone()
        if not row:
            raise NotFoundError("recovery checkpoint not found")
        attempt = self.store.conn.execute("SELECT task_id, executor_id, lease_id, fence FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone()
        if not attempt or attempt["task_id"] != row["task_id"] or attempt["executor_id"] != row["executor_id"] or attempt["lease_id"] != row["lease_id"] or int(attempt["fence"]) != int(row["fence"]):
            raise ConflictError("recovery checkpoint identity is inconsistent")
        return row

    def _reboot_authorized(self, body, attempt_id, expected_nonce=None, *, allow_consumed=False):
        """Validate durable, attempt-bound recovery authorization.

        A nonce supplied by a caller is not sufficient by itself.  It must be
        the nonce persisted by ``prepare_reboot`` for this exact attempt and
        must still be within its short validity window.
        """
        attempt = self.store.conn.execute("SELECT recovery_nonce, recovery_nonce_expires_at, recovery_nonce_used FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        nonce = attempt["recovery_nonce"] if attempt else None
        if "authorization_nonce" in body:
            raise ValidationError("authorization_nonce is not supported; use authorization")
        authorization = body.get("authorization")
        supplied = body.get("nonce")
        if not nonce:
            raise ValidationError("prepare_reboot is required before recovery")
        if attempt["recovery_nonce_used"] and not allow_consumed:
            raise ConflictError("recovery authorization has already been consumed")
        if attempt["recovery_nonce_expires_at"] and attempt["recovery_nonce_expires_at"] <= now():
            raise ValidationError("recovery authorization has expired")
        if not supplied or not authorization or str(supplied) != str(nonce) or str(authorization) != str(nonce) or (expected_nonce is not None and str(expected_nonce) != str(nonce)):
            raise ValidationError("recovery nonce authorization is required")
        return nonce

    def _validate_attempt_lease(self, row, body, current, *, require_epoch=True, allow_expired=False):
        """Validate the complete attempt fence before a mutating side effect."""
        if require_epoch:
            self.store._validate_runtime_epoch(
                body.get("runtime_epoch"),
                identity="executor",
                identity_id=row["executor_id"] if row else None,
                required=True,
            )
        if not row or row["settled"] or int(row["runtime_epoch"]) != current:
            raise LeaseError("attempt lease is stale or already settled")
        try:
            supplied_fence = int(body.get("fence", 0))
        except (TypeError, ValueError) as exc:
            raise LeaseError("attempt fence is invalid") from exc
        if row["lease_id"] != body.get("lease_id") or int(row["fence"]) != supplied_fence:
            raise LeaseError("attempt lease is stale or already settled")
        if not allow_expired and row["lease_expires_at"]:
            try:
                if datetime.fromisoformat(row["lease_expires_at"]) <= datetime.now(timezone.utc):
                    raise LeaseError("attempt lease has expired")
            except ValueError as exc:
                raise LeaseError("attempt lease deadline is invalid") from exc

    def prepare_reboot(self, body=None, *, identity=None):
        """Issue a one-shot nonce for an attempt's recovery handshake."""
        body = body or {}
        attempt_id = body.get("attempt_id")
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        self._assert_attempt_identity(row, identity)
        if not row or row["settled"]:
            raise LeaseError("attempt lease is stale or already settled")
        current = self.store._current_runtime_epoch()
        self._validate_attempt_lease(row, body, current)
        with self.store._mutex:
            with self.store._transaction():
                current_row = self.store.conn.execute("SELECT recovery_nonce, recovery_nonce_expires_at, recovery_nonce_used FROM attempts WHERE id=?", (attempt_id,)).fetchone()
                if current_row["recovery_nonce"] and not current_row["recovery_nonce_used"] and (not current_row["recovery_nonce_expires_at"] or current_row["recovery_nonce_expires_at"] > now()):
                    nonce = current_row["recovery_nonce"]
                    expires_at = current_row["recovery_nonce_expires_at"]
                else:
                    nonce = new_id() + new_id()
                    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(timespec="milliseconds")
                    self.store.conn.execute("UPDATE attempts SET recovery_nonce=?, recovery_nonce_expires_at=?, recovery_nonce_used=0 WHERE id=? AND settled=0", (nonce, expires_at, attempt_id))
        expires_in = max(0, int((datetime.fromisoformat(expires_at) - datetime.now(timezone.utc)).total_seconds()))
        return {"attempt_id": attempt_id, "task_id": row["task_id"], "executor_id": row["executor_id"], "runtime_epoch": current, "nonce": nonce, "expires_in_seconds": expires_in}

    def checkpoint_attempt(self, attempt_id, body, *, identity=None):
        """Persist a bounded, fsync'd R1 checkpoint before a reboot request."""
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current = self.store._current_runtime_epoch()
            self._validate_attempt_lease(row, body, current)
            nonce = self._reboot_authorized(body, attempt_id)
            payload = body.get("checkpoint", body.get("state", {}))
            if not isinstance(payload, (dict, list)):
                raise ValidationError("checkpoint must be an object or array")
            durable_bytes = durable_json_bytes(payload)
            if len(durable_bytes) > CHECKPOINT_MAX_BYTES:
                raise ValidationError("recovery checkpoint exceeds 1 MiB bound")
            # A repeated request with the same durable authorization and bytes
            # is idempotent.  A different payload is a conflict, never a new
            # checkpoint that could be resumed accidentally.
            existing = self.store.conn.execute("SELECT * FROM recovery_checkpoints WHERE attempt_id=? AND nonce=? ORDER BY created_at DESC LIMIT 1", (attempt_id, nonce)).fetchone()
            if existing:
                existing_bytes = Path(existing["checkpoint_path"]).read_bytes()
                if sha256_bytes(existing_bytes) != existing["checkpoint_digest"] or json.loads(existing_bytes.decode("utf-8")) != payload:
                    raise ConflictError("recovery checkpoint authorization already binds different bytes")
                return {"checkpoint_id": existing["id"], "attempt_id": existing["attempt_id"], "task_id": existing["task_id"], "runtime_epoch": existing["runtime_epoch"], "nonce": nonce, "digest": "sha256:" + existing["checkpoint_digest"], "size": existing["checkpoint_size"], "state": existing["state"], "path": existing["checkpoint_path"]}
            checkpoint_id = new_id()
            path = self.store.root / "checkpoints" / f"{checkpoint_id}.json"
            root_identity, root_fd, _ = _pin_directory(self.store.root)
            checkpoints_fd = -1
            try:
                checkpoints_fd = _mkdir_chain_at(root_fd, "checkpoints")
                _write_bytes_at(checkpoints_fd, f"{checkpoint_id}.json", durable_bytes)
                os.fsync(checkpoints_fd)
            finally:
                if checkpoints_fd >= 0:
                    os.close(checkpoints_fd)
                os.close(root_fd)
                _close_pinned(root_identity)
            if durable_bytes != durable_json_bytes(payload):
                raise ConflictError("checkpoint serializer changed while writing")
            digest = sha256_bytes(durable_bytes)
            # atomic_json_write fsyncs the file; fsync the containing directory
            # as well so the rename survives a sudden power loss.
            timestamp = now()
            with self.store._transaction():
                self.store.conn.execute("INSERT INTO recovery_checkpoints(id, attempt_id, task_id, executor_id, runtime_epoch, lease_id, fence, nonce, checkpoint_path, checkpoint_digest, checkpoint_size, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'durable', ?, ?)", (checkpoint_id, attempt_id, row["task_id"], row["executor_id"], current, row["lease_id"], row["fence"], nonce, str(path), digest, len(durable_bytes), timestamp, timestamp))
            return {"checkpoint_id": checkpoint_id, "attempt_id": attempt_id, "task_id": row["task_id"], "runtime_epoch": current, "nonce": nonce, "digest": "sha256:" + digest, "size": len(durable_bytes), "state": "durable", "path": str(path)}

    create_checkpoint = checkpoint_attempt

    def request_reboot(self, body, *, identity=None):
        """Execute only an allowlisted reboot command after durable checkpointing."""
        # Claim and consume the one-shot authorization in the same SQLite
        # transaction as the durable-state transition.  The executor is
        # intentionally called after commit (it may block or terminate the
        # process), but no competing request can pass the claim meanwhile.
        with self.store._mutex:
            current = self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", required=True)
            row = self._checkpoint_row(body.get("checkpoint_id"), body.get("attempt_id"))
            self._assert_attempt_identity(row, identity)
            if row["state"] in {"executed", "resumed"} and row["recovery_receipt_json"]:
                # A completed request is safely replayable, but still require
                # the exact original nonce and authorization.
                self._reboot_authorized(body, row["attempt_id"], row["nonce"], allow_consumed=True)
                return json.loads(row["recovery_receipt_json"])
            self._reboot_authorized(body, row["attempt_id"], row["nonce"])
            command = str(body.get("command") or "reboot")
            if command not in self.reboot_allowlist:
                raise ValidationError("reboot command is not allowlisted", details={"command": command, "allowlist": sorted(self.reboot_allowlist)})
            if int(row["runtime_epoch"]) != self.store._current_runtime_epoch():
                raise LeaseError("reboot checkpoint belongs to a stale runtime epoch")
            attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (row["attempt_id"],)).fetchone()
            self._validate_attempt_lease(attempt, {**body, "lease_id": row["lease_id"], "fence": row["fence"]}, current)
            checkpoint_bytes = Path(row["checkpoint_path"]).read_bytes()
            if sha256_bytes(checkpoint_bytes) != row["checkpoint_digest"]:
                raise ConflictError("recovery checkpoint digest mismatch")
            checkpoint = json.loads(checkpoint_bytes.decode("utf-8"))
            if row["state"] != "durable":
                raise ConflictError("reboot has already been requested", details={"state": row["state"]})
            if self.reboot_executor is None:
                raise ConflictError("reboot executor is unavailable; tests must inject a safe executor")
            timestamp = now()
            with self.store._transaction():
                consumed = self.store.conn.execute("UPDATE attempts SET recovery_nonce_used=1 WHERE id=? AND recovery_nonce_used=0", (row["attempt_id"],))
                if consumed.rowcount != 1:
                    raise ConflictError("recovery authorization has already been consumed")
                claimed = self.store.conn.execute("UPDATE recovery_checkpoints SET state='reboot_requested', updated_at=? WHERE id=? AND state='durable'", (timestamp, row["id"]))
                if claimed.rowcount != 1:
                    raise ConflictError("reboot has already been requested", details={"state": row["state"]})
        executor = self.reboot_executor
        import inspect
        try:
            signature = inspect.signature(executor)
        except (TypeError, ValueError):
            # Some extension/callable objects do not expose a signature.  A
            # single positional invocation is the only safe fallback; never
            # retry after a TypeError raised by the executor itself.
            call = lambda: executor(command, checkpoint)
        else:
            try:
                signature.bind(command=command, checkpoint=checkpoint)
            except TypeError:
                signature.bind(command, checkpoint)
                call = lambda: executor(command, checkpoint)
            else:
                call = lambda: executor(command=command, checkpoint=checkpoint)
        try:
            outcome = call()
        except Exception as exc:
            failure = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": row["attempt_id"], "task_id": row["task_id"], "runtime_epoch": current, "command": command, "status": "failed", "error": {"type": type(exc).__name__, "message": str(exc)}}
            with self.store._mutex:
                with self.store._transaction():
                    self.store.conn.execute("UPDATE recovery_checkpoints SET state='executor_failed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state='reboot_requested'", (canonical_json(failure), now(), row["id"]))
            raise
        receipt = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": row["attempt_id"], "task_id": row["task_id"], "runtime_epoch": self.store._current_runtime_epoch(), "command": command, "status": "executed", "executor_result": outcome}
        with self.store._mutex:
            with self.store._transaction():
                self.store.conn.execute("UPDATE recovery_checkpoints SET state='executed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state='reboot_requested'", (canonical_json(receipt), now(), row["id"]))
        return receipt

    def resume_attempt(self, body, *, identity=None):
        with self.store._mutex:
            current = self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", required=True)
            row = self._checkpoint_row(body.get("checkpoint_id"), body.get("attempt_id"))
            self._assert_attempt_identity(row, identity)
            # request_reboot consumes the one-shot authorization.  The exact
            # consumed token remains the authorization for this checkpoint's
            # one successful resume; it is not a newly reusable nonce.
            self._reboot_authorized(body, row["attempt_id"], row["nonce"], allow_consumed=True)
            if row["state"] == "resumed" and row["recovery_receipt_json"]:
                receipt = json.loads(row["recovery_receipt_json"])
                attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (receipt["attempt_id"],)).fetchone()
                if attempt:
                    return {"receipt": receipt, "attempt": {"attempt_id": attempt["id"], "task_id": attempt["task_id"], "lease_id": attempt["lease_id"], "fence": attempt["fence"], "lease_expires_at": attempt["lease_expires_at"], "runtime_epoch": attempt["runtime_epoch"]}}
            if row["state"] not in {"recovered", "reboot_requested", "executed"}:
                raise ConflictError("checkpoint is not ready for resume", details={"state": row["state"]})
            checkpoint_bytes = Path(row["checkpoint_path"]).read_bytes()
            if sha256_bytes(checkpoint_bytes) != row["checkpoint_digest"]:
                raise ConflictError("recovery checkpoint digest mismatch")
            checkpoint = json.loads(checkpoint_bytes.decode("utf-8"))
            # Claim this exact task.  Never use claim_next here: a mismatch
            # must not consume an unrelated queued task.
            lease_id = new_id()
            claim = self.store._claim_task(row["task_id"], row["executor_id"], lease_id, runtime_epoch=current)
            task = claim["task"]
            if task.get("status") != "running" or task.get("id") != row["task_id"]:
                raise ConflictError("checkpoint task is not queued for resume")
            attempt_id = new_id()
            with self.store._transaction():
                self.store.conn.execute("INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", (attempt_id, row["task_id"], lease_id, task["lease_fence"], row["executor_id"], task["lease_expires_at"], current))
                self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=? AND status='running'", (attempt_id, row["task_id"]))
            resumed_attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            receipt = {"type": "runtime.recovery.receipt", "version": 1, "checkpoint_id": row["id"], "attempt_id": resumed_attempt["id"], "task_id": row["task_id"], "runtime_epoch": current, "command": "resume", "status": "resumed", "checkpoint_digest": "sha256:" + row["checkpoint_digest"], "checkpoint": checkpoint}
            with self.store._transaction():
                self.store.conn.execute("UPDATE recovery_checkpoints SET state='resumed', recovery_receipt_json=?, updated_at=? WHERE id=? AND state IN ('recovered', 'reboot_requested', 'executed')", (canonical_json(receipt), now(), row["id"]))
            return {"receipt": receipt, "attempt": {"attempt_id": resumed_attempt["id"], "task_id": row["task_id"], "lease_id": resumed_attempt["lease_id"], "fence": resumed_attempt["fence"], "lease_expires_at": resumed_attempt["lease_expires_at"], "runtime_epoch": current}}

    resume = resume_attempt

    def heartbeat_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", identity_id=row["executor_id"] if row else None, required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone() if row else None
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.heartbeat", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current)
            recorded = None
            def record(value):
                nonlocal recorded
                expires = value["task"].get("lease_expires_at")
                self.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expires, attempt_id))
                result = {"attempt_id": attempt_id, "task_id": row["task_id"], "lease_id": row["lease_id"], "fence": row["fence"], "lease_expires_at": expires, "runtime_epoch": self.store._current_runtime_epoch()}
                recorded = self._command_record("attempt.heartbeat", attempt_id, idempotency_key, request_hash, result, project_id=project_id or "unscoped")
            self.store.heartbeat_task(row["task_id"], row["lease_id"], fence=row["fence"], lease_seconds=body.get("lease_seconds", 30), record=record)
            return recorded

    def fail_attempt(self, attempt_id, body, *, idempotency_key=None, identity=None):
        idempotency_key = require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            self._assert_attempt_identity(row, identity)
            current = self.store._current_runtime_epoch()
            self.store._validate_runtime_epoch(body.get("runtime_epoch"), identity="executor", identity_id=row["executor_id"] if row else None, required=True)
            task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["task_id"],)).fetchone() if row else None
            project_id = self.store.conn.execute("SELECT project_id FROM runs WHERE id=?", (task["run_id"],)).fetchone()[0] if task else "unscoped"
            request_hash = hashlib.sha256(canonical_json({"attempt_id": attempt_id, "body": body}).encode()).hexdigest()
            replay = self._command_replay("attempt.fail", attempt_id, idempotency_key, request_hash, project_id=project_id or "unscoped")
            if replay is not None:
                return replay
            self._validate_attempt_lease(row, body, current)
            if "reason" in body:
                raise ValidationError("reason is not supported; use error")
            failure = body.get("error") or {"code": "executor_failed"}
            recorded = None
            def record(value, *, event_ids=(), primary_stream_id=None, resulting_stream_seq=None):
                nonlocal recorded
                recorded = self._command_record("attempt.fail", attempt_id, idempotency_key, request_hash, self._task_resource(value), project_id=project_id or "unscoped", event_ids=event_ids, primary_stream_id=primary_stream_id, resulting_stream_seq=resulting_stream_seq)
            self.store.fail_task(row["task_id"], row["lease_id"], failure, fence=row["fence"], attempt_id=attempt_id, record=record)
            return recorded

    def events_page(self, aggregate_id=None, *, cursor=None, limit=50):
        rows = self.store.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        if aggregate_id:
            rows = [row for row in rows if aggregate_id in (row["task_id"], row["run_id"])]
        scope = f"events:{aggregate_id or '*'}"
        return _page_rows(
            rows, scope=scope, cursor=cursor, limit=limit,
            key_fn=lambda row: (str(row["id"]),),
            resource_fn=lambda row: {"event_id": str(row["id"]), "sequence": int(row["id"]), "cursor": str(row["id"]), "event_type": row["kind"], "aggregate_type": "task" if row["task_id"] else "run", "aggregate_id": row["task_id"] or row["run_id"], "payload": json.loads(row["payload_json"]), "occurred_at": row["created_at"]},
        )
