from __future__ import annotations

from .cas import ContentAddressedStore
from .backup import create_backup, restore_backup, structured_export
from .store import RealmStore
from .util import atomic_json_write
from .util import canonical_json, new_id, now
import hashlib
import json
import sqlite3
import base64
from pathlib import Path
from .errors import ConflictError, NotFoundError, ValidationError, LeaseError
from .contract_metadata import PROTOCOL, SCHEMA_DIGEST


class RuntimeService:
    """Neutral application service composed by the daemon or an isolated test."""

    def __init__(self, root, *, display_name="Workspace", realm_id=None):
        self.store = RealmStore(root)
        self.cas = ContentAddressedStore(self.store.cas_root)
        self.realm = self.store.ensure_realm(display_name, realm_id=realm_id)
        self._ensure_default_capability()

    def close(self):
        self.store.close()

    def backup(self, destination):
        return create_backup(self.store, destination)

    def restore(self, backup_dir, destination):
        return restore_backup(backup_dir, destination)

    def export_structured(self, destination=None):
        value = structured_export(self.store)
        if destination is not None:
            atomic_json_write(Path(destination).expanduser().resolve(), value)
        return value

    def health(self):
        return {"status": "ok", "protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "runtime_epoch": 1}

    def realm_resource(self):
        row = self.store.realm
        return {"realm_id": row["id"], "display_name": row["display_name"], "version": 1, "created_at": row["created_at"]}

    def handshake(self, body):
        requested = list(body.get("requested_scopes") or [])
        actor = body.get("authenticated_actor")
        if not actor:
            raise ValidationError("authenticated actor is required")
        return {"protocol": PROTOCOL, "schema_digest": SCHEMA_DIGEST, "session_id": new_id(), "actor_id": actor, "realm_id": self.realm["id"], "scopes": requested}

    def create_project(self, body, *, idempotency_key=None):
        name = str(body.get("name") or "")
        slug = str(body.get("slug") or "-".join(name.lower().split()))
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in slug).strip("-") or "project"
        return self.store.create_project(slug, name, body.get("metadata"), idempotency_key=idempotency_key or body.get("idempotency_key"))

    def get_project(self, selector):
        return self.store.get_project(selector)

    def list_projects(self):
        return {"items": [self._project_resource(value) for value in self.store.list_projects()["items"]], "next_cursor": None}

    def update_project(self, selector, body):
        return self.store.update_project(selector, name=body.get("name"), metadata=body.get("metadata"), expected_version=body.get("expected_version"))

    def _project_resource(self, value):
        return {"project_id": value["id"], "realm_id": value["realm_id"], "slug": value["slug"], "name": value["name"], "metadata": value.get("metadata", {}), "version": value["version"], "created_at": value["created_at"], "updated_at": value["updated_at"], "archived": False}

    def _timeline_resource(self, timeline_id):
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row: raise NotFoundError("timeline not found")
        shots = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
        refs = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
        return {"timeline_id": row["id"], "project_id": row["project_id"], "version": row["version"], "archived": bool(row["archived_at"]), "shots": [{"shot_id": x["id"], "start_ms": x["start_ms"], "duration_ms": x["duration_ms"], "reference_ids": json.loads(x["reference_ids_json"])} for x in shots], "references": [{"reference_id": x["id"], "object_id": x["object_id"], **({"role": x["role"]} if x["role"] else {})} for x in refs]}

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

    def update_timeline(self, timeline_id, body):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
            if not row:
                raise NotFoundError("timeline not found")
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
                timestamp = now()
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
            return resource

    def create_timeline(self, project_id, timeline_id):
        if not timeline_id:
            raise ValidationError("timeline_id is required")
        project = self.store.get_project(project_id)
        self.store.conn.execute("INSERT OR IGNORE INTO timelines(id, project_id, version, created_at, archived_at) VALUES (?, ?, 1, ?, NULL)", (timeline_id, project["id"], now()))
        resource = self._timeline_resource(timeline_id)
        self._record_timeline_revision(timeline_id, resource)
        return resource

    def list_timelines(self, project_id):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id FROM timelines WHERE project_id=? ORDER BY created_at", (project["id"],))
        return {"items": [self._timeline_resource(x["id"]) for x in rows], "next_cursor": None}

    def _shot_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_shot_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"shot_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "start_ms": int(row["start_ms"]), "duration_ms": int(row["duration_ms"]), "reference_ids": json.loads(row["reference_ids_json"]), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def _reference_resource(self, row):
        state = self.store.conn.execute("SELECT version, archived_at FROM timeline_reference_state WHERE id=?", (row["id"],)).fetchone()
        timeline = self.store.conn.execute("SELECT project_id FROM timelines WHERE id=?", (row["timeline_id"],)).fetchone()
        return {"reference_id": row["id"], "timeline_id": row["timeline_id"], "project_id": timeline["project_id"], "object_id": row["object_id"], **({"role": row["role"]} if row["role"] else {}), "version": int(state["version"] if state else 1), "archived": bool(state and state["archived_at"])}

    def list_project_tasks(self, project_id, *, limit=50):
        project = self.store.get_project(project_id)
        limit = max(1, min(int(limit), 200))
        rows = self.store.conn.execute("SELECT id FROM tasks WHERE run_id IN (SELECT id FROM runs WHERE project_id=?) ORDER BY created_at, id LIMIT ?", (project["id"], limit)).fetchall()
        return {"items": [self._task_resource(self.store.get_task(row["id"])) for row in rows], "next_cursor": None}

    def list_project_runs(self, project_id, *, limit=50):
        project = self.store.get_project(project_id)
        limit = max(1, min(int(limit), 200))
        rows = self.store.conn.execute("SELECT id FROM runs WHERE project_id=? ORDER BY created_at, id LIMIT ?", (project["id"], limit)).fetchall()
        return {"items": [self.run(row["id"]) for row in rows], "next_cursor": None}

    def list_project_shots(self, project_id, *, include_archived=False, limit=50):
        project = self.store.get_project(project_id)
        limit = max(1, min(int(limit), 200))
        query = "SELECT s.* FROM timeline_shots s JOIN timelines t ON t.id=s.timeline_id LEFT JOIN timeline_shot_state st ON st.id=s.id WHERE t.project_id=?"
        if not include_archived: query += " AND st.archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY s.id LIMIT ?", (project["id"], limit)).fetchall()
        return {"items": [self._shot_resource(row) for row in rows], "next_cursor": None}

    def list_project_references(self, project_id, *, include_archived=False, limit=50):
        project = self.store.get_project(project_id)
        limit = max(1, min(int(limit), 200))
        query = "SELECT r.* FROM timeline_references r JOIN timelines t ON t.id=r.timeline_id LEFT JOIN timeline_reference_state st ON st.id=r.id WHERE t.project_id=?"
        if not include_archived: query += " AND st.archived_at IS NULL"
        rows = self.store.conn.execute(query + " ORDER BY r.id LIMIT ?", (project["id"], limit)).fetchall()
        return {"items": [self._reference_resource(row) for row in rows], "next_cursor": None}

    def list_timeline_history(self, timeline_id, *, limit=50):
        self._timeline_resource(timeline_id)
        limit = max(1, min(int(limit), 200))
        rows = self.store.conn.execute("SELECT * FROM timeline_revisions WHERE timeline_id=? ORDER BY version LIMIT ?", (timeline_id, limit)).fetchall()
        items = [{"timeline_id": timeline_id, "version": int(row["version"]), "shots": json.loads(row["shots_json"]), "references": json.loads(row["references_json"]), "created_at": row["created_at"]} for row in rows]
        if not items:
            current = self._timeline_resource(timeline_id)
            items = [{"timeline_id": timeline_id, "version": current["version"], "shots": current["shots"], "references": current["references"], "created_at": now()}]
        return {"items": items, "next_cursor": None}

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

    def archive_timeline(self, timeline_id, body):
        expected = self._expected_version(body)
        with self.store._mutex:
            current = self._timeline_resource(timeline_id)
            if current["version"] != expected:
                raise ConflictError("timeline version conflict", details={"expected": expected, "actual": current["version"]})
            with self.store._transaction():
                self.store.conn.execute("UPDATE timelines SET archived_at=?, version=? WHERE id=?", (now(), expected + 1, timeline_id))
                resource = self._timeline_resource(timeline_id)
                self._record_timeline_revision(timeline_id, resource)
            return resource

    def recover_timeline(self, timeline_id, body):
        expected = self._expected_version(body)
        target = body.get("version")
        if isinstance(target, bool) or not isinstance(target, int) or target < 1:
            raise ValidationError("version must be a positive integer")
        with self.store._mutex:
            current = self._timeline_resource(timeline_id)
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
            return resource

    def create_shot(self, timeline_id, body):
        if int(body.get("duration_ms", 0)) < 1 or int(body.get("start_ms", 0)) < 0: raise ValidationError("invalid shot timing")
        self._timeline_resource(timeline_id)
        self.store.conn.execute("INSERT OR REPLACE INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (body["shot_id"], timeline_id, int(body["start_ms"]), int(body["duration_ms"]), canonical_json(body.get("reference_ids", []))))
        self.store.conn.execute("INSERT OR IGNORE INTO timeline_shot_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["shot_id"],))
        return self._shot_resource(self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (body["shot_id"],)).fetchone())

    def get_shot(self, shot_id):
        row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
        if not row: raise NotFoundError("shot not found")
        return self._shot_resource(row)

    def create_reference(self, timeline_id, body):
        self._timeline_resource(timeline_id)
        self.store.conn.execute("INSERT OR REPLACE INTO timeline_references VALUES (?, ?, ?, ?)", (body["reference_id"], timeline_id, body["object_id"], body.get("role")))
        self.store.conn.execute("INSERT OR IGNORE INTO timeline_reference_state(id, version, archived_at) VALUES (?, 1, NULL)", (body["reference_id"],))
        return self._reference_resource(self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (body["reference_id"],)).fetchone())

    def _document_resource(self, row):
        value = dict(row)
        value["document_id"] = value.pop("id")
        value["content"] = json.loads(value.pop("content_json"))
        return value

    def create_document(self, project_id, body):
        project = self.store.get_project(project_id)
        document_id = str(body.get("document_id") or "")
        kind = str(body.get("kind") or "")
        if not document_id or not kind or "content" not in body:
            raise ValidationError("document_id, kind, and content are required")
        content = body["content"]
        with self.store._mutex:
            existing = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
            if existing:
                if existing["kind"] == kind and json.loads(existing["content_json"]) == content:
                    return self._document_resource(existing)
                raise ConflictError("document already exists", details={"document_id": document_id})
            timestamp = now()
            self.store.conn.execute("INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)", (document_id, project["id"], kind, canonical_json(content), timestamp, timestamp))
            return self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())

    def list_documents(self, project_id):
        project = self.store.get_project(project_id)
        return {"items": [self._document_resource(row) for row in self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? ORDER BY created_at, id", (project["id"],))], "next_cursor": None}

    def get_document(self, project_id, document_id):
        project = self.store.get_project(project_id)
        row = self.store.conn.execute("SELECT * FROM project_documents WHERE project_id=? AND id=?", (project["id"], document_id)).fetchone()
        if not row:
            raise NotFoundError("document not found")
        return self._document_resource(row)

    def update_document(self, project_id, document_id, body):
        expected = self._expected_version(body)
        project = self.store.get_project(project_id)
        with self.store._mutex:
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
            return self._document_resource(self.store.conn.execute("SELECT * FROM project_documents WHERE id=?", (document_id,)).fetchone())

    def _generation_resource(self, row):
        value = dict(row)
        value["generation_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    def create_generation(self, project_id, body):
        project = self.store.get_project(project_id)
        generation_id = str(body.get("generation_id") or "")
        if not generation_id:
            raise ValidationError("generation_id is required")
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValidationError("generation metadata must be an object")
        with self.store._mutex:
            try:
                self.store.conn.execute("INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)", (generation_id, project["id"], body.get("source_task_id"), body.get("type", "generation"), body.get("status", "created"), canonical_json(metadata), now(), now()))
            except sqlite3.IntegrityError as exc:
                raise ConflictError("generation already exists", details={"generation_id": generation_id}) from exc
            return self._generation_resource(self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone())

    def list_generations(self, project_id):
        project = self.store.get_project(project_id)
        return {"items": [self._generation_resource(row) for row in self.store.conn.execute("SELECT * FROM generations WHERE project_id=? ORDER BY created_at, id", (project["id"],))], "next_cursor": None}

    def get_generation(self, generation_id):
        row = self.store.conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
        if not row:
            raise NotFoundError("generation not found")
        return self._generation_resource(row)

    def create_variant(self, generation_id, body):
        self.get_generation(generation_id)
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
        with self.store._mutex:
            try:
                self.store.conn.execute("INSERT INTO generation_variants VALUES (?, ?, ?, ?, ?, ?)", (variant_id, generation_id, object_id, body.get("variant_type", "original"), canonical_json(metadata), now()))
            except sqlite3.IntegrityError as exc:
                raise ConflictError("generation variant already exists", details={"variant_id": variant_id}) from exc
            return self._variant_resource(self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone())

    @staticmethod
    def _variant_resource(row):
        value = dict(row)
        value["variant_id"] = value.pop("id")
        value["metadata"] = json.loads(value.pop("metadata_json"))
        if value.get("object_id"):
            value["object_id"] = "sha256:" + value["object_id"]
        return value

    def list_variants(self, generation_id):
        self.get_generation(generation_id)
        return {"items": [self._variant_resource(row) for row in self.store.conn.execute("SELECT * FROM generation_variants WHERE generation_id=? ORDER BY created_at, id", (generation_id,))], "next_cursor": None}

    def get_variant(self, variant_id):
        row = self.store.conn.execute("SELECT * FROM generation_variants WHERE id=?", (variant_id,)).fetchone()
        if not row:
            raise NotFoundError("generation variant not found")
        return self._variant_resource(row)

    def get_reference(self, reference_id):
        row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
        if not row: raise NotFoundError("reference not found")
        return self._reference_resource(row)

    def _update_shot_state(self, shot_id, body, *, archived=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
            if not row: raise NotFoundError("shot not found")
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
            return self.get_shot(shot_id)

    def update_shot(self, shot_id, body): return self._update_shot_state(shot_id, body)
    def archive_shot(self, shot_id, body): return self._update_shot_state(shot_id, body, archived=True)
    def recover_shot(self, shot_id, body): return self._update_shot_state(shot_id, body, archived=False)

    def _update_reference_state(self, reference_id, body, *, archived=None):
        expected = self._expected_version(body)
        with self.store._mutex:
            row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
            if not row: raise NotFoundError("reference not found")
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
            return self.get_reference(reference_id)

    def update_reference(self, reference_id, body): return self._update_reference_state(reference_id, body)
    def archive_reference(self, reference_id, body): return self._update_reference_state(reference_id, body, archived=True)
    def recover_reference(self, reference_id, body): return self._update_reference_state(reference_id, body, archived=False)

    def ingest(self, project, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None):
        obj = self.cas.put(data, expected_digest=expected_digest)
        row = self.store.record_object(obj["digest"], obj["size"], media_type, original_name)
        self.store.add_object_ref(project, obj["digest"])
        return row | {"project": self.store.get_project(project)["id"], "deduplicated": obj["deduplicated"]}

    def ingest_object(self, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None):
        obj = self.cas.put(data, expected_digest=(expected_digest or "").removeprefix("sha256:") or None)
        return self._object_resource(self.store.record_object(obj["digest"], obj["size"], media_type, original_name))

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

    def list_project_objects(self, project, *, limit=50):
        limit = max(1, min(int(limit), 200))
        items = []
        for row in self.store.list_project_objects(project)[:limit]:
            item = self._object_resource(row)
            item["relation"] = row["relation"]
            items.append(item)
        return {"items": items, "next_cursor": None}

    def create_media_relation(self, project, body):
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
        with self.store._mutex:
            try:
                self.store.conn.execute("INSERT INTO media_relations VALUES (?, ?, ?, ?, ?, ?)", (project_id, source, target, kind, canonical_json(metadata), now()))
            except sqlite3.IntegrityError as exc:
                raise ConflictError("media relation already exists") from exc
        return {"project_id": project_id, "from_object_id": "sha256:" + source, "to_object_id": "sha256:" + target, "kind": kind, "metadata": metadata, "created_at": self.store.conn.execute("SELECT created_at FROM media_relations WHERE project_id=? AND from_digest=? AND to_digest=? AND kind=?", (project_id, source, target, kind)).fetchone()[0]}

    def list_media_relations(self, project, *, limit=50):
        project_id = self.store.get_project(project)["id"]
        limit = max(1, min(int(limit), 200))
        rows = self.store.conn.execute("SELECT * FROM media_relations WHERE project_id=? ORDER BY created_at, from_digest, to_digest, kind LIMIT ?", (project_id, limit)).fetchall()
        return {"items": [{"project_id": row["project_id"], "from_object_id": "sha256:" + row["from_digest"], "to_object_id": "sha256:" + row["to_digest"], "kind": row["kind"], "metadata": json.loads(row["metadata_json"]), "created_at": row["created_at"]} for row in rows], "next_cursor": None}

    def create_task(self, body):
        capability = body.get("capability_id") or body.get("capability")
        digest = body.get("capability_digest", "sha256:" + hashlib.sha256(str(capability).encode()).hexdigest())
        value = self.store.create_task(capability, {"input_object_ids": body.get("input_object_ids", []), "schema_version": body.get("schema_version", "1"), "capability_digest": digest, "spec": body.get("spec", {})}, body.get("project"), body.get("idempotency_key"), body.get("settlement_effect") or body.get("expected_effect"), digest)
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
        resource = {"task_id": task["id"], "run_id": run["id"], "state": "succeeded" if task["status"] == "completed" else ("cancelled" if task["status"] == "cancelled" else task["status"]), "version": int(task.get("attempt", 0)) + 1, "capability_id": task["capability"], "capability_digest": task.get("capability_digest") or spec.get("capability_digest", "sha256:" + hashlib.sha256(task["capability"].encode()).hexdigest()), "schema_version": spec.get("schema_version", "1"), "input_object_ids": spec.get("input_object_ids", []), "idempotency_key": run.get("idempotency_key") or task["id"], "created_at": task["created_at"], "updated_at": task["updated_at"], "attempt_id": task.get("attempt_id")}
        if task.get("waiting_reason"):
            resource["waiting_reason"] = task["waiting_reason"]
        if task.get("lease_fence"):
            resource["lease_fence"] = task["lease_fence"]
        if task.get("lease_expires_at"):
            resource["lease_expires_at"] = task["lease_expires_at"]
        return resource

    def claim(self, task_id, body):
        return self.store.claim_task(task_id, body.get("worker_id", "worker"), body.get("lease_token", ""))

    def settle(self, task_id, body):
        return self.store.settle_task(task_id, body.get("lease_token", ""), body.get("result", {}), effect=body.get("effect"), output_objects=body.get("output_objects"), fence=body.get("fence"))

    def heartbeat(self, task_id, body):
        return self.store.heartbeat_task(task_id, body.get("lease_token", ""), fence=body.get("fence"), lease_seconds=body.get("lease_seconds", 30))

    def cancel(self, task_id):
        return self.store.cancel_task(task_id)

    def cancel_task_canonical(self, task_id, body=None):
        current = self.store.get_task(task_id)
        expected = (body or {}).get("expected_version")
        if expected is not None and int(expected) != int(current["task"].get("attempt", 0)) + 1:
            raise ConflictError("stale task version", details={"expected": expected, "actual": int(current["task"].get("attempt", 0)) + 1})
        return self._task_resource(self.store.cancel_task(task_id))

    def retry_task(self, task_id, body=None):
        with self.store._mutex:
            current = self.store.get_task(task_id)
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
                self.store.conn.execute("UPDATE tasks SET status='queued', lease_token=NULL, worker_id=NULL, lease_expires_at=NULL, waiting_reason=NULL, result_json=NULL, attempt_id=NULL, updated_at=? WHERE id=?", (timestamp, task_id))
                self.store.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=?", (timestamp, current["run"]["id"]))
                self.store._append_event(current["run"]["id"], task_id, "task.retried", {"from_status": status, "attempt": version})
            return self._task_resource(self.store.get_task(task_id))

    def events(self, run_id):
        return self.store.list_events(run_id)

    def register_worker(self, body):
        return self.store.register_worker(body.get("worker_id", ""), body.get("capabilities", []), body.get("max_concurrency", 1), body.get("resource_keys", []), readiness=body.get("readiness", "ready"), readiness_reason=body.get("readiness_reason"))

    def _ensure_default_capability(self):
        digest = "sha256:" + hashlib.sha256(b"render.basic").hexdigest()
        self.store.register_capability("render.basic", digest, required_resource_keys=[], estimated_output_bytes=1)

    def list_capabilities(self):
        rows = self.store.conn.execute("SELECT * FROM capabilities ORDER BY id").fetchall()
        return {"items": [{"capability_id": r["id"], "definition_digest": r["definition_digest"], "status": r["status"], "required_resource_keys": json.loads(r["required_resource_keys_json"]), "estimated_scratch_bytes": r["estimated_scratch_bytes"], "estimated_output_bytes": r["estimated_output_bytes"], "unavailable_reason": r["unavailable_reason"]} for r in rows]}

    def register_capability(self, body):
        value = self.store.register_capability(body.get("capability_id", ""), body.get("definition_digest", ""), required_resource_keys=body.get("required_resource_keys", []), status=body.get("status", "ready"), unavailable_reason=body.get("unavailable_reason"), estimated_scratch_bytes=body.get("estimated_scratch_bytes", 0), estimated_output_bytes=body.get("estimated_output_bytes", 0))
        return {"capability_id": value["id"], "definition_digest": value["definition_digest"], "status": value["status"], "required_resource_keys": value["required_resource_keys"], "estimated_scratch_bytes": value["estimated_scratch_bytes"], "estimated_output_bytes": value["estimated_output_bytes"], "unavailable_reason": value.get("unavailable_reason")}

    def worker_heartbeat(self, worker_id, body):
        return self.store.heartbeat_worker(worker_id, ready=body.get("ready"), reason=body.get("reason"))

    def register_executor(self, body):
        if not body.get("executor_id"):
            raise ValidationError("executor_id is required")
        max_concurrency = int(body.get("max_concurrency", 1))
        if max_concurrency < 1:
            raise ValidationError("max_concurrency must be positive")
        capabilities = body.get("capabilities", [])
        self.store.register_worker(body["executor_id"], capabilities, max_concurrency, body.get("resource_keys", []), readiness=body.get("readiness", "ready"), readiness_reason=body.get("readiness_reason"))
        self.store.conn.execute("INSERT OR REPLACE INTO executors VALUES (?, ?, ?, ?, ?, ?)", (body["executor_id"], max_concurrency, canonical_json(body.get("resource_keys", [])), canonical_json(capabilities), body.get("protocol", "workspace.v1"), now()))
        return {"executor_id": body["executor_id"], "max_concurrency": max_concurrency, "resource_keys": body.get("resource_keys", []), "capabilities": capabilities, "protocol": body.get("protocol", "workspace.v1"), "readiness": body.get("readiness", "ready")}

    def claim_next(self, body):
        caps = set(body.get("capability_ids", []))
        rows = self.store.conn.execute("SELECT id, capability FROM tasks WHERE status='queued' ORDER BY created_at").fetchall()
        row = next((x for x in rows if not caps or x["capability"] in caps), None)
        if row is None:
            return None
        attempt_id, lease_id = new_id(), new_id()
        value = self.store.claim_task(row["id"], body["executor_id"], lease_id)
        if value["task"]["status"] != "running":
            return {"task": self._task_resource(value), "waiting_reason": value["task"].get("waiting_reason") or "waiting_for_worker"}
        task = value["task"]
        fence = int(task.get("lease_fence") or task.get("attempt") or 1)
        expires = task.get("lease_expires_at") or now()
        self.store.conn.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, 0)", (attempt_id, row["id"], lease_id, fence, body["executor_id"], expires))
        self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=?", (attempt_id, row["id"]))
        return {"attempt_id": attempt_id, "task_id": row["id"], "lease_id": lease_id, "fence": fence, "lease_expires_at": expires}

    def settle_attempt(self, attempt_id, body):
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        if not row or row["settled"] or row["lease_id"] != body.get("lease_id") or int(row["fence"]) != int(body.get("fence", 0)):
            raise LeaseError("attempt lease is stale or already settled")
        outputs = self._publish_outputs(body.get("outputs", []))
        result = {"outputs": outputs}
        value = self.store.settle_task(row["task_id"], row["lease_id"], result, effect=body.get("effect"), fence=body.get("fence"))
        self.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (attempt_id,))
        return self._task_resource(value)

    def _publish_outputs(self, outputs):
        if not isinstance(outputs, list):
            raise ValidationError("outputs must be a list")
        published = []
        for output in outputs:
            if not isinstance(output, dict) or not output.get("digest"):
                raise ValidationError("each output requires a digest")
            digest = str(output["digest"]).removeprefix("sha256:")
            data_field = output.get("data_base64")
            if data_field is not None:
                try:
                    data = base64.b64decode(data_field, validate=True)
                except (ValueError, TypeError) as exc:
                    raise ValidationError("output data_base64 is invalid") from exc
                stored = self.cas.put(data, expected_digest=digest)
                size = stored["size"]
            else:
                path = self.cas.path_for(digest)
                if not path.is_file():
                    raise ConflictError("output must be published to runtime CAS before settlement", details={"digest": output["digest"]})
                size = path.stat().st_size
                self.cas.verify(digest)
            self.store.record_object(digest, size, output.get("media_type", "application/octet-stream"), output.get("name"))
            published.append({key: value for key, value in output.items() if key != "data_base64"})
        return published

    def heartbeat_attempt(self, attempt_id, body):
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        if not row or row["settled"] or row["lease_id"] != body.get("lease_id") or int(row["fence"]) != int(body.get("fence", 0)):
            raise LeaseError("attempt lease is stale or already settled")
        value = self.store.heartbeat_task(row["task_id"], row["lease_id"], fence=row["fence"], lease_seconds=body.get("lease_seconds", 30))
        expires = value["task"].get("lease_expires_at")
        self.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expires, attempt_id))
        return {"attempt_id": attempt_id, "task_id": row["task_id"], "lease_id": row["lease_id"], "fence": row["fence"], "lease_expires_at": expires}

    def fail_attempt(self, attempt_id, body):
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        if not row or row["settled"] or row["lease_id"] != body.get("lease_id") or int(row["fence"]) != int(body.get("fence", 0)):
            raise LeaseError("attempt lease is stale or already settled")
        failure = body.get("error") or body.get("reason") or {"code": "executor_failed"}
        value = self.store.fail_task(row["task_id"], row["lease_id"], failure, fence=row["fence"])
        self.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (attempt_id,))
        return self._task_resource(value)

    def events_page(self, aggregate_id=None, *, cursor=None, limit=50):
        try:
            page_size = max(1, min(200, int(limit)))
            after = int(cursor or 0)
        except (TypeError, ValueError) as exc:
            raise ValidationError("cursor and limit must be valid integers") from exc
        rows = self.store.conn.execute("SELECT * FROM events WHERE id>? ORDER BY id", (after,)).fetchall()
        items = []
        for row in rows:
            if aggregate_id and aggregate_id not in (row["task_id"], row["run_id"]): continue
            items.append({"event_id": str(row["id"]), "sequence": int(row["id"]), "cursor": str(row["id"]), "event_type": row["kind"], "aggregate_type": "task" if row["task_id"] else "run", "aggregate_id": row["task_id"] or row["run_id"], "payload": json.loads(row["payload_json"]), "occurred_at": row["created_at"]})
        next_cursor = None
        if len(items) > page_size:
            items = items[:page_size]
            next_cursor = items[-1]["cursor"]
        return {"items": items, "next_cursor": next_cursor}
