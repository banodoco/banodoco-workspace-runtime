from __future__ import annotations

from .cas import ContentAddressedStore
from .store import RealmStore
from .util import canonical_json, new_id, now
import hashlib
import json
from .errors import ConflictError, NotFoundError, ValidationError, LeaseError


class RuntimeService:
    """Neutral application service composed by the daemon or an isolated test."""

    def __init__(self, root, *, display_name="Workspace"):
        self.store = RealmStore(root)
        self.cas = ContentAddressedStore(self.store.cas_root)
        self.realm = self.store.ensure_realm(display_name)
        # These small protocol tables are additive to the Stage 1 store schema;
        # keeping them here lets old realms upgrade without a destructive
        # migration while making attempts and composition durable.
        self.store.conn.executescript("""
        CREATE TABLE IF NOT EXISTS capabilities (
          id TEXT PRIMARY KEY, definition_digest TEXT NOT NULL, status TEXT NOT NULL,
          required_resource_keys_json TEXT NOT NULL, estimated_scratch_bytes INTEGER NOT NULL,
          estimated_output_bytes INTEGER NOT NULL, unavailable_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS executors (
          id TEXT PRIMARY KEY, max_concurrency INTEGER NOT NULL,
          resource_keys_json TEXT NOT NULL, capabilities_json TEXT NOT NULL,
          protocol TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attempts (
          id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
          lease_id TEXT NOT NULL, fence INTEGER NOT NULL, executor_id TEXT NOT NULL,
          lease_expires_at TEXT NOT NULL, settled INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS timelines (
          id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
          version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS timeline_shots (
          id TEXT PRIMARY KEY, timeline_id TEXT NOT NULL REFERENCES timelines(id),
          start_ms INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
          reference_ids_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS timeline_references (
          id TEXT PRIMARY KEY, timeline_id TEXT NOT NULL REFERENCES timelines(id),
          object_id TEXT NOT NULL, role TEXT
        );
        """)
        try:
            self.store.conn.execute("ALTER TABLE tasks ADD COLUMN attempt_id TEXT")
        except Exception:
            pass
        self._ensure_default_capability()

    def close(self):
        self.store.close()

    def health(self):
        return {"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:92a7ec05df9ee82945142e7f294b82236f9bb69e3e3f612adc04b67665b43bf5", "runtime_epoch": 1}

    def realm_resource(self):
        row = self.store.realm
        return {"realm_id": row["id"], "display_name": row["display_name"], "version": 1, "created_at": row["created_at"]}

    def handshake(self, body):
        requested = list(body.get("requested_scopes") or [])
        return {"protocol": "workspace.v1", "schema_digest": "sha256:92a7ec05df9ee82945142e7f294b82236f9bb69e3e3f612adc04b67665b43bf5", "session_id": new_id(), "actor_id": str(body.get("client_name") or "anonymous"), "realm_id": self.realm["id"], "scopes": requested}

    def create_project(self, body, *, idempotency_key=None):
        name = str(body.get("name") or "")
        slug = str(body.get("slug") or "-".join(name.lower().split()))
        slug = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in slug).strip("-") or "project"
        return self.store.create_project(slug, name, body.get("metadata"), idempotency_key=idempotency_key or body.get("idempotency_key"))

    def get_project(self, selector):
        return self.store.get_project(selector)

    def list_projects(self):
        return self.store.list_projects()

    def update_project(self, selector, body):
        return self.store.update_project(selector, name=body.get("name"), metadata=body.get("metadata"), expected_version=body.get("expected_version"))

    def _project_resource(self, value):
        return {"project_id": value["id"], "realm_id": value["realm_id"], "name": value["name"], "version": value["version"], "created_at": value["created_at"], "updated_at": value["updated_at"], "archived": False}

    def _timeline_resource(self, timeline_id):
        row = self.store.conn.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
        if not row: raise NotFoundError("timeline not found")
        shots = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
        refs = [dict(x) for x in self.store.conn.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
        return {"timeline_id": row["id"], "project_id": row["project_id"], "version": row["version"], "shots": [{"shot_id": x["id"], "start_ms": x["start_ms"], "duration_ms": x["duration_ms"], "reference_ids": json.loads(x["reference_ids_json"])} for x in shots], "references": [{"reference_id": x["id"], "object_id": x["object_id"], **({"role": x["role"]} if x["role"] else {})} for x in refs]}

    def create_timeline(self, project_id, timeline_id):
        project = self.store.get_project(project_id)
        self.store.conn.execute("INSERT OR IGNORE INTO timelines VALUES (?, ?, 1, ?)", (timeline_id, project["id"], now()))
        return self._timeline_resource(timeline_id)

    def list_timelines(self, project_id):
        project = self.store.get_project(project_id)
        rows = self.store.conn.execute("SELECT id FROM timelines WHERE project_id=? ORDER BY created_at", (project["id"],))
        return {"items": [self._timeline_resource(x["id"]) for x in rows], "next_cursor": None}

    def create_shot(self, timeline_id, body):
        if int(body.get("duration_ms", 0)) < 1 or int(body.get("start_ms", 0)) < 0: raise ValidationError("invalid shot timing")
        self._timeline_resource(timeline_id)
        self.store.conn.execute("INSERT OR REPLACE INTO timeline_shots VALUES (?, ?, ?, ?, ?)", (body["shot_id"], timeline_id, int(body["start_ms"]), int(body["duration_ms"]), canonical_json(body.get("reference_ids", []))))
        return next(x for x in self._timeline_resource(timeline_id)["shots"] if x["shot_id"] == body["shot_id"])

    def get_shot(self, shot_id):
        row = self.store.conn.execute("SELECT * FROM timeline_shots WHERE id=?", (shot_id,)).fetchone()
        if not row: raise NotFoundError("shot not found")
        return {"shot_id": row["id"], "start_ms": row["start_ms"], "duration_ms": row["duration_ms"], "reference_ids": json.loads(row["reference_ids_json"])}

    def create_reference(self, timeline_id, body):
        self._timeline_resource(timeline_id)
        self.store.conn.execute("INSERT OR REPLACE INTO timeline_references VALUES (?, ?, ?, ?)", (body["reference_id"], timeline_id, body["object_id"], body.get("role")))
        return {k: v for k, v in body.items() if k in {"reference_id", "object_id", "role"}}

    def get_reference(self, reference_id):
        row = self.store.conn.execute("SELECT * FROM timeline_references WHERE id=?", (reference_id,)).fetchone()
        if not row: raise NotFoundError("reference not found")
        return {"reference_id": row["id"], "object_id": row["object_id"], **({"role": row["role"]} if row["role"] else {})}

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

    def create_task(self, body):
        capability = body.get("capability_id") or body.get("capability")
        value = self.store.create_task(capability, {"input_object_ids": body.get("input_object_ids", []), "schema_version": body.get("schema_version", "1"), "capability_digest": body.get("capability_digest", "sha256:" + hashlib.sha256(str(capability).encode()).hexdigest()), "spec": body.get("spec", {})}, body.get("project"), body.get("idempotency_key"), body.get("settlement_effect") or body.get("expected_effect"))
        return value

    def task(self, task_id):
        return self.store.get_task(task_id)

    def _task_resource(self, value):
        task, run = value["task"], value["run"]
        spec = task.get("spec", {})
        return {"task_id": task["id"], "run_id": run["id"], "state": "succeeded" if task["status"] == "completed" else ("cancelled" if task["status"] == "cancelled" else task["status"]), "version": int(task.get("attempt", 0)) + 1, "capability_id": task["capability"], "capability_digest": spec.get("capability_digest", "sha256:" + hashlib.sha256(task["capability"].encode()).hexdigest()), "schema_version": spec.get("schema_version", "1"), "input_object_ids": spec.get("input_object_ids", []), "idempotency_key": run.get("idempotency_key") or task["id"], "created_at": task["created_at"], "updated_at": task["updated_at"], "attempt_id": task.get("attempt_id")}

    def claim(self, task_id, body):
        return self.store.claim_task(task_id, body.get("worker_id", "worker"), body.get("lease_token", ""))

    def settle(self, task_id, body):
        return self.store.settle_task(task_id, body.get("lease_token", ""), body.get("result", {}), effect=body.get("effect"), output_objects=body.get("output_objects"))

    def cancel(self, task_id):
        return self.store.cancel_task(task_id)

    def cancel_task_canonical(self, task_id, body=None):
        current = self.store.get_task(task_id)
        expected = (body or {}).get("expected_version")
        if expected is not None and int(expected) != int(current["task"].get("attempt", 0)) + 1:
            raise ConflictError("stale task version", details={"expected": expected, "actual": int(current["task"].get("attempt", 0)) + 1})
        return self._task_resource(self.store.cancel_task(task_id))

    def retry_task(self, task_id, body=None):
        current = self.store.get_task(task_id)
        expected = (body or {}).get("expected_version")
        version = int(current["task"].get("attempt", 0)) + 1
        if expected is not None and int(expected) != version:
            raise ConflictError("stale task version", details={"expected": expected, "actual": version})
        self.store.conn.execute("UPDATE tasks SET status='queued', lease_token=NULL, worker_id=NULL, updated_at=? WHERE id=?", (now(), task_id))
        self.store.conn.execute("UPDATE runs SET status='queued', updated_at=? WHERE id=?", (now(), current["run"]["id"]))
        return self._task_resource(self.store.get_task(task_id))

    def events(self, run_id):
        return self.store.list_events(run_id)

    def register_worker(self, body):
        return self.store.register_worker(body.get("worker_id", ""), body.get("capabilities", []), body.get("max_concurrency", 1), body.get("resource_keys", []))

    def _ensure_default_capability(self):
        digest = "sha256:" + hashlib.sha256(b"render.basic").hexdigest()
        self.store.conn.execute("INSERT OR IGNORE INTO capabilities VALUES (?, ?, 'ready', ?, 0, 1, NULL)", ("render.basic", digest, "[]"))

    def list_capabilities(self):
        rows = self.store.conn.execute("SELECT * FROM capabilities ORDER BY id").fetchall()
        return {"items": [{"capability_id": r["id"], "definition_digest": r["definition_digest"], "status": r["status"], "required_resource_keys": json.loads(r["required_resource_keys_json"]), "estimated_scratch_bytes": r["estimated_scratch_bytes"], "estimated_output_bytes": r["estimated_output_bytes"], "unavailable_reason": r["unavailable_reason"]} for r in rows]}

    def register_executor(self, body):
        if not body.get("executor_id"):
            raise ValidationError("executor_id is required")
        self.store.conn.execute("INSERT OR REPLACE INTO executors VALUES (?, ?, ?, ?, ?, ?)", (body["executor_id"], int(body.get("max_concurrency", 1)), canonical_json(body.get("resource_keys", [])), canonical_json(body.get("capabilities", [])), body.get("protocol", "workspace.v1"), now()))
        return {"executor_id": body["executor_id"], "max_concurrency": int(body.get("max_concurrency", 1)), "resource_keys": body.get("resource_keys", []), "capabilities": body.get("capabilities", []), "protocol": body.get("protocol", "workspace.v1")}

    def claim_next(self, body):
        caps = set(body.get("capability_ids", []))
        rows = self.store.conn.execute("SELECT id, capability FROM tasks WHERE status='queued' ORDER BY created_at").fetchall()
        row = next((x for x in rows if not caps or x["capability"] in caps), None)
        if row is None:
            return None
        attempt_id, lease_id, fence = new_id(), new_id(), 1
        self.store.claim_task(row["id"], body["executor_id"], lease_id)
        expires = now()
        self.store.conn.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, 0)", (attempt_id, row["id"], lease_id, fence, body["executor_id"], expires))
        self.store.conn.execute("UPDATE tasks SET attempt_id=? WHERE id=?", (attempt_id, row["id"]))
        return {"attempt_id": attempt_id, "task_id": row["id"], "lease_id": lease_id, "fence": fence, "lease_expires_at": expires}

    def settle_attempt(self, attempt_id, body):
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        if not row or row["settled"] or row["lease_id"] != body.get("lease_id") or int(row["fence"]) != int(body.get("fence", 0)):
            raise LeaseError("attempt lease is stale or already settled")
        result = {"outputs": body.get("outputs", [])}
        value = self.store.settle_task(row["task_id"], row["lease_id"], result, effect=body.get("effect"))
        self.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (attempt_id,))
        return self._task_resource(value)

    def heartbeat_attempt(self, attempt_id, body):
        row = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        if not row or row["settled"] or row["lease_id"] != body.get("lease_id") or int(row["fence"]) != int(body.get("fence", 0)):
            raise LeaseError("attempt lease is stale or already settled")
        return {"attempt_id": attempt_id, "task_id": row["task_id"], "lease_id": row["lease_id"], "fence": row["fence"], "lease_expires_at": now()}

    def events_page(self, aggregate_id=None):
        rows = self.store.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        items = []
        for row in rows:
            if aggregate_id and aggregate_id not in (row["task_id"], row["run_id"]): continue
            items.append({"event_id": str(row["id"]), "sequence": int(row["id"]), "cursor": str(row["id"]), "event_type": row["kind"], "aggregate_type": "task" if row["task_id"] else "run", "aggregate_id": row["task_id"] or row["run_id"], "payload": json.loads(row["payload_json"]), "occurred_at": row["created_at"]})
        return {"items": items, "next_cursor": None}
