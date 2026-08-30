from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from .errors import ConflictError, NotFoundError, OwnerBusyError, ValidationError
from .util import canonical_json, new_id, now

try:
    import fcntl
except ImportError:  # pragma: no cover - supported beta host is POSIX
    fcntl = None


SCHEMA_VERSION = 1


class RealmStore:
    """The sole durable writer for one realm.

    A daemon holds ``owner.lock`` for its lifetime.  The connection is
    private to this object and every mutating operation runs under the
    process lock and a SQLite transaction.
    """

    def __init__(self, root: str | Path, *, create: bool = True, acquire_owner: bool = True):
        self.root = Path(root).expanduser().resolve()
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.root / "owner.lock"
        self.db_path = self.root / "realm.sqlite3"
        self.cas_root = self.root / "cas" / "sha256"
        self.staging_root = self.root / "staging"
        self._lock_file = None
        self._mutex = threading.RLock()
        self.conn = None
        if acquire_owner:
            self._acquire_owner()
        try:
            self._open()
        except Exception:
            self.close()
            raise

    @contextmanager
    def _transaction(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    def _acquire_owner(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_file = open(self.lock_path, "a+")
        if fcntl is not None:
            try:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                self._lock_file.close()
                self._lock_file = None
                raise OwnerBusyError("another runtime daemon owns this realm") from exc

    def _open(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.cas_root.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self._migrate()

    def _migrate(self):
        self.conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        version = self.conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise ValidationError(f"database schema {version} is newer than runtime {SCHEMA_VERSION}")
        if version < 1:
            try:
                self.conn.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS realm (
                    id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, realm_id TEXT NOT NULL REFERENCES realm(id),
                    slug TEXT NOT NULL, name TEXT NOT NULL, metadata_json TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    idempotency_key TEXT, UNIQUE(realm_id, slug), UNIQUE(realm_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS objects (
                    digest TEXT PRIMARY KEY, size INTEGER NOT NULL, media_type TEXT NOT NULL,
                    original_name TEXT, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_objects (
                    project_id TEXT NOT NULL REFERENCES projects(id), digest TEXT NOT NULL REFERENCES objects(digest),
                    relation TEXT NOT NULL DEFAULT 'managed', created_at TEXT NOT NULL,
                    PRIMARY KEY(project_id, digest, relation)
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), capability TEXT NOT NULL,
                    spec_json TEXT NOT NULL, status TEXT NOT NULL, idempotency_key TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), capability TEXT NOT NULL,
                    spec_json TEXT NOT NULL, status TEXT NOT NULL, lease_token TEXT,
                    worker_id TEXT, attempt INTEGER NOT NULL DEFAULT 0, expected_effect_json TEXT,
                    result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id),
                    task_id TEXT, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
                    previous_hash TEXT, event_hash TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workers (
                    id TEXT PRIMARY KEY, capabilities_json TEXT NOT NULL, max_concurrency INTEGER NOT NULL,
                    resource_keys_json TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reservations (
                    task_id TEXT NOT NULL REFERENCES tasks(id), resource_key TEXT NOT NULL,
                    lease_token TEXT NOT NULL, created_at TEXT NOT NULL, released_at TEXT,
                    PRIMARY KEY(task_id, resource_key)
                );
                CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);
                CREATE INDEX IF NOT EXISTS idx_projects_realm ON projects(realm_id);
                INSERT INTO schema_migrations(version, applied_at) VALUES (1, datetime('now'));
                COMMIT;
                """)
            except Exception:
                self.conn.rollback()
                raise

    def close(self):
        with self._mutex:
            if self.conn is not None:
                self.conn.close()
                self.conn = None
            if self._lock_file is not None:
                if fcntl is not None:
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                self._lock_file.close()
                self._lock_file = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def realm(self):
        row = self.conn.execute("SELECT * FROM realm LIMIT 1").fetchone()
        return dict(row) if row else None

    def ensure_realm(self, display_name: str = "Workspace"):
        with self._mutex:
            row = self.realm
            if row:
                return row
            rid, timestamp = new_id(), now()
            self.conn.execute("INSERT INTO realm VALUES (?, ?, ?, ?)", (rid, display_name, timestamp, timestamp))
            return dict(self.conn.execute("SELECT * FROM realm WHERE id=?", (rid,)).fetchone())

    def _project(self, selector: str):
        row = self.conn.execute("SELECT * FROM projects WHERE id=? OR slug=?", (selector, selector)).fetchone()
        if not row:
            raise NotFoundError("project not found", details={"project": selector})
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        return result

    def create_project(self, slug: str, name: str, metadata=None, *, idempotency_key=None):
        if not slug or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in slug):
            raise ValidationError("slug must contain only letters, numbers, '-' or '_'")
        if not name:
            raise ValidationError("name is required")
        with self._mutex:
            realm = self.ensure_realm()
            if idempotency_key:
                prior = self.conn.execute("SELECT * FROM projects WHERE realm_id=? AND idempotency_key=?", (realm["id"], idempotency_key)).fetchone()
                if prior:
                    if prior["slug"] != slug or prior["name"] != name or json.loads(prior["metadata_json"]) != (metadata or {}):
                        raise ConflictError("idempotency key was already used with different input")
                    return self._project(prior["id"])
            try:
                pid, timestamp = new_id(), now()
                self.conn.execute("INSERT INTO projects(id, realm_id, slug, name, metadata_json, version, created_at, updated_at, idempotency_key) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                                  (pid, realm["id"], slug, name, canonical_json(metadata or {}), timestamp, timestamp, idempotency_key))
            except sqlite3.IntegrityError as exc:
                raise ConflictError("project slug already exists") from exc
            return self._project(pid)

    def get_project(self, selector: str):
        with self._mutex:
            return self._project(selector)

    def list_projects(self):
        return [self._project(row["id"]) for row in self.conn.execute("SELECT id FROM projects ORDER BY created_at")]

    def update_project(self, selector: str, *, name=None, metadata=None, expected_version=None):
        with self._mutex:
            current = self._project(selector)
            if expected_version is not None and expected_version != current["version"]:
                raise ConflictError("stale project version", details={"expected": expected_version, "actual": current["version"]})
            changed_name = current["name"] if name is None else name
            changed_meta = current["metadata"] if metadata is None else metadata
            timestamp = now()
            self.conn.execute("UPDATE projects SET name=?, metadata_json=?, version=version+1, updated_at=? WHERE id=?",
                              (changed_name, canonical_json(changed_meta), timestamp, current["id"]))
            return self._project(current["id"])

    def add_object_ref(self, project: str, digest: str, relation="managed"):
        with self._mutex:
            p = self._project(project)
            if not self.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone():
                raise NotFoundError("object not found")
            self.conn.execute("INSERT OR IGNORE INTO project_objects VALUES (?, ?, ?, ?)", (p["id"], digest, relation, now()))

    def list_project_objects(self, project: str):
        p = self._project(project)
        rows = self.conn.execute("SELECT o.*, po.relation FROM objects o JOIN project_objects po ON po.digest=o.digest WHERE po.project_id=? ORDER BY o.created_at", (p["id"],)).fetchall()
        return [dict(row) for row in rows]

    def record_object(self, digest, size, media_type, original_name=None):
        with self._mutex:
            self.conn.execute("INSERT OR IGNORE INTO objects VALUES (?, ?, ?, ?, ?)", (digest, size, media_type, original_name, now()))
            return dict(self.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone())

    def create_task(self, capability, spec, project=None, idempotency_key=None, expected_effect=None):
        if not capability:
            raise ValidationError("capability is required")
        with self._mutex:
            project_id = self._project(project)["id"] if project else None
            with self._transaction():
                if idempotency_key:
                    old = self.conn.execute("SELECT * FROM runs WHERE project_id IS ? AND idempotency_key=?", (project_id, idempotency_key)).fetchone()
                    if old:
                        if old["spec_json"] != canonical_json(spec) or old["capability"] != capability:
                            raise ConflictError("idempotency key was already used with different input")
                        task = self.conn.execute("SELECT * FROM tasks WHERE run_id=?", (old["id"],)).fetchone()
                        return self._task_result(old, task)
                timestamp, run_id, task_id = now(), new_id(), new_id()
                self.conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)", (run_id, project_id, capability, canonical_json(spec), idempotency_key, timestamp, timestamp))
                self.conn.execute("INSERT INTO tasks(id, run_id, capability, spec_json, status, expected_effect_json, created_at, updated_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)", (task_id, run_id, capability, canonical_json(spec), canonical_json(expected_effect) if expected_effect else None, timestamp, timestamp))
                self._append_event(run_id, task_id, "task.admitted", {"capability": capability})
                run = dict(self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())
                task = dict(self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
                return self._task_result(run, task)

    def _task_result(self, run, task):
        result = dict(task)
        result["spec"] = json.loads(result.pop("spec_json"))
        if result.get("expected_effect_json"):
            result["expected_effect"] = json.loads(result.pop("expected_effect_json"))
        else:
            result.pop("expected_effect_json", None)
        if result.get("result_json") is not None:
            result["result"] = json.loads(result["result_json"])
        return {"run": dict(run), "task": result}

    def get_task(self, task_id):
        row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise NotFoundError("task not found")
        run = self.conn.execute("SELECT * FROM runs WHERE id=?", (row["run_id"],)).fetchone()
        return self._task_result(run, row)

    def list_events(self, run_id):
        rows = self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload_json"])} for row in rows]

    def _append_event(self, run_id, task_id, kind, payload):
        previous = self.conn.execute("SELECT event_hash FROM events WHERE run_id=? ORDER BY id DESC LIMIT 1", (run_id,)).fetchone()
        previous_hash = previous[0] if previous else ""
        timestamp = now()
        event_hash = hashlib.sha256(canonical_json({"run_id":run_id,"task_id":task_id,"kind":kind,"payload":payload,"previous_hash":previous_hash,"created_at":timestamp}).encode()).hexdigest()
        self.conn.execute("INSERT INTO events(run_id, task_id, kind, payload_json, previous_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (run_id, task_id, kind, canonical_json(payload), previous_hash, event_hash, timestamp))
        return event_hash

    def claim_task(self, task_id, worker_id, lease_token):
        with self._mutex:
            if not worker_id or not lease_token:
                raise ValidationError("worker_id and lease_token are required")
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] != "queued":
                raise ConflictError("task is not claimable", details={"status": task["status"]})
            with self._transaction():
                self.conn.execute("UPDATE tasks SET status='running', worker_id=?, lease_token=?, attempt=attempt+1, updated_at=? WHERE id=? AND status='queued'", (worker_id, lease_token, now(), task_id))
                self.conn.execute("UPDATE runs SET status='running', updated_at=? WHERE id=?", (now(), task["run_id"]))
                self._append_event(task["run_id"], task_id, "task.claimed", {"worker_id": worker_id, "attempt": task["attempt"] + 1})
                return self.get_task(task_id)

    def register_worker(self, worker_id, capabilities, max_concurrency=1, resource_keys=None):
        if not worker_id or max_concurrency < 1:
            raise ValidationError("worker_id and positive max_concurrency are required")
        with self._mutex:
            timestamp = now()
            self.conn.execute("INSERT INTO workers(id, capabilities_json, max_concurrency, resource_keys_json, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET capabilities_json=excluded.capabilities_json, max_concurrency=excluded.max_concurrency, resource_keys_json=excluded.resource_keys_json, last_seen_at=excluded.last_seen_at", (worker_id, canonical_json(capabilities or []), max_concurrency, canonical_json(resource_keys or []), timestamp, timestamp))
            row = self.conn.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
            return dict(row) | {"capabilities": json.loads(row["capabilities_json"]), "resource_keys": json.loads(row["resource_keys_json"])}

    def settle_task(self, task_id, lease_token, result, *, effect=None, output_objects=None):
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] != "running" or task["lease_token"] != lease_token:
                raise LeaseError("attempt lease is stale or already settled")
            declared = json.loads(task["expected_effect_json"]) if task["expected_effect_json"] else None
            if effect is not None and declared != effect:
                raise ValidationError("settlement effect was not predeclared", details={"declared": declared})
            if declared is not None and effect is None:
                raise ValidationError("declared settlement effect is required")
            with self._transaction():
                timestamp = now()
                self.conn.execute("UPDATE tasks SET status='completed', result_json=?, updated_at=? WHERE id=?", (canonical_json(result), timestamp, task_id))
                self.conn.execute("UPDATE runs SET status='completed', updated_at=? WHERE id=?", (timestamp, task["run_id"]))
                self._append_event(task["run_id"], task_id, "task.completed", {"result": result, "effect": effect, "objects": output_objects or []})
                return self.get_task(task_id)

    def cancel_task(self, task_id):
        with self._mutex:
            task = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise NotFoundError("task not found")
            if task["status"] in ("completed", "cancelled"):
                return self.get_task(task_id)
            with self._transaction():
                self.conn.execute("UPDATE tasks SET status='cancelled', updated_at=? WHERE id=?", (now(), task_id))
                self.conn.execute("UPDATE runs SET status='cancelled', updated_at=? WHERE id=?", (now(), task["run_id"]))
                self._append_event(task["run_id"], task_id, "task.cancelled", {})
                return self.get_task(task_id)

    def doctor(self):
        quick = self.conn.execute("PRAGMA quick_check").fetchone()[0]
        fk = self.conn.execute("PRAGMA foreign_key_check").fetchall()
        objects = self.conn.execute("SELECT digest FROM objects").fetchall()
        missing = [row[0] for row in objects if not (self.cas_root / row[0][:2] / row[0][2:]).is_file()]
        event_errors = []
        for run in self.conn.execute("SELECT id FROM runs"):
            previous = ""
            for event in self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (run[0],)):
                if event["previous_hash"] != previous:
                    event_errors.append({"run_id": run[0], "event_id": event["id"], "reason": "broken_link"})
                expected = hashlib.sha256(canonical_json({"run_id": event["run_id"], "task_id": event["task_id"], "kind": event["kind"], "payload": json.loads(event["payload_json"]), "previous_hash": event["previous_hash"], "created_at": event["created_at"]}).encode()).hexdigest()
                if expected != event["event_hash"]:
                    event_errors.append({"run_id": run[0], "event_id": event["id"], "reason": "hash_mismatch"})
                previous = event["event_hash"]
        healthy = quick == "ok" and not fk and not missing and not event_errors
        return {"state": "ready" if healthy else "unhealthy", "ok": healthy, "schema_version": SCHEMA_VERSION, "checks": {"sqlite_quick_check": quick, "foreign_keys": not bool(fk), "cas_missing": missing, "event_chain_errors": event_errors}}
