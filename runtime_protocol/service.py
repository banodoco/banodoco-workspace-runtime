from __future__ import annotations

from .cas import ContentAddressedStore
from .store import RealmStore


class RuntimeService:
    """Neutral application service composed by the daemon or an isolated test."""

    def __init__(self, root, *, display_name="Workspace"):
        self.store = RealmStore(root)
        self.cas = ContentAddressedStore(self.store.cas_root)
        self.realm = self.store.ensure_realm(display_name)

    def close(self):
        self.store.close()

    def health(self):
        return {"ok": True, "realm_id": self.realm["id"], "protocol_version": "core-v1", "schema_version": 1, "doctor": self.store.doctor()}

    def create_project(self, body):
        return self.store.create_project(body.get("slug", ""), body.get("name", ""), body.get("metadata"), idempotency_key=body.get("idempotency_key"))

    def get_project(self, selector):
        return self.store.get_project(selector)

    def list_projects(self):
        return self.store.list_projects()

    def update_project(self, selector, body):
        return self.store.update_project(selector, name=body.get("name"), metadata=body.get("metadata"), expected_version=body.get("expected_version"))

    def ingest(self, project, data: bytes, *, media_type="application/octet-stream", original_name=None, expected_digest=None):
        obj = self.cas.put(data, expected_digest=expected_digest)
        row = self.store.record_object(obj["digest"], obj["size"], media_type, original_name)
        self.store.add_object_ref(project, obj["digest"])
        return row | {"project": self.store.get_project(project)["id"], "deduplicated": obj["deduplicated"]}

    def object(self, digest):
        row = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if not row:
            from .errors import NotFoundError
            raise NotFoundError("object not found")
        return dict(row), self.cas.read(digest)

    def objects(self, project):
        return self.store.list_project_objects(project)

    def create_task(self, body):
        return self.store.create_task(body.get("capability", ""), body.get("spec", {}), body.get("project"), body.get("idempotency_key"), body.get("expected_effect"))

    def task(self, task_id):
        return self.store.get_task(task_id)

    def claim(self, task_id, body):
        return self.store.claim_task(task_id, body.get("worker_id", "worker"), body.get("lease_token", ""))

    def settle(self, task_id, body):
        return self.store.settle_task(task_id, body.get("lease_token", ""), body.get("result", {}), effect=body.get("effect"), output_objects=body.get("output_objects"))

    def cancel(self, task_id):
        return self.store.cancel_task(task_id)

    def events(self, run_id):
        return self.store.list_events(run_id)

    def register_worker(self, body):
        return self.store.register_worker(body.get("worker_id", ""), body.get("capabilities", []), body.get("max_concurrency", 1), body.get("resource_keys", []))
