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
