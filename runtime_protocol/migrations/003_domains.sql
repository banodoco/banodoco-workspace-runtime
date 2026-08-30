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
CREATE TABLE IF NOT EXISTS project_documents (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  kind TEXT NOT NULL, content_json TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(project_id, id)
);
CREATE TABLE IF NOT EXISTS generations (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  source_task_id TEXT REFERENCES tasks(id), type TEXT NOT NULL DEFAULT 'generation',
  status TEXT NOT NULL DEFAULT 'created', metadata_json TEXT NOT NULL DEFAULT '{}',
  version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS generation_variants (
  id TEXT PRIMARY KEY, generation_id TEXT NOT NULL REFERENCES generations(id),
  object_id TEXT REFERENCES objects(digest), variant_type TEXT NOT NULL DEFAULT 'original',
  metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
  UNIQUE(generation_id, id)
);
