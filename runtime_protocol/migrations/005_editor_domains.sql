-- Version/archive state for ordered timeline mounts and neutral media lineage.
CREATE TABLE IF NOT EXISTS timeline_shot_state (
  id TEXT PRIMARY KEY REFERENCES timeline_shots(id),
  version INTEGER NOT NULL DEFAULT 1,
  archived_at TEXT
);
CREATE TABLE IF NOT EXISTS timeline_reference_state (
  id TEXT PRIMARY KEY REFERENCES timeline_references(id),
  version INTEGER NOT NULL DEFAULT 1,
  archived_at TEXT
);
CREATE TABLE IF NOT EXISTS media_relations (
  project_id TEXT NOT NULL REFERENCES projects(id),
  from_digest TEXT NOT NULL REFERENCES objects(digest),
  to_digest TEXT NOT NULL REFERENCES objects(digest),
  kind TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  PRIMARY KEY(project_id, from_digest, to_digest, kind)
);
CREATE INDEX IF NOT EXISTS idx_media_relations_project ON media_relations(project_id, created_at);
