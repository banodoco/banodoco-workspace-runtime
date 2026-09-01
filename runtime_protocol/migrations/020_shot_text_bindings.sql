-- Immutable, project-scoped text pointers for project shots.
CREATE TABLE IF NOT EXISTS shot_text_bindings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  shot_id TEXT NOT NULL REFERENCES project_shots(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('prompt', 'voiceover_script', 'transcript')),
  slot TEXT CHECK (slot IS NULL OR (kind = 'prompt' AND length(slot) BETWEEN 1 AND 64)),
  media_digest TEXT NOT NULL REFERENCES objects(digest) ON DELETE RESTRICT,
  event_stream_id TEXT NOT NULL UNIQUE,
  head_seq INTEGER NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS shot_text_binding_singleton
  ON shot_text_bindings(project_id, shot_id, kind) WHERE slot IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS shot_text_binding_slot
  ON shot_text_bindings(project_id, shot_id, kind, slot) WHERE slot IS NOT NULL;
CREATE INDEX IF NOT EXISTS shot_text_binding_lookup
  ON shot_text_bindings(project_id, shot_id, kind, slot);

CREATE TABLE IF NOT EXISTS shot_text_binding_events (
  event_id TEXT PRIMARY KEY,
  binding_id TEXT NOT NULL REFERENCES shot_text_bindings(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  seq INTEGER NOT NULL CHECK (seq > 0),
  kind TEXT NOT NULL CHECK (kind IN ('shot.text_binding.created', 'shot.text_binding.rebound')),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(binding_id, seq)
);
CREATE INDEX IF NOT EXISTS shot_text_binding_events_order
  ON shot_text_binding_events(project_id, binding_id, seq);
