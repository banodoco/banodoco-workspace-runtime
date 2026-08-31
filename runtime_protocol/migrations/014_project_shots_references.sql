CREATE TABLE IF NOT EXISTS project_shots (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(trim(name)) > 0),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT
);
CREATE TABLE IF NOT EXISTS shot_items (
  id TEXT PRIMARY KEY,
  shot_id TEXT NOT NULL REFERENCES project_shots(id) ON DELETE CASCADE,
  media_id TEXT NOT NULL,
  sort_key TEXT NOT NULL,
  source_frame INTEGER,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(shot_id, sort_key)
);
CREATE INDEX IF NOT EXISTS shot_items_media ON shot_items(media_id, shot_id);
CREATE TABLE IF NOT EXISTS project_references (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('character','place','object','clothing','other')),
  name TEXT NOT NULL CHECK (length(trim(name)) > 0),
  description TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT
);
CREATE TABLE IF NOT EXISTS media_references (
  id TEXT PRIMARY KEY,
  reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
  media_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('canonical','used_as_input','depicts','inspired_by')),
  ordinal INTEGER NOT NULL DEFAULT 0 CHECK (ordinal >= 0),
  is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0,1)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  CHECK (role = 'canonical' OR is_primary = 0)
);
CREATE TABLE IF NOT EXISTS reference_links (
  from_reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
  to_reference_id TEXT NOT NULL REFERENCES project_references(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('belongs_to','wears','located_in','associated_with','related_to')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  PRIMARY KEY(from_reference_id, to_reference_id, kind),
  CHECK (from_reference_id <> to_reference_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS reference_one_primary_canonical ON media_references(reference_id) WHERE role='canonical' AND is_primary=1;
CREATE UNIQUE INDEX IF NOT EXISTS reference_media_role_unique ON media_references(reference_id, media_id, role);
CREATE INDEX IF NOT EXISTS references_project_kind ON project_references(project_id, kind, name, id);
