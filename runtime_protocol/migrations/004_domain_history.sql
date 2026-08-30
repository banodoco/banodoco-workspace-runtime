-- Durable timeline snapshots make history/diff/recovery independent of files.
ALTER TABLE timelines ADD COLUMN archived_at TEXT;
CREATE TABLE IF NOT EXISTS timeline_revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timeline_id TEXT NOT NULL REFERENCES timelines(id),
  version INTEGER NOT NULL,
  shots_json TEXT NOT NULL,
  references_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(timeline_id, version)
);
CREATE INDEX IF NOT EXISTS idx_timeline_revisions_timeline ON timeline_revisions(timeline_id, version);
