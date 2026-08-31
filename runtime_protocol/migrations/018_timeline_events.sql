-- Timeline/document commands have their own aggregate stream.  Keeping this
-- separate from run events makes the receipt's event identity truthful
-- without inventing a synthetic run for a timeline mutation.
CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timeline_id TEXT NOT NULL REFERENCES timelines(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_events_timeline ON timeline_events(timeline_id, id);
