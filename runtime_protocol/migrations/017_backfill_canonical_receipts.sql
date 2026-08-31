-- Receipt backfill provenance.  The singleton row is written in the same
-- transaction as the historical receipt updates and schema version marker.
CREATE TABLE IF NOT EXISTS canonical_receipt_backfills (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_schema_version INTEGER NOT NULL,
    backfilled_count INTEGER NOT NULL CHECK (backfilled_count >= 0),
    completed_at TEXT NOT NULL
);
