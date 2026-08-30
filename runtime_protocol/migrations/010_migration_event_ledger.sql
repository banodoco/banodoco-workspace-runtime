-- B10 migration event/stream ledger.  The runtime event chain is keyed by
-- runtime runs, while a legacy Astrid source is keyed by project/aggregate
-- streams.  Keep the imported source ledger in the runtime database with an
-- explicit source->destination mapping so migration reconciliation can inspect
-- exact stream identities, heads, and event relationships.
CREATE TABLE IF NOT EXISTS migration_event_streams (
    source_stream_id TEXT PRIMARY KEY,
    destination_stream_id TEXT NOT NULL UNIQUE,
    project_id TEXT,
    stream_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    head_seq INTEGER NOT NULL,
    source_ordinal INTEGER NOT NULL DEFAULT 0,
    source_created_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS migration_events (
    source_event_id TEXT PRIMARY KEY,
    destination_event_id TEXT NOT NULL UNIQUE,
    source_stream_id TEXT NOT NULL REFERENCES migration_event_streams(source_stream_id),
    destination_stream_id TEXT NOT NULL REFERENCES migration_event_streams(destination_stream_id),
    project_id TEXT,
    project_seq INTEGER,
    seq INTEGER NOT NULL,
    source_ordinal INTEGER NOT NULL DEFAULT 0,
    subject_type TEXT,
    subject_id TEXT,
    changes_json TEXT,
    kind TEXT NOT NULL,
    schema_version TEXT,
    idempotency_key TEXT,
    txn_id TEXT,
    actor_kind TEXT,
    payload_json TEXT NOT NULL,
    source_created_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_migration_events_stream
    ON migration_events(destination_stream_id, seq);
