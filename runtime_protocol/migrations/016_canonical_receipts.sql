-- Canonical durable mutation receipt metadata.  These columns live on the
-- idempotency record so the mutation, its event(s), sequence allocation, and
-- replay material are one atomic row/transaction.
ALTER TABLE command_idempotency ADD COLUMN txn_id TEXT;
ALTER TABLE command_idempotency ADD COLUMN primary_stream_id TEXT;
ALTER TABLE command_idempotency ADD COLUMN resulting_stream_seq INTEGER;
ALTER TABLE command_idempotency ADD COLUMN first_project_seq INTEGER;
ALTER TABLE command_idempotency ADD COLUMN last_project_seq INTEGER;
ALTER TABLE command_idempotency ADD COLUMN event_ids_json TEXT;

CREATE TABLE IF NOT EXISTS project_sequences (
    project_id TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL CHECK (next_seq > 0)
);
