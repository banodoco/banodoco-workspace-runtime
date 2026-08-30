-- B6.3 recovery records.  Every worker identity and attempt is bound to the
-- boot epoch that admitted it; checkpoint bytes live in an fsync'd sidecar
-- and this table is the durable index/receipt.
ALTER TABLE workers ADD COLUMN runtime_epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE executors ADD COLUMN runtime_epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE tasks ADD COLUMN runtime_epoch INTEGER;
ALTER TABLE attempts ADD COLUMN runtime_epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE reservations ADD COLUMN runtime_epoch INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS recovery_checkpoints (
    id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(id),
    task_id TEXT NOT NULL REFERENCES tasks(id),
    executor_id TEXT NOT NULL,
    runtime_epoch INTEGER NOT NULL,
    lease_id TEXT NOT NULL,
    fence INTEGER NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    checkpoint_path TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL,
    checkpoint_size INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'durable',
    recovery_receipt_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recovery_checkpoints_attempt ON recovery_checkpoints(attempt_id, created_at);
