CREATE TABLE IF NOT EXISTS command_idempotency (
    command_kind TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(command_kind, aggregate_id, idempotency_key)
);
