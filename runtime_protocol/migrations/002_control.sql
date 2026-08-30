CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY, definition_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready', required_resource_keys_json TEXT NOT NULL DEFAULT '[]',
    estimated_scratch_bytes INTEGER NOT NULL DEFAULT 0, estimated_output_bytes INTEGER NOT NULL DEFAULT 0,
    unavailable_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
ALTER TABLE workers ADD COLUMN readiness TEXT NOT NULL DEFAULT 'ready';
ALTER TABLE workers ADD COLUMN readiness_reason TEXT;
ALTER TABLE tasks ADD COLUMN capability_digest TEXT;
ALTER TABLE tasks ADD COLUMN waiting_reason TEXT;
ALTER TABLE tasks ADD COLUMN lease_expires_at TEXT;
ALTER TABLE tasks ADD COLUMN lease_fence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reservations ADD COLUMN worker_id TEXT;
ALTER TABLE reservations ADD COLUMN fence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reservations ADD COLUMN lease_expires_at TEXT;
CREATE INDEX IF NOT EXISTS idx_tasks_worker_status ON tasks(worker_id, status);
CREATE INDEX IF NOT EXISTS idx_reservations_active ON reservations(worker_id, resource_key, released_at);
