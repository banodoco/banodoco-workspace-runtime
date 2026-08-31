-- Collapse the transitional worker registry into the canonical executor
-- registry.  Older realms may contain state in either table because the
-- convergence runtime mirrored registrations while the executor API was
-- introduced.  Copy worker-only identities once, preserve canonical
-- executor rows when both exist, move lease ownership to executor_id, then
-- remove the obsolete table in the same migration transaction.
ALTER TABLE executors ADD COLUMN readiness TEXT NOT NULL DEFAULT 'ready';
ALTER TABLE executors ADD COLUMN readiness_reason TEXT;
ALTER TABLE executors ADD COLUMN last_seen_at TEXT;

INSERT INTO executors(
    id, max_concurrency, resource_keys_json, capabilities_json, protocol,
    created_at, runtime_epoch, readiness, readiness_reason, last_seen_at
)
SELECT
    w.id, w.max_concurrency, w.resource_keys_json, w.capabilities_json,
    'workspace.v1', w.created_at, w.runtime_epoch, w.readiness,
    w.readiness_reason, w.last_seen_at
FROM workers AS w
WHERE NOT EXISTS (SELECT 1 FROM executors AS e WHERE e.id = w.id);

ALTER TABLE tasks RENAME COLUMN worker_id TO executor_id;
ALTER TABLE reservations RENAME COLUMN worker_id TO executor_id;
DROP INDEX IF EXISTS idx_tasks_worker_status;
DROP INDEX IF EXISTS idx_reservations_active;
CREATE INDEX IF NOT EXISTS idx_tasks_executor_status ON tasks(executor_id, status);
CREATE INDEX IF NOT EXISTS idx_reservations_active ON reservations(executor_id, resource_key, released_at);

DROP TABLE workers;
