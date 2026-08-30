-- Durable runtime boot/session state. The database, rather than a process
-- pid or discovery file, is the source of truth for recovery fencing.
CREATE TABLE IF NOT EXISTS runtime_lifecycle (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    runtime_epoch INTEGER NOT NULL,
    boot_id TEXT NOT NULL,
    previous_boot_id TEXT,
    started_at TEXT NOT NULL,
    recovered_task_count INTEGER NOT NULL DEFAULT 0
);
