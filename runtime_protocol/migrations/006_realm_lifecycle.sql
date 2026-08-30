-- Lifecycle is separate from realm authority so a tombstone is durable and
-- auditable without changing the stable realm identity or foreign keys.
CREATE TABLE IF NOT EXISTS realm_lifecycle (
  realm_id TEXT PRIMARY KEY REFERENCES realm(id),
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'tombstoned')),
  tombstoned_at TEXT,
  reason TEXT,
  version INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO realm_lifecycle(realm_id, state, version)
  SELECT id, 'active', 1 FROM realm;
