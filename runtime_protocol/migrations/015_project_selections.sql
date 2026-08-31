-- Actor-scoped routing preferences belong to the neutral runtime realm.
-- They intentionally carry no filesystem path or product-specific payload.
CREATE TABLE IF NOT EXISTS project_selections (
    actor_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('workspace', 'user')),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (actor_id, scope)
);
CREATE INDEX IF NOT EXISTS project_selections_project ON project_selections(project_id);
