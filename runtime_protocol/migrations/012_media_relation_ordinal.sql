-- Media lineage edges are ordered authored data. The ordinal is part of the
-- normative identity so two valid edges with the same endpoints and kind are
-- not collapsed during import.
ALTER TABLE media_relations RENAME TO media_relations_legacy;

CREATE TABLE media_relations (
  project_id TEXT NOT NULL REFERENCES projects(id),
  from_digest TEXT NOT NULL REFERENCES objects(digest),
  to_digest TEXT NOT NULL REFERENCES objects(digest),
  kind TEXT NOT NULL,
  ordinal INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  PRIMARY KEY(project_id, from_digest, to_digest, kind, ordinal)
);

INSERT INTO media_relations(project_id, from_digest, to_digest, kind, ordinal, metadata_json, created_at)
SELECT project_id, from_digest, to_digest, kind, 0, metadata_json, created_at
FROM media_relations_legacy;

DROP TABLE media_relations_legacy;
CREATE INDEX idx_media_relations_project ON media_relations(project_id, created_at);
