-- B10.2 owner-data preservation ledger.
--
-- These source tables do not yet have a proven shared product query/transaction
-- contract.  Preserve their complete authored rows in one neutral, runtime-
-- owned ledger instead of dropping them or pretending they are native domain
-- rows.  source_key/source_ordinal make composite identities and ordering
-- explicit; row_sha256 makes truncation or mutation fail closed.
CREATE TABLE IF NOT EXISTS migration_owner_records (
    source_table TEXT NOT NULL,
    source_key TEXT NOT NULL,
    source_ordinal INTEGER NOT NULL,
    row_json TEXT NOT NULL,
    row_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(source_table, source_key),
    UNIQUE(source_table, source_ordinal)
);

CREATE INDEX IF NOT EXISTS idx_migration_owner_records_order
    ON migration_owner_records(source_table, source_ordinal);
