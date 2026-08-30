-- B6.3 recovery authorization.  The nonce is durable state on the admitted
-- attempt, rather than a value which exists only in a caller's memory.
ALTER TABLE attempts ADD COLUMN recovery_nonce TEXT;
ALTER TABLE attempts ADD COLUMN recovery_nonce_expires_at TEXT;
ALTER TABLE attempts ADD COLUMN recovery_nonce_used INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_recovery_nonce
    ON attempts(recovery_nonce) WHERE recovery_nonce IS NOT NULL;
