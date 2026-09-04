ALTER TABLE executors ADD COLUMN source_digest TEXT;
ALTER TABLE executors ADD COLUMN dependency_digest TEXT;
ALTER TABLE executors ADD COLUMN source_epoch TEXT;
