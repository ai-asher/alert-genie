-- Add parent_approval_id to approvals for revision chain.
-- ALTER TABLE IF NOT EXISTS works on PostgreSQL 9.6+ and is tolerated by SQLite via the
-- isAlreadyExistsErr fallback (SQLite errors with "duplicate column name").
ALTER TABLE approvals ADD COLUMN parent_approval_id TEXT;
