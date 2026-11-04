-- 0008_audit_logs_immutability.sql
-- Cryptographic chaining and immutability trigger for audit_logs table

ALTER TABLE audit_logs
    ADD COLUMN prev_hash VARCHAR(64),
    ADD COLUMN entry_hash VARCHAR(64) UNIQUE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_entry_hash ON audit_logs (entry_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at_id ON audit_logs (created_at DESC, id DESC);

-- Drop foreign key constraint to users table.
-- Audit logs must retain their historical actor user_id even if the user is subsequently
-- purged or deleted, and foreign key ON DELETE SET NULL triggers would violate immutability.
ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;

-- Prevent any UPDATE, DELETE, or TRUNCATE operations on audit_logs
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs entries are immutable: UPDATE, DELETE, and TRUNCATE operations are strictly prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_audit_log_modification
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_modification();

CREATE TRIGGER trg_prevent_audit_log_truncate
BEFORE TRUNCATE ON audit_logs
FOR EACH STATEMENT
EXECUTE FUNCTION prevent_audit_log_modification();
