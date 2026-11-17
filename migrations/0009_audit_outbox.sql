-- 0009_audit_outbox.sql
-- Durable hand-off queue for audit events (transactional outbox).
--
-- Request handlers INSERT a row here (cheap, lock-free). A background worker
-- later moves rows, in `seq` order, into the hash-chained `audit_logs` table
-- inside ONE transaction that also deletes them, so every event is chained
-- exactly once and survives crashes and queue overflows.

CREATE TABLE audit_outbox (
    seq            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Serialized `AuditLog` (before chaining).
    payload        JSONB       NOT NULL,
    enqueued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Set when a row cannot be deserialized (e.g. version skew during a
    -- rolling upgrade). Quarantined rows are skipped, never deleted.
    quarantined_at TIMESTAMPTZ
);

-- Drain scans pending rows in order.
CREATE INDEX idx_audit_outbox_pending ON audit_outbox (seq) WHERE quarantined_at IS NULL;
