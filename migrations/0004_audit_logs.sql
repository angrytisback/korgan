-- 0004_audit_logs.sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY, -- UUIDv7
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip INET,
    user_agent TEXT,
    request_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    event_status VARCHAR(16) NOT NULL, -- 'success' | 'failure' | 'blocked'
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_time ON audit_logs (user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_time ON audit_logs (event_type, created_at DESC);
