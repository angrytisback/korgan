-- 0006_oauth2_providers.sql
-- Makes password_hash nullable for OAuth-only users
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- OAuth accounts linked to users
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_user_id VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_oauth_accounts_provider_user ON oauth_accounts (provider, provider_user_id);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts (user_id);
