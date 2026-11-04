-- 0003_sessions_and_mfa.sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY, -- UUIDv7 (also embedded as `sid` in JWT Access Token)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id UUID NOT NULL, -- Groups rotated refresh tokens for reuse detection
    refresh_token_hash TEXT NOT NULL UNIQUE, -- SHA-256 hex/base64 of opaque token
    user_agent TEXT,
    device_name TEXT,
    ip_address INET NOT NULL,
    is_replaced BOOLEAN NOT NULL DEFAULT FALSE, -- True when rotated; if used again -> COMPROMISED!
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_active ON sessions (user_id, last_active_at DESC)
    WHERE revoked_at IS NULL AND is_replaced = FALSE;
CREATE INDEX idx_sessions_family ON sessions (token_family_id);

CREATE TABLE user_mfa (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL DEFAULT 'v1',
    totp_secret_ciphertext BYTEA NOT NULL, -- AES-256-GCM encrypted
    totp_secret_nonce BYTEA NOT NULL,      -- 12-byte GCM nonce
    backup_code_hashes TEXT[] NOT NULL DEFAULT '{}', -- SHA-256 hashes of unused 8-char backup codes
    verified_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
