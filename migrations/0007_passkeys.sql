-- 0007_passkeys.sql
-- FIDO2 / WebAuthn passkey credentials

CREATE TABLE passkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    passkey_json JSONB NOT NULL,
    name TEXT NOT NULL DEFAULT 'Passkey',
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passkeys_user_id ON passkeys (user_id);
CREATE UNIQUE INDEX idx_passkeys_credential_id ON passkeys (credential_id);
