-- 0001_extensions_and_types.sql
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE account_status AS ENUM ('unverified', 'active', 'suspended', 'deactivated', 'pending_deletion');
