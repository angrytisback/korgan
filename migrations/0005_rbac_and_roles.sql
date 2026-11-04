-- 0005_rbac_and_roles.sql
-- Adds role-based access control (RBAC) to users table.
ALTER TABLE users ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user';

CREATE INDEX idx_users_role ON users (role);
