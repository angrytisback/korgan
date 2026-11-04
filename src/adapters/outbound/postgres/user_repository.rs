//! PostgreSQL implementation of [`UserRepository`] with compile-time verified queries.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::adapters::outbound::postgres::models::{PgAccountStatus, UserMfaRow, UserRow};
use crate::domain::entities::{User, UserMfa};
use crate::domain::value_objects::{EmailAddress, PasswordHash, UserId, Username};
use crate::ports::errors::PortError;
use crate::ports::repositories::UserRepository;

/// PostgreSQL user repository backed by `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    /// Creates a new [`PostgresUserRepository`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Maps sqlx database errors to standard [`PortError`] values without leaking internal info.
    fn map_sqlx_error(e: sqlx::Error, action: &'static str) -> PortError {
        if let Some(db_err) = e.as_database_error()
            && db_err.code().as_deref() == Some("23505")
        {
            return PortError::conflict(format!(
                "unique constraint violation during {action}: {}",
                db_err.message()
            ));
        }
        PortError::database(format!("{action} failed: {e}"))
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let user_uuid = id.to_uuid();

        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id,
                email,
                username,
                password_hash,
                status as "status: PgAccountStatus",
                role,
                email_verified_at,
                mfa_enabled,
                failed_login_attempts,
                locked_until,
                deletion_scheduled_at,
                created_at,
                updated_at
            FROM users
            WHERE id = $1
            "#,
            user_uuid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_id"))?;

        row.map(User::try_from).transpose()
    }

    async fn find_by_email(&self, email: &EmailAddress) -> Result<Option<User>, PortError> {
        let email_str = email.as_str();

        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id,
                email,
                username,
                password_hash,
                status as "status: PgAccountStatus",
                role,
                email_verified_at,
                mfa_enabled,
                failed_login_attempts,
                locked_until,
                deletion_scheduled_at,
                created_at,
                updated_at
            FROM users
            WHERE email = $1
            "#,
            email_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_email"))?;

        row.map(User::try_from).transpose()
    }

    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, PortError> {
        let username_str = username.as_str();

        let row = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id,
                email,
                username,
                password_hash,
                status as "status: PgAccountStatus",
                role,
                email_verified_at,
                mfa_enabled,
                failed_login_attempts,
                locked_until,
                deletion_scheduled_at,
                created_at,
                updated_at
            FROM users
            WHERE username = $1
            "#,
            username_str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_username"))?;

        row.map(User::try_from).transpose()
    }

    async fn create(&self, user: &User) -> Result<(), PortError> {
        let pg_status: PgAccountStatus = user.status.into();
        let user_uuid = user.id.to_uuid();
        let username_str = user.username.as_ref().map(|u| u.as_str());
        let failed_attempts = i16::try_from(user.failed_login_attempts).unwrap_or(i16::MAX);
        let password_hash_str = user.password_hash.as_ref().map(|p| p.as_str());

        sqlx::query!(
            r#"
            INSERT INTO users (
                id,
                email,
                username,
                password_hash,
                status,
                role,
                email_verified_at,
                mfa_enabled,
                failed_login_attempts,
                locked_until,
                deletion_scheduled_at,
                created_at,
                updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
            )
            "#,
            user_uuid,
            user.email.as_str(),
            username_str,
            password_hash_str,
            pg_status as PgAccountStatus,
            user.role.as_str(),
            user.email_verified_at,
            user.mfa_enabled,
            failed_attempts,
            user.locked_until,
            user.deletion_scheduled_at,
            user.created_at,
            user.updated_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "create user"))?;

        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), PortError> {
        let pg_status: PgAccountStatus = user.status.into();
        let user_uuid = user.id.to_uuid();
        let username_str = user.username.as_ref().map(|u| u.as_str());
        let failed_attempts = i16::try_from(user.failed_login_attempts).unwrap_or(i16::MAX);
        let password_hash_str = user.password_hash.as_ref().map(|p| p.as_str());

        sqlx::query!(
            r#"
            UPDATE users SET
                email = $2,
                username = $3,
                password_hash = $4,
                status = $5,
                role = $6,
                email_verified_at = $7,
                mfa_enabled = $8,
                failed_login_attempts = $9,
                locked_until = $10,
                deletion_scheduled_at = $11,
                updated_at = $12
            WHERE id = $1
            "#,
            user_uuid,
            user.email.as_str(),
            username_str,
            password_hash_str,
            pg_status as PgAccountStatus,
            user.role.as_str(),
            user.email_verified_at,
            user.mfa_enabled,
            failed_attempts,
            user.locked_until,
            user.deletion_scheduled_at,
            user.updated_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "update user"))?;

        Ok(())
    }

    async fn update_password(
        &self,
        user_id: &UserId,
        new_hash: &PasswordHash,
        history_depth: u16,
    ) -> Result<(), PortError> {
        let user_uuid = user_id.to_uuid();
        let now = Utc::now();
        let history_id = Uuid::now_v7();
        let depth_i64 = i64::from(history_depth);

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| PortError::database(format!("failed to begin transaction: {e}")))?;

        // 1. Update user password hash
        sqlx::query!(
            r#"
            UPDATE users SET
                password_hash = $2,
                updated_at = $3
            WHERE id = $1
            "#,
            user_uuid,
            new_hash.as_str(),
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "update password hash"))?;

        // 2. Append new hash to password_history
        sqlx::query!(
            r#"
            INSERT INTO password_history (
                id,
                user_id,
                password_hash,
                created_at
            ) VALUES (
                $1, $2, $3, $4
            )
            "#,
            history_id,
            user_uuid,
            new_hash.as_str(),
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "insert password history"))?;

        // 3. Prune old history entries beyond configured retention depth
        sqlx::query!(
            r#"
            DELETE FROM password_history
            WHERE user_id = $1
              AND id NOT IN (
                  SELECT id FROM password_history
                  WHERE user_id = $1
                  ORDER BY created_at DESC
                  LIMIT $2
              )
            "#,
            user_uuid,
            depth_i64
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "prune password history"))?;

        tx.commit()
            .await
            .map_err(|e| PortError::database(format!("failed to commit transaction: {e}")))?;

        Ok(())
    }

    async fn get_password_history(
        &self,
        user_id: &UserId,
        limit: u32,
    ) -> Result<Vec<PasswordHash>, PortError> {
        let user_uuid = user_id.to_uuid();
        let limit_i64 = i64::from(limit);

        let rows = sqlx::query!(
            r#"
            SELECT password_hash
            FROM password_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            user_uuid,
            limit_i64
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "get password history"))?;

        let mut hashes = Vec::with_capacity(rows.len());
        for row in rows {
            let hash = PasswordHash::new(row.password_hash)
                .map_err(|e| PortError::database(format!("invalid history hash: {e}")))?;
            hashes.push(hash);
        }

        Ok(hashes)
    }

    async fn find_mfa(&self, user_id: &UserId) -> Result<Option<UserMfa>, PortError> {
        let user_uuid = user_id.to_uuid();

        let row = sqlx::query_as::<_, UserMfaRow>(
            r#"
            SELECT
                user_id,
                key_id,
                totp_secret_ciphertext,
                totp_secret_nonce,
                backup_code_hashes,
                verified_at,
                updated_at
            FROM user_mfa
            WHERE user_id = $1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_mfa"))?;

        row.map(UserMfa::try_from).transpose()
    }

    async fn save_mfa(&self, mfa: &UserMfa) -> Result<(), PortError> {
        let user_uuid = mfa.user_id.to_uuid();

        sqlx::query(
            r#"
            INSERT INTO user_mfa (
                user_id,
                key_id,
                totp_secret_ciphertext,
                totp_secret_nonce,
                backup_code_hashes,
                verified_at,
                updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7
            )
            ON CONFLICT (user_id) DO UPDATE SET
                key_id = EXCLUDED.key_id,
                totp_secret_ciphertext = EXCLUDED.totp_secret_ciphertext,
                totp_secret_nonce = EXCLUDED.totp_secret_nonce,
                backup_code_hashes = EXCLUDED.backup_code_hashes,
                verified_at = EXCLUDED.verified_at,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(user_uuid)
        .bind(&mfa.key_id)
        .bind(&mfa.totp_secret_ciphertext)
        .bind(&mfa.totp_secret_nonce)
        .bind(&mfa.backup_code_hashes)
        .bind(mfa.verified_at)
        .bind(mfa.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "save_mfa"))?;

        Ok(())
    }

    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError> {
        let user_uuid = user_id.to_uuid();
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(|e| {
            PortError::database(format!("failed to begin delete_mfa transaction: {e}"))
        })?;

        sqlx::query!(
            r#"
            DELETE FROM user_mfa
            WHERE user_id = $1
            "#,
            user_uuid
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "delete user_mfa record"))?;

        sqlx::query!(
            r#"
            UPDATE users SET
                mfa_enabled = false,
                updated_at = $2
            WHERE id = $1
            "#,
            user_uuid,
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "disable user mfa_enabled flag"))?;

        tx.commit().await.map_err(|e| {
            PortError::database(format!("failed to commit delete_mfa transaction: {e}"))
        })?;

        Ok(())
    }

    async fn consume_backup_code(
        &self,
        user_id: &UserId,
        code_hash: &str,
    ) -> Result<bool, PortError> {
        let user_uuid = user_id.to_uuid();

        let result = sqlx::query(
            r#"
            UPDATE user_mfa
            SET backup_code_hashes = array_remove(backup_code_hashes, $2),
                updated_at = NOW()
            WHERE user_id = $1 AND $2 = ANY(backup_code_hashes)
            "#,
        )
        .bind(user_uuid)
        .bind(code_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "consume_backup_code"))?;

        Ok(result.rows_affected() > 0)
    }

    async fn record_failed_login_atomic(
        &self,
        user_id: &UserId,
        max_attempts: u16,
        lockout_until: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<chrono::Utc>>), PortError> {
        let user_uuid = user_id.to_uuid();
        let max_attempts_i16 = i16::try_from(max_attempts).unwrap_or(i16::MAX);

        #[derive(sqlx::FromRow)]
        struct FailedLoginRow {
            failed_login_attempts: i16,
            locked_until: Option<chrono::DateTime<chrono::Utc>>,
        }

        let row = sqlx::query_as::<_, FailedLoginRow>(
            r#"
            UPDATE users
            SET
                failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN failed_login_attempts + 1 >= $2 THEN $3
                    ELSE locked_until
                END,
                updated_at = $4
            WHERE id = $1
            RETURNING failed_login_attempts, locked_until
            "#,
        )
        .bind(user_uuid)
        .bind(max_attempts_i16)
        .bind(lockout_until)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "record_failed_login_atomic"))?;

        match row {
            Some(r) => {
                let attempts = u16::try_from(r.failed_login_attempts).unwrap_or(u16::MAX);
                Ok((attempts, r.locked_until))
            }
            None => Err(PortError::not_found("user")),
        }
    }

    async fn reset_failed_logins(
        &self,
        user_id: &UserId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError> {
        let user_uuid = user_id.to_uuid();

        sqlx::query(
            r#"
            UPDATE users
            SET
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(user_uuid)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "reset_failed_logins"))?;

        Ok(())
    }

    async fn list_paginated(&self, limit: u32, offset: u64) -> Result<Vec<User>, PortError> {
        let limit_i64 = i64::from(limit);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let rows = sqlx::query_as!(
            UserRow,
            r#"
            SELECT
                id,
                email,
                username,
                password_hash,
                status as "status: PgAccountStatus",
                role,
                email_verified_at,
                mfa_enabled,
                failed_login_attempts,
                locked_until,
                deletion_scheduled_at,
                created_at,
                updated_at
            FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit_i64,
            offset_i64
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_paginated"))?;

        rows.into_iter().map(User::try_from).collect()
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as "count!" FROM users
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "count_all"))?;

        Ok(u64::try_from(row.count).unwrap_or(0))
    }

    async fn purge_expired_unverified(
        &self,
        created_before: chrono::DateTime<chrono::Utc>,
        max_purge: u32,
    ) -> Result<u64, PortError> {
        let max_purge_i64 = i64::from(max_purge);

        let row: (i64,) = sqlx::query_as(
            r#"
            WITH deleted AS (
                DELETE FROM users
                WHERE id IN (
                    SELECT id FROM users
                    WHERE status = 'unverified' AND created_at < $1
                    LIMIT $2
                )
                RETURNING id
            )
            SELECT count(*) FROM deleted
            "#,
        )
        .bind(created_before)
        .bind(max_purge_i64)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "purge_expired_unverified"))?;

        let count_u64 = u64::try_from(row.0).unwrap_or(0);
        Ok(count_u64)
    }

    async fn has_admin_user(&self) -> Result<bool, PortError> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM users WHERE role IN ('admin', 'superadmin')
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "has_admin_user"))?;

        Ok(exists)
    }
}
