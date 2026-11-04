//! PostgreSQL implementation of [`SessionRepository`] with compile-time verified queries.

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use sqlx::PgPool;

use crate::adapters::outbound::postgres::models::SessionRow;
use crate::domain::entities::Session;
use crate::domain::value_objects::{SessionId, TokenFamilyId, UserId};
use crate::ports::errors::PortError;
use crate::ports::repositories::SessionRepository;

/// PostgreSQL session repository backed by `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    /// Creates a new [`PostgresSessionRepository`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Maps sqlx database errors to standard [`PortError`] values.
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
impl SessionRepository for PostgresSessionRepository {
    async fn create(&self, session: &Session) -> Result<(), PortError> {
        let session_id = session.id.to_uuid();
        let user_id = session.user_id.to_uuid();
        let family_id = session.token_family_id.to_uuid();
        let ip_network = IpNetwork::from(session.ip_address);
        let now = session.created_at;

        let result = sqlx::query(
            r#"
            INSERT INTO sessions (
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            )
            SELECT
                $1,
                users.id,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8,
                $9,
                $10,
                $11,
                $12
            FROM users
            WHERE users.id = $13
              AND users.status = 'active'
              AND (users.locked_until IS NULL OR users.locked_until <= $12)
            "#,
        )
        .bind(session_id)
        .bind(family_id)
        .bind(&session.refresh_token_hash)
        .bind(session.user_agent.as_deref())
        .bind(session.device_name.as_deref())
        .bind(ip_network)
        .bind(session.is_replaced)
        .bind(session.last_active_at)
        .bind(session.expires_at)
        .bind(session.revoked_at)
        .bind(session.revoke_reason.as_deref())
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "create session"))?;

        if result.rows_affected() == 0 {
            return Err(PortError::conflict(
                "user account is not active or is locked",
            ));
        }

        metrics::gauge!("korgan_active_sessions_gauge").increment(1.0);

        Ok(())
    }

    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError> {
        let session_id = id.to_uuid();

        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            FROM sessions
            WHERE id = $1
            "#,
            session_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_id"))?;

        row.map(Session::try_from).transpose()
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, PortError> {
        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            FROM sessions
            WHERE refresh_token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_token_hash"))?;

        row.map(Session::try_from).transpose()
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        let user_uuid = user_id.to_uuid();
        let limit_i64 = i64::from(limit);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let rows = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            FROM sessions
            WHERE user_id = $1
            ORDER BY last_active_at DESC
            LIMIT $2 OFFSET $3
            "#,
            user_uuid,
            limit_i64,
            offset_i64
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_by_user_id"))?;

        rows.into_iter().map(Session::try_from).collect()
    }

    async fn update(&self, session: &Session) -> Result<(), PortError> {
        let session_id = session.id.to_uuid();

        sqlx::query!(
            r#"
            UPDATE sessions SET
                is_replaced = $2,
                last_active_at = $3,
                revoked_at = $4,
                revoke_reason = $5
            WHERE id = $1
            "#,
            session_id,
            session.is_replaced,
            session.last_active_at,
            session.revoked_at,
            session.revoke_reason.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "update session"))?;

        Ok(())
    }

    async fn replace_atomic(&self, token_hash: &str) -> Result<Option<Session>, PortError> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            UPDATE sessions
            SET is_replaced = true, last_active_at = NOW()
            WHERE refresh_token_hash = $1 AND is_replaced = false AND revoked_at IS NULL AND expires_at > NOW()
            RETURNING
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            "#
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "replace_atomic"))?;

        row.map(Session::try_from).transpose()
    }

    async fn rotate_atomic(
        &self,
        old_token_hash: &str,
        new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
        let new_session_id = new_session.id.to_uuid();
        let new_token_hash = &new_session.refresh_token_hash;
        let user_agent = new_session.user_agent.as_deref();
        let device_name = new_session.device_name.as_deref();
        let ip_network = IpNetwork::from(new_session.ip_address);
        let expires_at = new_session.expires_at;
        let last_active_at = new_session.last_active_at;
        let created_at = new_session.created_at;

        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            WITH updated AS (
                UPDATE sessions
                SET is_replaced = true, last_active_at = $1
                FROM users
                WHERE sessions.refresh_token_hash = $2
                  AND sessions.user_id = users.id
                  AND users.status = 'active'
                  AND (users.locked_until IS NULL OR users.locked_until <= $1)
                  AND sessions.is_replaced = false
                  AND sessions.revoked_at IS NULL
                  AND sessions.expires_at > NOW()
                RETURNING
                    sessions.id,
                    sessions.user_id,
                    sessions.token_family_id,
                    sessions.refresh_token_hash,
                    sessions.user_agent,
                    sessions.device_name,
                    sessions.ip_address,
                    sessions.is_replaced,
                    sessions.last_active_at,
                    sessions.expires_at,
                    sessions.revoked_at,
                    sessions.revoke_reason,
                    sessions.created_at
            ),
            inserted AS (
                INSERT INTO sessions (
                    id,
                    user_id,
                    token_family_id,
                    refresh_token_hash,
                    user_agent,
                    device_name,
                    ip_address,
                    is_replaced,
                    last_active_at,
                    expires_at,
                    revoked_at,
                    revoke_reason,
                    created_at
                )
                SELECT
                    $3,
                    updated.user_id,
                    updated.token_family_id,
                    $4,
                    $5,
                    COALESCE($6, updated.device_name),
                    $7,
                    false,
                    $1,
                    $8,
                    NULL::TIMESTAMPTZ,
                    NULL::TEXT,
                    $9
                FROM updated
                JOIN users ON users.id = updated.user_id
                WHERE users.status = 'active'
                  AND (users.locked_until IS NULL OR users.locked_until <= $1)
                RETURNING id
            )
            SELECT
                id,
                user_id,
                token_family_id,
                refresh_token_hash,
                user_agent,
                device_name,
                ip_address,
                is_replaced,
                last_active_at,
                expires_at,
                revoked_at,
                revoke_reason,
                created_at
            FROM updated
            WHERE EXISTS (SELECT 1 FROM inserted)
            "#,
        )
        .bind(last_active_at)
        .bind(old_token_hash)
        .bind(new_session_id)
        .bind(new_token_hash)
        .bind(user_agent)
        .bind(device_name)
        .bind(ip_network)
        .bind(expires_at)
        .bind(created_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "rotate_atomic"))?;

        row.map(Session::try_from).transpose()
    }

    async fn revoke_by_id(&self, id: &SessionId, reason: &str) -> Result<(), PortError> {
        let session_id = id.to_uuid();

        let result = sqlx::query!(
            r#"
            UPDATE sessions SET
                revoked_at = NOW(),
                revoke_reason = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            session_id,
            reason
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "revoke_by_id"))?;

        if result.rows_affected() > 0 {
            metrics::gauge!("korgan_active_sessions_gauge")
                .decrement(result.rows_affected() as f64);
        }

        Ok(())
    }

    async fn revoke_by_id_and_user_id(
        &self,
        id: &SessionId,
        user_id: &UserId,
        reason: &str,
    ) -> Result<Option<SessionId>, PortError> {
        let session_id = id.to_uuid();
        let user_uuid = user_id.to_uuid();

        #[derive(sqlx::FromRow)]
        struct IdRow {
            id: uuid::Uuid,
        }

        let row = sqlx::query_as::<_, IdRow>(
            r#"
            UPDATE sessions SET
                revoked_at = NOW(),
                revoke_reason = $3
            WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
            RETURNING id
            "#,
        )
        .bind(session_id)
        .bind(user_uuid)
        .bind(reason)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "revoke_by_id_and_user_id"))?;

        if row.is_some() {
            metrics::gauge!("korgan_active_sessions_gauge").decrement(1.0);
        }

        row.map(|r| SessionId::from_uuid(r.id))
            .transpose()
            .map_err(PortError::database)
    }

    async fn revoke_family(
        &self,
        family_id: &TokenFamilyId,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let family_uuid = family_id.to_uuid();

        #[derive(sqlx::FromRow)]
        struct IdRow {
            id: uuid::Uuid,
        }

        let rows = sqlx::query_as::<_, IdRow>(
            r#"
            UPDATE sessions SET
                revoked_at = NOW(),
                revoke_reason = $2
            WHERE token_family_id = $1 AND revoked_at IS NULL
            RETURNING id
            "#,
        )
        .bind(family_uuid)
        .bind(reason)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "revoke_family"))?;

        if !rows.is_empty() {
            metrics::gauge!("korgan_active_sessions_gauge").decrement(rows.len() as f64);
        }

        rows.into_iter()
            .map(|r| SessionId::from_uuid(r.id).map_err(PortError::database))
            .collect()
    }

    async fn revoke_all_user_sessions(
        &self,
        user_id: &UserId,
        except_session: Option<&SessionId>,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let user_uuid = user_id.to_uuid();
        let except_uuid = except_session.map(|s| s.to_uuid());

        #[derive(sqlx::FromRow)]
        struct IdRow {
            id: uuid::Uuid,
        }

        let rows = sqlx::query_as::<_, IdRow>(
            r#"
            UPDATE sessions SET
                revoked_at = NOW(),
                revoke_reason = $3
            WHERE user_id = $1
              AND ($2::uuid IS NULL OR id != $2)
              AND revoked_at IS NULL
            RETURNING id
            "#,
        )
        .bind(user_uuid)
        .bind(except_uuid)
        .bind(reason)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "revoke_all_user_sessions"))?;

        if !rows.is_empty() {
            metrics::gauge!("korgan_active_sessions_gauge").decrement(rows.len() as f64);
        }

        rows.into_iter()
            .map(|r| SessionId::from_uuid(r.id).map_err(PortError::database))
            .collect()
    }

    async fn purge_expired(&self, max_purge: u32) -> Result<u64, PortError> {
        let max_purge_i64 = i64::from(max_purge);

        let row: (i64, i64) = sqlx::query_as(
            r#"
            WITH to_delete AS (
                SELECT id, (revoked_at IS NULL AND is_replaced = false) AS was_active
                FROM sessions
                WHERE expires_at < NOW() OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '1 day')
                LIMIT $1
            ),
            deleted AS (
                DELETE FROM sessions
                WHERE id IN (SELECT id FROM to_delete)
                RETURNING id
            )
            SELECT
                COALESCE((SELECT count(*) FROM deleted), 0)::bigint AS total,
                COALESCE((SELECT count(*) FROM to_delete WHERE was_active), 0)::bigint AS active_count
            "#,
        )
        .bind(max_purge_i64)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "purge_expired"))?;

        let total_u64 = u64::try_from(row.0).unwrap_or(0);
        let active_u64 = u64::try_from(row.1).unwrap_or(0);
        if active_u64 > 0 {
            metrics::gauge!("korgan_active_sessions_gauge").decrement(active_u64 as f64);
        }
        Ok(total_u64)
    }

    async fn count_active(&self) -> Result<u64, PortError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM sessions
            WHERE revoked_at IS NULL AND is_replaced = false AND expires_at > NOW()
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "count_active"))?;

        Ok(u64::try_from(count).unwrap_or(0))
    }
}
