//! PostgreSQL implementation of [`AuditLogRepository`] with compile-time verified queries.

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use sqlx::PgPool;

use crate::adapters::outbound::postgres::models::AuditLogRow;
use crate::domain::entities::AuditLog;
use crate::domain::value_objects::UserId;
use crate::ports::errors::PortError;
use crate::ports::repositories::AuditLogRepository;

/// PostgreSQL audit log repository backed by `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresAuditLogRepository {
    pool: PgPool,
}

impl PostgresAuditLogRepository {
    /// Creates a new [`PostgresAuditLogRepository`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Maps sqlx database errors to standard [`PortError`] values.
    fn map_sqlx_error(e: sqlx::Error, action: &'static str) -> PortError {
        PortError::database(format!("{action} failed: {e}"))
    }
}

#[async_trait]
impl AuditLogRepository for PostgresAuditLogRepository {
    async fn append(&self, entry: &AuditLog) -> Result<(), PortError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::map_sqlx_error(e, "begin transaction"))?;

        sqlx::query("SELECT pg_advisory_xact_lock(75798247);")
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::map_sqlx_error(e, "acquire advisory xact lock"))?;

        let log_id = entry.id.to_uuid();
        let user_uuid = entry.user_id.as_ref().map(|u| u.to_uuid());
        let request_uuid = entry.request_id.to_uuid();
        let actor_ip = entry.actor_ip.map(IpNetwork::from);
        let event_status_str = entry.event_status.as_str();

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id,
                user_id,
                actor_ip,
                user_agent,
                request_id,
                event_type,
                event_status,
                metadata,
                prev_hash,
                entry_hash,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )
            "#,
        )
        .bind(log_id)
        .bind(user_uuid)
        .bind(actor_ip)
        .bind(entry.user_agent.as_deref())
        .bind(request_uuid)
        .bind(&entry.event_type)
        .bind(event_status_str)
        .bind(&entry.metadata)
        .bind(entry.prev_hash.as_deref())
        .bind(entry.entry_hash.as_deref())
        .bind(entry.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "append audit log"))?;

        tx.commit()
            .await
            .map_err(|e| Self::map_sqlx_error(e, "commit audit log"))?;

        metrics::gauge!("korgan_audit_chain_length").increment(1.0);

        Ok(())
    }

    async fn append_and_chain(&self, entry: &mut AuditLog) -> Result<(), PortError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::map_sqlx_error(e, "begin transaction"))?;

        // Prevent concurrent chain forks across horizontal korgan instances
        sqlx::query("SELECT pg_advisory_xact_lock(75798247);")
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::map_sqlx_error(e, "acquire advisory xact lock"))?;

        let row: Option<(Option<String>,)> = sqlx::query_as(
            r#"
            SELECT entry_hash
            FROM audit_logs
            WHERE entry_hash IS NOT NULL
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_latest_entry_hash"))?;

        let prev_hash = row.and_then(|(hash,)| hash);
        entry.chain_to(prev_hash.as_deref());

        let log_id = entry.id.to_uuid();
        let user_uuid = entry.user_id.as_ref().map(|u| u.to_uuid());
        let request_uuid = entry.request_id.to_uuid();
        let actor_ip = entry.actor_ip.map(IpNetwork::from);
        let event_status_str = entry.event_status.as_str();

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id,
                user_id,
                actor_ip,
                user_agent,
                request_id,
                event_type,
                event_status,
                metadata,
                prev_hash,
                entry_hash,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )
            "#,
        )
        .bind(log_id)
        .bind(user_uuid)
        .bind(actor_ip)
        .bind(entry.user_agent.as_deref())
        .bind(request_uuid)
        .bind(&entry.event_type)
        .bind(event_status_str)
        .bind(&entry.metadata)
        .bind(entry.prev_hash.as_deref())
        .bind(entry.entry_hash.as_deref())
        .bind(entry.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "append audit log"))?;

        tx.commit()
            .await
            .map_err(|e| Self::map_sqlx_error(e, "commit audit log"))?;

        metrics::gauge!("korgan_audit_chain_length").increment(1.0);

        Ok(())
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        let user_uuid = user_id.to_uuid();
        let limit_i64 = i64::from(limit);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT
                id,
                user_id,
                actor_ip,
                user_agent,
                request_id,
                event_type,
                event_status,
                metadata,
                prev_hash,
                entry_hash,
                created_at
            FROM audit_logs
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_uuid)
        .bind(limit_i64)
        .bind(offset_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_by_user_id"))?;

        rows.into_iter().map(AuditLog::try_from).collect()
    }

    async fn list_recent(&self, limit: u32, offset: u64) -> Result<Vec<AuditLog>, PortError> {
        let limit_i64 = i64::from(limit);
        let offset_i64 = i64::try_from(offset).unwrap_or(i64::MAX);

        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT
                id,
                user_id,
                actor_ip,
                user_agent,
                request_id,
                event_type,
                event_status,
                metadata,
                prev_hash,
                entry_hash,
                created_at
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit_i64)
        .bind(offset_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_recent"))?;

        rows.into_iter().map(AuditLog::try_from).collect()
    }

    async fn find_latest_entry_hash(&self) -> Result<Option<String>, PortError> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            r#"
            SELECT entry_hash
            FROM audit_logs
            WHERE entry_hash IS NOT NULL
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_latest_entry_hash"))?;

        Ok(row.and_then(|(hash,)| hash))
    }

    async fn list_all_chronological(&self) -> Result<Vec<AuditLog>, PortError> {
        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT
                id,
                user_id,
                actor_ip,
                user_agent,
                request_id,
                event_type,
                event_status,
                metadata,
                prev_hash,
                entry_hash,
                created_at
            FROM audit_logs
            ORDER BY created_at ASC, id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_all_chronological"))?;

        rows.into_iter().map(AuditLog::try_from).collect()
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM audit_logs
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "count_all"))?;

        Ok(u64::try_from(count).unwrap_or(0))
    }
}
