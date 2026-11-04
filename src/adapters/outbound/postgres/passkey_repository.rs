//! PostgreSQL implementation of [`PasskeyRepository`].

use async_trait::async_trait;
use sqlx::PgPool;

use crate::adapters::outbound::postgres::models::PasskeyRow;
use crate::domain::entities::Passkey;
use crate::domain::value_objects::{PasskeyId, UserId};
use crate::ports::errors::PortError;
use crate::ports::repositories::PasskeyRepository;

/// PostgreSQL passkey repository backed by `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresPasskeyRepository {
    pool: PgPool,
}

impl PostgresPasskeyRepository {
    /// Creates a new [`PostgresPasskeyRepository`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

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
impl PasskeyRepository for PostgresPasskeyRepository {
    async fn save(&self, passkey: &Passkey) -> Result<(), PortError> {
        let id = passkey.id.as_uuid();
        let user_id = passkey.user_id.as_uuid();

        sqlx::query!(
            r#"
            INSERT INTO passkeys (
                id,
                user_id,
                credential_id,
                passkey_json,
                name,
                last_used_at,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                passkey_json = EXCLUDED.passkey_json,
                name = EXCLUDED.name,
                last_used_at = EXCLUDED.last_used_at
            "#,
            id,
            user_id,
            &passkey.credential_id,
            &passkey.passkey_json,
            passkey.name,
            passkey.last_used_at,
            passkey.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "save passkey"))?;

        Ok(())
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, PortError> {
        let row = sqlx::query_as!(
            PasskeyRow,
            r#"
            SELECT
                id,
                user_id,
                credential_id,
                passkey_json,
                name,
                last_used_at,
                created_at
            FROM passkeys
            WHERE credential_id = $1
            "#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find passkey by credential id"))?;

        row.map(Passkey::try_from).transpose()
    }

    async fn find_by_id(&self, id: &PasskeyId) -> Result<Option<Passkey>, PortError> {
        let id_uuid = id.as_uuid();

        let row = sqlx::query_as!(
            PasskeyRow,
            r#"
            SELECT
                id,
                user_id,
                credential_id,
                passkey_json,
                name,
                last_used_at,
                created_at
            FROM passkeys
            WHERE id = $1
            "#,
            id_uuid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find passkey by id"))?;

        row.map(Passkey::try_from).transpose()
    }

    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<Passkey>, PortError> {
        let user_id_uuid = user_id.as_uuid();

        let rows = sqlx::query_as!(
            PasskeyRow,
            r#"
            SELECT
                id,
                user_id,
                credential_id,
                passkey_json,
                name,
                last_used_at,
                created_at
            FROM passkeys
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id_uuid
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list passkeys by user id"))?;

        rows.into_iter().map(Passkey::try_from).collect()
    }

    async fn delete_by_id(&self, id: &PasskeyId) -> Result<(), PortError> {
        let id_uuid = id.as_uuid();

        sqlx::query!(
            r#"
            DELETE FROM passkeys
            WHERE id = $1
            "#,
            id_uuid
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "delete passkey by id"))?;

        Ok(())
    }

    async fn delete_by_id_and_user_id(
        &self,
        id: &PasskeyId,
        user_id: &UserId,
    ) -> Result<bool, PortError> {
        let id_uuid = id.as_uuid();
        let user_uuid = user_id.to_uuid();

        let result = sqlx::query(
            r#"
            DELETE FROM passkeys
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(id_uuid)
        .bind(user_uuid)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "delete passkey by id and user id"))?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_credential_state(
        &self,
        id: &PasskeyId,
        passkey_json: &serde_json::Value,
        last_used_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError> {
        let id_uuid = id.as_uuid();

        let result = sqlx::query(
            r#"
            UPDATE passkeys
            SET passkey_json = $2, last_used_at = $3
            WHERE id = $1
              AND (
                (COALESCE((passkey_json->'cred'->>'counter')::bigint, 0) = 0 AND COALESCE(($2->'cred'->>'counter')::bigint, 0) = 0)
                OR COALESCE(($2->'cred'->>'counter')::bigint, 0) > COALESCE((passkey_json->'cred'->>'counter')::bigint, 0)
              )
            "#,
        )
        .bind(id_uuid)
        .bind(passkey_json)
        .bind(last_used_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "update passkey credential state"))?;

        if result.rows_affected() == 0 {
            if self.find_by_id(id).await?.is_none() {
                return Err(PortError::not_found("Passkey"));
            }
            return Err(PortError::conflict(
                "passkey counter state conflict or replay detected",
            ));
        }

        Ok(())
    }
}
