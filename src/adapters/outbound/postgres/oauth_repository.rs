//! PostgreSQL implementation of [`OAuthAccountRepository`].

use async_trait::async_trait;
use sqlx::PgPool;

use crate::adapters::outbound::postgres::models::OAuthAccountRow;
use crate::domain::entities::{OAuthAccount, OAuthProvider};
use crate::domain::value_objects::UserId;
use crate::ports::errors::PortError;
use crate::ports::repositories::OAuthAccountRepository;

/// PostgreSQL OAuth account repository backed by `sqlx::PgPool`.
#[derive(Debug, Clone)]
pub struct PostgresOAuthAccountRepository {
    pool: PgPool,
}

impl PostgresOAuthAccountRepository {
    /// Creates a new [`PostgresOAuthAccountRepository`].
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
impl OAuthAccountRepository for PostgresOAuthAccountRepository {
    async fn find_by_provider_and_id(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        let provider_str = provider.as_str();

        let row = sqlx::query_as!(
            OAuthAccountRow,
            r#"
            SELECT
                id,
                user_id,
                provider,
                provider_user_id,
                created_at
            FROM oauth_accounts
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider_str,
            provider_user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "find_by_provider_and_id"))?;

        row.map(OAuthAccount::try_from).transpose()
    }

    async fn create(&self, account: &OAuthAccount) -> Result<(), PortError> {
        let id_uuid = account.id.to_uuid();
        let user_uuid = account.user_id.to_uuid();
        let provider_str = account.provider.as_str();

        sqlx::query!(
            r#"
            INSERT INTO oauth_accounts (
                id,
                user_id,
                provider,
                provider_user_id,
                created_at
            ) VALUES (
                $1, $2, $3, $4, $5
            )
            "#,
            id_uuid,
            user_uuid,
            provider_str,
            account.provider_user_id,
            account.created_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "create oauth account"))?;

        Ok(())
    }

    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        let user_uuid = user_id.to_uuid();

        let rows = sqlx::query_as!(
            OAuthAccountRow,
            r#"
            SELECT
                id,
                user_id,
                provider,
                provider_user_id,
                created_at
            FROM oauth_accounts
            WHERE user_id = $1
            ORDER BY created_at ASC
            "#,
            user_uuid
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::map_sqlx_error(e, "list_by_user_id"))?;

        rows.into_iter().map(OAuthAccount::try_from).collect()
    }
}
