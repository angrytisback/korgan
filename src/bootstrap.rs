//! Composition root: builds every outbound adapter, wires the use cases and
//! returns a ready-to-serve [`AppState`] plus its background [`EventWorker`].
//!
//! This is the only place that knows both the concrete adapters and the
//! application layer; everything else depends on ports.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;

use crate::adapters::inbound::http::AppState;
use crate::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use crate::adapters::outbound::hibp::{NoopHibpClient, ReqwestHibpClient};
use crate::adapters::outbound::mail::{ConsoleMailProvider, ResendMailProvider, SmtpMailProvider};
use crate::adapters::outbound::oauth::{GithubOAuthAdapter, GoogleOAuthAdapter, NoopOAuthProvider};
use crate::adapters::outbound::postgres::{
    PostgresAuditLogRepository, PostgresOAuthAccountRepository, PostgresPasskeyRepository,
    PostgresSessionRepository, PostgresUnitOfWork, PostgresUserRepository,
};
use crate::adapters::outbound::redis::{RedisRateLimiter, RedisTokenStore};
use crate::application::workers::{EventBus, EventWorker};
use crate::config::{MailProvider as ConfigMailProvider, Settings};
use crate::domain::entities::OAuthProvider;
use crate::ports::cache::{RateLimiterPort, TokenStore};
use crate::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use crate::ports::services::{
    HibpClient, MailProvider, OAuthProviderPort, PasswordHasher, SecretCipher, TokenSigner,
    TotpService, WebAuthnService,
};

/// SQL migrations embedded into the binary at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Applies all pending embedded migrations.
///
/// `sqlx` holds a PostgreSQL advisory lock while migrating, so several
/// replicas starting at the same time serialize safely: one applies the
/// migrations, the others find nothing left to do.
///
/// # Errors
///
/// Returns an error if the database is unreachable, a migration fails, or an
/// already-applied migration was modified.
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

/// Boxed error returned while assembling the application.
pub type BootError = Box<dyn std::error::Error + Send + Sync>;

/// Creates a complete [`AppState`] and background [`EventWorker`] from validated configuration.
///
/// Database and Redis connection pools are created lazily, permitting initialization in test
/// and offline environments where live databases are not running.
///
/// # Errors
///
/// Returns an error if cryptographic key material cannot be parsed or configuration is invalid.
pub fn build_state(settings: Arc<Settings>) -> Result<(AppState, EventWorker), BootError> {
    // 1. Database & Cache Pools
    let pg_pool = build_pg_pool(&settings)?;
    let redis_pool = build_redis_pool(&settings)?;

    // 2. Repositories
    let user_repo: Arc<dyn UserRepository> = Arc::new(PostgresUserRepository::new(pg_pool.clone()));
    let session_repo: Arc<dyn SessionRepository> =
        Arc::new(PostgresSessionRepository::new(pg_pool.clone()));
    let audit_repo: Arc<dyn AuditLogRepository> =
        Arc::new(PostgresAuditLogRepository::new(pg_pool.clone()));
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> =
        Arc::new(PostgresOAuthAccountRepository::new(pg_pool.clone()));
    let passkey_repo: Arc<dyn PasskeyRepository> =
        Arc::new(PostgresPasskeyRepository::new(pg_pool.clone()));

    // 3. Cache & Rate Limiting
    let token_store: Arc<dyn TokenStore> = Arc::new(RedisTokenStore::new(
        redis_pool.clone(),
        settings.redis.key_prefix.clone(),
    ));
    let rate_limiter: Arc<dyn RateLimiterPort> = Arc::new(RedisRateLimiter::new(
        redis_pool.clone(),
        settings.redis.key_prefix.clone(),
    ));

    // 4. Cryptography Services
    let password_hasher: Arc<dyn PasswordHasher> =
        Arc::new(Argon2PasswordHasher::new_with_concurrency(
            settings.crypto.argon2_memory_kib,
            settings.crypto.argon2_iterations,
            settings.crypto.argon2_parallelism,
            settings.crypto.argon2_max_concurrency,
        )?);

    let token_signer: Arc<dyn TokenSigner> = Arc::new(Ed25519JwtService::from_pkcs8_pem(
        settings.crypto.normalized_ed25519_pem().expose_secret(),
        Some(settings.crypto.ed25519_key_id.clone()),
    )?);

    let secret_cipher: Arc<dyn SecretCipher> = Arc::new(Aes256GcmCipher::from_base64(
        settings.crypto.aes_master_key.expose_secret(),
    )?);

    let totp_service: Arc<dyn TotpService> = Arc::new(Rfc6238TotpService::new());

    // 5. External Services (HIBP & Mail & OAuth)
    let hibp_client: Arc<dyn HibpClient> = if settings.hibp.enabled {
        Arc::new(ReqwestHibpClient::new(settings.hibp.api_url.clone()))
    } else {
        Arc::new(NoopHibpClient)
    };

    let mail_provider: Arc<dyn MailProvider> = match settings.mail.provider {
        ConfigMailProvider::Console => {
            Arc::new(ConsoleMailProvider::new(settings.mail.from_address.clone()))
        }
        ConfigMailProvider::Smtp => Arc::new(SmtpMailProvider::new(
            &settings.mail.from_address,
            &settings.mail.smtp,
        )?),
        ConfigMailProvider::Resend => {
            if let Some(ref api_key) = settings.mail.resend.api_key {
                Arc::new(ResendMailProvider::new(
                    settings.mail.from_address.clone(),
                    api_key.clone(),
                ))
            } else {
                Arc::new(ConsoleMailProvider::new(settings.mail.from_address.clone()))
            }
        }
        ConfigMailProvider::Ses => {
            Arc::new(ConsoleMailProvider::new(settings.mail.from_address.clone()))
        }
    };

    let google_oauth: Arc<dyn OAuthProviderPort> = if settings.oauth.google.enabled {
        if let (Some(client_id), Some(client_secret), Some(redirect_uri)) = (
            &settings.oauth.google.client_id,
            &settings.oauth.google.client_secret,
            &settings.oauth.google.redirect_uri,
        ) {
            Arc::new(GoogleOAuthAdapter::new(
                client_id.clone(),
                client_secret.clone(),
                redirect_uri.clone(),
            ))
        } else {
            Arc::new(NoopOAuthProvider::new(OAuthProvider::Google))
        }
    } else {
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google))
    };

    let github_oauth: Arc<dyn OAuthProviderPort> = if settings.oauth.github.enabled {
        if let (Some(client_id), Some(client_secret), Some(redirect_uri)) = (
            &settings.oauth.github.client_id,
            &settings.oauth.github.client_secret,
            &settings.oauth.github.redirect_uri,
        ) {
            Arc::new(GithubOAuthAdapter::new(
                client_id.clone(),
                client_secret.clone(),
                redirect_uri.clone(),
            ))
        } else {
            Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub))
        }
    } else {
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub))
    };

    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebauthnRsAdapter::new(
        &settings.webauthn.rp_id,
        &settings.webauthn.rp_origin,
    )?);

    // 6. Asynchronous Event Bus & Background Worker
    let audit_outbox = Arc::new(PostgresAuditLogRepository::new(pg_pool.clone()));
    let (event_bus, event_rx) = EventBus::new(settings.workers.event_queue_capacity);
    let event_bus = event_bus
        .with_audit_outbox(audit_outbox.clone())
        .with_unit_of_work(Arc::new(PostgresUnitOfWork::new(pg_pool.clone())));
    let event_worker = EventWorker::new(
        event_rx,
        mail_provider.clone(),
        audit_repo.clone(),
        settings.server.public_base_url.clone(),
    )
    .with_audit_outbox(
        audit_outbox,
        event_bus.audit_outbox_wake(),
        settings.workers.audit_outbox_batch_size,
        Duration::from_millis(settings.workers.audit_outbox_poll_ms),
    );

    let state = AppState::with_ports(
        settings,
        user_repo,
        session_repo,
        audit_repo,
        oauth_account_repo,
        passkey_repo,
        token_store,
        rate_limiter,
        password_hasher,
        token_signer,
        secret_cipher,
        totp_service,
        hibp_client,
        mail_provider,
        google_oauth,
        github_oauth,
        webauthn_service,
        event_bus,
        pg_pool,
        redis_pool,
    );

    Ok((state, event_worker))
}

/// Builds the lazy PostgreSQL pool from validated settings.
///
/// Honors every pool-related key: size bounds, acquire/idle timeouts and the
/// server-side `statement_timeout`.
pub fn build_pg_pool(settings: &Settings) -> Result<sqlx::PgPool, BootError> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    let db = &settings.database;
    let mut options: PgConnectOptions = db.url.expose_secret().parse()?;
    if db.statement_timeout_secs > 0 {
        let millis = db.statement_timeout_secs.saturating_mul(1_000);
        options = options.options([("statement_timeout", millis.to_string())]);
    }

    Ok(PgPoolOptions::new()
        .max_connections(db.max_connections)
        .min_connections(db.min_connections)
        .acquire_timeout(Duration::from_secs(db.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(db.idle_timeout_secs))
        .connect_lazy_with(options))
}

/// Builds the Redis pool with a bounded size and bounded waits, so a Redis
/// stall fails fast (fail-closed) instead of queueing requests indefinitely.
pub fn build_redis_pool(settings: &Settings) -> Result<deadpool_redis::Pool, BootError> {
    let redis = &settings.redis;
    let wait = Some(Duration::from_secs(redis.connect_timeout_secs));

    let mut config = deadpool_redis::Config::from_url(redis.url.expose_secret());
    let mut pool_config = deadpool_redis::PoolConfig::new(redis.pool_size);
    pool_config.timeouts = deadpool_redis::Timeouts {
        wait,
        create: wait,
        recycle: wait,
    };
    config.pool = Some(pool_config);

    Ok(config.create_pool(Some(deadpool_redis::Runtime::Tokio1))?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn settings(extra: &[(&str, &str)]) -> Result<Settings, Box<dyn std::error::Error>> {
        let mut env = HashMap::from([
            ("DATABASE_URL".to_owned(), "postgres://u:p@localhost:5432/db".to_owned()),
            ("REDIS_URL".to_owned(), "redis://localhost:6379".to_owned()),
            (
                "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----".to_owned(),
            ),
            (
                "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
                "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=".to_owned(),
            ),
        ]);
        env.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        Ok(Settings::load_from_env(env)?)
    }

    #[tokio::test]
    async fn pg_pool_honors_configured_bounds_and_timeouts()
    -> Result<(), Box<dyn std::error::Error>> {
        let settings = settings(&[
            ("KORGAN__DATABASE__MAX_CONNECTIONS", "7"),
            ("KORGAN__DATABASE__MIN_CONNECTIONS", "1"),
            ("KORGAN__DATABASE__ACQUIRE_TIMEOUT_SECS", "3"),
            ("KORGAN__DATABASE__IDLE_TIMEOUT_SECS", "42"),
        ])?;
        let pool = build_pg_pool(&settings).map_err(|e| e.to_string())?;
        let options = pool.options();
        assert_eq!(options.get_max_connections(), 7);
        assert_eq!(options.get_min_connections(), 1);
        assert_eq!(options.get_acquire_timeout(), Duration::from_secs(3));
        assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(42)));
        Ok(())
    }

    #[tokio::test]
    async fn redis_pool_honors_configured_size_and_timeouts()
    -> Result<(), Box<dyn std::error::Error>> {
        let settings = settings(&[
            ("KORGAN__REDIS__POOL_SIZE", "5"),
            ("KORGAN__REDIS__CONNECT_TIMEOUT_SECS", "2"),
        ])?;
        let pool = build_redis_pool(&settings).map_err(|e| e.to_string())?;
        assert_eq!(pool.status().max_size, 5);
        let timeouts = pool.timeouts();
        assert_eq!(timeouts.wait, Some(Duration::from_secs(2)));
        assert_eq!(timeouts.create, Some(Duration::from_secs(2)));
        assert_eq!(timeouts.recycle, Some(Duration::from_secs(2)));
        Ok(())
    }
}
