//! Shared application state injected into every handler and route.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;

use crate::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use crate::adapters::outbound::hibp::{NoopHibpClient, ReqwestHibpClient};
use crate::adapters::outbound::mail::{ConsoleMailProvider, ResendMailProvider, SmtpMailProvider};
use crate::adapters::outbound::oauth::{GithubOAuthAdapter, GoogleOAuthAdapter, NoopOAuthProvider};
use crate::adapters::outbound::postgres::{
    PostgresAuditLogRepository, PostgresOAuthAccountRepository, PostgresPasskeyRepository,
    PostgresSessionRepository, PostgresUserRepository,
};
use crate::adapters::outbound::redis::{RedisRateLimiter, RedisTokenStore};
use crate::application::use_cases::admin::{
    BanUserUseCase, BootstrapSuperadminUseCase, ListUsersUseCase, UnbanUserUseCase,
    UnlockUserUseCase, VerifyAuditChainUseCase,
};
use crate::application::use_cases::auth::{
    IssueWsTicketUseCase, LoginConfig, LoginUseCase, RefreshSessionUseCase, RegisterUserUseCase,
    VerifyEmailUseCase, VerifyWsTicketUseCase,
};
use crate::application::use_cases::mfa::{
    DisableTotpUseCase, EnableTotpUseCase, SetupTotpUseCase, VerifyMfaLoginUseCase,
};
use crate::application::use_cases::oauth::{GenerateOAuthUrlUseCase, OAuthCallbackUseCase};
use crate::application::use_cases::passkeys::{
    DeletePasskeyUseCase, FinishPasskeyLoginUseCase, FinishPasskeyRegistrationUseCase,
    ListPasskeysUseCase, StartPasskeyLoginUseCase, StartPasskeyRegistrationUseCase,
};
use crate::application::use_cases::password::{
    ChangePasswordUseCase, ForgotPasswordUseCase, ResetPasswordUseCase,
};
use crate::application::use_cases::sessions::{
    ListSessionsUseCase, RevokeAllSessionsUseCase, RevokeSessionUseCase,
};
use crate::application::use_cases::user::{GetProfileUseCase, UpdateProfileUseCase};
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

/// State shared by all handlers and middlewares.
#[derive(Clone)]
pub struct AppState {
    /// Validated, immutable configuration.
    pub settings: Arc<Settings>,

    // Outbound Port Interfaces
    pub user_repo: Arc<dyn UserRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub audit_repo: Arc<dyn AuditLogRepository>,
    pub oauth_account_repo: Arc<dyn OAuthAccountRepository>,
    pub passkey_repo: Arc<dyn PasskeyRepository>,
    pub token_store: Arc<dyn TokenStore>,
    pub rate_limiter: Arc<dyn RateLimiterPort>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub secret_cipher: Arc<dyn SecretCipher>,
    pub totp_service: Arc<dyn TotpService>,
    pub hibp_client: Arc<dyn HibpClient>,
    pub mail_provider: Arc<dyn MailProvider>,
    pub google_oauth: Arc<dyn OAuthProviderPort>,
    pub github_oauth: Arc<dyn OAuthProviderPort>,
    pub webauthn_service: Arc<dyn WebAuthnService>,
    pub event_bus: EventBus,

    // Core Business Logic Use Cases
    pub register_use_case: RegisterUserUseCase,
    pub login_use_case: LoginUseCase,
    pub refresh_session_use_case: RefreshSessionUseCase,
    pub verify_email_use_case: VerifyEmailUseCase,
    pub generate_oauth_url_use_case: GenerateOAuthUrlUseCase,
    pub oauth_callback_use_case: OAuthCallbackUseCase,
    pub start_passkey_registration_use_case: StartPasskeyRegistrationUseCase,
    pub finish_passkey_registration_use_case: FinishPasskeyRegistrationUseCase,
    pub start_passkey_login_use_case: StartPasskeyLoginUseCase,
    pub finish_passkey_login_use_case: FinishPasskeyLoginUseCase,
    pub list_passkeys_use_case: ListPasskeysUseCase,
    pub delete_passkey_use_case: DeletePasskeyUseCase,
    pub forgot_password_use_case: ForgotPasswordUseCase,
    pub reset_password_use_case: ResetPasswordUseCase,
    pub change_password_use_case: ChangePasswordUseCase,
    pub setup_totp_use_case: SetupTotpUseCase,
    pub enable_totp_use_case: EnableTotpUseCase,
    pub disable_totp_use_case: DisableTotpUseCase,
    pub verify_mfa_login_use_case: VerifyMfaLoginUseCase,
    pub list_sessions_use_case: ListSessionsUseCase,
    pub revoke_session_use_case: RevokeSessionUseCase,
    pub revoke_all_sessions_use_case: RevokeAllSessionsUseCase,
    pub get_profile_use_case: GetProfileUseCase,
    pub update_profile_use_case: UpdateProfileUseCase,
    pub list_users_use_case: ListUsersUseCase,
    pub ban_user_use_case: BanUserUseCase,
    pub unban_user_use_case: UnbanUserUseCase,
    pub issue_ws_ticket_use_case: IssueWsTicketUseCase,
    pub verify_ws_ticket_use_case: VerifyWsTicketUseCase,
    pub bootstrap_use_case: BootstrapSuperadminUseCase,
    pub verify_audit_chain_use_case: VerifyAuditChainUseCase,
    pub unlock_user_use_case: UnlockUserUseCase,

    // Database & Cache Pools (used for health & readiness probes)
    pub pg_pool: sqlx::PgPool,
    pub redis_pool: deadpool_redis::Pool,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Constructs [`AppState`] from explicit port implementations.
    ///
    /// Useful for dependency injection during unit and integration testing.
    #[allow(clippy::too_many_arguments)]
    pub fn with_ports(
        settings: Arc<Settings>,
        user_repo: Arc<dyn UserRepository>,
        session_repo: Arc<dyn SessionRepository>,
        audit_repo: Arc<dyn AuditLogRepository>,
        oauth_account_repo: Arc<dyn OAuthAccountRepository>,
        passkey_repo: Arc<dyn PasskeyRepository>,
        token_store: Arc<dyn TokenStore>,
        rate_limiter: Arc<dyn RateLimiterPort>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_signer: Arc<dyn TokenSigner>,
        secret_cipher: Arc<dyn SecretCipher>,
        totp_service: Arc<dyn TotpService>,
        hibp_client: Arc<dyn HibpClient>,
        mail_provider: Arc<dyn MailProvider>,
        google_oauth: Arc<dyn OAuthProviderPort>,
        github_oauth: Arc<dyn OAuthProviderPort>,
        webauthn_service: Arc<dyn WebAuthnService>,
        event_bus: EventBus,
        pg_pool: sqlx::PgPool,
        redis_pool: deadpool_redis::Pool,
    ) -> Self {
        let register_use_case = RegisterUserUseCase::new(
            user_repo.clone(),
            password_hasher.clone(),
            token_store.clone(),
            hibp_client.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.email_verification_ttl_secs),
        );

        let login_config = LoginConfig {
            max_failed_attempts: settings.auth.max_failed_login_attempts,
            lockout_duration: Duration::from_secs(settings.auth.lockout_duration_secs),
            rate_limit_window: Duration::from_secs(60),
            max_attempts_per_ip: 10,
            access_token_ttl: Duration::from_secs(settings.auth.access_token_ttl_secs),
            refresh_token_ttl: Duration::from_secs(settings.auth.refresh_token_ttl_secs),
            mfa_ticket_ttl: Duration::from_secs(settings.auth.mfa_challenge_ttl_secs),
            jwt_issuer: settings.auth.issuer.clone(),
            jwt_audience: settings.auth.audience.clone(),
        };

        let login_use_case = LoginUseCase::new(
            user_repo.clone(),
            session_repo.clone(),
            password_hasher.clone(),
            token_signer.clone(),
            token_store.clone(),
            rate_limiter.clone(),
            event_bus.clone(),
            login_config,
        );

        let refresh_session_use_case = RefreshSessionUseCase::new(
            session_repo.clone(),
            user_repo.clone(),
            token_signer.clone(),
            token_store.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.access_token_ttl_secs),
            Duration::from_secs(settings.auth.refresh_token_ttl_secs),
            settings.auth.issuer.clone(),
            settings.auth.audience.clone(),
        );

        let verify_email_use_case =
            VerifyEmailUseCase::new(user_repo.clone(), token_store.clone(), event_bus.clone());

        let generate_oauth_url_use_case = GenerateOAuthUrlUseCase::new(
            google_oauth.clone(),
            github_oauth.clone(),
            token_store.clone(),
            Duration::from_secs(600),
        );

        let oauth_callback_use_case = OAuthCallbackUseCase::new(
            user_repo.clone(),
            oauth_account_repo.clone(),
            session_repo.clone(),
            token_signer.clone(),
            token_store.clone(),
            google_oauth.clone(),
            github_oauth.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.access_token_ttl_secs),
            Duration::from_secs(settings.auth.refresh_token_ttl_secs),
            settings.auth.issuer.clone(),
            settings.auth.audience.clone(),
        );

        let start_passkey_registration_use_case = StartPasskeyRegistrationUseCase::new(
            user_repo.clone(),
            passkey_repo.clone(),
            webauthn_service.clone(),
            token_store.clone(),
            Duration::from_secs(120),
        );

        let finish_passkey_registration_use_case = FinishPasskeyRegistrationUseCase::new(
            passkey_repo.clone(),
            webauthn_service.clone(),
            token_store.clone(),
            event_bus.clone(),
        );

        let start_passkey_login_use_case = StartPasskeyLoginUseCase::new(
            webauthn_service.clone(),
            token_store.clone(),
            Duration::from_secs(120),
        );

        let finish_passkey_login_use_case = FinishPasskeyLoginUseCase::new(
            user_repo.clone(),
            passkey_repo.clone(),
            session_repo.clone(),
            webauthn_service.clone(),
            token_store.clone(),
            token_signer.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.access_token_ttl_secs),
            Duration::from_secs(settings.auth.refresh_token_ttl_secs),
            settings.auth.issuer.clone(),
            settings.auth.audience.clone(),
        );

        let list_passkeys_use_case = ListPasskeysUseCase::new(passkey_repo.clone());
        let delete_passkey_use_case =
            DeletePasskeyUseCase::new(passkey_repo.clone(), event_bus.clone());

        let forgot_password_use_case = ForgotPasswordUseCase::new(
            user_repo.clone(),
            token_store.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.password_reset_ttl_secs),
        );

        let reset_password_use_case = ResetPasswordUseCase::new(
            user_repo.clone(),
            session_repo.clone(),
            password_hasher.clone(),
            token_store.clone(),
            hibp_client.clone(),
            event_bus.clone(),
            settings.auth.password_history_depth,
        );

        let change_password_use_case = ChangePasswordUseCase::new(
            user_repo.clone(),
            session_repo.clone(),
            password_hasher.clone(),
            token_store.clone(),
            hibp_client.clone(),
            event_bus.clone(),
            settings.auth.password_history_depth,
        );

        let setup_totp_use_case = SetupTotpUseCase::new(
            user_repo.clone(),
            totp_service.clone(),
            token_store.clone(),
            "Korgan".to_owned(),
            Duration::from_secs(settings.auth.mfa_challenge_ttl_secs),
        );

        let enable_totp_use_case = EnableTotpUseCase::new(
            user_repo.clone(),
            totp_service.clone(),
            secret_cipher.clone(),
            token_store.clone(),
            event_bus.clone(),
        );

        let disable_totp_use_case = DisableTotpUseCase::new(
            user_repo.clone(),
            password_hasher.clone(),
            event_bus.clone(),
        );

        let verify_mfa_login_use_case = VerifyMfaLoginUseCase::new(
            user_repo.clone(),
            session_repo.clone(),
            totp_service.clone(),
            secret_cipher.clone(),
            token_signer.clone(),
            token_store.clone(),
            event_bus.clone(),
            Duration::from_secs(settings.auth.access_token_ttl_secs),
            Duration::from_secs(settings.auth.refresh_token_ttl_secs),
            settings.auth.issuer.clone(),
            settings.auth.audience.clone(),
            settings.auth.max_failed_login_attempts,
            Duration::from_secs(settings.auth.lockout_duration_secs),
        );

        let list_sessions_use_case = ListSessionsUseCase::new(session_repo.clone());
        let revoke_session_use_case =
            RevokeSessionUseCase::new(session_repo.clone(), token_store.clone(), event_bus.clone());
        let revoke_all_sessions_use_case = RevokeAllSessionsUseCase::new(
            session_repo.clone(),
            token_store.clone(),
            event_bus.clone(),
        );

        let get_profile_use_case = GetProfileUseCase::new(user_repo.clone());
        let update_profile_use_case = UpdateProfileUseCase::new(user_repo.clone());
        let list_users_use_case = ListUsersUseCase::new(user_repo.clone());
        let ban_user_use_case = BanUserUseCase::new(
            user_repo.clone(),
            session_repo.clone(),
            token_store.clone(),
            event_bus.clone(),
        );
        let unban_user_use_case = UnbanUserUseCase::new(user_repo.clone(), event_bus.clone());
        let issue_ws_ticket_use_case = IssueWsTicketUseCase::new(token_store.clone());
        let verify_ws_ticket_use_case = VerifyWsTicketUseCase::new(token_store.clone());
        let bootstrap_use_case = BootstrapSuperadminUseCase::new(
            user_repo.clone(),
            password_hasher.clone(),
            event_bus.clone(),
        );
        let verify_audit_chain_use_case = VerifyAuditChainUseCase::new(audit_repo.clone());
        let unlock_user_use_case = UnlockUserUseCase::new(user_repo.clone(), event_bus.clone());

        Self {
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
            register_use_case,
            login_use_case,
            refresh_session_use_case,
            verify_email_use_case,
            generate_oauth_url_use_case,
            oauth_callback_use_case,
            start_passkey_registration_use_case,
            finish_passkey_registration_use_case,
            start_passkey_login_use_case,
            finish_passkey_login_use_case,
            list_passkeys_use_case,
            delete_passkey_use_case,
            forgot_password_use_case,
            reset_password_use_case,
            change_password_use_case,
            setup_totp_use_case,
            enable_totp_use_case,
            disable_totp_use_case,
            verify_mfa_login_use_case,
            list_sessions_use_case,
            revoke_session_use_case,
            revoke_all_sessions_use_case,
            get_profile_use_case,
            update_profile_use_case,
            list_users_use_case,
            ban_user_use_case,
            unban_user_use_case,
            issue_ws_ticket_use_case,
            verify_ws_ticket_use_case,
            bootstrap_use_case,
            verify_audit_chain_use_case,
            unlock_user_use_case,
            pg_pool,
            redis_pool,
        }
    }

    /// Synchronizes Prometheus telemetry gauges with persistent storage counts.
    pub async fn sync_telemetry_gauges(&self) {
        if let Ok(count) = self.audit_repo.count_all().await {
            metrics::gauge!("korgan_audit_chain_length").set(count as f64);
        }
        if let Ok(count) = self.session_repo.count_active().await {
            metrics::gauge!("korgan_active_sessions_gauge").set(count as f64);
        }
    }

    /// Creates a complete [`AppState`] and background [`EventWorker`] from validated configuration.
    ///
    /// Database and Redis connection pools are created lazily, permitting initialization in test
    /// and offline environments where live databases are not running.
    ///
    /// # Errors
    ///
    /// Returns an error if cryptographic key material cannot be parsed or configuration is invalid.
    pub fn from_settings(
        settings: Arc<Settings>,
    ) -> Result<(Self, EventWorker), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Database & Cache Pools
        let pg_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(settings.database.max_connections)
            .connect_lazy(settings.database.url.expose_secret())?;

        let redis_cfg = deadpool_redis::Config::from_url(settings.redis.url.expose_secret());
        let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

        // 2. Repositories
        let user_repo: Arc<dyn UserRepository> =
            Arc::new(PostgresUserRepository::new(pg_pool.clone()));
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
        let (event_bus, event_rx) = EventBus::new(1024);
        let event_worker = EventWorker::new(
            event_rx,
            mail_provider.clone(),
            audit_repo.clone(),
            settings.server.public_base_url.clone(),
        );

        let state = Self::with_ports(
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

    /// Performs readiness checks against the database pool and Redis connection.
    ///
    /// # Errors
    ///
    /// Returns an error if either PostgreSQL or Redis cannot be contacted.
    pub async fn check_readiness(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Check PostgreSQL
        sqlx::query("SELECT 1")
            .execute(&self.pg_pool)
            .await
            .map_err(|e| format!("database probe failed: {e}"))?;

        // 2. Check Redis / Valkey
        let mut conn = self
            .redis_pool
            .get()
            .await
            .map_err(|e| format!("redis pool acquire failed: {e}"))?;

        deadpool_redis::redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| format!("redis ping failed: {e}"))?;

        Ok(())
    }
}
