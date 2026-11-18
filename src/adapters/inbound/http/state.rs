//! Shared application state injected into every handler and route.

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

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
use crate::application::workers::EventBus;
use crate::config::Settings;
use crate::ports::cache::{RateLimiterPort, TokenStore};
use crate::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use crate::ports::services::{
    HibpClient, MailProvider, OAuthProviderPort, PasswordHasher, SecretCipher, TokenSigner,
    TotpService, WebAuthnService,
};

/// Inner state shared across all HTTP handlers, extractors, and middleware.
///
/// It carries only what the HTTP layer needs: the use cases, and the few
/// infrastructure handles that extractors, middleware and probes use directly
/// (token verification, blacklist, rate limiter, the pools for readiness).
/// Raw adapters that exist only to build the use cases (mail, TOTP, cipher,
/// HIBP, OAuth and WebAuthn providers, the event bus) are *not* stored here.
/// Fields are crate-private except the handful the binary (GC worker, CLI)
/// and the integration tests access directly.
pub struct AppStateInner {
    /// Validated, immutable configuration.
    pub(crate) settings: Arc<Settings>,

    // Outbound Port Interfaces
    pub user_repo: Arc<dyn UserRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub(crate) audit_repo: Arc<dyn AuditLogRepository>,
    pub(crate) passkey_repo: Arc<dyn PasskeyRepository>,
    pub(crate) token_store: Arc<dyn TokenStore>,
    pub(crate) rate_limiter: Arc<dyn RateLimiterPort>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub(crate) token_signer: Arc<dyn TokenSigner>,

    // Core Business Logic Use Cases
    pub(crate) register_use_case: RegisterUserUseCase,
    pub(crate) login_use_case: LoginUseCase,
    pub(crate) refresh_session_use_case: RefreshSessionUseCase,
    pub(crate) verify_email_use_case: VerifyEmailUseCase,
    pub(crate) generate_oauth_url_use_case: GenerateOAuthUrlUseCase,
    pub(crate) oauth_callback_use_case: OAuthCallbackUseCase,
    pub(crate) start_passkey_registration_use_case: StartPasskeyRegistrationUseCase,
    pub(crate) finish_passkey_registration_use_case: FinishPasskeyRegistrationUseCase,
    pub(crate) start_passkey_login_use_case: StartPasskeyLoginUseCase,
    pub(crate) finish_passkey_login_use_case: FinishPasskeyLoginUseCase,
    pub(crate) list_passkeys_use_case: ListPasskeysUseCase,
    pub(crate) delete_passkey_use_case: DeletePasskeyUseCase,
    pub(crate) forgot_password_use_case: ForgotPasswordUseCase,
    pub(crate) reset_password_use_case: ResetPasswordUseCase,
    pub(crate) change_password_use_case: ChangePasswordUseCase,
    pub(crate) setup_totp_use_case: SetupTotpUseCase,
    pub(crate) enable_totp_use_case: EnableTotpUseCase,
    pub(crate) disable_totp_use_case: DisableTotpUseCase,
    pub(crate) verify_mfa_login_use_case: VerifyMfaLoginUseCase,
    pub(crate) list_sessions_use_case: ListSessionsUseCase,
    pub(crate) revoke_session_use_case: RevokeSessionUseCase,
    pub(crate) revoke_all_sessions_use_case: RevokeAllSessionsUseCase,
    pub(crate) get_profile_use_case: GetProfileUseCase,
    pub(crate) update_profile_use_case: UpdateProfileUseCase,
    pub(crate) list_users_use_case: ListUsersUseCase,
    pub(crate) ban_user_use_case: BanUserUseCase,
    pub(crate) unban_user_use_case: UnbanUserUseCase,
    pub(crate) issue_ws_ticket_use_case: IssueWsTicketUseCase,
    pub(crate) verify_ws_ticket_use_case: VerifyWsTicketUseCase,
    pub bootstrap_use_case: BootstrapSuperadminUseCase,
    pub verify_audit_chain_use_case: VerifyAuditChainUseCase,
    pub unlock_user_use_case: UnlockUserUseCase,

    // Database & Cache Pools (used for health & readiness probes)
    pub pg_pool: sqlx::PgPool,
    pub(crate) redis_pool: deadpool_redis::Pool,
}

impl std::fmt::Debug for AppStateInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateInner")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// Cheaply cloneable handle to shared [`AppStateInner`] state.
///
/// Wrapping the 43 state fields behind a single [`Arc`] reduces per-request
/// `State<AppState>` extraction from ~100 atomic reference-count updates to 1.
pub struct AppState {
    inner: Arc<AppStateInner>,
}

impl Clone for AppState {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

impl Deref for AppState {
    type Target = AppStateInner;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

struct SharedPortRefs<'a> {
    settings: &'a Settings,
    user_repo: &'a Arc<dyn UserRepository>,
    session_repo: &'a Arc<dyn SessionRepository>,
    audit_repo: &'a Arc<dyn AuditLogRepository>,
    passkey_repo: &'a Arc<dyn PasskeyRepository>,
    token_store: &'a Arc<dyn TokenStore>,
    rate_limiter: &'a Arc<dyn RateLimiterPort>,
    password_hasher: &'a Arc<dyn PasswordHasher>,
    token_signer: &'a Arc<dyn TokenSigner>,
}

struct AuthUseCases {
    register: RegisterUserUseCase,
    login: LoginUseCase,
    refresh_session: RefreshSessionUseCase,
    verify_email: VerifyEmailUseCase,
}

struct OAuthAndPasskeyUseCases {
    generate_oauth_url: GenerateOAuthUrlUseCase,
    oauth_callback: OAuthCallbackUseCase,
    start_passkey_registration: StartPasskeyRegistrationUseCase,
    finish_passkey_registration: FinishPasskeyRegistrationUseCase,
    start_passkey_login: StartPasskeyLoginUseCase,
    finish_passkey_login: FinishPasskeyLoginUseCase,
    list_passkeys: ListPasskeysUseCase,
    delete_passkey: DeletePasskeyUseCase,
}

struct PasswordAndMfaUseCases {
    forgot_password: ForgotPasswordUseCase,
    reset_password: ResetPasswordUseCase,
    change_password: ChangePasswordUseCase,
    setup_totp: SetupTotpUseCase,
    enable_totp: EnableTotpUseCase,
    disable_totp: DisableTotpUseCase,
    verify_mfa_login: VerifyMfaLoginUseCase,
}

struct SessionUserAdminUseCases {
    list_sessions: ListSessionsUseCase,
    revoke_session: RevokeSessionUseCase,
    revoke_all_sessions: RevokeAllSessionsUseCase,
    get_profile: GetProfileUseCase,
    update_profile: UpdateProfileUseCase,
    list_users: ListUsersUseCase,
    ban_user: BanUserUseCase,
    unban_user: UnbanUserUseCase,
    issue_ws_ticket: IssueWsTicketUseCase,
    verify_ws_ticket: VerifyWsTicketUseCase,
    bootstrap: BootstrapSuperadminUseCase,
    verify_audit_chain: VerifyAuditChainUseCase,
    unlock_user: UnlockUserUseCase,
}

fn build_auth_use_cases(
    ports: &SharedPortRefs<'_>,
    hibp_client: &Arc<dyn HibpClient>,
    event_bus: &EventBus,
) -> AuthUseCases {
    let auth = &ports.settings.auth;
    let register = RegisterUserUseCase::new(
        ports.user_repo.clone(),
        ports.password_hasher.clone(),
        ports.token_store.clone(),
        hibp_client.clone(),
        event_bus.clone(),
        Duration::from_secs(auth.email_verification_ttl_secs),
    );

    let login_config = LoginConfig {
        max_failed_attempts: auth.max_failed_login_attempts,
        lockout_duration: Duration::from_secs(auth.lockout_duration_secs),
        rate_limit_window: Duration::from_secs(ports.settings.rate_limit.window_secs),
        max_attempts_per_ip: ports.settings.rate_limit.login_max_requests,
        access_token_ttl: Duration::from_secs(auth.access_token_ttl_secs),
        refresh_token_ttl: Duration::from_secs(auth.refresh_token_ttl_secs),
        mfa_ticket_ttl: Duration::from_secs(auth.mfa_challenge_ttl_secs),
        jwt_issuer: auth.issuer.clone().into(),
        jwt_audience: auth.audience.clone().into(),
    };

    let login = LoginUseCase::new(
        ports.user_repo.clone(),
        ports.session_repo.clone(),
        ports.password_hasher.clone(),
        ports.token_signer.clone(),
        ports.token_store.clone(),
        ports.rate_limiter.clone(),
        event_bus.clone(),
        login_config,
    );

    let refresh_session = RefreshSessionUseCase::new(
        ports.session_repo.clone(),
        ports.user_repo.clone(),
        ports.token_signer.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(auth.access_token_ttl_secs),
        Duration::from_secs(auth.refresh_token_ttl_secs),
        auth.issuer.clone(),
        auth.audience.clone(),
    );

    let verify_email = VerifyEmailUseCase::new(
        ports.user_repo.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );

    AuthUseCases {
        register,
        login,
        refresh_session,
        verify_email,
    }
}

fn build_oauth_and_passkey_use_cases(
    ports: &SharedPortRefs<'_>,
    oauth_account_repo: Arc<dyn OAuthAccountRepository>,
    google_oauth: Arc<dyn OAuthProviderPort>,
    github_oauth: Arc<dyn OAuthProviderPort>,
    webauthn_service: Arc<dyn WebAuthnService>,
    event_bus: &EventBus,
) -> OAuthAndPasskeyUseCases {
    let auth = &ports.settings.auth;
    let generate_oauth_url = GenerateOAuthUrlUseCase::new(
        google_oauth.clone(),
        github_oauth.clone(),
        ports.token_store.clone(),
        Duration::from_secs(600),
    );

    let oauth_callback = OAuthCallbackUseCase::new(
        ports.user_repo.clone(),
        oauth_account_repo,
        ports.session_repo.clone(),
        ports.token_signer.clone(),
        ports.token_store.clone(),
        google_oauth,
        github_oauth,
        event_bus.clone(),
        Duration::from_secs(auth.access_token_ttl_secs),
        Duration::from_secs(auth.refresh_token_ttl_secs),
        auth.issuer.clone(),
        auth.audience.clone(),
    );

    let start_passkey_registration = StartPasskeyRegistrationUseCase::new(
        ports.user_repo.clone(),
        ports.passkey_repo.clone(),
        webauthn_service.clone(),
        ports.token_store.clone(),
        Duration::from_secs(120),
    );

    let finish_passkey_registration = FinishPasskeyRegistrationUseCase::new(
        ports.passkey_repo.clone(),
        webauthn_service.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );

    let start_passkey_login = StartPasskeyLoginUseCase::new(
        webauthn_service.clone(),
        ports.token_store.clone(),
        Duration::from_secs(120),
    );

    let finish_passkey_login = FinishPasskeyLoginUseCase::new(
        ports.user_repo.clone(),
        ports.passkey_repo.clone(),
        ports.session_repo.clone(),
        webauthn_service,
        ports.token_store.clone(),
        ports.token_signer.clone(),
        event_bus.clone(),
        Duration::from_secs(auth.access_token_ttl_secs),
        Duration::from_secs(auth.refresh_token_ttl_secs),
        auth.issuer.clone(),
        auth.audience.clone(),
    );

    let list_passkeys = ListPasskeysUseCase::new(ports.passkey_repo.clone());
    let delete_passkey = DeletePasskeyUseCase::new(ports.passkey_repo.clone(), event_bus.clone());

    OAuthAndPasskeyUseCases {
        generate_oauth_url,
        oauth_callback,
        start_passkey_registration,
        finish_passkey_registration,
        start_passkey_login,
        finish_passkey_login,
        list_passkeys,
        delete_passkey,
    }
}

fn build_password_and_mfa_use_cases(
    ports: &SharedPortRefs<'_>,
    hibp_client: Arc<dyn HibpClient>,
    totp_service: Arc<dyn TotpService>,
    secret_cipher: Arc<dyn SecretCipher>,
    event_bus: &EventBus,
) -> PasswordAndMfaUseCases {
    let auth = &ports.settings.auth;
    let forgot_password = ForgotPasswordUseCase::new(
        ports.user_repo.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(auth.password_reset_ttl_secs),
    );

    let reset_password = ResetPasswordUseCase::new(
        ports.user_repo.clone(),
        ports.session_repo.clone(),
        ports.password_hasher.clone(),
        ports.token_store.clone(),
        hibp_client.clone(),
        event_bus.clone(),
        auth.password_history_depth,
    );

    let change_password = ChangePasswordUseCase::new(
        ports.user_repo.clone(),
        ports.session_repo.clone(),
        ports.password_hasher.clone(),
        ports.token_store.clone(),
        hibp_client,
        event_bus.clone(),
        auth.password_history_depth,
    );

    let setup_totp = SetupTotpUseCase::new(
        ports.user_repo.clone(),
        totp_service.clone(),
        ports.token_store.clone(),
        "Korgan".to_owned(),
        Duration::from_secs(auth.mfa_challenge_ttl_secs),
    );

    let enable_totp = EnableTotpUseCase::new(
        ports.user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );

    let disable_totp = DisableTotpUseCase::new(
        ports.user_repo.clone(),
        ports.password_hasher.clone(),
        event_bus.clone(),
    );

    let verify_mfa_login = VerifyMfaLoginUseCase::new(
        ports.user_repo.clone(),
        ports.session_repo.clone(),
        totp_service,
        secret_cipher,
        ports.token_signer.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(auth.access_token_ttl_secs),
        Duration::from_secs(auth.refresh_token_ttl_secs),
        auth.issuer.clone(),
        auth.audience.clone(),
        auth.max_failed_login_attempts,
        Duration::from_secs(auth.lockout_duration_secs),
    );

    PasswordAndMfaUseCases {
        forgot_password,
        reset_password,
        change_password,
        setup_totp,
        enable_totp,
        disable_totp,
        verify_mfa_login,
    }
}

fn build_session_user_admin_use_cases(
    ports: &SharedPortRefs<'_>,
    event_bus: EventBus,
) -> SessionUserAdminUseCases {
    let list_sessions = ListSessionsUseCase::new(ports.session_repo.clone());
    let revoke_session = RevokeSessionUseCase::new(
        ports.session_repo.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );
    let revoke_all_sessions = RevokeAllSessionsUseCase::new(
        ports.session_repo.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );

    let get_profile = GetProfileUseCase::new(ports.user_repo.clone());
    let update_profile = UpdateProfileUseCase::new(ports.user_repo.clone());
    let list_users = ListUsersUseCase::new(ports.user_repo.clone());
    let ban_user = BanUserUseCase::new(
        ports.user_repo.clone(),
        ports.session_repo.clone(),
        ports.token_store.clone(),
        event_bus.clone(),
    );
    let unban_user = UnbanUserUseCase::new(ports.user_repo.clone(), event_bus.clone());
    let issue_ws_ticket = IssueWsTicketUseCase::new(ports.token_store.clone());
    let verify_ws_ticket = VerifyWsTicketUseCase::new(ports.token_store.clone());
    let bootstrap = BootstrapSuperadminUseCase::new(
        ports.user_repo.clone(),
        ports.password_hasher.clone(),
        event_bus.clone(),
    );
    let verify_audit_chain = VerifyAuditChainUseCase::new(ports.audit_repo.clone());
    let unlock_user = UnlockUserUseCase::new(ports.user_repo.clone(), event_bus);

    SessionUserAdminUseCases {
        list_sessions,
        revoke_session,
        revoke_all_sessions,
        get_profile,
        update_profile,
        list_users,
        ban_user,
        unban_user,
        issue_ws_ticket,
        verify_ws_ticket,
        bootstrap,
        verify_audit_chain,
        unlock_user,
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
        _mail_provider: Arc<dyn MailProvider>,
        google_oauth: Arc<dyn OAuthProviderPort>,
        github_oauth: Arc<dyn OAuthProviderPort>,
        webauthn_service: Arc<dyn WebAuthnService>,
        event_bus: EventBus,
        pg_pool: sqlx::PgPool,
        redis_pool: deadpool_redis::Pool,
    ) -> Self {
        let ports = SharedPortRefs {
            settings: &settings,
            user_repo: &user_repo,
            session_repo: &session_repo,
            audit_repo: &audit_repo,
            passkey_repo: &passkey_repo,
            token_store: &token_store,
            rate_limiter: &rate_limiter,
            password_hasher: &password_hasher,
            token_signer: &token_signer,
        };

        let auth = build_auth_use_cases(&ports, &hibp_client, &event_bus);
        let oauth_passkey = build_oauth_and_passkey_use_cases(
            &ports,
            oauth_account_repo,
            google_oauth,
            github_oauth,
            webauthn_service,
            &event_bus,
        );
        let password_mfa = build_password_and_mfa_use_cases(
            &ports,
            hibp_client,
            totp_service,
            secret_cipher,
            &event_bus,
        );
        let session_admin = build_session_user_admin_use_cases(&ports, event_bus);

        Self {
            inner: Arc::new(AppStateInner {
                settings,
                user_repo,
                session_repo,
                audit_repo,
                passkey_repo,
                token_store,
                rate_limiter,
                password_hasher,
                token_signer,
                register_use_case: auth.register,
                login_use_case: auth.login,
                refresh_session_use_case: auth.refresh_session,
                verify_email_use_case: auth.verify_email,
                generate_oauth_url_use_case: oauth_passkey.generate_oauth_url,
                oauth_callback_use_case: oauth_passkey.oauth_callback,
                start_passkey_registration_use_case: oauth_passkey.start_passkey_registration,
                finish_passkey_registration_use_case: oauth_passkey.finish_passkey_registration,
                start_passkey_login_use_case: oauth_passkey.start_passkey_login,
                finish_passkey_login_use_case: oauth_passkey.finish_passkey_login,
                list_passkeys_use_case: oauth_passkey.list_passkeys,
                delete_passkey_use_case: oauth_passkey.delete_passkey,
                forgot_password_use_case: password_mfa.forgot_password,
                reset_password_use_case: password_mfa.reset_password,
                change_password_use_case: password_mfa.change_password,
                setup_totp_use_case: password_mfa.setup_totp,
                enable_totp_use_case: password_mfa.enable_totp,
                disable_totp_use_case: password_mfa.disable_totp,
                verify_mfa_login_use_case: password_mfa.verify_mfa_login,
                list_sessions_use_case: session_admin.list_sessions,
                revoke_session_use_case: session_admin.revoke_session,
                revoke_all_sessions_use_case: session_admin.revoke_all_sessions,
                get_profile_use_case: session_admin.get_profile,
                update_profile_use_case: session_admin.update_profile,
                list_users_use_case: session_admin.list_users,
                ban_user_use_case: session_admin.ban_user,
                unban_user_use_case: session_admin.unban_user,
                issue_ws_ticket_use_case: session_admin.issue_ws_ticket,
                verify_ws_ticket_use_case: session_admin.verify_ws_ticket,
                bootstrap_use_case: session_admin.bootstrap,
                verify_audit_chain_use_case: session_admin.verify_audit_chain,
                unlock_user_use_case: session_admin.unlock_user,
                pg_pool,
                redis_pool,
            }),
        }
    }

    /// Synchronizes Prometheus telemetry gauges with persistent storage counts.
    pub async fn sync_telemetry_gauges(&self) {
        if let Ok(count) = self.audit_repo.count_all().await {
            let gauge_val = u32::try_from(count).map_or_else(|_| f64::from(u32::MAX), f64::from);
            metrics::gauge!("korgan_audit_chain_length").set(gauge_val);
        }
        if let Ok(count) = self.session_repo.count_active().await {
            let gauge_val = u32::try_from(count).map_or_else(|_| f64::from(u32::MAX), f64::from);
            metrics::gauge!("korgan_active_sessions_gauge").set(gauge_val);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_is_pointer_sized_shallow_arc() {
        assert_eq!(
            std::mem::size_of::<AppState>(),
            std::mem::size_of::<Arc<AppStateInner>>()
        );
    }
}
