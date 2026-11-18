//! Processes `OAuth2` provider callback, links or creates user, and issues sessions.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use smallvec::smallvec;

use crate::application::dto::{AuthTokensResult, OAuthCallbackCommand};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{
    SESSION_BLACKLIST_TTL, blacklist_sessions, generate_opaque_token,
};
use crate::application::workers::EventBus;
use crate::domain::entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Session, User,
    audit_events,
};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{OAuthAccountRepository, SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, OAuthProfile, OAuthProviderPort, TokenSigner};

/// Processes an external `OAuth2` callback, establishing user authentication.
#[derive(Clone)]
pub struct OAuthCallbackUseCase {
    user_repo: Arc<dyn UserRepository>,
    oauth_repo: Arc<dyn OAuthAccountRepository>,
    session_repo: Arc<dyn SessionRepository>,
    token_signer: Arc<dyn TokenSigner>,
    token_store: Arc<dyn TokenStore>,
    google_provider: Arc<dyn OAuthProviderPort>,
    github_provider: Arc<dyn OAuthProviderPort>,
    event_bus: EventBus,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    jwt_issuer: Cow<'static, str>,
    jwt_audience: Cow<'static, str>,
}

impl std::fmt::Debug for OAuthCallbackUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCallbackUseCase")
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .finish_non_exhaustive()
    }
}

impl OAuthCallbackUseCase {
    /// Creates a new [`OAuthCallbackUseCase`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        oauth_repo: Arc<dyn OAuthAccountRepository>,
        session_repo: Arc<dyn SessionRepository>,
        token_signer: Arc<dyn TokenSigner>,
        token_store: Arc<dyn TokenStore>,
        google_provider: Arc<dyn OAuthProviderPort>,
        github_provider: Arc<dyn OAuthProviderPort>,
        event_bus: EventBus,
        access_token_ttl: Duration,
        refresh_token_ttl: Duration,
        jwt_issuer: impl Into<Cow<'static, str>>,
        jwt_audience: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            user_repo,
            oauth_repo,
            session_repo,
            token_signer,
            token_store,
            google_provider,
            github_provider,
            event_bus,
            access_token_ttl,
            refresh_token_ttl,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
        }
    }

    /// Executes the callback workflow.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Forbidden`] if the state token is invalid/expired (CSRF attempt),
    /// or other [`AppError`] variants if code exchange or database operations fail.
    pub async fn execute(&self, cmd: OAuthCallbackCommand) -> Result<AuthTokensResult, AppError> {
        let res = self.execute_internal(cmd).await;
        match &res {
            Ok(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "oauth", "status" => "success").increment(1);
            }
            Err(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "oauth", "status" => "failure").increment(1);
            }
        }
        res
    }

    async fn execute_internal(
        &self,
        cmd: OAuthCallbackCommand,
    ) -> Result<AuthTokensResult, AppError> {
        let profile = self.validate_state_and_exchange(&cmd).await?;
        let now = Utc::now();
        let user = self
            .resolve_or_link_user(cmd.provider, profile, now)
            .await?;

        self.issue_oauth_session_tokens(user.id, cmd, now).await
    }

    async fn validate_state_and_exchange(
        &self,
        cmd: &OAuthCallbackCommand,
    ) -> Result<OAuthProfile, AppError> {
        // 1. Validate anti-CSRF state parameter and browser cookie binding (RFC 6749 Section 10.12)
        let cookie_matches = cmd.cookie_state.as_deref().is_some_and(|c| c == cmd.state);

        let state_key = format!("oauth:state:{}:{}", cmd.provider.as_str(), cmd.state);
        // Anti-replay: State token must be consumed unconditionally on any callback attempt
        let token_consumed = self.token_store.consume_token(&state_key, "valid").await?;
        let is_valid = cookie_matches && token_consumed;

        if !is_valid {
            self.event_bus
                .record_audit(AuditLog::new(
                    None,
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Blocked,
                    serde_json::json!({
                        "reason": if cookie_matches { "invalid_or_expired_oauth_state" } else { "oauth_state_cookie_mismatch" },
                        "provider": cmd.provider.as_str()
                    }),
                ))
                .await;

            return Err(AppError::Forbidden);
        }

        // 2. Exchange authorization code for external profile
        match cmd.provider {
            OAuthProvider::Google => self.google_provider.exchange_code(&cmd.code).await,
            OAuthProvider::GitHub => self.github_provider.exchange_code(&cmd.code).await,
        }
        .map_err(|e| match e {
            crate::ports::PortError::Cryptography(_) => AppError::Forbidden,
            other => AppError::from(other),
        })
    }

    async fn resolve_or_link_user(
        &self,
        provider: OAuthProvider,
        profile: OAuthProfile,
        now: DateTime<Utc>,
    ) -> Result<User, AppError> {
        let maybe_account = self
            .oauth_repo
            .find_by_provider_and_id(provider, &profile.provider_user_id)
            .await?;

        if let Some(account) = maybe_account {
            let user = self
                .user_repo
                .find_by_id(&account.user_id)
                .await?
                .ok_or_else(|| {
                    AppError::internal(
                        "linked user record missing",
                        "database consistency violation",
                    )
                })?;

            user.can_login(now)?;
            return Ok(user);
        }

        // Check if user already exists with the same verified email
        let maybe_user = self.user_repo.find_by_email(&profile.email).await?;

        let (user, is_new_user) = if let Some(existing_user) = maybe_user {
            let resolved = if existing_user.status == AccountStatus::Unverified {
                self.defend_pre_account_takeover(existing_user, now).await?
            } else {
                existing_user.can_login(now)?;
                existing_user
            };
            (resolved, false)
        } else {
            let mut new_user = User::new(profile.email, None, None);
            new_user.status = AccountStatus::Active;
            new_user.email_verified_at = Some(now);
            (new_user, true)
        };

        let new_account = OAuthAccount::new(user.id, provider, profile.provider_user_id);
        self.oauth_repo
            .link_oauth_account(if is_new_user { Some(&user) } else { None }, &new_account)
            .await?;
        Ok(user)
    }

    async fn defend_pre_account_takeover(
        &self,
        mut existing_user: User,
        now: DateTime<Utc>,
    ) -> Result<User, AppError> {
        // R1.3 Pre-account takeover defense:
        // 1. Clear password hash so attacker cannot authenticate with password
        existing_user.password_hash = None;
        // 2. Reset failed attempts and lockout trap set by attacker
        existing_user.failed_login_attempts = 0;
        existing_user.locked_until = None;
        // 3. Verify email and activate account
        existing_user.verify_email(now);
        // 4. Validate login eligibility
        existing_user.can_login(now)?;
        // 5. Persist changes to database (password_hash = NULL in SQL)
        self.user_repo.update(&existing_user).await?;
        // 6. Invalidate all existing sessions across all devices
        let revoked_ids = self
            .session_repo
            .revoke_all_user_sessions(
                &existing_user.id,
                None,
                "oauth_pre_account_takeover_defense",
            )
            .await?;

        // 7. Sync revoked sessions to distributed TokenStore blacklist
        blacklist_sessions(
            self.token_store.clone(),
            &revoked_ids,
            SESSION_BLACKLIST_TTL,
        )
        .await?;

        Ok(existing_user)
    }

    async fn issue_oauth_session_tokens(
        &self,
        user_id: crate::domain::value_objects::UserId,
        cmd: OAuthCallbackCommand,
        now: DateTime<Utc>,
    ) -> Result<AuthTokensResult, AppError> {
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let chrono_refresh_ttl = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token ttl configuration", e))?;

        let session = Session::new(
            user_id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            chrono_refresh_ttl,
        )
        .with_amr(smallvec![Cow::Borrowed("oauth")]);
        let audit = AuditLog::new(
            Some(user_id),
            Some(cmd.ip_address),
            cmd.user_agent,
            cmd.request_id,
            audit_events::LOGIN_SUCCESS,
            AuditEventStatus::Success,
            serde_json::json!({
                "provider": cmd.provider.as_str(),
                "oauth_login": true
            }),
        );

        // The session and its login audit entry commit in ONE transaction.
        self.event_bus
            .audited(
                async {
                    self.session_repo
                        .create(&session)
                        .await
                        .map_err(|e| match e {
                            crate::ports::PortError::Conflict { .. } => AppError::Forbidden,
                            other => AppError::from(other),
                        })?;
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;

        let expires_in = i64::try_from(self.access_token_ttl.as_secs()).unwrap_or(i64::MAX);
        let iat = now.timestamp();
        let claims = AccessTokenClaims {
            sub: user_id,
            sid: session.id,
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            exp: iat + expires_in,
            iat,
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in,
            session_id: session.id,
        })
    }
}
