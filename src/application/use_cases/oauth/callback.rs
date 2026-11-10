//! Processes OAuth2 provider callback, links or creates user, and issues sessions.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::application::dto::{AuthTokensResult, OAuthCallbackCommand};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Session, User,
    audit_events,
};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{OAuthAccountRepository, SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, OAuthProviderPort, TokenSigner};

/// Processes an external OAuth2 callback, establishing user authentication.
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
    jwt_issuer: String,
    jwt_audience: String,
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
        jwt_issuer: String,
        jwt_audience: String,
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
            jwt_issuer,
            jwt_audience,
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
        // 1. Validate anti-CSRF state parameter and browser cookie binding (RFC 6749 Section 10.12)
        let cookie_matches = cmd.cookie_state.as_deref().is_some_and(|c| c == cmd.state);

        let state_key = format!("oauth:state:{}:{}", cmd.provider.as_str(), cmd.state);
        // Anti-replay: State token must be consumed unconditionally on any callback attempt
        let token_consumed = self.token_store.consume_token(&state_key, "valid").await?;
        let is_valid = cookie_matches && token_consumed;

        if !is_valid {
            self.event_bus
                .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                    None,
                    Some(cmd.ip_address),
                    cmd.user_agent,
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Blocked,
                    serde_json::json!({
                        "reason": if !cookie_matches { "oauth_state_cookie_mismatch" } else { "invalid_or_expired_oauth_state" },
                        "provider": cmd.provider.as_str()
                    }),
                ))));

            return Err(AppError::Forbidden);
        }

        // 2. Exchange authorization code for external profile
        let profile = match cmd.provider {
            OAuthProvider::Google => self.google_provider.exchange_code(&cmd.code).await,
            OAuthProvider::GitHub => self.github_provider.exchange_code(&cmd.code).await,
        }
        .map_err(|e| match e {
            crate::ports::PortError::Cryptography(_) => AppError::Forbidden,
            other => AppError::from(other),
        })?;

        let now = Utc::now();

        // 3. Link or Create logic
        let maybe_account = self
            .oauth_repo
            .find_by_provider_and_id(cmd.provider, &profile.provider_user_id)
            .await?;

        let user = match maybe_account {
            Some(account) => {
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
                user
            }
            None => {
                // Check if user already exists with the same verified email
                let maybe_user = self.user_repo.find_by_email(&profile.email).await?;

                let (user, is_new_user) = match maybe_user {
                    Some(mut existing_user) => {
                        if existing_user.status == AccountStatus::Unverified {
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
                            if !revoked_ids.is_empty() {
                                let token_store = self.token_store.clone();
                                let entries: Vec<(String, &'static str, Duration)> = revoked_ids
                                    .into_iter()
                                    .map(|sid| {
                                        (
                                            format!("blacklist:session:{sid}"),
                                            "revoked",
                                            Duration::from_secs(30 * 86400),
                                        )
                                    })
                                    .collect();

                                crate::application::use_cases::shielded(move || {
                                    let token_store = token_store.clone();
                                    let entries = entries.clone();
                                    async move {
                                        let borrowed: Vec<(&str, &str, Duration)> = entries
                                            .iter()
                                            .map(|(k, v, ttl)| (k.as_str(), *v, *ttl))
                                            .collect();
                                        token_store.set_tokens_batch(&borrowed).await?;
                                        Ok(())
                                    }
                                })
                                .await?;
                            }
                        } else {
                            existing_user.can_login(now)?;
                        }
                        (existing_user, false)
                    }
                    None => {
                        let mut new_user = User::new(profile.email.clone(), None, None);
                        new_user.status = AccountStatus::Active;
                        new_user.email_verified_at = Some(now);
                        (new_user, true)
                    }
                };

                let new_account =
                    OAuthAccount::new(user.id, cmd.provider, profile.provider_user_id);
                self.oauth_repo
                    .link_oauth_account(if is_new_user { Some(&user) } else { None }, &new_account)
                    .await?;
                user
            }
        };

        // 4. Create Session & Tokens
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let chrono_refresh_ttl = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token ttl configuration", e))?;

        let session = Session::new(
            user.id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            chrono_refresh_ttl,
        )
        .with_amr(vec!["oauth".to_string()]);
        self.session_repo
            .create(&session)
            .await
            .map_err(|e| match e {
                crate::ports::PortError::Conflict { .. } => AppError::Forbidden,
                other => AppError::from(other),
            })?;

        let expires_in = self.access_token_ttl.as_secs() as i64;
        let claims = AccessTokenClaims {
            sub: user.id,
            sid: session.id,
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            exp: now.timestamp() + expires_in,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        // 5. Emit Audit Log
        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                Some(cmd.ip_address),
                cmd.user_agent,
                cmd.request_id,
                audit_events::LOGIN_SUCCESS,
                AuditEventStatus::Success,
                serde_json::json!({
                    "provider": cmd.provider.as_str(),
                    "oauth_login": true
                }),
            ))));

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in,
            session_id: session.id,
        })
    }
}
