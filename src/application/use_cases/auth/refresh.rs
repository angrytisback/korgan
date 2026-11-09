//! Refresh token session rotation use case implementation.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{AuthTokensResult, RefreshTokenCommand};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{generate_opaque_token, hash_token};
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog, Session};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, TokenSigner};

/// Coordinates token rotation with automatic replay attack detection.
#[derive(Clone)]
pub struct RefreshSessionUseCase {
    session_repo: Arc<dyn SessionRepository>,
    user_repo: Arc<dyn UserRepository>,
    token_signer: Arc<dyn TokenSigner>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    rotation_grace_period: chrono::Duration,
    jwt_issuer: String,
    jwt_audience: String,
}

impl std::fmt::Debug for RefreshSessionUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshSessionUseCase")
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("rotation_grace_period", &self.rotation_grace_period)
            .finish()
    }
}

impl RefreshSessionUseCase {
    /// Creates a new [`RefreshSessionUseCase`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_repo: Arc<dyn SessionRepository>,
        user_repo: Arc<dyn UserRepository>,
        token_signer: Arc<dyn TokenSigner>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
        access_token_ttl: Duration,
        refresh_token_ttl: Duration,
        jwt_issuer: String,
        jwt_audience: String,
    ) -> Self {
        Self {
            session_repo,
            user_repo,
            token_signer,
            token_store,
            event_bus,
            access_token_ttl,
            refresh_token_ttl,
            rotation_grace_period: chrono::Duration::seconds(10),
            jwt_issuer,
            jwt_audience,
        }
    }

    /// Overrides the default rotation grace period (10 seconds).
    #[must_use]
    pub fn with_rotation_grace_period(mut self, period: chrono::Duration) -> Self {
        self.rotation_grace_period = period;
        self
    }

    async fn handle_token_replay(
        &self,
        session: &Session,
        cmd: &RefreshTokenCommand,
    ) -> Result<AuthTokensResult, AppError> {
        let revoked_ids = self
            .session_repo
            .revoke_family(&session.token_family_id, "token_reuse_detected")
            .await?;

        let token_store = self.token_store.clone();
        let refresh_ttl = self.refresh_token_ttl;
        let mut entries: Vec<(String, &'static str, std::time::Duration)> =
            Vec::with_capacity(revoked_ids.len() + 1);
        entries.push((
            format!("blacklist:session:{}", session.id),
            "revoked",
            refresh_ttl,
        ));
        for sid in revoked_ids {
            entries.push((format!("blacklist:session:{sid}"), "revoked", refresh_ttl));
        }

        crate::application::use_cases::shielded(move || {
            let token_store = token_store.clone();
            let entries = entries.clone();
            async move {
                let borrowed: Vec<(&str, &str, std::time::Duration)> = entries
                    .iter()
                    .map(|(k, v, ttl)| (k.as_str(), *v, *ttl))
                    .collect();
                token_store.set_tokens_batch(&borrowed).await?;
                Ok(())
            }
        })
        .await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(session.user_id),
                Some(cmd.ip_address),
                cmd.user_agent.clone(),
                cmd.request_id,
                audit_events::TOKEN_REUSE_DETECTED,
                AuditEventStatus::Blocked,
                serde_json::json!({
                    "session_id": session.id.to_string(),
                    "token_family_id": session.token_family_id.to_string(),
                }),
            ))));

        metrics::counter!("korgan_token_reuse_events_total").increment(1);
        Err(AppError::TokenReuseDetected)
    }

    /// Executes token rotation, checking for replay attacks.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenReuseDetected`] and revokes the whole family if a previously
    /// rotated token is reused, [`AppError::TokenExpired`] if expired, or [`AppError::TokenInvalid`].
    pub async fn execute(&self, cmd: RefreshTokenCommand) -> Result<AuthTokensResult, AppError> {
        cmd.validate()?;

        let token_hash = hash_token(&cmd.refresh_token);
        let now = Utc::now();

        // 1. Look up existing session
        let existing = match self.session_repo.find_by_token_hash(&token_hash).await? {
            Some(s) => s,
            None => return Err(AppError::TokenInvalid),
        };

        if existing.is_revoked() {
            return Err(AppError::TokenInvalid);
        }

        // Expired token check MUST happen before replay check to ensure expired tokens
        // never trigger false-positive family revocations.
        if existing.is_expired(now) {
            return Err(AppError::TokenExpired);
        }

        if existing.is_replaced {
            if existing.is_replaced_within_grace(now, self.rotation_grace_period) {
                return Err(AppError::concurrent_refresh(1));
            }
            return self.handle_token_replay(&existing, &cmd).await;
        }

        // 2. Verify account is still eligible to login
        let user = self
            .user_repo
            .find_by_id(&existing.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        if let Err(domain_err) = user.can_login(now) {
            return Err(AppError::from(domain_err));
        }

        // 3. Prepare child session in token family
        let (new_raw_token, new_token_hash) = generate_opaque_token();
        let refresh_chrono = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token duration configuration", e))?;

        let user_id = existing.user_id;
        let mut session = existing;
        let new_session = session.rotate(
            new_token_hash,
            refresh_chrono,
            now,
            cmd.ip_address,
            cmd.user_agent.clone(),
        );

        // 4. Atomically mark old session replaced AND insert new session in single CTE/transaction
        let rotated = self
            .session_repo
            .rotate_atomic(&token_hash, &new_session)
            .await?;

        if rotated.is_none() {
            // Check if account status change or lockout caused rotate_atomic to reject session rotation
            let fresh_user = self.user_repo.find_by_id(&user_id).await?;
            if let Some(u) = fresh_user
                && let Err(domain_err) = u.can_login(now)
            {
                return Err(AppError::from(domain_err));
            }

            // Concurrent race detected: recheck session to trigger replay protection if replaced
            if let Some(recheck) = self.session_repo.find_by_token_hash(&token_hash).await? {
                if recheck.is_revoked() {
                    return Err(AppError::TokenInvalid);
                }
                if recheck.is_expired(now) {
                    return Err(AppError::TokenExpired);
                }
                if recheck.is_replaced {
                    if recheck.is_replaced_within_grace(now, self.rotation_grace_period) {
                        return Err(AppError::concurrent_refresh(1));
                    }
                    return self.handle_token_replay(&recheck, &cmd).await;
                }
            }
            return Err(AppError::TokenInvalid);
        }

        // Issue fresh access token
        let exp = now.timestamp() + self.access_token_ttl.as_secs() as i64;
        let iat = now.timestamp();
        let jti = uuid::Uuid::now_v7().to_string();

        let amr = if !new_session.amr.is_empty() {
            new_session.amr.clone()
        } else if user.mfa_enabled {
            vec!["pwd".to_string(), "mfa".to_string()]
        } else {
            vec!["pwd".to_string()]
        };

        let claims = AccessTokenClaims {
            sub: user.id,
            sid: new_session.id,
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            exp,
            iat,
            jti,
            auth_time: new_session.created_at.timestamp(),
            amr,
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        Ok(AuthTokensResult {
            access_token,
            refresh_token: new_raw_token,
            token_type: "Bearer",
            expires_in: self.access_token_ttl.as_secs() as i64,
            session_id: new_session.id,
        })
    }
}
