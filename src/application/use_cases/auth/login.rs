//! Login use case implementation.

use std::borrow::Cow;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use smallvec::smallvec;
use validator::Validate;

use crate::application::dto::{AuthTokensResult, LoginCommand, LoginOutcome, MfaChallengeResult};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::EventBus;
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog, Session, User};
use crate::domain::value_objects::{EmailAddress, RawPassword, UserId};
use crate::ports::cache::{RateLimiterPort, TokenStore};
use crate::ports::repositories::{SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, PasswordHasher, TokenSigner};

static FALLBACK_DUMMY_PW: LazyLock<Option<RawPassword>> =
    LazyLock::new(|| RawPassword::new("iam-dummy-password-fallback-timing").ok());

/// Configuration options for the login workflow.
#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// Maximum failed logins before temporary lockout.
    pub max_failed_attempts: u16,
    /// Lockout duration when max failed attempts reached.
    pub lockout_duration: Duration,
    /// Rate limit window for IP rate limiter.
    pub rate_limit_window: Duration,
    /// Maximum attempts allowed per IP in the rate limit window.
    pub max_attempts_per_ip: u32,
    /// Validity duration of Access Tokens.
    pub access_token_ttl: Duration,
    /// Validity duration of Refresh Tokens.
    pub refresh_token_ttl: Duration,
    /// Validity duration of ephemeral MFA challenge tickets.
    pub mfa_ticket_ttl: Duration,
    /// JWT issuer claim (`iss`).
    pub jwt_issuer: Cow<'static, str>,
    /// JWT audience claim (`aud`).
    pub jwt_audience: Cow<'static, str>,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::from_mins(15),
            rate_limit_window: Duration::from_secs(60),
            max_attempts_per_ip: 10,
            access_token_ttl: Duration::from_mins(15),
            refresh_token_ttl: Duration::from_hours(168),
            mfa_ticket_ttl: Duration::from_mins(5),
            jwt_issuer: Cow::Borrowed("https://auth.korgan.local"),
            jwt_audience: Cow::Borrowed("korgan"),
        }
    }
}

/// Coordinates user authentication.
#[derive(Clone)]
pub struct LoginUseCase {
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_signer: Arc<dyn TokenSigner>,
    token_store: Arc<dyn TokenStore>,
    rate_limiter: Arc<dyn RateLimiterPort>,
    event_bus: EventBus,
    config: LoginConfig,
}

impl std::fmt::Debug for LoginUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginUseCase")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LoginUseCase {
    /// Creates a new [`LoginUseCase`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_signer: Arc<dyn TokenSigner>,
        token_store: Arc<dyn TokenStore>,
        rate_limiter: Arc<dyn RateLimiterPort>,
        event_bus: EventBus,
        config: LoginConfig,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            password_hasher,
            token_signer,
            token_store,
            rate_limiter,
            event_bus,
            config,
        }
    }

    /// Executes the login workflow.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::RateLimited`] if IP rate limit is exceeded,
    /// [`AppError::InvalidCredentials`] if credentials do not match (with timing mitigation),
    /// or [`AppError::Forbidden`] if account is locked or inactive.
    pub async fn execute(&self, cmd: LoginCommand) -> Result<LoginOutcome, AppError> {
        let res = self.execute_internal(cmd).await;
        match &res {
            Ok(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "pwd", "status" => "success").increment(1);
            }
            Err(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "pwd", "status" => "failure").increment(1);
            }
        }
        res
    }

    async fn execute_internal(&self, cmd: LoginCommand) -> Result<LoginOutcome, AppError> {
        cmd.validate()?;

        let rate_limit_key = format!("login_ip:{}", cmd.ip_address);
        self.check_rate_limit(&rate_limit_key, &cmd).await?;

        let now = Utc::now();
        let user = self.authenticate_user(&cmd, now).await?;

        if user.mfa_enabled {
            return self.issue_mfa_challenge(user.id, cmd).await;
        }

        self.create_session_and_tokens(user.id, cmd, &rate_limit_key, now)
            .await
    }

    async fn check_rate_limit(
        &self,
        rate_limit_key: &str,
        cmd: &LoginCommand,
    ) -> Result<(), AppError> {
        let rate_status = self
            .rate_limiter
            .check_and_increment(
                rate_limit_key,
                self.config.max_attempts_per_ip,
                self.config.rate_limit_window,
            )
            .await?;

        if !rate_status.allowed {
            self.event_bus
                .record_audit(AuditLog::new(
                    None,
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Blocked,
                    serde_json::json!({ "reason": "rate_limited" }),
                ))
                .await;

            return Err(AppError::RateLimited {
                retry_after_secs: rate_status.retry_after_secs.unwrap_or(60),
            });
        }

        Ok(())
    }

    async fn authenticate_user(
        &self,
        cmd: &LoginCommand,
        now: DateTime<Utc>,
    ) -> Result<User, AppError> {
        let maybe_email = EmailAddress::parse(&cmd.email).ok();
        let maybe_password = RawPassword::new(&cmd.password).ok();

        let maybe_user = match &maybe_email {
            Some(e) => self.user_repo.find_by_email(e).await?,
            None => None,
        };

        let Some(user) = maybe_user else {
            // Timing-Attack Mitigation: compute dummy hash verification so response latency
            // is indistinguishable from an existing user's failed attempt.
            let pw_for_dummy = maybe_password
                .as_ref()
                .or_else(|| FALLBACK_DUMMY_PW.as_ref());
            if let Some(pw) = pw_for_dummy {
                let _ = self.password_hasher.verify_against_dummy_hash(pw).await;
            }

            self.event_bus
                .record_audit(AuditLog::new(
                    None,
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Failure,
                    serde_json::json!({ "reason": "user_not_found" }),
                ))
                .await;

            return Err(AppError::InvalidCredentials);
        };

        self.verify_credentials_or_record_failure(&user, maybe_password.as_ref(), cmd, now)
            .await?;

        // Re-verify user status immediately after password verification to prevent
        // race conditions where an administrative ban or status change occurred
        // during the password hashing calculation.
        let fresh_user = self
            .user_repo
            .find_by_id(&user.id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if let Err(domain_err) = fresh_user.can_login(now) {
            self.event_bus
                .record_audit(AuditLog::new(
                    Some(fresh_user.id),
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Blocked,
                    serde_json::json!({ "reason": domain_err.to_string() }),
                ))
                .await;

            return Err(AppError::from(domain_err));
        }

        Ok(fresh_user)
    }

    async fn verify_credentials_or_record_failure(
        &self,
        user: &User,
        maybe_password: Option<&RawPassword>,
        cmd: &LoginCommand,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let can_login_res = user.can_login(now);

        // Always execute password verification or dummy hash verification to maintain strict timing parity.
        let is_password_valid = match (maybe_password, &user.password_hash) {
            (Some(pw), Some(hash)) => self.password_hasher.verify_password(pw, hash).await?,
            (Some(pw), None) => {
                let _ = self.password_hasher.verify_against_dummy_hash(pw).await;
                false
            }
            (None, _) => {
                if let Some(pw) = FALLBACK_DUMMY_PW.as_ref() {
                    let _ = self.password_hasher.verify_against_dummy_hash(pw).await;
                }
                false
            }
        };

        if let Err(domain_err) = can_login_res {
            self.event_bus
                .record_audit(AuditLog::new(
                    Some(user.id),
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Blocked,
                    serde_json::json!({ "reason": domain_err.to_string() }),
                ))
                .await;

            return Err(AppError::from(domain_err));
        }

        if user.password_hash.is_none() {
            self.event_bus
                .record_audit(AuditLog::new(
                    Some(user.id),
                    Some(cmd.ip_address),
                    cmd.user_agent.clone(),
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Failure,
                    serde_json::json!({ "reason": "no_password_set" }),
                ))
                .await;

            return Err(AppError::from(crate::domain::DomainError::NoPasswordSet));
        }

        if !is_password_valid {
            let lockout_chrono = chrono::Duration::from_std(self.config.lockout_duration)
                .map_err(|e| AppError::internal("invalid lockout duration configuration", e))?;
            let lockout_until = now + lockout_chrono;
            // The failed-attempt counter (and lockout) and its audit entry commit
            // in ONE transaction.
            let _ = self
                .event_bus
                .audited_with(
                    async {
                        let outcome = self
                            .user_repo
                            .record_failed_login_atomic(
                                &user.id,
                                self.config.max_failed_attempts,
                                lockout_until,
                                now,
                            )
                            .await?;
                        Ok::<_, AppError>(outcome)
                    },
                    |(failed_attempts, locked_until)| {
                        let is_locked = locked_until.is_some_and(|until| until > now);
                        AuditLog::new(
                            Some(user.id),
                            Some(cmd.ip_address),
                            cmd.user_agent.clone(),
                            cmd.request_id,
                            audit_events::LOGIN_FAILED,
                            AuditEventStatus::Failure,
                            serde_json::json!({
                                "failed_attempts": failed_attempts,
                                "locked": is_locked
                            }),
                        )
                    },
                )
                .await?;

            return Err(AppError::InvalidCredentials);
        }

        Ok(())
    }

    async fn issue_mfa_challenge(
        &self,
        user_id: UserId,
        cmd: LoginCommand,
    ) -> Result<LoginOutcome, AppError> {
        let (raw_ticket, ticket_hash) = generate_opaque_token();
        let ticket_key = format!("mfa_ticket:{ticket_hash}");
        self.token_store
            .set_token(
                &ticket_key,
                &user_id.to_string(),
                self.config.mfa_ticket_ttl,
            )
            .await?;

        self.event_bus
            .record_audit(AuditLog::new(
                Some(user_id),
                Some(cmd.ip_address),
                cmd.user_agent,
                cmd.request_id,
                audit_events::MFA_CHALLENGED,
                AuditEventStatus::Success,
                serde_json::json!({ "mfa_type": "totp" }),
            ))
            .await;

        Ok(LoginOutcome::MfaRequired(MfaChallengeResult {
            mfa_ticket: raw_ticket,
            expires_in_secs: self.config.mfa_ticket_ttl.as_secs(),
        }))
    }

    async fn create_session_and_tokens(
        &self,
        user_id: UserId,
        cmd: LoginCommand,
        rate_limit_key: &str,
        now: DateTime<Utc>,
    ) -> Result<LoginOutcome, AppError> {
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let refresh_chrono = chrono::Duration::from_std(self.config.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token duration configuration", e))?;

        let session = Session::new(
            user_id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            refresh_chrono,
        )
        .with_amr(smallvec![Cow::Borrowed("pwd")]);

        let audit = AuditLog::new(
            Some(user_id),
            Some(cmd.ip_address),
            cmd.user_agent,
            cmd.request_id,
            audit_events::LOGIN_SUCCESS,
            AuditEventStatus::Success,
            serde_json::json!({ "session_id": session.id.to_string() }),
        );

        // Session creation (which re-checks the account status in the database),
        // the failed-attempt reset and the login audit entry commit in ONE
        // transaction; resetting the Redis rate limiter follows.
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
                    // Atomically reset failed login attempts without mutating any
                    // other column (such as account status).
                    self.user_repo.reset_failed_logins(&user_id, now).await?;
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;
        let _ = self.rate_limiter.reset(rate_limit_key).await;

        let access_ttl_secs =
            i64::try_from(self.config.access_token_ttl.as_secs()).unwrap_or(i64::MAX);
        let iat = now.timestamp();
        let exp = iat + access_ttl_secs;
        let jti = uuid::Uuid::now_v7().to_string();

        let claims = AccessTokenClaims {
            sub: user_id,
            sid: session.id,
            iss: self.config.jwt_issuer.clone(),
            aud: self.config.jwt_audience.clone(),
            exp,
            iat,
            jti,
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        Ok(LoginOutcome::Authenticated(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in: access_ttl_secs,
            session_id: session.id,
        }))
    }
}
