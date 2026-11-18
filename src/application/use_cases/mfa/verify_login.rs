//! MFA challenge verification and token issuance use case.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use smallvec::smallvec;
use validator::Validate;

use crate::application::dto::{AuthTokensResult, VerifyMfaLoginCommand};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{generate_opaque_token, hash_token};
use crate::application::workers::EventBus;
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog, Session};
use crate::domain::value_objects::UserId;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, SecretCipher, TokenSigner, TotpService};

/// Coordinates verifying second factor (TOTP or backup code) and issuing session tokens.
#[derive(Clone)]
pub struct VerifyMfaLoginUseCase {
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    totp_service: Arc<dyn TotpService>,
    secret_cipher: Arc<dyn SecretCipher>,
    token_signer: Arc<dyn TokenSigner>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    jwt_issuer: Cow<'static, str>,
    jwt_audience: Cow<'static, str>,
    max_failed_attempts: u16,
    lockout_duration: Duration,
}

impl std::fmt::Debug for VerifyMfaLoginUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyMfaLoginUseCase")
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("max_failed_attempts", &self.max_failed_attempts)
            .field("lockout_duration", &self.lockout_duration)
            .finish_non_exhaustive()
    }
}

impl VerifyMfaLoginUseCase {
    /// Creates a new [`VerifyMfaLoginUseCase`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        session_repo: Arc<dyn SessionRepository>,
        totp_service: Arc<dyn TotpService>,
        secret_cipher: Arc<dyn SecretCipher>,
        token_signer: Arc<dyn TokenSigner>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
        access_token_ttl: Duration,
        refresh_token_ttl: Duration,
        jwt_issuer: impl Into<Cow<'static, str>>,
        jwt_audience: impl Into<Cow<'static, str>>,
        max_failed_attempts: u16,
        lockout_duration: Duration,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            totp_service,
            secret_cipher,
            token_signer,
            token_store,
            event_bus,
            access_token_ttl,
            refresh_token_ttl,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
            max_failed_attempts,
            lockout_duration,
        }
    }

    /// Verifies either a 6-digit TOTP code or an 8-character backup code, then issues tokens.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenInvalid`] if the MFA ticket is expired or invalid,
    /// [`AppError::InvalidCredentials`] if the code does not verify,
    /// or [`AppError::Forbidden`] if the account is locked.
    pub async fn execute(&self, cmd: VerifyMfaLoginCommand) -> Result<AuthTokensResult, AppError> {
        let res = self.execute_internal(cmd).await;
        match &res {
            Ok(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "mfa", "status" => "success").increment(1);
            }
            Err(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "mfa", "status" => "failure").increment(1);
            }
        }
        res
    }

    async fn execute_internal(
        &self,
        cmd: VerifyMfaLoginCommand,
    ) -> Result<AuthTokensResult, AppError> {
        cmd.validate()?;

        let ticket_hash = hash_token(&cmd.mfa_ticket);
        let key = format!("mfa_ticket:{ticket_hash}");

        // Single-use: atomically retrieve and delete ticket
        let Some(user_id_str) = self.token_store.get_and_delete(&key).await? else {
            return Err(AppError::TokenInvalid);
        };

        let user_id: UserId = user_id_str
            .parse()
            .map_err(|e| AppError::internal("invalid user id in token store", e))?;

        let user = self
            .user_repo
            .find_by_id(&user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        let now = Utc::now();
        if let Err(domain_err) = user.can_login(now) {
            return Err(AppError::from(domain_err));
        }

        let verified = self.verify_second_factor(user.id, &cmd.code, now).await?;
        if !verified {
            self.record_mfa_failure(user.id, &cmd, now).await?;
            return Err(AppError::InvalidCredentials);
        }

        self.issue_mfa_session_tokens(user.id, cmd, now).await
    }

    async fn verify_second_factor(
        &self,
        user_id: UserId,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let maybe_mfa = self.user_repo.find_mfa(&user_id).await?;
        let mut mfa = match maybe_mfa {
            Some(m) if m.is_verified() => m,
            _ => return Err(AppError::InvalidCredentials),
        };

        // Verify either 6-digit TOTP or 8-char backup code
        if code.len() == 6 {
            let replay_key = format!("totp_used:{user_id}:{code}");
            let now_secs = u64::try_from(now.timestamp()).unwrap_or(0);
            let ok = {
                let secret_bytes = self.secret_cipher.decrypt_with_aad(
                    &mfa.totp_secret_ciphertext,
                    &mfa.totp_secret_nonce,
                    mfa.user_id.as_bytes(),
                )?;
                self.totp_service
                    .verify_code(secret_bytes.as_bytes(), code, now_secs)?
            };
            if ok {
                // Atomic SET NX lock prevents both concurrent parallel and sequential replay
                Ok(self
                    .token_store
                    .set_if_not_exists(&replay_key, "1", Duration::from_secs(120))
                    .await?)
            } else {
                Ok(false)
            }
        } else if code.len() == 8 {
            let code_hash = hash_token(code);
            // Constant-time traversal across all 10 indices
            let in_memory_valid = mfa.consume_backup_code(&code_hash);
            if in_memory_valid {
                // Atomic persistence-level CAS consumption prevents concurrent double-spending
                Ok(self
                    .user_repo
                    .consume_backup_code(&user_id, &code_hash)
                    .await?)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn record_mfa_failure(
        &self,
        user_id: UserId,
        cmd: &VerifyMfaLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let lockout_chrono = chrono::Duration::from_std(self.lockout_duration)
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
                            &user_id,
                            self.max_failed_attempts,
                            lockout_until,
                            now,
                        )
                        .await?;
                    Ok::<_, AppError>(outcome)
                },
                |(failed_attempts, locked_until)| {
                    let is_locked = locked_until.is_some_and(|until| until > now);
                    AuditLog::new(
                        Some(user_id),
                        Some(cmd.ip_address),
                        cmd.user_agent.clone(),
                        cmd.request_id,
                        audit_events::LOGIN_FAILED,
                        AuditEventStatus::Failure,
                        serde_json::json!({
                            "reason": "invalid_mfa_code",
                            "failed_attempts": failed_attempts,
                            "locked": is_locked
                        }),
                    )
                },
            )
            .await?;

        Ok(())
    }

    async fn issue_mfa_session_tokens(
        &self,
        user_id: UserId,
        cmd: VerifyMfaLoginCommand,
        now: DateTime<Utc>,
    ) -> Result<AuthTokensResult, AppError> {
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let refresh_chrono = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token duration configuration", e))?;

        let session = Session::new(
            user_id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            refresh_chrono,
        )
        .with_amr(smallvec![Cow::Borrowed("pwd"), Cow::Borrowed("mfa")]);
        let audit = AuditLog::new(
            Some(user_id),
            Some(cmd.ip_address),
            cmd.user_agent,
            cmd.request_id,
            audit_events::LOGIN_SUCCESS,
            AuditEventStatus::Success,
            serde_json::json!({ "session_id": session.id.to_string(), "mfa_verified": true }),
        );

        // Session creation (guarding against concurrent bans), the failed-attempt
        // reset and the login audit entry commit in ONE transaction.
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
                    self.user_repo.reset_failed_logins(&user_id, now).await?;
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;

        let access_ttl_secs = i64::try_from(self.access_token_ttl.as_secs()).unwrap_or(i64::MAX);
        let iat = now.timestamp();
        let exp = iat + access_ttl_secs;
        let jti = uuid::Uuid::now_v7().to_string();

        let claims = AccessTokenClaims {
            sub: user_id,
            sid: session.id,
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            exp,
            iat,
            jti,
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in: access_ttl_secs,
            session_id: session.id,
        })
    }
}
