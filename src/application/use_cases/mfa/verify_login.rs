//! MFA challenge verification and token issuance use case.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{AuthTokensResult, VerifyMfaLoginCommand};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{generate_opaque_token, hash_token};
use crate::application::workers::{AppEvent, EventBus};
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
    jwt_issuer: String,
    jwt_audience: String,
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
            .finish()
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
        jwt_issuer: String,
        jwt_audience: String,
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
            jwt_issuer,
            jwt_audience,
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
        let user_id_str = match self.token_store.get_and_delete(&key).await? {
            Some(s) => s,
            None => return Err(AppError::TokenInvalid),
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

        let maybe_mfa = self.user_repo.find_mfa(&user_id).await?;
        let mut mfa = match maybe_mfa {
            Some(m) if m.is_verified() => m,
            _ => return Err(AppError::InvalidCredentials),
        };

        // Verify either 6-digit TOTP or 8-char backup code
        let verified = if cmd.code.len() == 6 {
            let replay_key = format!("totp_used:{}:{}", user.id, cmd.code);
            let ok = {
                let secret_bytes = self.secret_cipher.decrypt_with_aad(
                    &mfa.totp_secret_ciphertext,
                    &mfa.totp_secret_nonce,
                    mfa.user_id.as_bytes(),
                )?;
                self.totp_service.verify_code(
                    secret_bytes.as_bytes(),
                    &cmd.code,
                    now.timestamp() as u64,
                )?
            };
            if ok {
                // Atomic SET NX lock prevents both concurrent parallel and sequential replay
                self.token_store
                    .set_if_not_exists(&replay_key, "1", Duration::from_secs(120))
                    .await?
            } else {
                false
            }
        } else if cmd.code.len() == 8 {
            let code_hash = hash_token(&cmd.code);
            // Constant-time traversal across all 10 indices
            let in_memory_valid = mfa.consume_backup_code(&code_hash);
            if !in_memory_valid {
                false
            } else {
                // Atomic persistence-level CAS consumption prevents concurrent double-spending
                self.user_repo
                    .consume_backup_code(&user.id, &code_hash)
                    .await?
            }
        } else {
            false
        };

        if !verified {
            let lockout_chrono = chrono::Duration::from_std(self.lockout_duration)
                .map_err(|e| AppError::internal("invalid lockout duration configuration", e))?;
            let lockout_until = now + lockout_chrono;
            let (failed_attempts, locked_until) = self
                .user_repo
                .record_failed_login_atomic(&user.id, self.max_failed_attempts, lockout_until, now)
                .await?;

            let is_locked = locked_until.is_some_and(|until| until > now);

            self.event_bus
                .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                    Some(user.id),
                    Some(cmd.ip_address),
                    cmd.user_agent,
                    cmd.request_id,
                    audit_events::LOGIN_FAILED,
                    AuditEventStatus::Failure,
                    serde_json::json!({
                        "reason": "invalid_mfa_code",
                        "failed_attempts": failed_attempts,
                        "locked": is_locked
                    }),
                ))));

            return Err(AppError::InvalidCredentials);
        }

        // Verification succeeded: create session first, guarding against concurrent bans
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let refresh_chrono = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token duration configuration", e))?;

        let session = Session::new(
            user.id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            refresh_chrono,
        )
        .with_amr(vec!["pwd".to_string(), "mfa".to_string()]);
        self.session_repo
            .create(&session)
            .await
            .map_err(|e| match e {
                crate::ports::PortError::Conflict { .. } => AppError::Forbidden,
                other => AppError::from(other),
            })?;

        // Session created successfully: atomically reset failed login attempts without
        // overwriting any other fields (such as account status).
        self.user_repo.reset_failed_logins(&user.id, now).await?;

        let exp = now.timestamp() + self.access_token_ttl.as_secs() as i64;
        let iat = now.timestamp();
        let jti = uuid::Uuid::now_v7().to_string();

        let claims = AccessTokenClaims {
            sub: user.id,
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

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                Some(cmd.ip_address),
                cmd.user_agent,
                cmd.request_id,
                audit_events::LOGIN_SUCCESS,
                AuditEventStatus::Success,
                serde_json::json!({ "session_id": session.id.to_string(), "mfa_verified": true }),
            ))));

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in: self.access_token_ttl.as_secs() as i64,
            session_id: session.id,
        })
    }
}
