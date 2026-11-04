//! TOTP activation and backup code generation use case.

use std::sync::Arc;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{EnableTotpCommand, TotpEnabledResult};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{decode_base32, generate_backup_codes};
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog, UserMfa};
use crate::domain::errors::FieldViolation;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;
use crate::ports::services::{SecretCipher, TotpService};

/// Coordinates finalizing TOTP MFA enrollment.
#[derive(Clone)]
pub struct EnableTotpUseCase {
    user_repo: Arc<dyn UserRepository>,
    totp_service: Arc<dyn TotpService>,
    secret_cipher: Arc<dyn SecretCipher>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for EnableTotpUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnableTotpUseCase").finish()
    }
}

impl EnableTotpUseCase {
    /// Creates a new [`EnableTotpUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        totp_service: Arc<dyn TotpService>,
        secret_cipher: Arc<dyn SecretCipher>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            user_repo,
            totp_service,
            secret_cipher,
            token_store,
            event_bus,
        }
    }

    /// Verifies the first 6-digit TOTP code, encrypts secret at rest with AES-256-GCM,
    /// generates 10 backup codes, and activates MFA.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenExpired`] if setup was not initiated or timed out,
    /// [`AppError::Validation`] if code does not match, or [`AppError::Unauthenticated`].
    pub async fn execute(&self, cmd: EnableTotpCommand) -> Result<TotpEnabledResult, AppError> {
        cmd.validate()?;

        let pending_key = format!("pending_totp:{}", cmd.user_id);
        let maybe_secret_str = self.token_store.get_token(&pending_key).await?;

        let secret_str = match maybe_secret_str {
            Some(s) => s,
            None => return Err(AppError::TokenExpired),
        };

        let secret_bytes = decode_base32(&secret_str).ok_or_else(|| {
            AppError::internal(
                "corrupt pending TOTP secret",
                std::io::Error::other("invalid base32"),
            )
        })?;

        let now = Utc::now();
        let is_valid =
            self.totp_service
                .verify_code(&secret_bytes, &cmd.code, now.timestamp() as u64)?;

        if !is_valid {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "code",
                "invalid TOTP code",
            )]));
        }

        // Clean up pending ephemeral setup secret
        self.token_store.delete_token(&pending_key).await?;

        // Encrypt secret at rest via AES-256-GCM with fresh nonce and user_id as AAD
        let (ciphertext, nonce) = self
            .secret_cipher
            .encrypt_with_aad(&secret_bytes, cmd.user_id.as_bytes())?;

        // Generate 10 single-use backup codes
        let (plaintexts, hashes) = generate_backup_codes(10);

        let mut mfa = UserMfa::new(cmd.user_id, ciphertext, nonce, hashes);
        mfa.verify(now);
        self.user_repo.save_mfa(&mfa).await?;

        let mut user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        user.enable_mfa(now);
        self.user_repo.update(&user).await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::MFA_ENABLED,
                AuditEventStatus::Success,
                serde_json::json!({ "mfa_type": "totp" }),
            ))));

        Ok(TotpEnabledResult {
            backup_codes: plaintexts,
        })
    }
}
