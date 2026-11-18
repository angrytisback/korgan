//! TOTP initialization use case.

use std::sync::Arc;
use std::time::Duration;

use validator::Validate;
use zeroize::{Zeroize, Zeroizing};

use crate::application::dto::{SetupTotpCommand, TotpSetupResult};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{encode_base32, seal_pending_totp_secret};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;
use crate::ports::services::{SecretCipher, TotpService};

/// Default validity lifetime for pending TOTP setups (15 minutes).
pub const DEFAULT_PENDING_TOTP_TTL: Duration = Duration::from_mins(15);

/// Coordinates initiation of TOTP Multi-Factor Authentication.
#[derive(Clone)]
pub struct SetupTotpUseCase {
    user_repo: Arc<dyn UserRepository>,
    totp_service: Arc<dyn TotpService>,
    token_store: Arc<dyn TokenStore>,
    secret_cipher: Arc<dyn SecretCipher>,
    issuer: String,
    pending_ttl: Duration,
}

impl std::fmt::Debug for SetupTotpUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupTotpUseCase")
            .field("issuer", &self.issuer)
            .field("pending_ttl", &self.pending_ttl)
            .finish_non_exhaustive()
    }
}

impl SetupTotpUseCase {
    /// Creates a new [`SetupTotpUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        totp_service: Arc<dyn TotpService>,
        token_store: Arc<dyn TokenStore>,
        secret_cipher: Arc<dyn SecretCipher>,
        issuer: String,
        pending_ttl: Duration,
    ) -> Self {
        Self {
            user_repo,
            totp_service,
            token_store,
            secret_cipher,
            issuer,
            pending_ttl,
        }
    }

    /// Generates a new TOTP secret and inline QR code SVG.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Unauthenticated`] if user not found, or [`AppError::Internal`].
    pub async fn execute(&self, cmd: SetupTotpCommand) -> Result<TotpSetupResult, AppError> {
        cmd.validate()?;

        let user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        // An enrolled factor can only be replaced after it has been disabled
        // (step-up + password); otherwise a hijacked session could swap it out.
        if user.mfa_enabled {
            return Err(AppError::Conflict);
        }

        let user_id = user.id;
        let email = user.email;
        let totp_service = self.totp_service.clone();
        let issuer = self.issuer.clone();
        let mut secret_bytes = Zeroizing::new(self.totp_service.generate_secret()?);
        // The cache only ever sees the AES-256-GCM sealed form of the pending secret.
        let sealed_secret =
            seal_pending_totp_secret(self.secret_cipher.as_ref(), &user_id, &secret_bytes)?;

        let (qr_code_svg, mut base32_secret) = tokio::task::spawn_blocking(move || {
            let qr_res = totp_service.generate_qr_code_svg(&email, &secret_bytes, &issuer);
            let outcome = qr_res.map(|svg| (svg, Zeroizing::new(encode_base32(&secret_bytes))));
            secret_bytes.zeroize();
            outcome
        })
        .await
        .map_err(|e| AppError::internal("TOTP setup generation task failed", e))??;

        let pending_key = format!("pending_totp:{user_id}");

        self.token_store
            .set_token(&pending_key, &sealed_secret, self.pending_ttl)
            .await?;

        Ok(TotpSetupResult {
            secret: std::mem::take(&mut *base32_secret),
            qr_code_svg,
        })
    }
}
