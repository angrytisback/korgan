//! TOTP initialization use case.

use std::sync::Arc;
use std::time::Duration;

use validator::Validate;

use crate::application::dto::{SetupTotpCommand, TotpSetupResult};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::encode_base32;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;
use crate::ports::services::TotpService;

/// Default validity lifetime for pending TOTP setups (15 minutes).
pub const DEFAULT_PENDING_TOTP_TTL: Duration = Duration::from_secs(15 * 60);

/// Coordinates initiation of TOTP Multi-Factor Authentication.
#[derive(Clone)]
pub struct SetupTotpUseCase {
    user_repo: Arc<dyn UserRepository>,
    totp_service: Arc<dyn TotpService>,
    token_store: Arc<dyn TokenStore>,
    issuer: String,
    pending_ttl: Duration,
}

impl std::fmt::Debug for SetupTotpUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupTotpUseCase")
            .field("issuer", &self.issuer)
            .field("pending_ttl", &self.pending_ttl)
            .finish()
    }
}

impl SetupTotpUseCase {
    /// Creates a new [`SetupTotpUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        totp_service: Arc<dyn TotpService>,
        token_store: Arc<dyn TokenStore>,
        issuer: String,
        pending_ttl: Duration,
    ) -> Self {
        Self {
            user_repo,
            totp_service,
            token_store,
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

        let secret_bytes = self.totp_service.generate_secret()?;
        let qr_code_svg =
            self.totp_service
                .generate_qr_code_svg(&user.email, &secret_bytes, &self.issuer)?;

        let base32_secret = encode_base32(&secret_bytes);
        let pending_key = format!("pending_totp:{}", user.id);

        self.token_store
            .set_token(&pending_key, &base32_secret, self.pending_ttl)
            .await?;

        Ok(TotpSetupResult {
            secret: base32_secret,
            qr_code_svg,
        })
    }
}
