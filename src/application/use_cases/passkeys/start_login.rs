//! Use case: initiate discoverable WebAuthn passkey login ceremony.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::application::dto::passkeys::PasskeyLoginStartResult;
use crate::application::error::AppError;
use crate::ports::cache::TokenStore;
use crate::ports::services::WebAuthnService;

/// Orchestrates initiating discoverable WebAuthn passkey authentication.
#[derive(Clone)]
pub struct StartPasskeyLoginUseCase {
    webauthn_service: Arc<dyn WebAuthnService>,
    token_store: Arc<dyn TokenStore>,
    challenge_ttl: Duration,
}

impl std::fmt::Debug for StartPasskeyLoginUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartPasskeyLoginUseCase")
            .finish_non_exhaustive()
    }
}

impl StartPasskeyLoginUseCase {
    /// Creates a new [`StartPasskeyLoginUseCase`].
    #[must_use]
    pub fn new(
        webauthn_service: Arc<dyn WebAuthnService>,
        token_store: Arc<dyn TokenStore>,
        challenge_ttl: Duration,
    ) -> Self {
        Self {
            webauthn_service,
            token_store,
            challenge_ttl,
        }
    }

    /// Generates discoverable authentication options and stores the challenge state in cache.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if challenge generation or caching fails.
    pub async fn execute(&self) -> Result<PasskeyLoginStartResult, AppError> {
        let (rcr, auth_state) = self.webauthn_service.start_discoverable_login()?;

        let challenge_id = Uuid::now_v7();
        let state_json = serde_json::to_string(&auth_state)
            .map_err(|e| AppError::internal("failed to serialize authentication state", e))?;

        let cache_key = format!("passkey:login:{challenge_id}");
        self.token_store
            .set_token(&cache_key, &state_json, self.challenge_ttl)
            .await?;

        Ok(PasskeyLoginStartResult {
            challenge_id,
            options: rcr,
        })
    }
}
