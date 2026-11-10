//! Use case: initiate WebAuthn passkey registration ceremony.

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::application::dto::passkeys::PasskeyRegistrationStartResult;
use crate::application::error::AppError;
use crate::domain::value_objects::UserId;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{PasskeyRepository, UserRepository};
use crate::ports::services::WebAuthnService;

/// Default ephemeral challenge time-to-live (2 minutes).
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// Orchestrates initiating WebAuthn passkey credential registration.
#[derive(Clone)]
pub struct StartPasskeyRegistrationUseCase {
    user_repo: Arc<dyn UserRepository>,
    passkey_repo: Arc<dyn PasskeyRepository>,
    webauthn_service: Arc<dyn WebAuthnService>,
    token_store: Arc<dyn TokenStore>,
    challenge_ttl: Duration,
}

impl std::fmt::Debug for StartPasskeyRegistrationUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartPasskeyRegistrationUseCase")
            .finish_non_exhaustive()
    }
}

impl StartPasskeyRegistrationUseCase {
    /// Creates a new [`StartPasskeyRegistrationUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        passkey_repo: Arc<dyn PasskeyRepository>,
        webauthn_service: Arc<dyn WebAuthnService>,
        token_store: Arc<dyn TokenStore>,
        challenge_ttl: Duration,
    ) -> Self {
        Self {
            user_repo,
            passkey_repo,
            webauthn_service,
            token_store,
            challenge_ttl,
        }
    }

    /// Generates registration options and stores the registration challenge in cache.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if the user does not exist or challenge creation/caching fails.
    pub async fn execute(
        &self,
        user_id: UserId,
    ) -> Result<PasskeyRegistrationStartResult, AppError> {
        let user = self
            .user_repo
            .find_by_id(&user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let username = user
            .username
            .as_ref()
            .map_or_else(|| user.email.as_str(), |u| u.as_str());

        let existing_passkeys = self.passkey_repo.list_by_user_id(&user_id).await?;

        let (ccr, reg_state) =
            self.webauthn_service
                .start_registration(&user_id, username, &existing_passkeys)?;

        let challenge_id = Uuid::now_v7();
        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| AppError::internal("failed to serialize registration state", e))?;

        let cache_key = format!("passkey:reg:{user_id}:{challenge_id}");
        self.token_store
            .set_token(&cache_key, &state_json, self.challenge_ttl)
            .await?;

        Ok(PasskeyRegistrationStartResult {
            challenge_id,
            options: ccr,
        })
    }
}
