//! Use case: complete WebAuthn passkey registration ceremony.

use std::net::IpAddr;
use std::sync::Arc;

use validator::Validate;
use webauthn_rs::prelude::PasskeyRegistration;

use crate::application::dto::passkeys::{
    PasskeyRegistrationFinishCommand, PasskeyRegistrationFinishResult,
};
use crate::application::error::AppError;
use crate::application::workers::events::EventBus;
use crate::domain::entities::{AuditEventStatus, AuditLog, Passkey, audit_events};
use crate::domain::errors::DomainError;
use crate::domain::value_objects::{RequestId, UserId};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::PasskeyRepository;
use crate::ports::services::WebAuthnService;

/// Orchestrates completing WebAuthn passkey credential registration.
#[derive(Clone)]
pub struct FinishPasskeyRegistrationUseCase {
    passkey_repo: Arc<dyn PasskeyRepository>,
    webauthn_service: Arc<dyn WebAuthnService>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for FinishPasskeyRegistrationUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishPasskeyRegistrationUseCase")
            .finish_non_exhaustive()
    }
}

impl FinishPasskeyRegistrationUseCase {
    /// Creates a new [`FinishPasskeyRegistrationUseCase`].
    #[must_use]
    pub fn new(
        passkey_repo: Arc<dyn PasskeyRepository>,
        webauthn_service: Arc<dyn WebAuthnService>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            passkey_repo,
            webauthn_service,
            token_store,
            event_bus,
        }
    }

    /// Verifies the registration response and persists the new passkey credential.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if validation fails, challenge expired, or signature verification fails.
    pub async fn execute(
        &self,
        user_id: UserId,
        cmd: PasskeyRegistrationFinishCommand,
        request_id: RequestId,
        actor_ip: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<PasskeyRegistrationFinishResult, AppError> {
        cmd.validate()?;

        let cache_key = format!("passkey:reg:{user_id}:{}", cmd.challenge_id);
        let state_json = self
            .token_store
            .get_and_delete(&cache_key)
            .await?
            .ok_or(DomainError::ChallengeExpired)?;

        let reg_state: PasskeyRegistration =
            serde_json::from_str(&state_json).map_err(|_| DomainError::ChallengeExpired)?;

        let webauthn = self.webauthn_service.clone();
        let credential = cmd.credential;
        let verified_passkey = tokio::task::spawn_blocking(move || {
            webauthn.finish_registration(&credential, &reg_state)
        })
        .await
        .map_err(|e| AppError::internal("passkey registration verification task failed", e))??;

        let credential_id = verified_passkey.cred_id().to_vec();
        let passkey_json = serde_json::to_value(&verified_passkey)
            .map_err(|e| AppError::internal("failed to serialize verified passkey", e))?;

        let passkey_name = cmd.name.unwrap_or_else(|| "Passkey".to_owned());
        let passkey = Passkey::new(user_id, credential_id, passkey_json, passkey_name);

        let audit = AuditLog::new(
            Some(user_id),
            actor_ip,
            user_agent,
            request_id,
            audit_events::PASSKEY_REGISTERED,
            AuditEventStatus::Success,
            serde_json::json!({
                "passkey_id": passkey.id,
                "passkey_name": passkey.name,
            }),
        );
        // The passkey and its audit entry commit together.
        self.event_bus
            .audited(
                async {
                    self.passkey_repo.save(&passkey).await?;
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;

        Ok(PasskeyRegistrationFinishResult {
            id: passkey.id,
            name: passkey.name,
            created_at: passkey.created_at,
        })
    }
}
