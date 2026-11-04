//! Use case: delete a registered passkey device.

use std::net::IpAddr;
use std::sync::Arc;

use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{AuditEventStatus, AuditLog, audit_events};
use crate::domain::errors::DomainError;
use crate::domain::value_objects::{PasskeyId, RequestId, UserId};
use crate::ports::repositories::PasskeyRepository;

/// Orchestrates removing a registered passkey credential.
#[derive(Clone)]
pub struct DeletePasskeyUseCase {
    passkey_repo: Arc<dyn PasskeyRepository>,
    event_bus: EventBus,
}

impl std::fmt::Debug for DeletePasskeyUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeletePasskeyUseCase")
            .finish_non_exhaustive()
    }
}

impl DeletePasskeyUseCase {
    /// Creates a new [`DeletePasskeyUseCase`].
    #[must_use]
    pub fn new(passkey_repo: Arc<dyn PasskeyRepository>, event_bus: EventBus) -> Self {
        Self {
            passkey_repo,
            event_bus,
        }
    }

    /// Validates ownership and deletes the specified passkey.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if the passkey is not found, not owned by the user, or deletion fails.
    pub async fn execute(
        &self,
        user_id: UserId,
        passkey_id: PasskeyId,
        request_id: RequestId,
        actor_ip: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), AppError> {
        let passkey = self
            .passkey_repo
            .find_by_id(&passkey_id)
            .await?
            .ok_or(DomainError::PasskeyNotFound)?;

        if passkey.user_id != user_id {
            return Err(AppError::Forbidden);
        }

        let deleted = self
            .passkey_repo
            .delete_by_id_and_user_id(&passkey_id, &user_id)
            .await?;

        if !deleted {
            return Err(AppError::from(DomainError::PasskeyNotFound));
        }

        let audit = AuditLog::new(
            Some(user_id),
            actor_ip,
            user_agent,
            request_id,
            audit_events::PASSKEY_DELETED,
            AuditEventStatus::Success,
            serde_json::json!({
                "passkey_id": passkey_id,
                "passkey_name": passkey.name,
            }),
        );
        self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));

        Ok(())
    }
}
