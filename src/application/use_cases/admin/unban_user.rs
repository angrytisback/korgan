//! Administratively unban user use case.

use std::sync::Arc;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{UnbanUserCommand, UnbanUserResult};
use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::RequestId;
use crate::ports::repositories::UserRepository;

/// Coordinates administratively unbanning a user.
#[derive(Clone)]
pub struct UnbanUserUseCase {
    user_repo: Arc<dyn UserRepository>,
    event_bus: EventBus,
}

impl std::fmt::Debug for UnbanUserUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnbanUserUseCase").finish()
    }
}

impl UnbanUserUseCase {
    /// Creates a new [`UnbanUserUseCase`].
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>, event_bus: EventBus) -> Self {
        Self {
            user_repo,
            event_bus,
        }
    }

    /// Restores a suspended user to active status and dispatches an audit log.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if the user does not exist,
    /// [`AppError::Validation`] on invalid input, or [`AppError::Internal`].
    pub async fn execute(&self, cmd: UnbanUserCommand) -> Result<UnbanUserResult, AppError> {
        cmd.validate()?;

        let mut user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let now = Utc::now();
        user.unban(now);
        self.user_repo.update(&user).await?;

        // Dispatch security audit event
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "unbanned_by".to_string(),
            serde_json::Value::String(cmd.actor_id.to_string()),
        );

        let audit = AuditLog::new(
            Some(cmd.user_id),
            None,
            None,
            RequestId::new(),
            "USER_UNBANNED",
            AuditEventStatus::Success,
            serde_json::Value::Object(metadata),
        );
        self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));

        Ok(UnbanUserResult {
            id: user.id,
            status: user.status,
            unbanned: true,
        })
    }
}
