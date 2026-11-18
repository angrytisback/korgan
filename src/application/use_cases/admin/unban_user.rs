//! Administratively unban user use case.

use std::sync::Arc;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{UnbanUserCommand, UnbanUserResult};
use crate::application::error::AppError;
use crate::application::workers::EventBus;
use crate::domain::entities::{AccountStatus, AuditEventStatus, AuditLog};
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

        if cmd.actor_id == user.id || !cmd.actor_role.can_manage(user.role) {
            tracing::warn!(
                actor_id = %cmd.actor_id,
                target_id = %user.id,
                "rejecting admin unban: actor may not manage target"
            );
            return Err(AppError::Forbidden);
        }
        // Only a suspended account can be unbanned; unbanning anything else
        // would silently change an unrelated lifecycle state.
        if user.status != AccountStatus::Suspended {
            return Err(AppError::Conflict);
        }

        let now = Utc::now();
        user.unban(now);
        let restored_status = user.status;
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
        self.event_bus
            .audited(
                async {
                    // Granular compare-and-set: never rewrite the whole record.
                    if !self
                        .user_repo
                        .set_status_if(&cmd.user_id, AccountStatus::Suspended, restored_status, now)
                        .await?
                    {
                        return Err(AppError::Conflict);
                    }
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;

        Ok(UnbanUserResult {
            id: user.id,
            status: user.status,
            unbanned: true,
        })
    }
}
