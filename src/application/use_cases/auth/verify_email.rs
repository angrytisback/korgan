//! Email verification use case implementation.

use std::sync::Arc;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::VerifyEmailCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::hash_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::UserId;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;

/// Coordinates e-mail confirmation via single-use token.
#[derive(Clone)]
pub struct VerifyEmailUseCase {
    user_repo: Arc<dyn UserRepository>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for VerifyEmailUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyEmailUseCase").finish()
    }
}

impl VerifyEmailUseCase {
    /// Creates a new [`VerifyEmailUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            user_repo,
            token_store,
            event_bus,
        }
    }

    /// Verifies the user's e-mail address and activates their account.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenInvalid`] if the token does not exist or has expired,
    /// [`AppError::NotFound`] if the referenced user no longer exists.
    pub async fn execute(&self, cmd: VerifyEmailCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let token_hash = hash_token(&cmd.token);
        let key = format!("verify_email:{token_hash}");

        // Single-use: atomically retrieve and delete token
        let user_id_str = match self.token_store.get_and_delete(&key).await? {
            Some(s) => s,
            None => return Err(AppError::TokenInvalid),
        };

        let user_id: UserId = user_id_str
            .parse()
            .map_err(|e| AppError::internal("invalid user id in token store", e))?;

        let mut user = self
            .user_repo
            .find_by_id(&user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        match user.status {
            crate::domain::entities::AccountStatus::Suspended
            | crate::domain::entities::AccountStatus::Deactivated
            | crate::domain::entities::AccountStatus::PendingDeletion => {
                return Err(AppError::Forbidden);
            }
            crate::domain::entities::AccountStatus::Active
            | crate::domain::entities::AccountStatus::Unverified => {}
        }

        let now = Utc::now();
        user.verify_email(now);
        self.user_repo.update(&user).await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::EMAIL_VERIFIED,
                AuditEventStatus::Success,
                serde_json::json!({ "email": user.email.as_str() }),
            ))));

        Ok(())
    }
}
