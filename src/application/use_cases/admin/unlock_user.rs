//! Unlock user use case.

use std::sync::Arc;

use chrono::Utc;

use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::{EmailAddress, RequestId};
use crate::ports::repositories::UserRepository;

/// Use case to unlock a locked user account and reset failed login attempts.
#[derive(Clone)]
pub struct UnlockUserUseCase {
    user_repo: Arc<dyn UserRepository>,
    event_bus: EventBus,
}

impl std::fmt::Debug for UnlockUserUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockUserUseCase").finish()
    }
}

impl UnlockUserUseCase {
    /// Creates a new [`UnlockUserUseCase`].
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>, event_bus: EventBus) -> Self {
        Self {
            user_repo,
            event_bus,
        }
    }

    /// Clears `locked_until` and resets `failed_login_attempts` to 0.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if the user does not exist,
    /// or [`AppError::Validation`] if the email is invalid.
    pub async fn execute(&self, email: &str) -> Result<(), AppError> {
        let email_addr = EmailAddress::parse(email)?;

        let user = self
            .user_repo
            .find_by_email(&email_addr)
            .await?
            .ok_or(AppError::NotFound)?;

        let now = Utc::now();
        self.user_repo.reset_failed_logins(&user.id, now).await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                None,
                Some("korgan-cli-unlock".to_string()),
                RequestId::new(),
                "user_unlocked",
                AuditEventStatus::Success,
                serde_json::json!({
                    "email": user.email.as_str(),
                }),
            ))));

        Ok(())
    }
}
