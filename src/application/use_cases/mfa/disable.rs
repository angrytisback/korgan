//! MFA deactivation use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::DisableTotpCommand;
use crate::application::error::AppError;
use crate::application::workers::EventBus;
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::RawPassword;
use crate::ports::repositories::UserRepository;
use crate::ports::services::PasswordHasher;

/// Coordinates deactivating MFA on an account.
#[derive(Clone)]
pub struct DisableTotpUseCase {
    user_repo: Arc<dyn UserRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    event_bus: EventBus,
}

impl std::fmt::Debug for DisableTotpUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisableTotpUseCase").finish()
    }
}

impl DisableTotpUseCase {
    /// Creates a new [`DisableTotpUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            user_repo,
            password_hasher,
            event_bus,
        }
    }

    /// Disables MFA after verifying the user's password.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidCredentials`] if password is wrong,
    /// or [`AppError::Unauthenticated`] if user not found.
    pub async fn execute(&self, cmd: DisableTotpCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        let raw_password = RawPassword::new(&cmd.current_password)?;
        let is_valid = if let Some(hash) = &user.password_hash {
            self.password_hasher
                .verify_password(&raw_password, hash)
                .await?
        } else {
            let _ = self
                .password_hasher
                .verify_against_dummy_hash(&raw_password)
                .await;
            false
        };

        if !is_valid {
            return Err(AppError::InvalidCredentials);
        }
        self.event_bus
            .audited(
                async {
                    self.user_repo.delete_mfa(&user.id).await?;
                    Ok::<(), AppError>(())
                },
                AuditLog::new(
                    Some(user.id),
                    cmd.ip_address,
                    cmd.user_agent,
                    cmd.request_id,
                    audit_events::MFA_DISABLED,
                    AuditEventStatus::Success,
                    serde_json::json!({}),
                ),
            )
            .await?;

        Ok(())
    }
}
