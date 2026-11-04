//! Authenticated password change use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::ChangePasswordCommand;
use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::errors::FieldViolation;
use crate::domain::value_objects::RawPassword;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{SessionRepository, UserRepository};
use crate::ports::services::{HibpClient, PasswordHasher};

/// Coordinates authenticated password changes.
#[derive(Clone)]
pub struct ChangePasswordUseCase {
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_store: Arc<dyn TokenStore>,
    hibp_client: Arc<dyn HibpClient>,
    event_bus: EventBus,
    history_depth: u16,
}

impl std::fmt::Debug for ChangePasswordUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordUseCase")
            .field("history_depth", &self.history_depth)
            .finish()
    }
}

impl ChangePasswordUseCase {
    /// Creates a new [`ChangePasswordUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_store: Arc<dyn TokenStore>,
        hibp_client: Arc<dyn HibpClient>,
        event_bus: EventBus,
        history_depth: u16,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            password_hasher,
            token_store,
            hibp_client,
            event_bus,
            history_depth,
        }
    }

    /// Changes the user's password after verifying their current password.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidCredentials`] if current password is wrong,
    /// [`AppError::Validation`] if new password was breached or recently used,
    /// or [`AppError::Unauthenticated`].
    pub async fn execute(&self, cmd: ChangePasswordCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        let raw_current = RawPassword::new(&cmd.current_password)?;
        let is_valid = match &user.password_hash {
            Some(hash) => {
                self.password_hasher
                    .verify_password(&raw_current, hash)
                    .await?
            }
            None => {
                let _ = self
                    .password_hasher
                    .verify_against_dummy_hash(&raw_current)
                    .await;
                false
            }
        };

        if !is_valid {
            return Err(AppError::InvalidCredentials);
        }

        let raw_new = RawPassword::new(&cmd.new_password)?;

        if self.hibp_client.is_password_breached(&raw_new).await? {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "new_password",
                "this password has appeared in a known data breach and cannot be used",
            )]));
        }

        if let Some(ref current_hash) = user.password_hash
            && self
                .password_hasher
                .verify_password(&raw_new, current_hash)
                .await?
        {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "new_password",
                "new password cannot be the same as your current password",
            )]));
        }

        let history = self
            .user_repo
            .get_password_history(&user.id, self.history_depth as u32)
            .await?;

        for hist_hash in history {
            if self
                .password_hasher
                .verify_password(&raw_new, &hist_hash)
                .await?
            {
                return Err(AppError::Validation(vec![FieldViolation::new(
                    "new_password",
                    format!(
                        "cannot reuse any of your last {} passwords",
                        self.history_depth
                    ),
                )]));
            }
        }

        let new_hash = self.password_hasher.hash_password(&raw_new).await?;
        self.user_repo
            .update_password(&user.id, &new_hash, self.history_depth)
            .await?;

        // Invalidate other sessions and sync to Redis blacklist
        let revoked_ids = self
            .session_repo
            .revoke_all_user_sessions(&user.id, None, "password_changed")
            .await?;

        let token_store = self.token_store.clone();
        let entries: Vec<(String, &'static str, std::time::Duration)> = revoked_ids
            .into_iter()
            .map(|sid| {
                (
                    format!("blacklist:session:{sid}"),
                    "revoked",
                    std::time::Duration::from_secs(30 * 86400),
                )
            })
            .collect();

        crate::application::use_cases::shielded(move || {
            let token_store = token_store.clone();
            let entries = entries.clone();
            async move {
                let borrowed: Vec<(&str, &str, std::time::Duration)> = entries
                    .iter()
                    .map(|(k, v, ttl)| (k.as_str(), *v, *ttl))
                    .collect();
                token_store.set_tokens_batch(&borrowed).await?;
                Ok(())
            }
        })
        .await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::PASSWORD_CHANGED,
                AuditEventStatus::Success,
                serde_json::json!({}),
            ))));

        Ok(())
    }
}
