//! Password reset completion use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::ResetPasswordCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::hash_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::errors::FieldViolation;
use crate::domain::value_objects::{RawPassword, UserId};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{SessionRepository, UserRepository};
use crate::ports::services::{HibpClient, PasswordHasher};

/// Default number of previous passwords tracked to prevent reuse.
pub const DEFAULT_PASSWORD_HISTORY_DEPTH: u16 = 5;

/// Coordinates password reset via verified token with reuse checks.
#[derive(Clone)]
pub struct ResetPasswordUseCase {
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_store: Arc<dyn TokenStore>,
    hibp_client: Arc<dyn HibpClient>,
    event_bus: EventBus,
    history_depth: u16,
}

impl std::fmt::Debug for ResetPasswordUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetPasswordUseCase")
            .field("history_depth", &self.history_depth)
            .finish()
    }
}

impl ResetPasswordUseCase {
    /// Creates a new [`ResetPasswordUseCase`].
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

    /// Resets the user's password, invalidates active sessions, and records history.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenInvalid`] if the token is invalid or expired,
    /// [`AppError::Validation`] if password was breached or recently used,
    /// or [`AppError::NotFound`].
    pub async fn execute(&self, cmd: ResetPasswordCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let raw_password = RawPassword::new(&cmd.new_password)?;

        if self.hibp_client.is_password_breached(&raw_password).await? {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "new_password",
                "this password has appeared in a known data breach and cannot be used",
            )]));
        }

        let token_hash = hash_token(&cmd.token);
        let key = format!("reset_password:{token_hash}");

        // Single-use: atomically retrieve and delete token
        let user_id_str = match self.token_store.get_and_delete(&key).await? {
            Some(s) => s,
            None => return Err(AppError::TokenInvalid),
        };

        let user_id: UserId = user_id_str
            .parse()
            .map_err(|e| AppError::internal("invalid user id in token store", e))?;

        let user = self
            .user_repo
            .find_by_id(&user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        match user.status {
            crate::domain::entities::AccountStatus::Active => {}
            _ => return Err(AppError::Forbidden),
        }

        // Check if matching current password
        if let Some(ref current_hash) = user.password_hash
            && self
                .password_hasher
                .verify_password(&raw_password, current_hash)
                .await?
        {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "new_password",
                "new password cannot be the same as your current password",
            )]));
        }

        // Check historical passwords
        let history = self
            .user_repo
            .get_password_history(&user.id, self.history_depth as u32)
            .await?;

        for hist_hash in history {
            if self
                .password_hasher
                .verify_password(&raw_password, &hist_hash)
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

        // Hash and atomically update password + history
        let new_hash = self.password_hasher.hash_password(&raw_password).await?;
        self.user_repo
            .update_password(&user.id, &new_hash, self.history_depth)
            .await?;

        // Invalidate all active sessions across all devices and sync to Redis blacklist
        let revoked_ids = self
            .session_repo
            .revoke_all_user_sessions(&user.id, None, "password_reset")
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
                audit_events::PASSWORD_RESET,
                AuditEventStatus::Success,
                serde_json::json!({}),
            ))));

        Ok(())
    }
}
