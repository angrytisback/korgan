//! Administratively ban user use case.

use std::sync::Arc;

use chrono::Utc;
use validator::Validate;

use crate::application::dto::{BanUserCommand, BanUserResult};
use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::RequestId;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{SessionRepository, UserRepository};

/// Coordinates administratively banning a user and revoking their sessions.
#[derive(Clone)]
pub struct BanUserUseCase {
    user_repo: Arc<dyn UserRepository>,
    session_repo: Arc<dyn SessionRepository>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for BanUserUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BanUserUseCase").finish()
    }
}

impl BanUserUseCase {
    /// Creates a new [`BanUserUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        session_repo: Arc<dyn SessionRepository>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            token_store,
            event_bus,
        }
    }

    /// Administratively bans the user, forces session revocation, and dispatches an audit log.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if the user does not exist,
    /// [`AppError::Validation`] on invalid input, or [`AppError::Internal`].
    pub async fn execute(&self, cmd: BanUserCommand) -> Result<BanUserResult, AppError> {
        cmd.validate()?;

        let mut user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let now = Utc::now();
        user.ban(now);
        self.user_repo.update(&user).await?;

        // Forcefully revoke all active sessions across all devices and sync to Redis blacklist
        let revoked_ids = self
            .session_repo
            .revoke_all_user_sessions(&cmd.user_id, None, "user_banned_by_admin")
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

        // Dispatch security audit event
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "banned_by".to_string(),
            serde_json::Value::String(cmd.actor_id.to_string()),
        );
        if let Some(ref r) = cmd.reason {
            metadata.insert("reason".to_string(), serde_json::Value::String(r.clone()));
        }

        let audit = AuditLog::new(
            Some(cmd.user_id),
            None,
            None,
            RequestId::new(),
            "USER_BANNED",
            AuditEventStatus::Success,
            serde_json::Value::Object(metadata),
        );
        self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));

        Ok(BanUserResult {
            id: user.id,
            status: user.status,
            banned: true,
        })
    }
}
