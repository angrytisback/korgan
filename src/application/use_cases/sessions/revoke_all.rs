//! Bulk session revocation use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::RevokeAllSessionsCommand;
use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::SessionRepository;

/// Coordinates revoking all sessions belonging to a user.
#[derive(Clone)]
pub struct RevokeAllSessionsUseCase {
    session_repo: Arc<dyn SessionRepository>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for RevokeAllSessionsUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokeAllSessionsUseCase").finish()
    }
}

impl RevokeAllSessionsUseCase {
    /// Creates a new [`RevokeAllSessionsUseCase`].
    #[must_use]
    pub fn new(
        session_repo: Arc<dyn SessionRepository>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            session_repo,
            token_store,
            event_bus,
        }
    }

    /// Revokes all active sessions for a user, optionally exempting the current session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Internal`] on persistence failure.
    pub async fn execute(&self, cmd: RevokeAllSessionsCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let revoked_ids = self
            .session_repo
            .revoke_all_user_sessions(
                &cmd.user_id,
                cmd.except_session_id.as_ref(),
                "user_revocation",
            )
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
                Some(cmd.user_id),
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::SESSION_REVOKED,
                AuditEventStatus::Success,
                serde_json::json!({
                    "revoked_all": true,
                    "exempt_session": cmd.except_session_id.map(|s| s.to_string()),
                }),
            ))));

        Ok(())
    }
}
