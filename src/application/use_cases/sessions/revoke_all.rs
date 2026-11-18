//! Bulk session revocation use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::RevokeAllSessionsCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{SESSION_BLACKLIST_TTL, blacklist_sessions};
use crate::application::workers::EventBus;
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

        let audit = AuditLog::new(
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
        );

        // Revocation and its audit entry commit in ONE transaction; the Redis
        // blacklist sync follows.
        let revoked_ids = self
            .event_bus
            .audited(
                async {
                    Ok::<_, AppError>(
                        self.session_repo
                            .revoke_all_user_sessions(
                                &cmd.user_id,
                                cmd.except_session_id.as_ref(),
                                "user_revocation",
                            )
                            .await?,
                    )
                },
                audit,
            )
            .await?;

        blacklist_sessions(
            self.token_store.clone(),
            &revoked_ids,
            SESSION_BLACKLIST_TTL,
        )
        .await?;

        Ok(())
    }
}
