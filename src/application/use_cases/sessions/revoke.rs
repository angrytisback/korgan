//! Single session revocation use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::RevokeSessionCommand;
use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::SessionRepository;

/// Coordinates revoking a single active session.
#[derive(Clone)]
pub struct RevokeSessionUseCase {
    session_repo: Arc<dyn SessionRepository>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
}

impl std::fmt::Debug for RevokeSessionUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokeSessionUseCase").finish()
    }
}

impl RevokeSessionUseCase {
    /// Creates a new [`RevokeSessionUseCase`].
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

    /// Revokes a session by ID after confirming ownership.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if session doesn't exist,
    /// [`AppError::Forbidden`] if session belongs to a different user.
    pub async fn execute(&self, cmd: RevokeSessionCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let revoked = self
            .session_repo
            .revoke_by_id_and_user_id(&cmd.session_id, &cmd.user_id, "user_logout")
            .await?;

        if revoked.is_none() {
            if let Some(session) = self.session_repo.find_by_id(&cmd.session_id).await?
                && session.user_id != cmd.user_id
            {
                return Err(AppError::Forbidden);
            }
            return Err(AppError::NotFound);
        }

        let token_store = self.token_store.clone();
        let session_id = cmd.session_id;
        crate::application::use_cases::shielded(move || {
            let token_store = token_store.clone();
            async move {
                token_store
                    .set_token(
                        &format!("blacklist:session:{session_id}"),
                        "revoked",
                        std::time::Duration::from_secs(30 * 86400),
                    )
                    .await?;
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
                serde_json::json!({ "session_id": cmd.session_id.to_string() }),
            ))));

        Ok(())
    }
}
