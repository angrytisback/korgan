//! Session listing use case implementation.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::{ListSessionsQuery, SessionSummary};
use crate::application::error::AppError;
use crate::ports::repositories::SessionRepository;

/// Coordinates querying active sessions for a user.
#[derive(Clone)]
pub struct ListSessionsUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl std::fmt::Debug for ListSessionsUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListSessionsUseCase").finish()
    }
}

impl ListSessionsUseCase {
    /// Creates a new [`ListSessionsUseCase`].
    #[must_use]
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// Lists active sessions for the user, highlighting current session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Validation`] on invalid query parameters.
    pub async fn execute(&self, query: ListSessionsQuery) -> Result<Vec<SessionSummary>, AppError> {
        query.validate()?;

        let sessions = self
            .session_repo
            .list_by_user_id(&query.user_id, query.limit, query.offset)
            .await?;

        let summaries = sessions
            .into_iter()
            .map(|s| SessionSummary {
                id: s.id,
                device_name: s.device_name,
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                is_current: query.current_session_id.is_some_and(|curr| curr == s.id),
                last_active_at: s.last_active_at,
                created_at: s.created_at,
            })
            .collect();

        Ok(summaries)
    }
}
