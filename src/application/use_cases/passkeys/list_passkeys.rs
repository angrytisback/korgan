//! Use case: list registered passkey devices for authenticated user.

use std::sync::Arc;

use crate::application::dto::passkeys::PasskeyItemResult;
use crate::application::error::AppError;
use crate::domain::value_objects::UserId;
use crate::ports::repositories::PasskeyRepository;

/// Orchestrates retrieving all passkey credentials owned by a user.
#[derive(Clone)]
pub struct ListPasskeysUseCase {
    passkey_repo: Arc<dyn PasskeyRepository>,
}

impl std::fmt::Debug for ListPasskeysUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListPasskeysUseCase")
            .finish_non_exhaustive()
    }
}

impl ListPasskeysUseCase {
    /// Creates a new [`ListPasskeysUseCase`].
    #[must_use]
    pub fn new(passkey_repo: Arc<dyn PasskeyRepository>) -> Self {
        Self { passkey_repo }
    }

    /// Fetches all passkeys registered for `user_id`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if persistence lookup fails.
    pub async fn execute(&self, user_id: UserId) -> Result<Vec<PasskeyItemResult>, AppError> {
        let passkeys = self.passkey_repo.list_by_user_id(&user_id).await?;

        let items = passkeys
            .into_iter()
            .map(|p| PasskeyItemResult {
                id: p.id,
                name: p.name,
                last_used_at: p.last_used_at,
                created_at: p.created_at,
            })
            .collect();

        Ok(items)
    }
}
