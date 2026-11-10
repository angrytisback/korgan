//! User profile query and update use cases.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::{GetProfileQuery, UpdateProfileCommand, UserProfileResult};
use crate::application::error::AppError;
use crate::domain::value_objects::Username;
use crate::ports::repositories::UserRepository;

/// Coordinates retrieving user profile information.
#[derive(Clone)]
pub struct GetProfileUseCase {
    user_repo: Arc<dyn UserRepository>,
}

impl std::fmt::Debug for GetProfileUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetProfileUseCase").finish()
    }
}

impl GetProfileUseCase {
    /// Creates a new [`GetProfileUseCase`].
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Fetches the profile for the given user.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Unauthenticated`] if user is not found.
    pub async fn execute(&self, query: GetProfileQuery) -> Result<UserProfileResult, AppError> {
        query.validate()?;

        let user = self
            .user_repo
            .find_by_id(&query.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        Ok(UserProfileResult {
            id: user.id,
            email: user.email.to_string(),
            username: user.username.map(|u| u.into_inner()),
            status: user.status,
            mfa_enabled: user.mfa_enabled,
            created_at: user.created_at,
        })
    }
}

/// Coordinates updating user profile attributes.
#[derive(Clone)]
pub struct UpdateProfileUseCase {
    user_repo: Arc<dyn UserRepository>,
}

impl std::fmt::Debug for UpdateProfileUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateProfileUseCase").finish()
    }
}

impl UpdateProfileUseCase {
    /// Creates a new [`UpdateProfileUseCase`].
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Updates username and other profile attributes.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Conflict`] if the username is taken,
    /// or [`AppError::Unauthenticated`].
    pub async fn execute(&self, cmd: UpdateProfileCommand) -> Result<UserProfileResult, AppError> {
        cmd.validate()?;

        // Verify the user exists
        let _ = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        let uname = match &cmd.username {
            Some(new_uname_str) => Some(Username::new(new_uname_str)?),
            None => None,
        };

        if let Some(ref u) = uname
            && let Some(existing) = self.user_repo.find_by_username(u).await?
            && existing.id != cmd.user_id
        {
            return Err(AppError::Conflict);
        }

        self.user_repo
            .update_username(&cmd.user_id, uname.as_ref())
            .await?;

        // Re-query fresh user to guarantee UserProfileResult reflects true database state
        let fresh_user = self
            .user_repo
            .find_by_id(&cmd.user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;

        Ok(UserProfileResult {
            id: fresh_user.id,
            email: fresh_user.email.to_string(),
            username: fresh_user.username.map(|u| u.into_inner()),
            status: fresh_user.status,
            mfa_enabled: fresh_user.mfa_enabled,
            created_at: fresh_user.created_at,
        })
    }
}
