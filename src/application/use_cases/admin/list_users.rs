//! Paginated user listing use case for admin backoffice.

use std::sync::Arc;

use validator::Validate;

use crate::application::dto::{AdminUserItem, ListUsersQuery, PaginatedUsersResult};
use crate::application::error::AppError;
use crate::ports::repositories::UserRepository;

/// Coordinates paginated user listings for administrators.
#[derive(Clone)]
pub struct ListUsersUseCase {
    user_repo: Arc<dyn UserRepository>,
}

impl std::fmt::Debug for ListUsersUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListUsersUseCase").finish()
    }
}

impl ListUsersUseCase {
    /// Creates a new [`ListUsersUseCase`].
    #[must_use]
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Executes the user list query with pagination.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Validation`] on invalid pagination parameters,
    /// or [`AppError::Internal`] on persistence failure.
    pub async fn execute(&self, query: ListUsersQuery) -> Result<PaginatedUsersResult, AppError> {
        query.validate()?;

        let offset = (query.page.saturating_sub(1)).saturating_mul(u64::from(query.per_page));
        let users = self
            .user_repo
            .list_paginated(query.per_page, offset)
            .await?;
        let total = self.user_repo.count_all().await?;

        let total_pages = if total == 0 {
            0
        } else {
            (total + u64::from(query.per_page) - 1) / u64::from(query.per_page)
        };

        let items = users
            .into_iter()
            .map(|u| AdminUserItem {
                id: u.id,
                email: u.email.to_string(),
                username: u.username.map(|un| un.into_inner()),
                role: u.role,
                status: u.status,
                email_verified: u.email_verified_at.is_some(),
                mfa_enabled: u.mfa_enabled,
                created_at: u.created_at,
                updated_at: u.updated_at,
            })
            .collect();

        Ok(PaginatedUsersResult {
            items,
            total,
            page: query.page,
            per_page: query.per_page,
            total_pages,
        })
    }
}
