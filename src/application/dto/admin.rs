//! Admin backoffice DTOs for user management and RBAC.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domain::entities::{AccountStatus, UserRole};
use crate::domain::value_objects::UserId;

/// Query parameters for paginated user listing.
#[derive(Debug, Clone, Copy, Validate)]
pub struct ListUsersQuery {
    /// 1-based page number.
    #[validate(range(min = 1))]
    pub page: u64,
    /// Number of items per page.
    #[validate(range(min = 1, max = 100))]
    pub per_page: u32,
}

impl Default for ListUsersQuery {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

/// Representation of a user for administrative views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserItem {
    /// Unique user identifier.
    pub id: UserId,
    /// Primary lowercase e-mail address.
    pub email: String,
    /// Optional username.
    pub username: Option<String>,
    /// Assigned authorization role.
    pub role: UserRole,
    /// Current account lifecycle status.
    pub status: AccountStatus,
    /// Whether email address has been verified.
    pub email_verified: bool,
    /// Whether MFA is enforced on this account.
    pub mfa_enabled: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Paginated result of user entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedUsersResult {
    /// Current page items.
    pub items: Vec<AdminUserItem>,
    /// Total number of users matching query.
    pub total: u64,
    /// Current page (1-based).
    pub page: u64,
    /// Items per page.
    pub per_page: u32,
    /// Total calculated pages.
    pub total_pages: u64,
}

/// Command to administratively ban a user.
#[derive(Debug, Clone, Validate)]
pub struct BanUserCommand {
    /// Identifier of the user being banned.
    pub user_id: UserId,
    /// Optional administrative reason for ban.
    #[validate(length(max = 256))]
    pub reason: Option<String>,
    /// Identifier of the admin performing the ban.
    pub actor_id: UserId,
}

/// Command to administratively unban a user.
#[derive(Debug, Clone, Validate)]
pub struct UnbanUserCommand {
    /// Identifier of the user being unbanned.
    pub user_id: UserId,
    /// Identifier of the admin performing the unban.
    pub actor_id: UserId,
}

/// Result of banning a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanUserResult {
    /// User identifier.
    pub id: UserId,
    /// New account status (`Suspended`).
    pub status: AccountStatus,
    /// Whether ban was applied.
    pub banned: bool,
}

/// Result of unbanning a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbanUserResult {
    /// User identifier.
    pub id: UserId,
    /// Restored account status (`Active`).
    pub status: AccountStatus,
    /// Whether unban was applied.
    pub unbanned: bool,
}
