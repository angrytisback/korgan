//! User profile DTO queries, commands and results.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domain::entities::AccountStatus;
use crate::domain::value_objects::{RequestId, UserId};

/// Query to fetch profile information for the authenticated user.
#[derive(Debug, Clone, Validate)]
pub struct GetProfileQuery {
    /// Authenticated user identifier.
    pub user_id: UserId,
}

/// Profile information returned to client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfileResult {
    /// User identifier.
    pub id: UserId,

    /// Primary e-mail address.
    pub email: String,

    /// Alphanumeric username, if set.
    pub username: Option<String>,

    /// Account lifecycle status.
    pub status: AccountStatus,

    /// Whether Multi-Factor Authentication is currently enabled.
    pub mfa_enabled: bool,

    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Command to update profile attributes.
#[derive(Debug, Clone, Validate)]
pub struct UpdateProfileCommand {
    /// Authenticated user identifier.
    pub user_id: UserId,

    /// New alphanumeric username candidate, or None.
    #[validate(length(
        min = 3,
        max = 30,
        message = "username must be between 3 and 30 characters"
    ))]
    pub username: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}
