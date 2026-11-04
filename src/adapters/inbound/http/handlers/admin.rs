//! Admin backoffice HTTP handlers.
//!
//! * `GET /api/v1/admin/users` - list users with pagination
//! * `POST /api/v1/admin/users/:id/ban` - administratively suspend a user and revoke all sessions
//! * `POST /api/v1/admin/users/:id/unban` - restore a suspended user to active status

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::AdminUser;
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::{
    AdminUserItem, BanUserCommand, BanUserResult, ListUsersQuery, PaginatedUsersResult,
    UnbanUserCommand, UnbanUserResult,
};
use crate::domain::value_objects::UserId;

/// Query parameters for listing users in the backoffice.
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct ListUsersParams {
    /// 1-based page number (default: 1).
    #[schema(example = 1, default = 1)]
    pub page: Option<u64>,
    /// Number of items per page (default: 20, max: 100).
    #[schema(example = 20, default = 20)]
    pub per_page: Option<u32>,
}

/// Admin representation of a user item.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminUserItemResponse {
    /// Unique user identifier.
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub id: String,
    /// Canonical e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Alphanumeric username, if set.
    #[schema(example = "johndoe")]
    pub username: Option<String>,
    /// Authorization role (e.g. `user`, `admin`).
    #[schema(example = "user")]
    pub role: String,
    /// Current account lifecycle status (e.g. `active`, `suspended`).
    #[schema(example = "active")]
    pub status: String,
    /// Whether email address has been confirmed.
    #[schema(example = true)]
    pub email_verified: bool,
    /// Whether MFA is enabled.
    #[schema(example = false)]
    pub mfa_enabled: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<AdminUserItem> for AdminUserItemResponse {
    fn from(item: AdminUserItem) -> Self {
        Self {
            id: item.id.to_string(),
            email: item.email,
            username: item.username,
            role: item.role.to_string(),
            status: item.status.to_string(),
            email_verified: item.email_verified,
            mfa_enabled: item.mfa_enabled,
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}

/// Paginated user list response for administrative views.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedUsersResponse {
    /// List of user items on the current page.
    pub items: Vec<AdminUserItemResponse>,
    /// Total count of users across all pages.
    #[schema(example = 42)]
    pub total: u64,
    /// Current page (1-based).
    #[schema(example = 1)]
    pub page: u64,
    /// Items per page.
    #[schema(example = 20)]
    pub per_page: u32,
    /// Total calculated pages.
    #[schema(example = 3)]
    pub total_pages: u64,
}

impl From<PaginatedUsersResult> for PaginatedUsersResponse {
    fn from(res: PaginatedUsersResult) -> Self {
        Self {
            items: res.items.into_iter().map(Into::into).collect(),
            total: res.total,
            page: res.page,
            per_page: res.per_page,
            total_pages: res.total_pages,
        }
    }
}

/// Request payload to administratively ban a user.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct BanUserRequest {
    /// Optional administrative reason for the ban.
    #[schema(example = "Abusive activity detected")]
    pub reason: Option<String>,
}

/// Response returned when a user is successfully banned.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BanUserResponse {
    /// User identifier.
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub id: String,
    /// Updated account status (`suspended`).
    #[schema(example = "suspended")]
    pub status: String,
    /// Whether user is currently banned.
    #[schema(example = true)]
    pub banned: bool,
}

impl From<BanUserResult> for BanUserResponse {
    fn from(res: BanUserResult) -> Self {
        Self {
            id: res.id.to_string(),
            status: res.status.to_string(),
            banned: res.banned,
        }
    }
}

/// Response returned when a user is successfully unbanned.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UnbanUserResponse {
    /// User identifier.
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub id: String,
    /// Updated account status (`active`).
    #[schema(example = "active")]
    pub status: String,
    /// Whether user is currently unbanned.
    #[schema(example = true)]
    pub unbanned: bool,
}

impl From<UnbanUserResult> for UnbanUserResponse {
    fn from(res: UnbanUserResult) -> Self {
        Self {
            id: res.id.to_string(),
            status: res.status.to_string(),
            unbanned: res.unbanned,
        }
    }
}

/// Retrieves a paginated list of all users.
#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "Admin",
    operation_id = "admin_list_users",
    security(("BearerAuth" = [])),
    params(ListUsersParams),
    responses(
        (status = 200, description = "Paginated list of users", body = PaginatedUsersResponse),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Insufficient permissions (admin required)", body = ProblemDetails),
        (status = 422, description = "Invalid pagination parameters", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(params): Query<ListUsersParams>,
) -> Result<Json<PaginatedUsersResponse>, ApiError> {
    let query = ListUsersQuery {
        page: params.page.unwrap_or(1),
        per_page: params.per_page.unwrap_or(20),
    };

    let result = state.list_users_use_case.execute(query).await?;
    Ok(Json(result.into()))
}

/// Administratively bans a user and revokes all of their active sessions.
#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/ban",
    tag = "Admin",
    operation_id = "admin_ban_user",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Target user ID to ban")
    ),
    request_body(content = Option<BanUserRequest>, description = "Optional reason for ban"),
    responses(
        (status = 200, description = "User successfully banned", body = BanUserResponse),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Insufficient permissions (admin required)", body = ProblemDetails),
        (status = 404, description = "Target user not found", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn ban_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    payload: Option<Json<BanUserRequest>>,
) -> Result<Json<BanUserResponse>, ApiError> {
    let user_id = UserId::from_uuid(id)?;
    let reason = payload.and_then(|p| p.0.reason);

    let cmd = BanUserCommand {
        user_id,
        reason,
        actor_id: admin.user_id,
    };

    let result = state.ban_user_use_case.execute(cmd).await?;
    Ok(Json(result.into()))
}

/// Restores a suspended user account to active status.
#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/unban",
    tag = "Admin",
    operation_id = "admin_unban_user",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Target user ID to unban")
    ),
    responses(
        (status = 200, description = "User successfully unbanned", body = UnbanUserResponse),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Insufficient permissions (admin required)", body = ProblemDetails),
        (status = 404, description = "Target user not found", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn unban_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<UnbanUserResponse>, ApiError> {
    let user_id = UserId::from_uuid(id)?;

    let cmd = UnbanUserCommand {
        user_id,
        actor_id: admin.user_id,
    };

    let result = state.unban_user_use_case.execute(cmd).await?;
    Ok(Json(result.into()))
}
