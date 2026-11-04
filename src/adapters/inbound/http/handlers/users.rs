//! User profile HTTP handlers.
//!
//! * `GET /api/v1/users/me` - retrieve authenticated caller's profile
//! * `PATCH /api/v1/users/me` - update profile attributes (e.g. username)

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::{AuthUser, ClientMetadata};
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::{GetProfileQuery, UpdateProfileCommand, UserProfileResult};

/// User profile response payload.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserProfileResponse {
    /// User identifier (UUIDv7 string).
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub id: String,

    /// Primary e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,

    /// Alphanumeric username, if set.
    #[schema(example = "johndoe")]
    pub username: Option<String>,

    /// Account lifecycle status.
    #[schema(example = "active")]
    pub status: String,

    /// Whether Multi-Factor Authentication is currently enabled.
    #[schema(example = false)]
    pub mfa_enabled: bool,

    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<UserProfileResult> for UserProfileResponse {
    fn from(p: UserProfileResult) -> Self {
        Self {
            id: p.id.to_string(),
            email: p.email,
            username: p.username,
            status: p.status.to_string(),
            mfa_enabled: p.mfa_enabled,
            created_at: p.created_at,
        }
    }
}

/// Profile update request payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    /// New alphanumeric username candidate, or null to remove username.
    #[schema(example = "newusername")]
    pub username: Option<String>,
}

/// Retrieves the profile for the authenticated caller.
#[utoipa::path(
    get,
    path = "/api/v1/users/me",
    tag = "Users",
    operation_id = "users_get_me",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "Caller profile", body = UserProfileResponse),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn me(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<UserProfileResponse>, ApiError> {
    let query = GetProfileQuery {
        user_id: auth_user.user_id,
    };

    let profile = state.get_profile_use_case.execute(query).await?;

    Ok(Json(profile.into()))
}

/// Updates attributes on the authenticated caller's profile.
#[utoipa::path(
    patch,
    path = "/api/v1/users/me",
    tag = "Users",
    operation_id = "users_update_me",
    security(("BearerAuth" = [])),
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "Profile updated", body = UserProfileResponse),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 409, description = "Username already taken", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn update(
    State(state): State<AppState>,
    auth_user: AuthUser,
    metadata: ClientMetadata,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfileResponse>, ApiError> {
    let cmd = UpdateProfileCommand {
        user_id: auth_user.user_id,
        username: body.username,
        request_id: metadata.request_id,
    };

    let profile = state.update_profile_use_case.execute(cmd).await?;

    Ok(Json(profile.into()))
}
