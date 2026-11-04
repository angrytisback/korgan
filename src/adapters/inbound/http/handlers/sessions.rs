//! Session management HTTP handlers.
//!
//! * `GET /api/v1/sessions` - list caller's active sessions
//! * `DELETE /api/v1/sessions/:id` - revoke specific session
//! * `DELETE /api/v1/sessions` - revoke all sessions except the current one

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::{AuthUser, ClientMetadata, StepUpUser};
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::{
    ListSessionsQuery, RevokeAllSessionsCommand, RevokeSessionCommand, SessionSummary,
};
use crate::domain::value_objects::SessionId;

/// Pagination query parameters for listing sessions.
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct ListSessionsParams {
    /// Maximum number of sessions to return (1-100, default 20).
    #[schema(example = 20, default = 20)]
    pub limit: Option<u32>,

    /// Offset for pagination (default 0).
    #[schema(example = 0, default = 0)]
    pub offset: Option<u64>,
}

/// Description of an active user session.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionResponse {
    /// Session identifier (UUIDv7 string).
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub id: String,

    /// Device or browser description.
    #[schema(example = "Safari on macOS")]
    pub device_name: Option<String>,

    /// Client User-Agent header string.
    #[schema(example = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...")]
    pub user_agent: Option<String>,

    /// Client IP address at last activity.
    #[schema(example = "192.168.1.100")]
    pub ip_address: String,

    /// Whether this session corresponds to the caller's current request.
    #[schema(example = true)]
    pub is_current: bool,

    /// Last activity timestamp.
    pub last_active_at: DateTime<Utc>,

    /// Session creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<SessionSummary> for SessionResponse {
    fn from(s: SessionSummary) -> Self {
        Self {
            id: s.id.to_string(),
            device_name: s.device_name,
            user_agent: s.user_agent,
            ip_address: s.ip_address.to_string(),
            is_current: s.is_current,
            last_active_at: s.last_active_at,
            created_at: s.created_at,
        }
    }
}

/// Lists all active sessions for the authenticated caller.
#[utoipa::path(
    get,
    path = "/api/v1/sessions",
    tag = "Sessions",
    operation_id = "sessions_list",
    security(("BearerAuth" = [])),
    params(ListSessionsParams),
    responses(
        (status = 200, description = "Active sessions list", body = Vec<SessionResponse>),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Query(params): Query<ListSessionsParams>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let query = ListSessionsQuery {
        user_id: auth_user.user_id,
        current_session_id: Some(auth_user.session_id),
        limit: params.limit.unwrap_or(20),
        offset: params.offset.unwrap_or(0),
    };

    let sessions = state.list_sessions_use_case.execute(query).await?;
    let response = sessions.into_iter().map(Into::into).collect();

    Ok(Json(response))
}

/// Revokes a specific session belonging to the authenticated caller.
#[utoipa::path(
    delete,
    path = "/api/v1/sessions/{id}",
    tag = "Sessions",
    operation_id = "sessions_revoke",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Session identifier (UUIDv7)")
    ),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Session belongs to another user", body = ProblemDetails),
        (status = 404, description = "Session not found", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    auth_user: AuthUser,
    metadata: ClientMetadata,
    Path(session_uuid): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let session_id = SessionId::from_uuid(session_uuid)?;

    let cmd = RevokeSessionCommand {
        user_id: auth_user.user_id,
        session_id,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.revoke_session_use_case.execute(cmd).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Revokes all active sessions for the user, exempting the caller's current session.
#[utoipa::path(
    delete,
    path = "/api/v1/sessions",
    tag = "Sessions",
    operation_id = "sessions_revoke_all",
    security(("BearerAuth" = [])),
    responses(
        (status = 204, description = "All other sessions revoked"),
        (status = 401, description = "Unauthenticated", body = ProblemDetails),
        (status = 403, description = "Step-up authentication required", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn revoke_all(
    State(state): State<AppState>,
    auth_user: StepUpUser,
    metadata: ClientMetadata,
) -> Result<StatusCode, ApiError> {
    let cmd = RevokeAllSessionsCommand {
        user_id: auth_user.user_id,
        except_session_id: Some(auth_user.session_id),
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.revoke_all_sessions_use_case.execute(cmd).await?;

    Ok(StatusCode::NO_CONTENT)
}
