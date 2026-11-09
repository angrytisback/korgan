//! Liveness and readiness probes.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::adapters::inbound::http::error::{ApiError, ErrorKind, ProblemDetails};
use crate::adapters::inbound::http::state::AppState;

/// Process health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// The process is running and able to serve requests.
    Ok,
}

/// Body of the liveness and readiness response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Always `ok` while the process is healthy.
    #[schema(example = "ok")]
    pub status: HealthStatus,
}

/// Liveness probe: succeeds whenever the process can serve HTTP requests.
///
/// Performs no dependency checks, so orchestrators never restart the service
/// because of a transient database or cache outage.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    operation_id = "health_live",
    responses(
        (status = 200, description = "The process is alive", body = HealthResponse),
        (
            status = 429,
            description = "Rate limit exceeded",
            body = ProblemDetails,
            content_type = "application/problem+json"
        ),
        (
            status = 500,
            description = "Unexpected server error",
            body = ProblemDetails,
            content_type = "application/problem+json"
        )
    )
)]
pub async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Ok,
    })
}

/// Readiness probe: validates connectivity to primary dependencies (PostgreSQL & Redis).
///
/// Returns 200 OK when both PostgreSQL and Redis are reachable.
/// Returns 503 Service Unavailable if any dependency check fails.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    operation_id = "health_ready",
    responses(
        (status = 200, description = "The process and dependencies are healthy", body = HealthResponse),
        (
            status = 503,
            description = "Service dependency unavailable",
            body = ProblemDetails,
            content_type = "application/problem+json"
        )
    )
)]
pub async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    state.check_readiness().await.map_err(|e| {
        tracing::warn!(error = %e, "readiness probe check failed");
        ApiError::new(ErrorKind::ServiceUnavailable)
    })?;

    Ok(Json(HealthResponse {
        status: HealthStatus::Ok,
    }))
}
