//! OAuth2 external authentication HTTP handlers.
//!
//! * `GET /api/v1/auth/oauth/:provider/url` - generate authorization URL with CSRF state
//! * `GET /api/v1/auth/oauth/:provider/callback` - process OAuth provider callback

use axum::Json;
use axum::extract::{Path, Query, State};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::auth::{AuthTokensResponse, attach_auth_cookies};
use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::ClientMetadata;
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::OAuthCallbackCommand;
use crate::domain::entities::OAuthProvider;

/// Authorization URL response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OAuthUrlResponse {
    /// External provider authorization URL with parameters and CSRF state token.
    #[schema(example = "https://accounts.google.com/o/oauth2/v2/auth?...")]
    pub url: String,
    /// Anti-CSRF state token.
    #[schema(example = "dGhpcyBpcyBhIHJhbmRvbSBzdGF0ZQ...")]
    pub state: String,
}

/// Query parameters passed back by external OAuth2 identity providers.
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
pub struct OAuthCallbackQuery {
    /// Authorization code issued by provider.
    #[schema(example = "4/0AX4XfWh...")]
    pub code: String,
    /// Anti-CSRF state parameter returned by provider.
    #[schema(example = "dGhpcyBpcyBhIHJhbmRvbSBzdGF0ZQ...")]
    pub state: String,
}

/// Generates an external OAuth2 authorization URL.
#[utoipa::path(
    get,
    path = "/api/v1/auth/oauth/{provider}/url",
    tag = "Auth",
    operation_id = "auth_oauth_url",
    params(
        ("provider" = String, Path, description = "OAuth provider ('google' or 'github')", example = "google")
    ),
    responses(
        (status = 200, description = "Authorization URL and state generated", body = OAuthUrlResponse),
        (status = 422, description = "Unsupported provider", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn generate_url(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
) -> Result<Json<OAuthUrlResponse>, ApiError> {
    let provider = OAuthProvider::parse(&provider_str)?;
    let res = state.generate_oauth_url_use_case.execute(provider).await?;

    Ok(Json(OAuthUrlResponse {
        url: res.url,
        state: res.state,
    }))
}

/// Processes an external OAuth2 identity provider callback.
#[utoipa::path(
    get,
    path = "/api/v1/auth/oauth/{provider}/callback",
    tag = "Auth",
    operation_id = "auth_oauth_callback",
    params(
        ("provider" = String, Path, description = "OAuth provider ('google' or 'github')", example = "google"),
        OAuthCallbackQuery
    ),
    responses(
        (status = 200, description = "Authentication successful; tokens issued", body = AuthTokensResponse),
        (status = 401, description = "Invalid credentials or code exchange failed", body = ProblemDetails),
        (status = 403, description = "Invalid or expired anti-CSRF state parameter", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn callback(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    jar: CookieJar,
    Path(provider_str): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<(CookieJar, Json<AuthTokensResponse>), ApiError> {
    let provider = OAuthProvider::parse(&provider_str)?;

    let cmd = OAuthCallbackCommand {
        provider,
        code: query.code,
        state: query.state,
        ip_address: metadata.ip,
        user_agent: metadata.user_agent,
        device_name: metadata.device_name,
        request_id: metadata.request_id,
    };

    let tokens = state.oauth_callback_use_case.execute(cmd).await?;

    let mut updated_jar = jar;
    if metadata.client_type.is_web() {
        updated_jar = attach_auth_cookies(updated_jar, &tokens, &state);
    }

    Ok((updated_jar, Json(tokens.into())))
}
