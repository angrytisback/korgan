//! OAuth2 external authentication HTTP handlers.
//!
//! * `GET /api/v1/auth/oauth/:provider/url` - generate authorization URL with CSRF state
//! * `GET /api/v1/auth/oauth/:provider/callback` - process OAuth provider callback

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cookie::time::Duration as CookieDuration;
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
    jar: CookieJar,
    Path(provider_str): Path<String>,
) -> Result<(CookieJar, Json<OAuthUrlResponse>), ApiError> {
    let provider = OAuthProvider::parse(&provider_str)?;
    let res = state.generate_oauth_url_use_case.execute(provider).await?;

    let host_state_cookie = Cookie::build(("__Host-oauth_state", res.state.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(300))
        .build();

    let updated_jar = jar.add(host_state_cookie);

    Ok((
        updated_jar,
        Json(OAuthUrlResponse {
            url: res.url,
            state: res.state,
        }),
    ))
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
) -> (CookieJar, Response) {
    let cookie_state = jar
        .get("__Host-oauth_state")
        .or_else(|| jar.get("oauth_state"))
        .map(|c| c.value().to_owned());

    // Ensure anti-CSRF cookie is cleared with Max-Age=0 across all response branches
    let clear_host_cookie = Cookie::build(("__Host-oauth_state", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build();
    let clear_fallback_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build();
    let cleared_jar = jar.add(clear_host_cookie).add(clear_fallback_cookie);

    let execute_result: Result<crate::application::dto::AuthTokensResult, ApiError> = async {
        let provider = OAuthProvider::parse(&provider_str)?;
        let cmd = OAuthCallbackCommand {
            provider,
            code: query.code,
            state: query.state,
            cookie_state,
            ip_address: metadata.ip,
            user_agent: metadata.user_agent,
            device_name: metadata.device_name,
            request_id: metadata.request_id,
        };
        state
            .oauth_callback_use_case
            .execute(cmd)
            .await
            .map_err(ApiError::from)
    }
    .await;

    match execute_result {
        Ok(tokens) => {
            let mut final_jar = cleared_jar;
            if metadata.client_type.is_web() {
                final_jar = attach_auth_cookies(final_jar, &tokens, &state);
            }
            (
                final_jar,
                Json(AuthTokensResponse::from(tokens)).into_response(),
            )
        }
        Err(err) => (cleared_jar, err.into_response()),
    }
}
