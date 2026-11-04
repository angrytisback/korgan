//! Router assembly and the global middleware stack.

use std::any::Any;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::timeout::TimeoutLayer;

use super::error::{ApiError, ErrorKind, problem_details_middleware};
use super::handlers::{
    admin, auth, fallback, health, jwks, metrics, mfa, oauth, passkeys, password, sessions, users,
};
use super::middleware::rate_limit::rate_limit_middleware;
use super::middleware::request_id::{X_REQUEST_ID, request_id_middleware};
use super::middleware::security_headers::security_headers_middleware;
use super::openapi;
use super::state::AppState;
use crate::config::Settings;

/// How long browsers may cache a CORS preflight result.
const CORS_MAX_AGE_SECS: u64 = 600;

/// Errors raised while assembling the router.
#[derive(Debug, Error)]
pub enum RouterError {
    /// A configured CORS origin is not a valid header value.
    #[error("server.cors_allowed_origins contains an invalid origin")]
    InvalidCorsOrigin,
    /// Failed to initialize application state from configuration.
    #[error("state initialization error: {0}")]
    StateInitialization(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Builds the fully-layered application router.
///
/// Layers, outermost first:
///
/// 1. sensitive-header redaction (`Authorization`, `Cookie`, `Set-Cookie`)
/// 2. request id / tracing span
/// 3. security headers
/// 4. CORS
/// 5. sliding-window rate limiting
/// 6. panic catcher (panics become RFC 9457 `500`s)
/// 7. RFC 9457 normaliser for framework-generated errors
/// 8. request timeout and body-size limit
///
/// # Errors
///
/// Returns [`RouterError`] when the CORS configuration cannot be applied.
pub fn build_router(state: AppState) -> Result<Router, RouterError> {
    let settings = state.settings.clone();
    let cors = cors_layer(&settings)?;

    let middleware_stack = ServiceBuilder::new()
        .layer(SetSensitiveHeadersLayer::new([
            AUTHORIZATION,
            COOKIE,
            SET_COOKIE,
        ]))
        .layer(from_fn(request_id_middleware))
        .layer(from_fn(security_headers_middleware))
        .layer(cors)
        .layer(from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(from_fn(problem_details_middleware))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            settings.server.request_timeout(),
        ))
        .layer(RequestBodyLimitLayer::new(
            settings.server.request_body_limit_bytes,
        ))
        .layer(DefaultBodyLimit::max(
            settings.server.request_body_limit_bytes,
        ));

    let api_v1 = Router::new()
        // Authentication
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/mfa/verify", post(auth::verify_mfa))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/verify-email", post(auth::verify_email))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/ws-ticket", post(auth::issue_ws_ticket))
        .route("/auth/ws-ticket/verify", post(auth::verify_ws_ticket))
        // OAuth2 Social Login
        .route("/auth/oauth/{provider}/url", get(oauth::generate_url))
        .route("/auth/oauth/{provider}/callback", get(oauth::callback))
        // WebAuthn / Passkeys
        .route(
            "/auth/passkeys/register/start",
            post(passkeys::register_start),
        )
        .route(
            "/auth/passkeys/register/finish",
            post(passkeys::register_finish),
        )
        .route("/auth/passkeys/login/start", post(passkeys::login_start))
        .route("/auth/passkeys/login/finish", post(passkeys::login_finish))
        // Password Management
        .route("/password/forgot", post(password::forgot))
        .route("/password/reset", post(password::reset))
        .route("/password/change", post(password::change))
        // Multi-Factor Authentication
        .route("/mfa/setup", post(mfa::setup))
        .route("/mfa/enable", post(mfa::enable))
        .route("/mfa/disable", post(mfa::disable))
        // Sessions
        .route(
            "/sessions",
            get(sessions::list).delete(sessions::revoke_all),
        )
        .route("/sessions/{id}", delete(sessions::revoke))
        // User Profile & Devices
        .route("/users/me", get(users::me).patch(users::update))
        .route("/users/me/passkeys", get(passkeys::list))
        .route("/users/me/passkeys/{id}", delete(passkeys::delete))
        // Admin Backoffice
        .route("/admin/users", get(admin::list_users))
        .route("/admin/users/{id}/ban", post(admin::ban_user))
        .route("/admin/users/{id}/unban", post(admin::unban_user));

    Ok(Router::new()
        .route("/health", get(health::live))
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/metrics", get(metrics::metrics))
        .route("/.well-known/jwks.json", get(jwks::jwks))
        .nest("/api/v1", api_v1)
        .merge(openapi::routes())
        .fallback(fallback::not_found)
        .layer(middleware_stack)
        .with_state(state))
}

/// Builds the CORS layer from the configured exact origins.
fn cors_layer(settings: &Settings) -> Result<CorsLayer, RouterError> {
    let origins = settings
        .server
        .cors_allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin.trim_end_matches('/')))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RouterError::InvalidCorsOrigin)?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            ACCEPT,
            CONTENT_TYPE,
            X_REQUEST_ID.clone(),
            HeaderName::from_static("x-client-type"),
            HeaderName::from_static("x-csrf-token"),
            HeaderName::from_static("x-device-name"),
        ])
        .expose_headers([
            X_REQUEST_ID.clone(),
            HeaderName::from_static("ratelimit-limit"),
            HeaderName::from_static("ratelimit-remaining"),
            HeaderName::from_static("ratelimit-reset"),
            http::header::RETRY_AFTER,
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(CORS_MAX_AGE_SECS)))
}

/// Converts a caught panic into a sanitised RFC 9457 `500` response.
///
/// The panic payload is logged for operators but never returned to clients.
fn panic_response(payload: Box<dyn Any + Send + 'static>) -> Response {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    tracing::error!(panic = %message, "request handler panicked");
    ApiError::new(ErrorKind::Internal).into_response()
}
