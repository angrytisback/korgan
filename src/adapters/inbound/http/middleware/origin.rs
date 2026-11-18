//! CSRF defence for cookie-authenticated browser traffic (KRG-SEC-03).
//!
//! `SameSite=Strict` is the first line of defence; this middleware adds an
//! `Origin` check on every state-changing request:
//!
//! * if the request carries an `Origin` header it must exactly match one of
//!   `server.cors_allowed_origins` (this also blocks login CSRF, where no
//!   session cookie exists yet), and
//! * if it carries a `__Host-` auth cookie it **must** carry an allowed
//!   `Origin` — browsers always send one on cross-origin and same-origin
//!   `POST`/`PATCH`/`PUT`/`DELETE`, so a missing header means a non-browser
//!   client replaying a cookie.
//!
//! Safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt. Pure Bearer/API clients
//! send neither an `Origin` nor a cookie and are unaffected.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{COOKIE, ORIGIN};
use http::{HeaderMap, Method};

use crate::adapters::inbound::http::error::{ApiError, ErrorKind};
use crate::adapters::inbound::http::state::AppState;

/// Cookie names that authenticate a browser session.
const AUTH_COOKIE_PREFIXES: [&str; 2] = ["__Host-access_token=", "__Host-refresh_token="];

/// Rejects cross-origin state-changing requests (see module docs).
pub async fn origin_check_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if origin_permitted(
        request.method(),
        request.headers(),
        &state.settings.server.cors_allowed_origins,
    ) {
        next.run(request).await
    } else {
        tracing::warn!(
            method = %request.method(),
            "rejecting state-changing request with missing or disallowed Origin"
        );
        ApiError::new(ErrorKind::Forbidden)
            .with_detail("request origin is not allowed")
            .into_response()
    }
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn has_auth_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .any(|c| AUTH_COOKIE_PREFIXES.iter().any(|p| c.starts_with(p)))
}

/// Pure decision function so the policy is unit-testable.
fn origin_permitted(method: &Method, headers: &HeaderMap, allowed: &[String]) -> bool {
    if is_safe_method(method) {
        return true;
    }
    match headers.get(ORIGIN) {
        Some(origin) => origin
            .to_str()
            .is_ok_and(|o| allowed.iter().any(|a| a.trim_end_matches('/') == o)),
        None => !has_auth_cookie(headers),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn allowed() -> Vec<String> {
        vec!["https://app.example.com/".to_owned()]
    }

    fn headers(origin: Option<&str>, cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(o) = origin {
            h.insert(
                ORIGIN,
                HeaderValue::from_str(o).unwrap_or(HeaderValue::from_static("")),
            );
        }
        if let Some(c) = cookie {
            h.insert(
                COOKIE,
                HeaderValue::from_str(c).unwrap_or(HeaderValue::from_static("")),
            );
        }
        h
    }

    #[test]
    fn safe_methods_are_exempt() {
        let h = headers(Some("https://evil.example"), Some("__Host-access_token=x"));
        assert!(origin_permitted(&Method::GET, &h, &allowed()));
    }

    #[test]
    fn cross_origin_cookie_post_is_rejected() {
        let h = headers(Some("https://evil.example"), Some("__Host-access_token=x"));
        assert!(!origin_permitted(&Method::POST, &h, &allowed()));
    }

    #[test]
    fn cross_origin_login_without_cookie_is_rejected() {
        let h = headers(Some("https://evil.example"), None);
        assert!(!origin_permitted(&Method::POST, &h, &allowed()));
    }

    #[test]
    fn opaque_null_origin_is_rejected() {
        let h = headers(Some("null"), Some("__Host-refresh_token=x"));
        assert!(!origin_permitted(&Method::DELETE, &h, &allowed()));
    }

    #[test]
    fn allowed_origin_cookie_post_passes() {
        let h = headers(
            Some("https://app.example.com"),
            Some("a=b; __Host-access_token=x"),
        );
        assert!(origin_permitted(&Method::POST, &h, &allowed()));
    }

    #[test]
    fn cookie_post_without_origin_is_rejected() {
        let h = headers(None, Some("theme=dark; __Host-refresh_token=x"));
        assert!(!origin_permitted(&Method::POST, &h, &allowed()));
    }

    #[test]
    fn bearer_client_without_origin_or_cookie_passes() {
        assert!(origin_permitted(
            &Method::POST,
            &HeaderMap::new(),
            &allowed()
        ));
    }
}
