//! Baseline security response headers (OWASP Secure Headers Project).

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderName, HeaderValue};

/// Headers added to every response unless a handler already set them.
static SECURITY_HEADERS: [(HeaderName, HeaderValue); 6] = [
    (
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ),
    (
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ),
    (
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    ),
    (
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    ),
    (
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    ),
    (
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-site"),
    ),
];

/// Strict CSP for the JSON API. Not applied to the interactive `/docs` UI,
/// which needs to load its own scripts and styles.
static API_CSP: (HeaderName, HeaderValue) = (
    HeaderName::from_static("content-security-policy"),
    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
);

/// Path prefix of the interactive API documentation.
const DOCS_PATH_PREFIX: &str = "/docs";

/// Middleware that appends the security headers to every response.
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let is_docs = request.uri().path().starts_with(DOCS_PATH_PREFIX);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    for (name, value) in &SECURITY_HEADERS {
        headers.entry(name).or_insert_with(|| value.clone());
    }
    if !is_docs {
        headers
            .entry(&API_CSP.0)
            .or_insert_with(|| API_CSP.1.clone());
    }

    response
}
