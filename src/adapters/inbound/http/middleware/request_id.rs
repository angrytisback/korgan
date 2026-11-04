//! Correlation-ID middleware.
//!
//! For every request this middleware:
//!
//! 1. reads `X-Request-Id` and keeps it when it is a valid UUID, otherwise
//!    generates a fresh UUIDv7;
//! 2. stores the [`RequestId`] in the request extensions and in a task-local so
//!    that [`IntoResponse`](axum::response::IntoResponse) implementations (which
//!    cannot see the request) can still produce the RFC 9457 `instance`;
//! 3. opens an `http_request` tracing span carrying `request_id`, so every log
//!    line emitted while handling the request is correlated;
//! 4. echoes the identifier in the `X-Request-Id` response header and logs one
//!    completion line.

use std::future::Future;
use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderName, HeaderValue};
use tracing::Instrument;

use crate::domain::value_objects::RequestId;

/// Name of the correlation header.
pub static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

tokio::task_local! {
    static CURRENT_REQUEST_ID: RequestId;
}

/// Returns the identifier of the request currently being handled, if any.
#[must_use]
pub fn current_request_id() -> Option<RequestId> {
    CURRENT_REQUEST_ID.try_with(|id| *id).ok()
}

/// Runs `future` with `request_id` installed as the current request identifier.
pub async fn scope_request_id<F: Future>(request_id: RequestId, future: F) -> F::Output {
    CURRENT_REQUEST_ID.scope(request_id, future).await
}

/// Axum middleware implementing the behaviour described in the module docs.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<RequestId>().ok())
        .unwrap_or_default();

    request.extensions_mut().insert(request_id);

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
    );
    let started = Instant::now();

    let mut response = scope_request_id(request_id, next.run(request))
        .instrument(span.clone())
        .await;

    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(X_REQUEST_ID.clone(), value);
    }

    span.in_scope(|| {
        tracing::info!(
            status = response.status().as_u16(),
            latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "request completed"
        );
    });

    response
}
