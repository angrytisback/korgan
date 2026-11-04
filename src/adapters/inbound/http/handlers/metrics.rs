//! Prometheus metrics HTTP handler.

use axum::response::IntoResponse;
use http::header::CONTENT_TYPE;

/// Serves Prometheus metrics in text format.
pub async fn metrics() -> impl IntoResponse {
    let output = crate::telemetry::render_metrics();
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        output,
    )
}
