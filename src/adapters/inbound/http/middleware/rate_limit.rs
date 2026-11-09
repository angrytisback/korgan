//! IP-based sliding-window rate limit middleware.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderName, HeaderValue};

use crate::adapters::inbound::http::error::{ApiError, ErrorKind};
use crate::adapters::inbound::http::state::AppState;

/// Standard rate limit header names.
pub static RATELIMIT_LIMIT: HeaderName = HeaderName::from_static("ratelimit-limit");
pub static RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("ratelimit-remaining");
pub static RATELIMIT_RESET: HeaderName = HeaderName::from_static("ratelimit-reset");

/// Extracts client IP address from connect info or headers.
fn extract_client_ip(request: &Request, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        // Check X-Forwarded-For first (rightmost IP)
        if let Some(forwarded) = request.headers().get("x-forwarded-for")
            && let Ok(s) = forwarded.to_str()
            && let Some(ip) = s.rsplit(',').find_map(|p| p.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }

        // Check X-Real-IP
        if let Some(real_ip) = request.headers().get("x-real-ip")
            && let Ok(s) = real_ip.to_str()
            && let Ok(ip) = s.trim().parse::<IpAddr>()
        {
            return ip;
        }
    }

    // Check ConnectInfo extension
    if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }

    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Axum middleware enforcing sliding-window rate limiting on all incoming HTTP requests.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.settings.rate_limit.enabled {
        return next.run(request).await;
    }

    let client_ip = extract_client_ip(&request, state.settings.rate_limit.trust_proxy_headers);
    let key = format!("http_rl:{client_ip}");

    let limit = state.settings.rate_limit.global_max_requests;
    let window = Duration::from_secs(state.settings.rate_limit.window_secs);
    let rate_status = match state
        .rate_limiter
        .check_and_increment(&key, limit, window)
        .await
    {
        Ok(status) => status,
        Err(e) => {
            tracing::error!(error = %e, "rate limiter check failed; failing closed with 503");
            return ApiError::new(ErrorKind::ServiceUnavailable).into_response();
        }
    };

    if !rate_status.allowed {
        let retry_after = rate_status.retry_after_secs.unwrap_or(60);
        let mut response = ApiError::new(ErrorKind::RateLimited)
            .with_retry_after(retry_after)
            .into_response();

        let headers = response.headers_mut();
        headers.insert(RATELIMIT_LIMIT.clone(), HeaderValue::from(limit));
        headers.insert(RATELIMIT_REMAINING.clone(), HeaderValue::from_static("0"));
        headers.insert(
            RATELIMIT_RESET.clone(),
            HeaderValue::from(rate_status.reset_epoch_secs),
        );
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from(retry_after));

        return response;
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(RATELIMIT_LIMIT.clone(), HeaderValue::from(limit));
    headers.insert(
        RATELIMIT_REMAINING.clone(),
        HeaderValue::from(rate_status.remaining),
    );
    headers.insert(
        RATELIMIT_RESET.clone(),
        HeaderValue::from(rate_status.reset_epoch_secs),
    );

    response
}
