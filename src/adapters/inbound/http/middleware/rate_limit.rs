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

/// Paths served by infrastructure probes and scrapers.
///
/// They must not depend on Redis (a cache outage would otherwise fail liveness
/// and make the orchestrator restart healthy pods) nor consume the per-IP
/// request budget of the probing host.
const EXEMPT_PATHS: [&str; 4] = ["/health", "/health/live", "/health/ready", "/metrics"];

#[inline]
fn is_exempt_path(path: &str) -> bool {
    EXEMPT_PATHS.contains(&path)
}

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
    if !state.settings.rate_limit.enabled || is_exempt_path(request.uri().path()) {
        return next.run(request).await;
    }

    let client_ip = extract_client_ip(&request, state.settings.rate_limit.trust_proxy_headers);
    let key = format!("http_rl:{client_ip}");
    let limit = state.settings.rate_limit.global_max_requests;
    enforce(&state, request, next, &key, limit).await
}

/// Endpoints with their own, stricter per-client budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointLimit {
    /// Account registration (`rate_limit.register_max_requests`).
    Register,
    /// Forgot-password requests (`rate_limit.forgot_password_max_requests`).
    ForgotPassword,
    /// MFA code verification (`rate_limit.mfa_max_requests`).
    MfaVerify,
}

impl EndpointLimit {
    #[inline]
    const fn bucket(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::ForgotPassword => "forgot_password",
            Self::MfaVerify => "mfa_verify",
        }
    }

    #[inline]
    const fn budget(self, settings: &crate::config::RateLimitSettings) -> u32 {
        match self {
            Self::Register => settings.register_max_requests,
            Self::ForgotPassword => settings.forgot_password_max_requests,
            Self::MfaVerify => settings.mfa_max_requests,
        }
    }
}

/// Per-endpoint sliding-window limit, applied in addition to the global one.
///
/// Fails closed (503) when the limiter backend errors, like the global limiter.
pub async fn endpoint_rate_limit_middleware(
    State((state, endpoint)): State<(AppState, EndpointLimit)>,
    request: Request,
    next: Next,
) -> Response {
    if !state.settings.rate_limit.enabled {
        return next.run(request).await;
    }

    let client_ip = extract_client_ip(&request, state.settings.rate_limit.trust_proxy_headers);
    let key = format!("ep_rl:{}:{client_ip}", endpoint.bucket());
    let limit = endpoint.budget(&state.settings.rate_limit);
    enforce(&state, request, next, &key, limit).await
}

/// Consumes one unit of `key`'s budget and either rejects (429/503) or
/// forwards the request, adding the `RateLimit-*` headers.
async fn enforce(
    state: &AppState,
    request: Request,
    next: Next,
    key: &str,
    limit: u32,
) -> Response {
    let window = Duration::from_secs(state.settings.rate_limit.window_secs);
    let rate_status = match state
        .rate_limiter
        .check_and_increment(key, limit, window)
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
