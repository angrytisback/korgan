//! IETF RFC 9457 (Problem Details for HTTP APIs) error contract.
//!
//! Every non-2xx response produced by the service is rendered by this module
//! as `application/problem+json`:
//!
//! ```json
//! {
//!   "type": "https://errors.korgan.dev/auth/token-reuse-detected",
//!   "title": "Refresh Token Reuse Detected",
//!   "status": 401,
//!   "detail": "...",
//!   "instance": "urn:uuid:0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f",
//!   "code": "AUTH_TOKEN_REUSE_DETECTED",
//!   "timestamp": "2026-10-20T11:20:00Z",
//!   "errors": [{ "field": "refresh_token", "reason": "..." }]
//! }
//! ```
//!
//! Internal failure details (database, cache, library errors) are written to
//! the log with the request id and are **never** part of the response body.

use std::borrow::Cow;

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, SecondsFormat, Utc};
use http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize, Serializer};
use utoipa::ToSchema;

use super::middleware::request_id::{X_REQUEST_ID, current_request_id};
use crate::application::AppError;
use crate::domain::DomainError;
use crate::domain::value_objects::RequestId;

/// Media type mandated by RFC 9457 Section 3.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// Body used in the (practically unreachable) event that serialization fails.
const FALLBACK_BODY: &[u8] =
    br#"{"type":"about:blank","title":"Internal Server Error","status":500}"#;

/// Detail text for every 5xx response; never contains internal information.
const INTERNAL_DETAIL: &str = "An unexpected error occurred. Please retry later and quote the request identifier in the `instance` field when contacting support.";

/// Machine-readable classification of an API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Malformed request syntax (400).
    BadRequest,
    /// Semantically invalid input (422).
    ValidationFailed,
    /// Wrong credentials / unknown account (401).
    InvalidCredentials,
    /// Missing or unusable authentication (401).
    Unauthenticated,
    /// Malformed or tampered token (401).
    TokenInvalid,
    /// Expired token (401).
    TokenExpired,
    /// Rotated refresh token replayed (401).
    TokenReuseDetected,
    /// Authenticated but not permitted (403).
    Forbidden,
    /// Unknown resource or route (404).
    NotFound,
    /// HTTP method not supported (405).
    MethodNotAllowed,
    /// Request took too long (408).
    RequestTimeout,
    /// State conflict (409).
    Conflict,
    /// Body exceeds the configured limit (413).
    PayloadTooLarge,
    /// Unsupported `Content-Type` (415).
    UnsupportedMediaType,
    /// Rate limit exceeded (429).
    RateLimited,
    /// Unexpected server failure (500).
    Internal,
    /// Dependency temporarily unavailable (503).
    ServiceUnavailable,
}

/// Static description of an [`ErrorKind`].
struct ErrorSpec {
    status: StatusCode,
    code: &'static str,
    type_uri: &'static str,
    title: &'static str,
    detail: &'static str,
}

impl ErrorSpec {
    #[inline]
    const fn new(
        status: StatusCode,
        code: &'static str,
        type_uri: &'static str,
        title: &'static str,
        detail: &'static str,
    ) -> Self {
        Self {
            status,
            code,
            type_uri,
            title,
            detail,
        }
    }
}

impl ErrorKind {
    #[inline]
    const fn spec(self) -> ErrorSpec {
        match self {
            Self::BadRequest
            | Self::ValidationFailed
            | Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::TokenInvalid
            | Self::TokenExpired
            | Self::TokenReuseDetected
            | Self::Forbidden => self.auth_and_validation_spec(),
            _ => self.resource_and_server_spec(),
        }
    }

    #[inline]
    const fn auth_and_validation_spec(self) -> ErrorSpec {
        match self {
            Self::BadRequest => ErrorSpec::new(
                StatusCode::BAD_REQUEST,
                "REQUEST_MALFORMED",
                concat!("https://errors.korgan.dev/", "request/malformed"),
                "Malformed Request",
                "The request could not be parsed. Check the syntax and try again.",
            ),
            Self::ValidationFailed => ErrorSpec::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
                concat!("https://errors.korgan.dev/", "validation/failed"),
                "Validation Failed",
                "One or more fields are invalid. See `errors` for details.",
            ),
            Self::InvalidCredentials => ErrorSpec::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_INVALID_CREDENTIALS",
                concat!("https://errors.korgan.dev/", "auth/invalid-credentials"),
                "Invalid Credentials",
                "Invalid credentials.",
            ),
            Self::Unauthenticated => ErrorSpec::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_UNAUTHENTICATED",
                concat!("https://errors.korgan.dev/", "auth/unauthenticated"),
                "Authentication Required",
                "Valid authentication is required to access this resource.",
            ),
            Self::TokenInvalid => ErrorSpec::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_TOKEN_INVALID",
                concat!("https://errors.korgan.dev/", "auth/token-invalid"),
                "Invalid Token",
                "The provided token is invalid.",
            ),
            Self::TokenExpired => ErrorSpec::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_TOKEN_EXPIRED",
                concat!("https://errors.korgan.dev/", "auth/token-expired"),
                "Token Expired",
                "The provided token has expired.",
            ),
            Self::TokenReuseDetected => ErrorSpec::new(
                StatusCode::UNAUTHORIZED,
                "AUTH_TOKEN_REUSE_DETECTED",
                concat!("https://errors.korgan.dev/", "auth/token-reuse-detected"),
                "Refresh Token Reuse Detected",
                "The provided refresh token has already been rotated. For your security, the entire session family has been revoked.",
            ),
            Self::Forbidden => ErrorSpec::new(
                StatusCode::FORBIDDEN,
                "AUTH_FORBIDDEN",
                concat!("https://errors.korgan.dev/", "auth/forbidden"),
                "Forbidden",
                "You do not have permission to perform this action.",
            ),
            _ => unreachable!(),
        }
    }

    #[inline]
    const fn resource_and_server_spec(self) -> ErrorSpec {
        match self {
            Self::NotFound => ErrorSpec::new(
                StatusCode::NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                concat!("https://errors.korgan.dev/", "resource/not-found"),
                "Resource Not Found",
                "The requested resource does not exist.",
            ),
            Self::MethodNotAllowed => ErrorSpec::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                concat!("https://errors.korgan.dev/", "request/method-not-allowed"),
                "Method Not Allowed",
                "The HTTP method is not supported for this resource.",
            ),
            Self::RequestTimeout => ErrorSpec::new(
                StatusCode::REQUEST_TIMEOUT,
                "REQUEST_TIMEOUT",
                concat!("https://errors.korgan.dev/", "request/timeout"),
                "Request Timeout",
                "The request took too long to process.",
            ),
            Self::Conflict => ErrorSpec::new(
                StatusCode::CONFLICT,
                "RESOURCE_CONFLICT",
                concat!("https://errors.korgan.dev/", "resource/conflict"),
                "Conflict",
                "The request conflicts with the current state of the resource.",
            ),
            Self::PayloadTooLarge => ErrorSpec::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                concat!("https://errors.korgan.dev/", "request/payload-too-large"),
                "Payload Too Large",
                "The request body exceeds the maximum allowed size.",
            ),
            Self::UnsupportedMediaType => ErrorSpec::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                concat!(
                    "https://errors.korgan.dev/",
                    "request/unsupported-media-type"
                ),
                "Unsupported Media Type",
                "The request `Content-Type` is not supported.",
            ),
            Self::RateLimited => ErrorSpec::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                concat!("https://errors.korgan.dev/", "rate-limit/exceeded"),
                "Too Many Requests",
                "Rate limit exceeded. Retry after the number of seconds given in the `Retry-After` header.",
            ),
            Self::Internal => ErrorSpec::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                concat!("https://errors.korgan.dev/", "server/internal-error"),
                "Internal Server Error",
                INTERNAL_DETAIL,
            ),
            Self::ServiceUnavailable => ErrorSpec::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                concat!("https://errors.korgan.dev/", "server/service-unavailable"),
                "Service Unavailable",
                "The service is temporarily unavailable. Please retry later.",
            ),
            _ => unreachable!(),
        }
    }

    /// Chooses the best-matching kind for an arbitrary HTTP status code.
    #[inline]
    #[must_use]
    pub const fn from_status(status: StatusCode) -> Self {
        match status.as_u16() {
            401 => Self::Unauthenticated,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            408 => Self::RequestTimeout,
            409 => Self::Conflict,
            413 => Self::PayloadTooLarge,
            415 => Self::UnsupportedMediaType,
            422 => Self::ValidationFailed,
            429 => Self::RateLimited,
            503 => Self::ServiceUnavailable,
            400..=499 => Self::BadRequest,
            _ => Self::Internal,
        }
    }
}

/// One field-level problem inside a [`ProblemDetails`] document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FieldError {
    /// Name of the offending request field.
    #[schema(example = "email")]
    pub field: String,
    /// Human-readable, non-sensitive explanation.
    #[schema(example = "must be a valid e-mail address")]
    pub reason: String,
}

/// RFC 9457 problem document, served as `application/problem+json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    /// URI reference identifying the problem type.
    #[serde(rename = "type")]
    #[schema(example = "https://errors.korgan.dev/auth/token-reuse-detected")]
    pub type_uri: Cow<'static, str>,
    /// Short, human-readable summary of the problem type.
    #[schema(example = "Refresh Token Reuse Detected")]
    pub title: Cow<'static, str>,
    /// HTTP status code.
    #[schema(example = 401)]
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    #[schema(
        example = "The provided refresh token has already been rotated. For your security, the entire session family has been revoked."
    )]
    pub detail: Cow<'static, str>,
    /// `urn:uuid:<request_id>` identifying this occurrence.
    #[schema(example = "urn:uuid:0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub instance: String,
    /// Stable machine-readable error code.
    #[schema(example = "AUTH_TOKEN_REUSE_DETECTED")]
    pub code: Cow<'static, str>,
    /// When the error was produced (RFC 3339, UTC).
    #[serde(serialize_with = "serialize_rfc3339_secs")]
    #[schema(value_type = String, format = DateTime, example = "2026-10-20T11:20:00Z")]
    pub timestamp: DateTime<Utc>,
    /// Field-level problems (validation failures).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
}

fn serialize_rfc3339_secs<S: Serializer>(
    timestamp: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// Error type returned by HTTP handlers; renders as RFC 9457.
#[derive(Debug)]
pub struct ApiError {
    kind: ErrorKind,
    status: StatusCode,
    detail: Option<Cow<'static, str>>,
    errors: Vec<FieldError>,
    retry_after_secs: Option<u64>,
    /// Internal cause, logged but never serialized.
    cause: Option<String>,
}

/// Convenience alias for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    /// Creates an error of the given kind with its default status and detail.
    #[inline]
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            status: kind.spec().status,
            detail: None,
            errors: Vec::new(),
            retry_after_secs: None,
            cause: None,
        }
    }

    /// Creates an error from a status code, preserving the exact status.
    #[inline]
    #[must_use]
    pub const fn from_status(status: StatusCode) -> Self {
        let mut error = Self::new(ErrorKind::from_status(status));
        error.status = status;
        error
    }

    /// Overrides the human-readable detail (never put internal data here).
    #[inline]
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attaches field-level errors.
    #[inline]
    #[must_use]
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
    }

    /// Sets the `Retry-After` header value in seconds.
    #[inline]
    #[must_use]
    pub const fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }

    /// The classification of this error.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The HTTP status that will be sent.
    #[inline]
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Builds the problem document for the given request identifier.
    #[must_use]
    pub fn to_problem(&self, request_id: RequestId) -> ProblemDetails {
        let spec = self.kind.spec();
        ProblemDetails {
            type_uri: Cow::Borrowed(spec.type_uri),
            title: Cow::Borrowed(spec.title),
            status: self.status.as_u16(),
            detail: self.detail.clone().unwrap_or(Cow::Borrowed(spec.detail)),
            instance: request_id.as_instance_urn(),
            code: Cow::Borrowed(spec.code),
            timestamp: Utc::now(),
            errors: self.errors.clone(),
        }
    }
}

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::Validation(violations) => Self::new(ErrorKind::ValidationFailed).with_errors(
                violations
                    .into_iter()
                    .map(|v| FieldError {
                        field: v.field,
                        reason: v.reason,
                    })
                    .collect(),
            ),
            AppError::InvalidCredentials => Self::new(ErrorKind::InvalidCredentials),
            AppError::Unauthenticated => Self::new(ErrorKind::Unauthenticated),
            AppError::TokenInvalid => Self::new(ErrorKind::TokenInvalid),
            AppError::TokenExpired => Self::new(ErrorKind::TokenExpired),
            AppError::TokenReuseDetected => Self::new(ErrorKind::TokenReuseDetected),
            AppError::Forbidden => Self::new(ErrorKind::Forbidden),
            AppError::NotFound => Self::new(ErrorKind::NotFound),
            AppError::Conflict => Self::new(ErrorKind::Conflict),
            AppError::ConcurrentRefresh { retry_after_secs } => Self::new(ErrorKind::Conflict)
                .with_detail("A concurrent token refresh is in progress. Please retry.")
                .with_retry_after(retry_after_secs),
            AppError::RateLimited { retry_after_secs } => {
                Self::new(ErrorKind::RateLimited).with_retry_after(retry_after_secs)
            }
            AppError::ServiceUnavailable => Self::new(ErrorKind::ServiceUnavailable),
            AppError::Internal { context, source } => {
                let mut api = Self::new(ErrorKind::Internal);
                api.cause = Some(describe_cause(
                    context,
                    source
                        .as_ref()
                        .map(|boxed| boxed.as_ref() as &(dyn std::error::Error + 'static)),
                ));
                api
            }
        }
    }
}

impl From<DomainError> for ApiError {
    #[inline]
    fn from(error: DomainError) -> Self {
        AppError::from(error).into()
    }
}

/// Renders `context` followed by the full `source` chain for logging.
fn describe_cause(context: &str, source: Option<&(dyn std::error::Error + 'static)>) -> String {
    let mut description = context.to_owned();
    let mut next = source;
    while let Some(error) = next {
        description.push_str(": ");
        description.push_str(&error.to_string());
        next = error.source();
    }
    description
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = current_request_id().unwrap_or_default();
        let problem = self.to_problem(request_id);

        if self.status.is_server_error() {
            tracing::error!(
                request_id = %request_id,
                code = %problem.code,
                status = problem.status,
                cause = self.cause.as_deref().unwrap_or("n/a"),
                "request failed with server error"
            );
        } else {
            tracing::debug!(
                request_id = %request_id,
                code = %problem.code,
                status = problem.status,
                "request rejected"
            );
        }

        let body = serde_json::to_vec(&problem).unwrap_or_else(|_| FALLBACK_BODY.to_vec());

        let mut response = Response::new(Body::from(body));
        *response.status_mut() = self.status;

        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        let mut req_buf = [0u8; 36];
        let req_id_str = request_id.encode_hyphenated(&mut req_buf);
        if let Ok(value) = HeaderValue::from_bytes(req_id_str.as_bytes()) {
            headers.insert(X_REQUEST_ID.clone(), value);
        }
        if let Some(seconds) = self.retry_after_secs {
            headers.insert(RETRY_AFTER, HeaderValue::from(seconds));
        }

        response
    }
}

/// Whether `headers` already declares a problem+json body.
#[inline]
fn is_problem_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(PROBLEM_JSON))
}

/// Middleware guaranteeing that *every* error response is RFC 9457.
///
/// Errors raised by framework layers (unmatched methods, body-limit and
/// timeout layers, extractor rejections) are not produced by [`ApiError`] and
/// would otherwise leak plain-text or empty bodies. Any 4xx/5xx response that
/// is not already `application/problem+json` is replaced; headers that carry
/// protocol meaning (`Allow`, `Retry-After`, `WWW-Authenticate`) are preserved.
pub async fn problem_details_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();

    if !(status.is_client_error() || status.is_server_error())
        || is_problem_json(response.headers())
    {
        return response;
    }

    let (parts, _discarded_body) = response.into_parts();
    let mut replacement = ApiError::from_status(parts.status).into_response();
    for name in [ALLOW, RETRY_AFTER, WWW_AUTHENTICATE] {
        if let Some(value) = parts.headers.get(&name) {
            replacement.headers_mut().insert(name, value.clone());
        }
    }
    replacement
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;
    use crate::adapters::inbound::http::middleware::request_id::scope_request_id;
    use crate::domain::FieldViolation;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    async fn render(
        error: ApiError,
        request_id: RequestId,
    ) -> Result<(Response, ProblemDetails), Box<dyn std::error::Error>> {
        let response = scope_request_id(request_id, async { error.into_response() }).await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 64 * 1024).await?;
        let problem: ProblemDetails = serde_json::from_slice(&bytes)?;
        Ok((Response::from_parts(parts, Body::empty()), problem))
    }

    #[tokio::test]
    async fn token_reuse_matches_the_documented_contract() -> TestResult {
        let request_id = RequestId::new();
        let (response, problem) = render(AppError::TokenReuseDetected.into(), request_id).await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .map(HeaderValue::as_bytes),
            Some(PROBLEM_JSON.as_bytes())
        );
        assert_eq!(
            problem.type_uri,
            "https://errors.korgan.dev/auth/token-reuse-detected"
        );
        assert_eq!(problem.code, "AUTH_TOKEN_REUSE_DETECTED");
        assert_eq!(problem.title, "Refresh Token Reuse Detected");
        assert_eq!(problem.status, 401);
        assert_eq!(problem.instance, format!("urn:uuid:{request_id}"));
        assert_eq!(problem.errors, []);
        Ok(())
    }

    #[tokio::test]
    async fn validation_errors_carry_field_details() -> TestResult {
        let error: ApiError = AppError::Validation(vec![FieldViolation::new(
            "email",
            "must be a valid e-mail address",
        )])
        .into();
        let (response, problem) = render(error, RequestId::new()).await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(problem.code, "VALIDATION_FAILED");
        assert_eq!(
            problem.errors,
            vec![FieldError {
                field: "email".to_owned(),
                reason: "must be a valid e-mail address".to_owned()
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn internal_errors_never_leak_their_cause() -> TestResult {
        let source = std::io::Error::other("connection to db-prod-1.internal:5432 refused");
        let error: ApiError = AppError::internal("loading user from users table", source).into();
        let (response, problem) = render(error, RequestId::new()).await?;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let rendered = serde_json::to_string(&problem)?;
        assert!(!rendered.contains("db-prod-1"));
        assert!(!rendered.contains("users table"));
        assert_eq!(problem.code, "INTERNAL_ERROR");
        Ok(())
    }

    #[tokio::test]
    async fn rate_limited_sets_retry_after() -> TestResult {
        let error: ApiError = AppError::RateLimited {
            retry_after_secs: 42,
        }
        .into();
        let (response, problem) = render(error, RequestId::new()).await?;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .map(HeaderValue::as_bytes),
            Some(b"42".as_slice())
        );
        assert_eq!(problem.code, "RATE_LIMIT_EXCEEDED");
        Ok(())
    }

    #[tokio::test]
    async fn response_echoes_request_id_header() -> TestResult {
        let request_id = RequestId::new();
        let (response, _) = render(ApiError::new(ErrorKind::NotFound), request_id).await?;
        assert_eq!(
            response
                .headers()
                .get(&X_REQUEST_ID)
                .map(HeaderValue::as_bytes),
            Some(request_id.to_string().as_bytes())
        );
        Ok(())
    }

    #[test]
    fn timestamp_is_serialized_with_second_precision() -> TestResult {
        let problem = ApiError::new(ErrorKind::Conflict).to_problem(RequestId::new());
        let value = serde_json::to_value(&problem)?;
        let timestamp = value
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .ok_or("timestamp missing")?;
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp.contains('.'));
        Ok(())
    }

    #[test]
    fn status_mapping_covers_documented_codes() {
        for (status, kind) in [
            (StatusCode::UNAUTHORIZED, ErrorKind::Unauthenticated),
            (StatusCode::FORBIDDEN, ErrorKind::Forbidden),
            (StatusCode::CONFLICT, ErrorKind::Conflict),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorKind::ValidationFailed,
            ),
            (StatusCode::TOO_MANY_REQUESTS, ErrorKind::RateLimited),
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorKind::Internal),
            (StatusCode::BAD_GATEWAY, ErrorKind::Internal),
            (StatusCode::URI_TOO_LONG, ErrorKind::BadRequest),
        ] {
            assert_eq!(ErrorKind::from_status(status), kind);
        }
    }

    #[test]
    fn from_status_preserves_the_original_status() {
        assert_eq!(
            ApiError::from_status(StatusCode::URI_TOO_LONG).status(),
            StatusCode::URI_TOO_LONG
        );
    }

    #[test]
    fn to_problem_borrows_static_strings_without_heap_allocation() {
        let problem = ApiError::new(ErrorKind::Forbidden).to_problem(RequestId::new());
        assert!(matches!(problem.type_uri, Cow::Borrowed(_)));
        assert!(matches!(problem.title, Cow::Borrowed(_)));
        assert!(matches!(problem.detail, Cow::Borrowed(_)));
        assert!(matches!(problem.code, Cow::Borrowed(_)));

        let static_override = ApiError::new(ErrorKind::Forbidden)
            .with_detail("static override")
            .to_problem(RequestId::new());
        assert!(matches!(static_override.detail, Cow::Borrowed(_)));

        let dynamic_override = ApiError::new(ErrorKind::Forbidden)
            .with_detail(format!("dynamic {}", 123))
            .to_problem(RequestId::new());
        assert!(matches!(dynamic_override.detail, Cow::Owned(_)));
    }
}
