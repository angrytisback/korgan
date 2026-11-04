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

/// Base of the stable, dereferenceable error type URIs.
const TYPE_BASE_URI: &str = "https://errors.korgan.dev";

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
    type_slug: &'static str,
    title: &'static str,
    detail: &'static str,
}

impl ErrorKind {
    const fn spec(self) -> ErrorSpec {
        match self {
            Self::BadRequest => ErrorSpec {
                status: StatusCode::BAD_REQUEST,
                code: "REQUEST_MALFORMED",
                type_slug: "request/malformed",
                title: "Malformed Request",
                detail: "The request could not be parsed. Check the syntax and try again.",
            },
            Self::ValidationFailed => ErrorSpec {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: "VALIDATION_FAILED",
                type_slug: "validation/failed",
                title: "Validation Failed",
                detail: "One or more fields are invalid. See `errors` for details.",
            },
            Self::InvalidCredentials => ErrorSpec {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_INVALID_CREDENTIALS",
                type_slug: "auth/invalid-credentials",
                title: "Invalid Credentials",
                detail: "Invalid credentials.",
            },
            Self::Unauthenticated => ErrorSpec {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_UNAUTHENTICATED",
                type_slug: "auth/unauthenticated",
                title: "Authentication Required",
                detail: "Valid authentication is required to access this resource.",
            },
            Self::TokenInvalid => ErrorSpec {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_TOKEN_INVALID",
                type_slug: "auth/token-invalid",
                title: "Invalid Token",
                detail: "The provided token is invalid.",
            },
            Self::TokenExpired => ErrorSpec {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_TOKEN_EXPIRED",
                type_slug: "auth/token-expired",
                title: "Token Expired",
                detail: "The provided token has expired.",
            },
            Self::TokenReuseDetected => ErrorSpec {
                status: StatusCode::UNAUTHORIZED,
                code: "AUTH_TOKEN_REUSE_DETECTED",
                type_slug: "auth/token-reuse-detected",
                title: "Refresh Token Reuse Detected",
                detail: "The provided refresh token has already been rotated. For your security, the entire session family has been revoked.",
            },
            Self::Forbidden => ErrorSpec {
                status: StatusCode::FORBIDDEN,
                code: "AUTH_FORBIDDEN",
                type_slug: "auth/forbidden",
                title: "Forbidden",
                detail: "You do not have permission to perform this action.",
            },
            Self::NotFound => ErrorSpec {
                status: StatusCode::NOT_FOUND,
                code: "RESOURCE_NOT_FOUND",
                type_slug: "resource/not-found",
                title: "Resource Not Found",
                detail: "The requested resource does not exist.",
            },
            Self::MethodNotAllowed => ErrorSpec {
                status: StatusCode::METHOD_NOT_ALLOWED,
                code: "METHOD_NOT_ALLOWED",
                type_slug: "request/method-not-allowed",
                title: "Method Not Allowed",
                detail: "The HTTP method is not supported for this resource.",
            },
            Self::RequestTimeout => ErrorSpec {
                status: StatusCode::REQUEST_TIMEOUT,
                code: "REQUEST_TIMEOUT",
                type_slug: "request/timeout",
                title: "Request Timeout",
                detail: "The request took too long to process.",
            },
            Self::Conflict => ErrorSpec {
                status: StatusCode::CONFLICT,
                code: "RESOURCE_CONFLICT",
                type_slug: "resource/conflict",
                title: "Conflict",
                detail: "The request conflicts with the current state of the resource.",
            },
            Self::PayloadTooLarge => ErrorSpec {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: "PAYLOAD_TOO_LARGE",
                type_slug: "request/payload-too-large",
                title: "Payload Too Large",
                detail: "The request body exceeds the maximum allowed size.",
            },
            Self::UnsupportedMediaType => ErrorSpec {
                status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
                code: "UNSUPPORTED_MEDIA_TYPE",
                type_slug: "request/unsupported-media-type",
                title: "Unsupported Media Type",
                detail: "The request `Content-Type` is not supported.",
            },
            Self::RateLimited => ErrorSpec {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "RATE_LIMIT_EXCEEDED",
                type_slug: "rate-limit/exceeded",
                title: "Too Many Requests",
                detail: "Rate limit exceeded. Retry after the number of seconds given in the `Retry-After` header.",
            },
            Self::Internal => ErrorSpec {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "INTERNAL_ERROR",
                type_slug: "server/internal-error",
                title: "Internal Server Error",
                detail: INTERNAL_DETAIL,
            },
            Self::ServiceUnavailable => ErrorSpec {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "SERVICE_UNAVAILABLE",
                type_slug: "server/service-unavailable",
                title: "Service Unavailable",
                detail: "The service is temporarily unavailable. Please retry later.",
            },
        }
    }

    /// Chooses the best-matching kind for an arbitrary HTTP status code.
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
    pub type_uri: String,
    /// Short, human-readable summary of the problem type.
    #[schema(example = "Refresh Token Reuse Detected")]
    pub title: String,
    /// HTTP status code.
    #[schema(example = 401)]
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    #[schema(
        example = "The provided refresh token has already been rotated. For your security, the entire session family has been revoked."
    )]
    pub detail: String,
    /// `urn:uuid:<request_id>` identifying this occurrence.
    #[schema(example = "urn:uuid:0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub instance: String,
    /// Stable machine-readable error code.
    #[schema(example = "AUTH_TOKEN_REUSE_DETECTED")]
    pub code: String,
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
    detail: Option<String>,
    errors: Vec<FieldError>,
    retry_after_secs: Option<u64>,
    /// Internal cause, logged but never serialized.
    cause: Option<String>,
}

/// Convenience alias for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    /// Creates an error of the given kind with its default status and detail.
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
    #[must_use]
    pub const fn from_status(status: StatusCode) -> Self {
        let mut error = Self::new(ErrorKind::from_status(status));
        error.status = status;
        error
    }

    /// Overrides the human-readable detail (never put internal data here).
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attaches field-level errors.
    #[must_use]
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
    }

    /// Sets the `Retry-After` header value in seconds.
    #[must_use]
    pub const fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_secs = Some(seconds);
        self
    }

    /// The classification of this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The HTTP status that will be sent.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Builds the problem document for the given request identifier.
    #[must_use]
    pub fn to_problem(&self, request_id: RequestId) -> ProblemDetails {
        let spec = self.kind.spec();
        ProblemDetails {
            type_uri: format!("{TYPE_BASE_URI}/{}", spec.type_slug),
            title: spec.title.to_owned(),
            status: self.status.as_u16(),
            detail: self
                .detail
                .clone()
                .unwrap_or_else(|| spec.detail.to_owned()),
            instance: request_id.as_instance_urn(),
            code: spec.code.to_owned(),
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
        if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
            headers.insert(X_REQUEST_ID.clone(), value);
        }
        if let Some(seconds) = self.retry_after_secs
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            headers.insert(RETRY_AFTER, value);
        }

        response
    }
}

/// Whether `headers` already declares a problem+json body.
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
        assert!(problem.errors.is_empty());
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
}
