//! Authentication HTTP handlers.
//!
//! * `POST /api/v1/auth/register` - user account registration
//! * `POST /api/v1/auth/login` - credential verification and session initiation
//! * `POST /api/v1/auth/mfa/verify` - exchange MFA challenge ticket + TOTP for tokens
//! * `POST /api/v1/auth/refresh` - refresh token rotation
//! * `POST /api/v1/auth/verify-email` - e-mail verification token consumption
//! * `POST /api/v1/auth/logout` - session revocation and cookie clearing

use axum::Json;
use axum::extract::State;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cookie::time::Duration as CookieDuration;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::adapters::inbound::http::error::{ApiError, ErrorKind, FieldError, ProblemDetails};
use crate::adapters::inbound::http::extractors::{AuthUser, ClientMetadata};
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::{
    AuthTokensResult, LoginCommand, LoginOutcome, MfaChallengeResult, RefreshTokenCommand,
    RegisterCommand, RevokeSessionCommand, VerifyEmailCommand, VerifyMfaLoginCommand,
};

/// Registration request payload.
#[derive(Clone, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Canonical account e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,

    /// Candidate password (minimum 8 characters).
    #[schema(example = "P@ssw0rd123!")]
    pub password: String,

    /// Optional alphanumeric username.
    #[schema(example = "johndoe")]
    pub username: Option<String>,
}

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("username", &self.username)
            .finish()
    }
}

/// Registration response payload.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Unique identifier of the registered user (UUIDv7 string).
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub user_id: String,

    /// Canonical e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,

    /// Account lifecycle status.
    #[schema(example = "unverified")]
    pub status: String,

    /// Whether e-mail confirmation is required.
    #[schema(example = true)]
    pub verification_required: bool,
}

/// Login request payload.
#[derive(Clone, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// Account e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,

    /// Plaintext candidate password.
    #[schema(example = "P@ssw0rd123!")]
    pub password: String,

    /// Optional client device description.
    #[schema(example = "Safari on macOS")]
    pub device_name: Option<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("device_name", &self.device_name)
            .finish()
    }
}

/// Token bundle issued upon successful authentication.
#[derive(Clone, Serialize, ToSchema)]
pub struct AuthTokensResponse {
    /// RFC 9068 EdDSA Access Token JWT.
    #[schema(example = "eyJhbGciOiJFZERTQSI...")]
    pub access_token: String,

    /// High-entropy Base64URL opaque refresh token.
    #[schema(example = "c1a2b3c4d5e6f...")]
    pub refresh_token: String,

    /// OAuth2 token type, always "Bearer".
    #[schema(example = "Bearer")]
    pub token_type: &'static str,

    /// Access token validity duration in seconds.
    #[schema(example = 900)]
    pub expires_in: i64,

    /// Session identifier tied to these tokens.
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub session_id: String,
}

impl std::fmt::Debug for AuthTokensResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthTokensResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl From<AuthTokensResult> for AuthTokensResponse {
    fn from(res: AuthTokensResult) -> Self {
        Self {
            access_token: res.access_token,
            refresh_token: res.refresh_token,
            token_type: res.token_type,
            expires_in: res.expires_in,
            session_id: res.session_id.to_string(),
        }
    }
}

/// Secondary factor challenge ticket issued when MFA is enabled.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MfaChallengeResponse {
    /// Ephemeral ticket required to complete MFA verification.
    #[schema(example = "mfa_ticket_abc123...")]
    pub mfa_ticket: String,

    /// Lifetime of ticket in seconds.
    #[schema(example = 300)]
    pub expires_in_secs: u64,
}

impl From<MfaChallengeResult> for MfaChallengeResponse {
    fn from(res: MfaChallengeResult) -> Self {
        Self {
            mfa_ticket: res.mfa_ticket,
            expires_in_secs: res.expires_in_secs,
        }
    }
}

/// Unified login response (either tokens or MFA challenge).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(untagged)]
pub enum LoginResponse {
    /// Successfully authenticated; tokens issued.
    Authenticated(AuthTokensResponse),
    /// Multi-factor authentication challenged.
    MfaRequired(MfaChallengeResponse),
}

/// MFA verification request payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct VerifyMfaRequest {
    /// Ephemeral challenge ticket from initial login.
    #[schema(example = "mfa_ticket_abc123...")]
    pub mfa_ticket: String,

    /// 6-digit TOTP code or 8-character backup code.
    #[schema(example = "123456")]
    pub code: String,

    /// Optional device description.
    #[schema(example = "Safari on macOS")]
    pub device_name: Option<String>,
}

/// Refresh token request payload.
#[derive(Debug, Clone, Deserialize, Default, ToSchema)]
pub struct RefreshTokenRequest {
    /// Refresh token string. Optional if delivered via HTTP-only cookie.
    #[schema(example = "c1a2b3c4d5e6f...")]
    #[serde(alias = "token")]
    pub refresh_token: Option<String>,
}

/// Email verification request payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    /// Opaque verification token from email.
    #[schema(example = "verify_token_123...")]
    pub token: String,
}

/// Generic message response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MessageResponse {
    /// Descriptive status message.
    #[schema(example = "Operation completed successfully.")]
    pub message: String,
}

impl MessageResponse {
    /// Creates a new message response.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Registers a new user account.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "Auth",
    operation_id = "auth_register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account registered successfully", body = RegisterResponse),
        (status = 409, description = "Email or username already exists", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn register(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let cmd = RegisterCommand {
        email: body.email,
        password: body.password,
        username: body.username,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    let res = state.register_use_case.execute(cmd).await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id: res.user_id.to_string(),
            email: res.email,
            status: res.status.to_string(),
            verification_required: res.verification_required,
        }),
    ))
}

/// Authenticates a user with primary credentials.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "Auth",
    operation_id = "auth_login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authentication successful or MFA challenged", body = LoginResponse),
        (status = 401, description = "Invalid credentials or account locked", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    let cmd = LoginCommand {
        email: body.email,
        password: body.password,
        ip_address: metadata.ip,
        user_agent: metadata.user_agent,
        device_name: body.device_name.or(metadata.device_name),
        request_id: metadata.request_id,
    };

    let outcome = state.login_use_case.execute(cmd).await?;

    match outcome {
        LoginOutcome::Authenticated(tokens) => {
            let mut updated_jar = jar;
            if metadata.client_type.is_web() {
                updated_jar = attach_auth_cookies(updated_jar, &tokens, &state);
            }
            Ok((
                updated_jar,
                Json(LoginResponse::Authenticated(tokens.into())),
            ))
        }
        LoginOutcome::MfaRequired(challenge) => {
            Ok((jar, Json(LoginResponse::MfaRequired(challenge.into()))))
        }
    }
}

/// Completes authentication when Multi-Factor Authentication is challenged.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/verify",
    tag = "Auth",
    operation_id = "auth_mfa_verify",
    request_body = VerifyMfaRequest,
    responses(
        (status = 200, description = "MFA verified; tokens issued", body = AuthTokensResponse),
        (status = 401, description = "Invalid code or expired MFA ticket", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn verify_mfa(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    jar: CookieJar,
    Json(body): Json<VerifyMfaRequest>,
) -> Result<(CookieJar, Json<AuthTokensResponse>), ApiError> {
    let cmd = VerifyMfaLoginCommand {
        mfa_ticket: body.mfa_ticket,
        code: body.code,
        ip_address: metadata.ip,
        user_agent: metadata.user_agent,
        device_name: body.device_name.or(metadata.device_name),
        request_id: metadata.request_id,
    };

    let tokens = state.verify_mfa_login_use_case.execute(cmd).await?;

    let mut updated_jar = jar;
    if metadata.client_type.is_web() {
        updated_jar = attach_auth_cookies(updated_jar, &tokens, &state);
    }

    Ok((updated_jar, Json(tokens.into())))
}

/// Rotates an existing refresh token and issues a fresh token pair.
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "Auth",
    operation_id = "auth_refresh",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Tokens rotated successfully", body = AuthTokensResponse),
        (status = 401, description = "Invalid token or replay attack detected", body = ProblemDetails),
        (status = 403, description = "Forbidden channel token submission", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    jar: CookieJar,
    body: Option<Json<RefreshTokenRequest>>,
) -> Result<(CookieJar, Json<AuthTokensResponse>), ApiError> {
    let token_from_body = body
        .and_then(|b| b.0.refresh_token)
        .filter(|t| !t.trim().is_empty());
    let token_from_cookie = jar
        .get("__Host-refresh_token")
        .or_else(|| jar.get("refresh_token"))
        .map(|c| c.value().to_owned())
        .filter(|t| !t.trim().is_empty());

    // 1. Ambiguous Token Injection: Reject if present in both channels
    if token_from_body.is_some() && token_from_cookie.is_some() {
        return Err(
            ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                field: "refresh_token".to_owned(),
                reason: "ambiguous token: token provided in both cookie and JSON body".to_owned(),
            }]),
        );
    }

    // 2. Dual-Mode Strict Channel Separation
    let raw_token = if metadata.client_type.is_web() {
        if token_from_body.is_some() {
            return Err(
                ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                    field: "refresh_token".to_owned(),
                    reason: "web clients must supply refresh token in cookie only".to_owned(),
                }]),
            );
        }
        token_from_cookie.ok_or_else(|| {
            ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                field: "refresh_token".to_owned(),
                reason: "refresh token cookie missing".to_owned(),
            }])
        })?
    } else {
        // Mobile or CLI client
        if token_from_cookie.is_some() {
            return Err(ApiError::new(ErrorKind::Forbidden)
                .with_detail("mobile and CLI clients must not supply tokens via cookies"));
        }
        token_from_body.ok_or_else(|| {
            ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                field: "refresh_token".to_owned(),
                reason: "refresh token required in request body".to_owned(),
            }])
        })?
    };

    let cmd = RefreshTokenCommand {
        refresh_token: raw_token,
        ip_address: metadata.ip,
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    let tokens = state.refresh_session_use_case.execute(cmd).await?;

    let mut updated_jar = jar;
    if metadata.client_type.is_web() {
        updated_jar = attach_auth_cookies(updated_jar, &tokens, &state);
    }

    Ok((updated_jar, Json(tokens.into())))
}

/// Verifies user's e-mail address via token link.
#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email",
    tag = "Auth",
    operation_id = "auth_verify_email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified successfully", body = MessageResponse),
        (status = 401, description = "Invalid or expired verification token", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn verify_email(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let cmd = VerifyEmailCommand {
        token: body.token,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.verify_email_use_case.execute(cmd).await?;

    Ok(Json(MessageResponse::new(
        "Email address verified successfully. You may now log in.",
    )))
}

/// Logs out the user by revoking the current session and clearing cookies.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "Auth",
    operation_id = "auth_logout",
    security(("BearerAuth" = [])),
    request_body = RefreshTokenRequest,
    responses(
        (status = 204, description = "Session revoked and cookies cleared"),
        (status = 401, description = "Unauthenticated or invalid session", body = ProblemDetails),
        (status = 403, description = "Forbidden channel token submission", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
    metadata: ClientMetadata,
    jar: CookieJar,
    body: Option<Json<RefreshTokenRequest>>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    let has_body_token = body
        .and_then(|b| b.0.refresh_token)
        .is_some_and(|t| !t.trim().is_empty());
    let has_cookie_token = jar
        .get("__Host-refresh_token")
        .or_else(|| jar.get("refresh_token"))
        .or_else(|| jar.get("access_token"))
        .is_some_and(|c| !c.value().trim().is_empty());

    // 1. Ambiguous token injection: reject if token supplied in both cookie and JSON body
    if has_body_token && has_cookie_token {
        return Err(
            ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                field: "token".to_owned(),
                reason: "ambiguous token: token provided in both cookie and JSON body".to_owned(),
            }]),
        );
    }

    // 2. Strict channel separation
    if metadata.client_type.is_web() {
        if has_body_token {
            return Err(
                ApiError::new(ErrorKind::ValidationFailed).with_errors(vec![FieldError {
                    field: "token".to_owned(),
                    reason: "web clients must not supply tokens in JSON body".to_owned(),
                }]),
            );
        }
    } else if has_cookie_token {
        return Err(ApiError::new(ErrorKind::Forbidden)
            .with_detail("mobile and CLI clients must not supply tokens via cookies"));
    }

    let cmd = RevokeSessionCommand {
        user_id: auth_user.user_id,
        session_id: auth_user.session_id,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.revoke_session_use_case.execute(cmd).await?;

    let updated_jar = if metadata.client_type.is_web() {
        clear_auth_cookies(jar, &state)
    } else {
        jar
    };

    Ok((updated_jar, StatusCode::NO_CONTENT))
}

/// Helper to attach `HttpOnly; Secure; SameSite=Strict` cookies for web clients.
pub(crate) fn attach_auth_cookies(
    mut jar: CookieJar,
    tokens: &AuthTokensResult,
    state: &AppState,
) -> CookieJar {
    let domain = state.settings.auth.cookie_domain.as_deref();

    // Access token cookie
    let access_cookie = build_cookie(
        "access_token",
        tokens.access_token.clone(),
        state.settings.auth.access_token_ttl_secs,
        domain,
    );
    jar = jar.add(access_cookie);

    // RFC 6265bis __Host- cookie prefix: MUST be Secure, Path=/, and MUST NOT include Domain attribute
    let host_refresh_cookie = Cookie::build(("__Host-refresh_token", tokens.refresh_token.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::seconds(
            state.settings.auth.refresh_token_ttl_secs as i64,
        ))
        .build();
    jar = jar.add(host_refresh_cookie);

    jar
}

/// Helper to clear auth cookies upon logout.
fn clear_auth_cookies(mut jar: CookieJar, state: &AppState) -> CookieJar {
    let domain = state.settings.auth.cookie_domain.as_deref();

    jar = jar.add(removal_cookie("access_token", domain));
    jar = jar.add(
        Cookie::build(("__Host-refresh_token", ""))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
            .max_age(CookieDuration::ZERO)
            .build(),
    );
    jar = jar.add(removal_cookie("refresh_token", domain));

    jar
}

fn build_cookie<'a>(
    name: &'static str,
    value: String,
    max_age_secs: u64,
    domain: Option<&str>,
) -> Cookie<'a> {
    let mut builder = Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::seconds(max_age_secs as i64));

    if let Some(dom) = domain {
        builder = builder.domain(dom.to_owned());
    }

    builder.build()
}

fn removal_cookie<'a>(name: &'static str, domain: Option<&str>) -> Cookie<'a> {
    let mut builder = Cookie::build((name, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::ZERO);

    if let Some(dom) = domain {
        builder = builder.domain(dom.to_owned());
    }

    builder.build()
}

/// WebSocket ticket issuance response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WsTicketResponse {
    /// 32-byte Base64URL ephemeral ticket.
    #[schema(example = "dGhpcy1pcy1hLXNhbXBsZS1iYXNlNjQtdXJsLXNlY3JldA")]
    pub ticket: String,
    /// Lifetime of ticket in seconds.
    #[schema(example = 15)]
    #[serde(default = "default_ws_ticket_ttl")]
    pub expires_in: u64,
}

const fn default_ws_ticket_ttl() -> u64 {
    15
}

/// WebSocket ticket verification request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct VerifyWsTicketRequest {
    /// Opaque ticket to verify and consume.
    #[schema(example = "dGhpcy1pcy1hLXNhbXBsZS1iYXNlNjQtdXJsLXNlY3JldA")]
    pub ticket: String,
}

/// WebSocket ticket verification response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyWsTicketResponse {
    /// Subject user identifier (UUIDv7 string).
    #[schema(example = "0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")]
    pub sub: String,
    /// Associated session identifier (UUIDv7 string).
    #[schema(example = "0192a8f0-7c1b-7000-8000-9a8b7c6d5e4f")]
    pub sid: String,
    /// Assigned authorization role.
    #[schema(example = "user")]
    pub role: String,
}

impl From<crate::ports::cache::WsTicketPayload> for VerifyWsTicketResponse {
    fn from(p: crate::ports::cache::WsTicketPayload) -> Self {
        Self {
            sub: p.sub,
            sid: p.sid,
            role: p.role,
        }
    }
}

/// Issues a short-lived (15s) single-use WebSocket/WebRTC ticket for the authenticated session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/ws-ticket",
    tag = "Authentication",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "WebSocket ephemeral ticket successfully issued", body = WsTicketResponse),
        (status = 401, description = "Unauthenticated or invalid access token", body = ProblemDetails),
        (status = 403, description = "Account not active or forbidden", body = ProblemDetails),
    )
)]
pub async fn issue_ws_ticket(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<WsTicketResponse>, ApiError> {
    let result = state
        .issue_ws_ticket_use_case
        .execute(
            auth_user.user_id,
            auth_user.session_id,
            auth_user.role.as_str().to_string(),
        )
        .await?;

    Ok(Json(WsTicketResponse {
        ticket: result.ticket,
        expires_in: result.expires_in,
    }))
}

/// Verifies and atomically consumes a single-use WebSocket ticket (internal endpoint for realtime gateways).
#[utoipa::path(
    post,
    path = "/api/v1/auth/ws-ticket/verify",
    tag = "Authentication",
    request_body = VerifyWsTicketRequest,
    responses(
        (status = 200, description = "Ticket successfully verified and consumed", body = VerifyWsTicketResponse),
        (status = 401, description = "Ticket is invalid, expired, already consumed, or session revoked", body = ProblemDetails),
    )
)]
pub async fn verify_ws_ticket(
    State(state): State<AppState>,
    Json(req): Json<VerifyWsTicketRequest>,
) -> Result<Json<VerifyWsTicketResponse>, ApiError> {
    let payload = state.verify_ws_ticket_use_case.execute(&req.ticket).await?;
    Ok(Json(payload.into()))
}
