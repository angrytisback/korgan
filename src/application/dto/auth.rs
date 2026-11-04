//! Authentication DTO commands and results.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domain::entities::AccountStatus;
use crate::domain::value_objects::{RequestId, SessionId, UserId};

/// Command to register a new user account.
#[derive(Clone, Validate)]
pub struct RegisterCommand {
    /// Canonical e-mail address.
    #[validate(email(message = "invalid e-mail format"))]
    pub email: String,

    /// Plaintext candidate password.
    #[validate(length(
        min = 8,
        max = 128,
        message = "password must be between 8 and 128 characters"
    ))]
    pub password: String,

    /// Optional alphanumeric username.
    #[validate(length(
        min = 3,
        max = 30,
        message = "username must be between 3 and 30 characters"
    ))]
    pub username: Option<String>,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for RegisterCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterCommand")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("username", &self.username)
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Command to authenticate using primary credentials (email + password).
#[derive(Clone, Validate)]
pub struct LoginCommand {
    /// Account e-mail address.
    #[validate(email(message = "invalid e-mail format"))]
    pub email: String,

    /// Plaintext password.
    #[validate(length(min = 1, max = 128, message = "password must not be empty"))]
    pub password: String,

    /// Client IP address.
    pub ip_address: IpAddr,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Client device name (e.g. "Safari on macOS").
    pub device_name: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for LoginCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCommand")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("device_name", &self.device_name)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Command to rotate an existing refresh token session.
#[derive(Clone, Validate)]
pub struct RefreshTokenCommand {
    /// Raw Base64URL-encoded refresh token.
    #[validate(length(min = 1, message = "refresh token must not be empty"))]
    pub refresh_token: String,

    /// Client IP address.
    pub ip_address: IpAddr,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for RefreshTokenCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenCommand")
            .field("refresh_token", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Command to verify user's e-mail address via single-use token.
#[derive(Clone, Validate)]
pub struct VerifyEmailCommand {
    /// Opaque verification token from verification link.
    #[validate(length(min = 1, message = "verification token must not be empty"))]
    pub token: String,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for VerifyEmailCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyEmailCommand")
            .field("token", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Command to complete authentication when MFA is challenged.
#[derive(Clone, Validate)]
pub struct VerifyMfaLoginCommand {
    /// Opaque challenge ticket returned by initial login.
    #[validate(length(min = 1, message = "MFA ticket must not be empty"))]
    pub mfa_ticket: String,

    /// 6-digit TOTP code or 8-character backup code.
    #[validate(length(
        min = 6,
        max = 8,
        message = "code must be 6-digit TOTP or 8-character backup code"
    ))]
    pub code: String,

    /// Client IP address.
    pub ip_address: IpAddr,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Client device name.
    pub device_name: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for VerifyMfaLoginCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyMfaLoginCommand")
            .field("mfa_ticket", &"[REDACTED]")
            .field("code", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("device_name", &self.device_name)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Result returned upon successful user registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResult {
    /// Unique identifier of the registered user.
    pub user_id: UserId,

    /// Normalized e-mail address.
    pub email: String,

    /// Initial account status.
    pub status: AccountStatus,

    /// Whether e-mail confirmation is required before account becomes active.
    pub verification_required: bool,
}

/// Token bundle issued upon successful authentication or rotation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTokensResult {
    /// RFC 9068 EdDSA Access Token JWT.
    pub access_token: String,

    /// High-entropy Base64URL opaque refresh token.
    pub refresh_token: String,

    /// OAuth2 token type, always "Bearer".
    pub token_type: &'static str,

    /// Access token validity duration in seconds.
    pub expires_in: i64,

    /// Unique session identifier associated with these tokens.
    pub session_id: SessionId,
}

impl std::fmt::Debug for AuthTokensResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthTokensResult")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// Challenge ticket issued when primary credentials are valid but MFA is required.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaChallengeResult {
    /// Ephemeral challenge ticket required to complete login.
    pub mfa_ticket: String,

    /// Validity lifetime of the ticket in seconds.
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for MfaChallengeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaChallengeResult")
            .field("mfa_ticket", &"[REDACTED]")
            .field("expires_in_secs", &self.expires_in_secs)
            .finish()
    }
}

/// Outcome of a login attempt: either full token issuance or MFA challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// Login completed; tokens issued.
    Authenticated(AuthTokensResult),

    /// Primary credentials valid, but secondary factor is required.
    MfaRequired(MfaChallengeResult),
}
