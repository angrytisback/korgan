//! Password management DTO commands.

use std::net::IpAddr;

use validator::Validate;

use crate::domain::value_objects::{RequestId, UserId};

/// Command to request a password reset e-mail.
#[derive(Debug, Clone, Validate)]
pub struct ForgotPasswordCommand {
    /// Account e-mail address.
    #[validate(email(message = "invalid e-mail format"))]
    pub email: String,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

/// Command to complete password reset using a single-use token.
#[derive(Clone, Validate)]
pub struct ResetPasswordCommand {
    /// Opaque reset token from the reset e-mail.
    #[validate(length(min = 1, message = "reset token must not be empty"))]
    pub token: String,

    /// New plaintext password candidate.
    #[validate(length(
        min = 8,
        max = 128,
        message = "password must be between 8 and 128 characters"
    ))]
    pub new_password: String,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for ResetPasswordCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetPasswordCommand")
            .field("token", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Command for an authenticated user to change their own password.
#[derive(Clone, Validate)]
pub struct ChangePasswordCommand {
    /// Authenticated caller identifier.
    pub user_id: UserId,

    /// Current plaintext password to verify authority.
    #[validate(length(min = 1, message = "current password must not be empty"))]
    pub current_password: String,

    /// New plaintext password candidate.
    #[validate(length(
        min = 8,
        max = 128,
        message = "password must be between 8 and 128 characters"
    ))]
    pub new_password: String,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

impl std::fmt::Debug for ChangePasswordCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordCommand")
            .field("user_id", &self.user_id)
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .field("request_id", &self.request_id)
            .finish()
    }
}
