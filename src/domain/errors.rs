//! Pure domain errors. No I/O, no framework types.

use chrono::{DateTime, Utc};
use thiserror::Error;

/// A single field-level validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldViolation {
    /// Name of the offending field as seen by API clients (e.g. `email`).
    pub field: String,
    /// Human-readable, non-sensitive explanation of the violation.
    pub reason: String,
}

impl FieldViolation {
    /// Creates a violation for `field` with the given `reason`.
    pub fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// Errors raised by domain invariants and value objects.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    /// One or more input values violated domain validation rules.
    #[error("validation failed for {} field(s)", .0.len())]
    Validation(Vec<FieldViolation>),

    /// A supplied identifier is not a valid, non-nil UUID.
    #[error("`{kind}` must be a valid, non-nil UUID")]
    InvalidIdentifier {
        /// The kind of identifier that was rejected (e.g. `user_id`).
        kind: &'static str,
    },

    /// An e-mail address does not comply with RFC rules or is invalid.
    #[error("invalid e-mail address: {reason}")]
    InvalidEmail {
        /// Explanation of the invalidity.
        reason: String,
    },

    /// Password is too short (NIST SP 800-63B requires at least 8 characters).
    #[error("password must be at least {min} characters long (was {actual})")]
    PasswordTooShort {
        /// Minimum permitted characters.
        min: usize,
        /// Actual characters provided.
        actual: usize,
    },

    /// Password is too long (NIST SP 800-63B permits up to 128 characters).
    #[error("password must be at most {max} characters long (was {actual})")]
    PasswordTooLong {
        /// Maximum permitted characters.
        max: usize,
        /// Actual characters provided.
        actual: usize,
    },

    /// Password failed strength or entropy validation.
    #[error("password does not meet security requirements: {reason}")]
    PasswordTooWeak {
        /// Explanation of the weakness.
        reason: String,
    },

    /// A password hash string is not a valid PHC-formatted Argon2id hash.
    #[error("invalid password hash format: {reason}")]
    InvalidPasswordHash {
        /// Explanation of format invalidity.
        reason: String,
    },

    /// Username contains illegal characters or violates length constraints.
    #[error("invalid username: {reason}")]
    InvalidUsername {
        /// Explanation of format invalidity.
        reason: String,
    },

    /// The user account is temporarily locked due to excessive failed logins.
    #[error("account is locked until {until}")]
    AccountLocked {
        /// When the lock expires (UTC).
        until: DateTime<Utc>,
    },

    /// The user account is not active (e.g., suspended, unverified, deactivated).
    #[error("account is not active (status: {status})")]
    AccountNotActive {
        /// Current account status.
        status: String,
    },

    /// The session has expired.
    #[error("session has expired")]
    SessionExpired,

    /// The session has been explicitly revoked.
    #[error("session has been revoked")]
    SessionRevoked,

    /// A rotated refresh token was used again; the session family is compromised.
    #[error("refresh token reuse detected")]
    TokenReuseDetected,

    /// Insufficient role or permissions to perform the requested action.
    #[error("insufficient permissions: {reason}")]
    InsufficientPermissions {
        /// Explanation of missing permission.
        reason: String,
    },

    /// Account does not have a password set (social login only).
    #[error("account has no password set; please log in via social login")]
    NoPasswordSet,

    /// An unsupported or unrecognized OAuth provider was requested.
    #[error("unsupported OAuth identity provider: {provider}")]
    InvalidOAuthProvider {
        /// The invalid provider string.
        provider: String,
    },

    /// WebAuthn passkey credential was not found or has been deleted.
    #[error("passkey credential not found")]
    PasskeyNotFound,

    /// WebAuthn registration or authentication challenge has expired or was already consumed.
    #[error("webauthn challenge has expired or was already used")]
    ChallengeExpired,

    /// WebAuthn credential assertion or attestation failed cryptographic verification.
    #[error("passkey verification failed: {reason}")]
    PasskeyVerificationFailed {
        /// Reason for failure.
        reason: String,
    },
}

impl DomainError {
    /// Extracts field violations associated with this domain error, if applicable.
    pub fn field_violations(&self) -> Vec<FieldViolation> {
        match self {
            Self::Validation(violations) => violations.clone(),
            Self::InvalidIdentifier { kind } => {
                vec![FieldViolation::new(*kind, "must be a valid, non-nil UUID")]
            }
            Self::InvalidEmail { reason } => {
                vec![FieldViolation::new("email", reason.clone())]
            }
            Self::PasswordTooShort { min, actual } => {
                vec![FieldViolation::new(
                    "password",
                    format!("password must be at least {min} characters long (was {actual})"),
                )]
            }
            Self::PasswordTooLong { max, actual } => {
                vec![FieldViolation::new(
                    "password",
                    format!("password must be at most {max} characters long (was {actual})"),
                )]
            }
            Self::PasswordTooWeak { reason } => {
                vec![FieldViolation::new("password", reason.clone())]
            }
            Self::InvalidPasswordHash { reason } => {
                vec![FieldViolation::new("password_hash", reason.clone())]
            }
            Self::InvalidUsername { reason } => {
                vec![FieldViolation::new("username", reason.clone())]
            }
            Self::AccountLocked { until } => {
                vec![FieldViolation::new(
                    "account",
                    format!("account is locked until {until}"),
                )]
            }
            Self::AccountNotActive { status } => {
                vec![FieldViolation::new(
                    "account",
                    format!("account is not active (status: {status})"),
                )]
            }
            Self::SessionExpired => {
                vec![FieldViolation::new("session", "session has expired")]
            }
            Self::SessionRevoked => {
                vec![FieldViolation::new("session", "session has been revoked")]
            }
            Self::TokenReuseDetected => {
                vec![FieldViolation::new(
                    "refresh_token",
                    "refresh token reuse detected",
                )]
            }
            Self::InsufficientPermissions { reason } => {
                vec![FieldViolation::new("role", reason.clone())]
            }
            Self::NoPasswordSet => {
                vec![FieldViolation::new(
                    "password",
                    "account has no password set; please log in via social login",
                )]
            }
            Self::InvalidOAuthProvider { provider } => {
                vec![FieldViolation::new(
                    "provider",
                    format!("unsupported OAuth provider `{provider}`"),
                )]
            }
            Self::PasskeyNotFound => {
                vec![FieldViolation::new(
                    "passkey",
                    "passkey credential not found",
                )]
            }
            Self::ChallengeExpired => {
                vec![FieldViolation::new(
                    "challenge",
                    "webauthn challenge has expired or was already used",
                )]
            }
            Self::PasskeyVerificationFailed { reason } => {
                vec![FieldViolation::new("passkey", reason.clone())]
            }
        }
    }
}
