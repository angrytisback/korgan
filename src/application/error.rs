//! Application-level error taxonomy.
//!
//! Use cases return [`AppError`]. The type is deliberately free of any
//! transport or infrastructure concern: the HTTP adapter decides how each
//! variant maps to a status code and RFC 9457 problem document.

use thiserror::Error;

use crate::domain::{DomainError, FieldViolation};

/// Boxed error source used to preserve the cause chain of internal failures
/// for logging without ever exposing it to clients.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by application use cases.
#[derive(Debug, Error)]
pub enum AppError {
    /// Input failed validation.
    #[error("validation failed")]
    Validation(Vec<FieldViolation>),

    /// Credentials are wrong or the account does not exist. Deliberately
    /// indistinguishable to prevent user enumeration.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// The caller is not authenticated.
    #[error("authentication required")]
    Unauthenticated,

    /// A token is malformed, tampered with or otherwise unusable.
    #[error("token is invalid")]
    TokenInvalid,

    /// A token has expired.
    #[error("token has expired")]
    TokenExpired,

    /// A rotated refresh token was presented again; its family was revoked.
    #[error("refresh token reuse detected")]
    TokenReuseDetected,

    /// The caller is authenticated but not allowed to perform the action.
    #[error("operation not permitted")]
    Forbidden,

    /// The requested resource does not exist (or is not visible to the caller).
    #[error("resource not found")]
    NotFound,

    /// The request conflicts with current state.
    #[error("resource conflict")]
    Conflict,

    /// A concurrent token refresh was detected within the grace window; the client should retry.
    #[error("concurrent token refresh in progress")]
    ConcurrentRefresh {
        /// Suggested retry delay in seconds.
        retry_after_secs: u64,
    },

    /// The caller exceeded a rate limit.
    #[error("rate limit exceeded")]
    RateLimited {
        /// Seconds until the caller may retry.
        retry_after_secs: u64,
    },

    /// A required dependency is temporarily unavailable.
    #[error("service temporarily unavailable")]
    ServiceUnavailable,

    /// An unexpected internal failure. The context and source are logged but
    /// never returned to clients.
    #[error("internal error: {context}")]
    Internal {
        /// Static description of what was being attempted.
        context: &'static str,
        /// Underlying cause, if any.
        #[source]
        source: Option<BoxError>,
    },
}

impl AppError {
    /// Creates a concurrent refresh error with recommended retry delay.
    #[must_use]
    pub const fn concurrent_refresh(retry_after_secs: u64) -> Self {
        Self::ConcurrentRefresh { retry_after_secs }
    }

    /// Wraps an unexpected failure, preserving its cause for logging.
    pub fn internal(context: &'static str, source: impl Into<BoxError>) -> Self {
        Self::Internal {
            context,
            source: Some(source.into()),
        }
    }
}

impl From<DomainError> for AppError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::Validation(violations) => Self::Validation(violations),
            DomainError::InvalidIdentifier { .. }
            | DomainError::InvalidEmail { .. }
            | DomainError::PasswordTooShort { .. }
            | DomainError::PasswordTooLong { .. }
            | DomainError::PasswordTooWeak { .. }
            | DomainError::InvalidPasswordHash { .. }
            | DomainError::InvalidUsername { .. }
            | DomainError::InvalidOAuthProvider { .. } => {
                Self::Validation(error.field_violations())
            }
            DomainError::AccountLocked { .. }
            | DomainError::AccountNotActive { .. }
            | DomainError::InsufficientPermissions { .. } => Self::Forbidden,
            DomainError::NoPasswordSet => Self::InvalidCredentials,
            DomainError::SessionExpired => Self::TokenExpired,
            DomainError::SessionRevoked => Self::TokenInvalid,
            DomainError::TokenReuseDetected => Self::TokenReuseDetected,
            DomainError::PasskeyNotFound => Self::NotFound,
            DomainError::ChallengeExpired => Self::TokenExpired,
            DomainError::PasskeyVerificationFailed { .. } => Self::InvalidCredentials,
        }
    }
}

impl From<crate::ports::PortError> for AppError {
    fn from(error: crate::ports::PortError) -> Self {
        use crate::ports::PortError;
        match error {
            PortError::NotFound { .. } => Self::NotFound,
            PortError::Conflict { .. } => Self::Conflict,
            PortError::Database(source) => Self::internal("database operation failed", source),
            PortError::Cache(source) => Self::internal("cache operation failed", source),
            PortError::ExternalService {
                service,
                message,
                source,
            } => {
                let src: BoxError = match source {
                    Some(s) => s,
                    None => Box::new(std::io::Error::other(format!("{service}: {message}"))),
                };
                Self::internal("external service call failed", src)
            }
            PortError::Cryptography(source) => {
                Self::internal("cryptographic operation failed", source)
            }
            PortError::Serialization(source) => Self::internal("serialization failed", source),
            PortError::RateLimit(source) => Self::internal("rate limiter error", source),
            PortError::ServiceUnavailable { .. } => Self::ServiceUnavailable,
            PortError::Unexpected(source) => Self::internal("unexpected port error", source),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let mut violations = Vec::new();
        for (field, field_errs) in errors.field_errors() {
            for err in field_errs {
                let reason = match &err.message {
                    Some(msg) => msg.to_string(),
                    None => format!("invalid value (rule: {})", err.code),
                };
                violations.push(FieldViolation::new(field.to_string(), reason));
            }
        }
        Self::Validation(violations)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn domain_validation_maps_to_app_validation() {
        let err: AppError =
            DomainError::Validation(vec![FieldViolation::new("email", "invalid")]).into();
        assert!(matches!(err, AppError::Validation(v) if v.len() == 1));
    }

    #[test]
    fn invalid_identifier_maps_to_field_violation() {
        let err: AppError = DomainError::InvalidIdentifier { kind: "user_id" }.into();
        assert!(
            matches!(err, AppError::Validation(v) if v.first().map(|f| f.field.as_str()) == Some("user_id"))
        );
    }

    #[test]
    fn internal_error_display_does_not_include_source() {
        let err = AppError::internal("loading user", std::io::Error::other("secret detail"));
        assert_eq!(err.to_string(), "internal error: loading user");
    }

    #[test]
    fn validator_errors_map_to_app_validation() -> Result<(), Box<dyn std::error::Error>> {
        use validator::Validate;

        #[derive(Validate)]
        struct Dummy {
            #[validate(email)]
            email: String,
        }

        let d = Dummy {
            email: "not-an-email".to_owned(),
        };
        let val_err = match d.validate() {
            Ok(_) => return Err("expected validation error".into()),
            Err(e) => e,
        };
        let app_err: AppError = val_err.into();
        match app_err {
            AppError::Validation(violations) => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].field, "email");
            }
            _ => return Err("expected Validation error".into()),
        }
        Ok(())
    }
}
