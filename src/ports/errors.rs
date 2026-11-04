//! Errors returned by outbound ports (infrastructure interfaces).

use thiserror::Error;

/// Boxed thread-safe error source.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Strongly-typed error taxonomy returned by repository, cache, and service ports.
#[derive(Debug, Error)]
pub enum PortError {
    /// The requested entity or resource was not found.
    #[error("resource not found: {resource}")]
    NotFound {
        /// Type of resource that could not be located.
        resource: &'static str,
    },

    /// A uniqueness or state conflict occurred.
    #[error("resource conflict: {message}")]
    Conflict {
        /// Explanation of the conflict.
        message: String,
    },

    /// A database or persistence operation failed.
    #[error("database error: {0}")]
    Database(#[source] BoxError),

    /// A cache or ephemeral storage operation failed.
    #[error("cache error: {0}")]
    Cache(#[source] BoxError),

    /// An external network service call failed (e.g. SMTP, Resend, HIBP).
    #[error("external service error ({service}): {message}")]
    ExternalService {
        /// Name of the external service.
        service: &'static str,
        /// Description of the error.
        message: String,
        /// Underlying error source, if available.
        #[source]
        source: Option<BoxError>,
    },

    /// A cryptographic operation failed (signing, hashing, verification, encryption).
    #[error("cryptography error: {0}")]
    Cryptography(#[source] BoxError),

    /// Data encoding, decoding or serialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[source] BoxError),

    /// Rate limiting calculation or storage failed.
    #[error("rate limit error: {0}")]
    RateLimit(#[source] BoxError),

    /// A required external dependency or overloaded component is temporarily unavailable.
    #[error("service unavailable: {message}")]
    ServiceUnavailable {
        /// Explanation of why the service is unavailable.
        message: String,
    },

    /// An unexpected internal port failure occurred.
    #[error("unexpected port error: {0}")]
    Unexpected(#[source] BoxError),
}

impl PortError {
    /// Creates a [`PortError::NotFound`].
    #[must_use]
    pub const fn not_found(resource: &'static str) -> Self {
        Self::NotFound { resource }
    }

    /// Creates a [`PortError::Conflict`].
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    /// Creates a [`PortError::Database`].
    pub fn database(source: impl Into<BoxError>) -> Self {
        Self::Database(source.into())
    }

    /// Creates a [`PortError::Cache`].
    pub fn cache(source: impl Into<BoxError>) -> Self {
        Self::Cache(source.into())
    }

    /// Creates a [`PortError::ExternalService`].
    pub fn external_service(
        service: &'static str,
        message: impl Into<String>,
        source: Option<BoxError>,
    ) -> Self {
        Self::ExternalService {
            service,
            message: message.into(),
            source,
        }
    }

    /// Creates a [`PortError::Cryptography`].
    pub fn cryptography(source: impl Into<BoxError>) -> Self {
        Self::Cryptography(source.into())
    }

    /// Convenient helper for cryptography errors with a message.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Cryptography(message.into().into())
    }

    /// Convenient helper for token security and signature failures.
    pub fn security(message: impl Into<String>) -> Self {
        Self::Cryptography(message.into().into())
    }

    /// Creates a [`PortError::Serialization`].
    pub fn serialization(source: impl Into<BoxError>) -> Self {
        Self::Serialization(source.into())
    }

    /// Creates a [`PortError::RateLimit`].
    pub fn rate_limit(source: impl Into<BoxError>) -> Self {
        Self::RateLimit(source.into())
    }

    /// Creates a [`PortError::ServiceUnavailable`].
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Creates a [`PortError::Unexpected`].
    pub fn unexpected(source: impl Into<BoxError>) -> Self {
        Self::Unexpected(source.into())
    }
}
