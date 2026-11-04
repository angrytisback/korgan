//! External OAuth2 account linkage domain entity and provider taxonomy.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::errors::DomainError;
use crate::domain::value_objects::{OAuthAccountId, UserId};

/// Supported external OAuth2 / OIDC identity providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    /// Google Identity Services / OpenID Connect.
    Google,
    /// GitHub OAuth Apps.
    GitHub,
}

impl OAuthProvider {
    /// Canonical lowercase string identifier matching database representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }

    /// Parses a string into an [`OAuthProvider`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidOAuthProvider`] if the string does not match a known provider.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s.to_ascii_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "github" => Ok(Self::GitHub),
            other => Err(DomainError::InvalidOAuthProvider {
                provider: other.to_owned(),
            }),
        }
    }
}

impl fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OAuthProvider {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Links an internal [`User`] account to an external Identity Provider account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthAccount {
    /// Unique identifier for this linkage record (RFC 9562 UUIDv7).
    pub id: OAuthAccountId,
    /// Internal user account ID.
    pub user_id: UserId,
    /// External provider identity.
    pub provider: OAuthProvider,
    /// Stable external user identifier issued by the identity provider (e.g. Google sub, GitHub id).
    pub provider_user_id: String,
    /// Link creation timestamp (UTC).
    pub created_at: DateTime<Utc>,
}

impl OAuthAccount {
    /// Creates a new OAuth account linkage for `user_id`.
    #[must_use]
    pub fn new(
        user_id: UserId,
        provider: OAuthProvider,
        provider_user_id: impl Into<String>,
    ) -> Self {
        Self {
            id: OAuthAccountId::new(),
            user_id,
            provider,
            provider_user_id: provider_user_id.into(),
            created_at: Utc::now(),
        }
    }
}
