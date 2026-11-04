//! No-op OAuth provider adapter when an external provider is disabled.

use async_trait::async_trait;

use crate::domain::entities::OAuthProvider;
use crate::ports::errors::PortError;
use crate::ports::services::{OAuthProfile, OAuthProviderPort};

/// No-op provider used when a provider is not enabled in configuration.
#[derive(Debug, Clone)]
pub struct NoopOAuthProvider {
    provider: OAuthProvider,
}

impl NoopOAuthProvider {
    /// Creates a new [`NoopOAuthProvider`].
    #[must_use]
    pub fn new(provider: OAuthProvider) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl OAuthProviderPort for NoopOAuthProvider {
    fn provider(&self) -> OAuthProvider {
        self.provider
    }

    fn build_authorization_url(&self, _state: &str) -> String {
        format!("https://disabled.example.com/oauth/{}", self.provider)
    }

    async fn exchange_code(&self, _code: &str) -> Result<OAuthProfile, PortError> {
        Err(PortError::external_service(
            self.provider.as_str(),
            format!(
                "OAuth provider `{}` is disabled in configuration",
                self.provider
            ),
            None,
        ))
    }
}
