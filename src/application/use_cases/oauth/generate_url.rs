//! Generates external OAuth authorization URL and stores CSRF state token.

use std::sync::Arc;
use std::time::Duration;

use crate::application::dto::OAuthUrlResult;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::{generate_opaque_token, pkce_s256_challenge};
use crate::domain::entities::OAuthProvider;
use crate::ports::cache::TokenStore;
use crate::ports::services::OAuthProviderPort;

/// Generates an authorization URL with a temporary anti-CSRF state token.
#[derive(Clone)]
pub struct GenerateOAuthUrlUseCase {
    google_provider: Arc<dyn OAuthProviderPort>,
    github_provider: Arc<dyn OAuthProviderPort>,
    token_store: Arc<dyn TokenStore>,
    state_ttl: Duration,
}

impl std::fmt::Debug for GenerateOAuthUrlUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateOAuthUrlUseCase")
            .field("state_ttl", &self.state_ttl)
            .finish_non_exhaustive()
    }
}

impl GenerateOAuthUrlUseCase {
    /// Creates a new [`GenerateOAuthUrlUseCase`].
    #[must_use]
    pub fn new(
        google_provider: Arc<dyn OAuthProviderPort>,
        github_provider: Arc<dyn OAuthProviderPort>,
        token_store: Arc<dyn TokenStore>,
        state_ttl: Duration,
    ) -> Self {
        Self {
            google_provider,
            github_provider,
            token_store,
            state_ttl,
        }
    }

    /// Executes the generation workflow for the given provider.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if state caching fails.
    pub async fn execute(&self, provider: OAuthProvider) -> Result<OAuthUrlResult, AppError> {
        let (raw_state, _) = generate_opaque_token();
        // RFC 7636: 256-bit random verifier, kept server-side next to the state.
        let (code_verifier, _) = generate_opaque_token();
        let code_challenge = pkce_s256_challenge(&code_verifier);

        let state_key = format!("oauth:state:{}:{}", provider.as_str(), raw_state);
        self.token_store
            .set_token(&state_key, &code_verifier, self.state_ttl)
            .await?;

        let url = match provider {
            OAuthProvider::Google => self
                .google_provider
                .build_authorization_url(&raw_state, &code_challenge),
            OAuthProvider::GitHub => self
                .github_provider
                .build_authorization_url(&raw_state, &code_challenge),
        };

        Ok(OAuthUrlResult {
            url,
            state: raw_state,
        })
    }
}
