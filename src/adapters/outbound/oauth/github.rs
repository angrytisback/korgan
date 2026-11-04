//! GitHub OAuth Apps outbound adapter.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::domain::entities::OAuthProvider;
use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::{OAuthProfile, OAuthProviderPort};

const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";

/// Outbound adapter for GitHub OAuth.
#[derive(Clone)]
pub struct GithubOAuthAdapter {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    redirect_uri: String,
    auth_url: String,
    token_url: String,
    user_url: String,
    emails_url: String,
}

impl std::fmt::Debug for GithubOAuthAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubOAuthAdapter")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    login: String,
    name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

impl GithubOAuthAdapter {
    /// Creates a new [`GithubOAuthAdapter`].
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::with_endpoints(
            client_id,
            client_secret,
            redirect_uri,
            GITHUB_AUTH_URL,
            GITHUB_TOKEN_URL,
            GITHUB_USER_URL,
            GITHUB_EMAILS_URL,
        )
    }

    /// Creates an adapter with custom endpoints (useful for integration testing).
    #[must_use]
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        user_url: impl Into<String>,
        emails_url: impl Into<String>,
    ) -> Self {
        let token_url_str = token_url.into();
        let user_url_str = user_url.into();
        let emails_url_str = emails_url.into();

        let allow_http = !token_url_str.starts_with("https://")
            || !user_url_str.starts_with("https://")
            || !emails_url_str.starts_with("https://");
        let client =
            crate::adapters::outbound::http_client::create_hardened_client("github", allow_http)
                .unwrap_or_default();

        Self {
            client,
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            auth_url: auth_url.into(),
            token_url: token_url_str,
            user_url: user_url_str,
            emails_url: emails_url_str,
        }
    }
}

#[async_trait]
impl OAuthProviderPort for GithubOAuthAdapter {
    fn provider(&self) -> OAuthProvider {
        OAuthProvider::GitHub
    }

    fn build_authorization_url(&self, state: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
            self.auth_url, self.client_id, self.redirect_uri, state
        )
    }

    async fn exchange_code(&self, code: &str) -> Result<OAuthProfile, PortError> {
        let params = [
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("redirect_uri", &self.redirect_uri),
        ];

        let res = self
            .client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "github",
                    format!("token request failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let status = res.status();
        let body_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "github",
            res,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        if !status.is_success() {
            let body_str = String::from_utf8_lossy(&body_bytes);
            return Err(PortError::external_service(
                "github",
                format!("token exchange error ({status}): {body_str}"),
                None,
            ));
        }

        let token_data: GithubTokenResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            PortError::external_service(
                "github",
                format!("failed to parse token response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        let user_res = self
            .client
            .get(&self.user_url)
            .bearer_auth(&token_data.access_token)
            .header("User-Agent", "korgan")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "github",
                    format!("user fetch failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let user_status = user_res.status();
        let user_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "github",
            user_res,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        if !user_status.is_success() {
            let body_str = String::from_utf8_lossy(&user_bytes);
            return Err(PortError::external_service(
                "github",
                format!("user fetch error ({user_status}): {body_str}"),
                None,
            ));
        }

        let gh_user: GithubUser = serde_json::from_slice(&user_bytes).map_err(|e| {
            PortError::external_service(
                "github",
                format!("failed to parse user response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        // Fetch verified email from /user/emails; never trust unverified public profile email
        let emails_res = self
            .client
            .get(&self.emails_url)
            .bearer_auth(&token_data.access_token)
            .header("User-Agent", "korgan")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "github",
                    format!("emails fetch failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let emails_status = emails_res.status();
        let emails_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "github",
            emails_res,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        if !emails_status.is_success() {
            let body_str = String::from_utf8_lossy(&emails_bytes);
            return Err(PortError::external_service(
                "github",
                format!("emails fetch error ({emails_status}): {body_str}"),
                None,
            ));
        }

        let emails: Vec<GithubEmail> = serde_json::from_slice(&emails_bytes).map_err(|e| {
            PortError::external_service(
                "github",
                format!("failed to parse emails response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        let verified_email = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified))
            .ok_or_else(|| {
                PortError::security(
                    "github account has no verified email (no verified email found on github account)",
                )
            })?;

        let email = EmailAddress::parse(&verified_email.email).map_err(|e| {
            PortError::external_service("github", format!("invalid email from github: {e}"), None)
        })?;

        Ok(OAuthProfile {
            provider: OAuthProvider::GitHub,
            provider_user_id: gh_user.id.to_string(),
            email,
            name: gh_user.name.or(Some(gh_user.login)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_email_selection_prefers_primary_verified() {
        let emails = [
            GithubEmail {
                email: "unverified@example.com".to_string(),
                primary: true,
                verified: false,
            },
            GithubEmail {
                email: "verified_secondary@example.com".to_string(),
                primary: false,
                verified: true,
            },
        ];

        let selected = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified));

        assert_eq!(
            selected.map(|e| e.email.as_str()),
            Some("verified_secondary@example.com")
        );
    }

    #[test]
    fn test_github_email_selection_rejects_unverified_only() {
        let emails = [
            GithubEmail {
                email: "unverified1@example.com".to_string(),
                primary: true,
                verified: false,
            },
            GithubEmail {
                email: "unverified2@example.com".to_string(),
                primary: false,
                verified: false,
            },
        ];

        let selected = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.verified));

        assert!(selected.is_none());
    }
}
