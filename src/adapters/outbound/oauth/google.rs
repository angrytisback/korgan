//! Google Identity Services (OIDC) outbound OAuth2 adapter.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::domain::entities::OAuthProvider;
use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::{OAuthProfile, OAuthProviderPort};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

/// Outbound adapter for Google Identity Services.
#[derive(Clone)]
pub struct GoogleOAuthAdapter {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    redirect_uri: String,
    auth_url: String,
    token_url: String,
    userinfo_url: String,
}

impl std::fmt::Debug for GoogleOAuthAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleOAuthAdapter")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: Option<bool>,
    name: Option<String>,
}

impl GoogleOAuthAdapter {
    /// Creates a new [`GoogleOAuthAdapter`].
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the hardened HTTP client cannot be built.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
    ) -> Result<Self, PortError> {
        Self::with_endpoints(
            client_id,
            client_secret,
            redirect_uri,
            GOOGLE_AUTH_URL,
            GOOGLE_TOKEN_URL,
            GOOGLE_USERINFO_URL,
        )
    }

    /// Creates an adapter with custom endpoints (useful for integration testing).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the hardened HTTP client cannot be built; the
    /// adapter never falls back to an unhardened client.
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        userinfo_url: impl Into<String>,
    ) -> Result<Self, PortError> {
        let token_url_str = token_url.into();
        let userinfo_url_str = userinfo_url.into();

        let allow_http =
            !token_url_str.starts_with("https://") || !userinfo_url_str.starts_with("https://");
        let client =
            crate::adapters::outbound::http_client::create_hardened_client("google", allow_http)?;

        Ok(Self {
            client,
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            auth_url: auth_url.into(),
            token_url: token_url_str,
            userinfo_url: userinfo_url_str,
        })
    }
}

#[async_trait]
impl OAuthProviderPort for GoogleOAuthAdapter {
    fn provider(&self) -> OAuthProvider {
        OAuthProvider::Google
    }

    fn build_authorization_url(&self, state: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("access_type", "offline")
            .append_pair("prompt", "select_account")
            .finish();
        format!("{}?{query}", self.auth_url)
    }

    async fn exchange_code(&self, code: &str) -> Result<OAuthProfile, PortError> {
        let params = [
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("redirect_uri", &self.redirect_uri),
            ("grant_type", "authorization_code"),
        ];

        let res = self
            .client
            .post(&self.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "google",
                    format!("token request failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let status = res.status();
        let body_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "google",
            res,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        if !status.is_success() {
            let body_str = String::from_utf8_lossy(&body_bytes);
            return Err(PortError::external_service(
                "google",
                format!("token exchange error ({status}): {body_str}"),
                None,
            ));
        }

        let token_data: GoogleTokenResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            PortError::external_service(
                "google",
                format!("failed to parse token response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        let userinfo_res = self
            .client
            .get(&self.userinfo_url)
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "google",
                    format!("userinfo request failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let userinfo_status = userinfo_res.status();
        let userinfo_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "google",
            userinfo_res,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        if !userinfo_status.is_success() {
            let body_str = String::from_utf8_lossy(&userinfo_bytes);
            return Err(PortError::external_service(
                "google",
                format!("userinfo fetch error ({userinfo_status}): {body_str}"),
                None,
            ));
        }

        let info: GoogleUserInfo = serde_json::from_slice(&userinfo_bytes).map_err(|e| {
            PortError::external_service(
                "google",
                format!("failed to parse userinfo response: {e}"),
                Some(Box::new(e)),
            )
        })?;

        if !info.email_verified.unwrap_or(false) {
            return Err(PortError::security("google account email is not verified"));
        }

        let email = EmailAddress::parse(&info.email).map_err(|e| {
            PortError::external_service("google", format!("invalid email from google: {e}"), None)
        })?;

        Ok(OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: info.sub,
            email,
            name: info.name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_percent_encodes_all_parameters() -> Result<(), Box<dyn std::error::Error>>
    {
        let adapter = GoogleOAuthAdapter::new(
            "client id&x=1",
            SecretString::from("secret"),
            "https://app.example.com/cb?a=b&c=d",
        )?;
        let url = adapter.build_authorization_url("st&ate=evil");
        assert!(url.contains("client_id=client+id%26x%3D1"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb%3Fa%3Db%26c%3Dd"));
        assert!(url.contains("state=st%26ate%3Devil"));
        assert!(!url.contains("&x=1") && !url.contains("&ate=evil"));
        Ok(())
    }

    #[test]
    fn test_google_user_info_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        // 1. Verified email
        let json_verified = r#"{"sub": "123", "email": "test@gmail.com", "email_verified": true}"#;
        let info: GoogleUserInfo = serde_json::from_str(json_verified)?;
        assert_eq!(info.email_verified, Some(true));

        // 2. Unverified email
        let json_unverified =
            r#"{"sub": "123", "email": "test@gmail.com", "email_verified": false}"#;
        let info: GoogleUserInfo = serde_json::from_str(json_unverified)?;
        assert_eq!(info.email_verified, Some(false));

        // 3. Missing email_verified field
        let json_missing = r#"{"sub": "123", "email": "test@gmail.com"}"#;
        let info: GoogleUserInfo = serde_json::from_str(json_missing)?;
        assert_eq!(info.email_verified, None);
        Ok(())
    }
}
