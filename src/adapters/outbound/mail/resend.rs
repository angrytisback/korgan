//! Resend REST API mail provider using `reqwest`.

use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::MailProvider;

const RESEND_API_URL: &str = "https://api.resend.com/emails";

#[derive(Serialize)]
struct ResendEmailRequest<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: &'a str,
    text: &'a str,
    html: &'a str,
}

/// Outbound email adapter for the Resend REST API.
#[derive(Clone)]
pub struct ResendMailProvider {
    client: Client,
    api_key: SecretString,
    from_address: String,
}

impl std::fmt::Debug for ResendMailProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResendMailProvider")
            .field("from_address", &self.from_address)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl ResendMailProvider {
    /// Creates a new [`ResendMailProvider`].
    #[must_use]
    pub fn new(from_address: impl Into<String>, api_key: SecretString) -> Self {
        let client =
            crate::adapters::outbound::http_client::create_hardened_client("resend", false)
                .unwrap_or_default();

        Self {
            client,
            api_key,
            from_address: from_address.into(),
        }
    }
}

#[async_trait]
impl MailProvider for ResendMailProvider {
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), PortError> {
        let request_body = ResendEmailRequest {
            from: &self.from_address,
            to: vec![to.as_str()],
            subject,
            text: text_body,
            html: html_body,
        };

        let mut headers = HeaderMap::new();
        let auth_val = format!("Bearer {}", self.api_key.expose_secret());
        let mut auth_header = HeaderValue::from_str(&auth_val)
            .map_err(|e| PortError::crypto(format!("invalid authorization header value: {e}")))?;
        auth_header.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_header);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let response = self
            .client
            .post(RESEND_API_URL)
            .headers(headers)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                PortError::external_service(
                    "resend",
                    format!("HTTP request to Resend failed: {e}"),
                    Some(Box::new(e)),
                )
            })?;

        let status = response.status();
        if !status.is_success() {
            let body_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
                "resend",
                response,
                crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
            )
            .await
            .unwrap_or_default();
            let error_text = String::from_utf8_lossy(&body_bytes);
            return Err(PortError::external_service(
                "resend",
                format!("Resend API returned error status {status}: {error_text}"),
                None,
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resend_provider_redacts_api_key_in_debug() {
        let provider =
            ResendMailProvider::new("no-reply@example.com", SecretString::new("re_12345".into()));
        let debug = format!("{provider:?}");
        assert!(!debug.contains("re_12345"));
        assert!(debug.contains("[REDACTED]"));
    }
}
