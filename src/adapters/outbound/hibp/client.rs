//! Have I Been Pwned k-Anonymity v1 client adapter.

use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

use crate::domain::value_objects::RawPassword;
use crate::ports::errors::PortError;
use crate::ports::services::HibpClient;

const HIBP_RANGE_API_URL: &str = "https://api.pwnedpasswords.com/range";
const USER_AGENT_VALUE: &str = "korgan-security-checker/0.1";

/// Production HIBP client communicating with the k-Anonymity range API.
#[derive(Debug, Clone)]
pub struct ReqwestHibpClient {
    client: Client,
    endpoint: String,
}

impl Default for ReqwestHibpClient {
    fn default() -> Self {
        Self::new(HIBP_RANGE_API_URL)
    }
}

impl ReqwestHibpClient {
    /// Creates a new [`ReqwestHibpClient`] pointing to the given endpoint.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let ep = endpoint.into();
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));

        let allow_http = !ep.starts_with("https://");
        let client =
            crate::adapters::outbound::http_client::create_hardened_client_builder(allow_http)
                .default_headers(headers)
                .build()
                .unwrap_or_default();

        Self {
            client,
            endpoint: ep,
        }
    }

    /// Computes the uppercase SHA-1 hash of the password and splits into (prefix, suffix).
    #[must_use]
    pub fn compute_prefix_and_suffix(password: &RawPassword) -> (String, String) {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        let hex = format!("{digest:X}");
        (hex[..5].to_string(), hex[5..].to_string())
    }
}

#[async_trait]
impl HibpClient for ReqwestHibpClient {
    async fn is_password_breached(&self, password: &RawPassword) -> Result<bool, PortError> {
        let (prefix, suffix) = Self::compute_prefix_and_suffix(password);
        let url = format!("{}/{prefix}", self.endpoint.trim_end_matches('/'));

        let response = self.client.get(&url).send().await.map_err(|e| {
            PortError::external_service(
                "hibp",
                format!("failed to query HIBP range API: {e}"),
                Some(Box::new(e)),
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(PortError::external_service(
                "hibp",
                format!("HIBP range API returned unexpected status {status}"),
                None,
            ));
        }

        let body_bytes = crate::adapters::outbound::http_client::read_response_body_limited(
            "hibp",
            response,
            crate::adapters::outbound::http_client::MAX_OUTBOUND_RESPONSE_BYTES,
        )
        .await?;

        let body = std::str::from_utf8(&body_bytes).map_err(|e| {
            PortError::external_service(
                "hibp",
                format!("failed to decode HIBP response as UTF-8: {e}"),
                Some(Box::new(e)),
            )
        })?;

        let suffix_bytes = suffix.as_bytes();

        for line in body.lines() {
            let line = line.trim();
            if let Some((entry_suffix, _count)) = line.split_once(':') {
                let entry_bytes = entry_suffix.trim().as_bytes();
                if entry_bytes.len() == suffix_bytes.len()
                    && bool::from(entry_bytes.ct_eq(suffix_bytes))
                {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

/// No-op HIBP client for environments where breached-password screening is disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopHibpClient;

#[async_trait]
impl HibpClient for NoopHibpClient {
    async fn is_password_breached(&self, _password: &RawPassword) -> Result<bool, PortError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn computes_sha1_prefix_and_suffix_correctly() -> TestResult {
        // "password" SHA-1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let pwd = RawPassword::new("password")?;
        let (prefix, suffix) = ReqwestHibpClient::compute_prefix_and_suffix(&pwd);

        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        Ok(())
    }

    #[tokio::test]
    async fn noop_client_always_returns_false() -> TestResult {
        let client = NoopHibpClient;
        let pwd = RawPassword::new("password123")?;
        let breached = client.is_password_breached(&pwd).await?;
        assert!(!breached);
        Ok(())
    }
}
