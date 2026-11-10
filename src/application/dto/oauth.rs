//! Data transfer objects for OAuth2 social authentication.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::domain::entities::OAuthProvider;
use crate::domain::value_objects::RequestId;

/// Result returned when generating an external OAuth2 authorization URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthUrlResult {
    /// Target provider authorization endpoint with query parameters.
    pub url: String,
    /// Anti-CSRF state token stored in cache.
    pub state: String,
}

/// Command to process an external OAuth2 identity provider callback.
#[derive(Debug, Clone)]
pub struct OAuthCallbackCommand {
    /// Target identity provider.
    pub provider: OAuthProvider,
    /// Authorization code issued by provider.
    pub code: String,
    /// Anti-CSRF state parameter returned by provider.
    pub state: String,
    /// Anti-CSRF state parameter retrieved from client browser cookie (__Host-oauth_state).
    pub cookie_state: Option<String>,
    /// Client IP address.
    pub ip_address: IpAddr,
    /// Client User-Agent header.
    pub user_agent: Option<String>,
    /// Client device description.
    pub device_name: Option<String>,
    /// Correlation request identifier.
    pub request_id: RequestId,
}
