//! Client metadata extractor for IP, User-Agent, `ClientType`, and `RequestId`.

use std::future::{Future, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use http::request::Parts;

use crate::adapters::inbound::http::state::AppState;
use crate::domain::value_objects::RequestId;

/// Classification of the calling client application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientType {
    /// Browser single-page application (SPA) or server-rendered web app.
    /// Expects `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
    Web,

    /// Native mobile application (iOS, Android).
    /// Expects tokens in the JSON response payload.
    Mobile,

    /// Command-line tool or automated script.
    /// Expects tokens in the JSON response payload.
    #[default]
    Cli,
}

impl ClientType {
    /// Parses client type from header string without heap allocation.
    #[inline]
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("web") {
            Self::Web
        } else if trimmed.eq_ignore_ascii_case("mobile") {
            Self::Mobile
        } else {
            Self::Cli
        }
    }

    /// Returns `true` if this client expects cookie-based delivery.
    #[inline]
    #[must_use]
    pub const fn is_web(self) -> bool {
        matches!(self, Self::Web)
    }
}

/// Extracted context describing the client connection.
#[derive(Debug, Clone)]
pub struct ClientMetadata {
    /// Client User-Agent header string.
    pub user_agent: Option<String>,

    /// User-friendly device description.
    pub device_name: Option<String>,

    /// Client IP address.
    pub ip: IpAddr,

    /// Correlation request identifier.
    pub request_id: RequestId,

    /// Client delivery preference (web cookies vs payload).
    pub client_type: ClientType,
}

impl FromRequestParts<AppState> for ClientMetadata {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let trust_proxy = state.settings.rate_limit.trust_proxy_headers;
        let ip = extract_ip(parts, trust_proxy);
        let user_agent = parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let device_name = parts
            .headers
            .get("x-device-name")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let client_type = parts
            .headers
            .get("x-client-type")
            .and_then(|v| v.to_str().ok())
            .map(ClientType::parse)
            .unwrap_or_default();

        let request_id = parts
            .extensions
            .get::<RequestId>()
            .copied()
            .unwrap_or_default();

        ready(Ok(Self {
            user_agent,
            device_name,
            ip,
            request_id,
            client_type,
        }))
    }
}

fn extract_ip(parts: &Parts, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(forwarded) = parts.headers.get("x-forwarded-for")
            && let Ok(s) = forwarded.to_str()
            && let Some(ip) = s.rsplit(',').find_map(|p| p.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }

        if let Some(real_ip) = parts.headers.get("x-real-ip")
            && let Ok(s) = real_ip.to_str()
            && let Ok(ip) = s.trim().parse::<IpAddr>()
        {
            return ip;
        }
    }

    if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }

    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_metadata_size_is_88_bytes() {
        assert_eq!(std::mem::size_of::<ClientMetadata>(), 88);
    }

    #[test]
    fn client_type_parse_is_case_insensitive_and_trims() {
        assert_eq!(ClientType::parse("web"), ClientType::Web);
        assert_eq!(ClientType::parse("  WEB "), ClientType::Web);
        assert_eq!(ClientType::parse("Mobile"), ClientType::Mobile);
        assert_eq!(ClientType::parse("cli"), ClientType::Cli);
        assert_eq!(ClientType::parse("unknown"), ClientType::Cli);
        assert!(ClientType::Web.is_web());
        assert!(!ClientType::Mobile.is_web());
        assert!(!ClientType::Cli.is_web());
    }
}
