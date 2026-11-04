//! HTTP handlers. Every handler carries a `#[utoipa::path]` annotation and
//! documents its RFC 9457 error responses.

pub mod admin;
pub mod auth;
pub mod fallback;
pub mod health;
pub mod jwks;
pub mod metrics;
pub mod mfa;
pub mod oauth;
pub mod passkeys;
pub mod password;
pub mod sessions;
pub mod users;
