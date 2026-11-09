//! Outbound OAuth2 / OpenID Connect identity provider adapters.

pub mod github;
pub mod google;
pub mod noop;

pub use github::GithubOAuthAdapter;
pub use google::GoogleOAuthAdapter;
pub use noop::NoopOAuthProvider;
