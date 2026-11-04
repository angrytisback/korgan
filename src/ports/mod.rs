//! Ports: the traits through which the application talks to the outside world.
//!
//! * [`repositories`] - persistence (`UserRepository`, `SessionRepository`, `AuditLogRepository`)
//! * [`cache`] - ephemeral state (`TokenStore`, `RateLimiterPort`)
//! * [`services`] - external capabilities (`PasswordHasher`, `TokenSigner`, `MailProvider`, `HibpClient`, `TotpService`)
//! * [`errors`] - strongly-typed [`PortError`]
//!
//! Every outbound trait is `Send + Sync + 'static` to support `Arc<dyn Trait>` dependency injection.

pub mod cache;
pub mod errors;
pub mod repositories;
pub mod services;

pub use cache::{RateLimitStatus, RateLimiterPort, TokenStore, WsTicketPayload};
pub use errors::{BoxError, PortError};
pub use repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
pub use services::{
    AccessTokenClaims, DecryptedSecret, HibpClient, MailProvider, OAuthProfile, OAuthProviderPort,
    PasswordHasher, SecretCipher, TokenSigner, TotpService, WebAuthnService,
};
