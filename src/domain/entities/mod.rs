//! Domain entities: User, Session, UserMfa, and AuditLog.
//!
//! Pure business objects without infrastructure or database bindings.

pub mod audit;
pub mod mfa;
pub mod oauth_account;
pub mod passkey;
pub mod session;
pub mod user;

pub use audit::{AuditEventStatus, AuditLog, audit_events};
pub use mfa::UserMfa;
pub use oauth_account::{OAuthAccount, OAuthProvider};
pub use passkey::Passkey;
pub use session::Session;
pub use user::{AccountStatus, PasswordHistory, User, UserRole};
