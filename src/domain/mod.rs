//! Domain layer: pure Rust, zero I/O.
//!
//! This module (and everything below it) MUST NOT depend on `axum`, `http`,
//! `sqlx` or any Redis client.

pub mod entities;
pub mod errors;
pub mod value_objects;

pub use entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey,
    PasswordHistory, Session, User, UserMfa, UserRole, audit_events,
};
pub use errors::{DomainError, FieldViolation};
pub use value_objects::{
    AuditLogId, EmailAddress, OAuthAccountId, PasskeyId, PasswordHash, RawPassword, RequestId,
    SessionId, TokenFamilyId, UserId, Username,
};
