//! Value objects: immutable, self-validating domain primitives.

pub mod email;
pub mod ids;
pub mod password;
pub mod username;

pub use email::{EmailAddress, MAX_EMAIL_LENGTH};
pub use ids::{AuditLogId, OAuthAccountId, PasskeyId, RequestId, SessionId, TokenFamilyId, UserId};
pub use password::{
    MAX_PASSWORD_BYTES, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, PasswordHash, RawPassword,
};
pub use username::{MAX_USERNAME_LENGTH, MIN_USERNAME_LENGTH, Username};
