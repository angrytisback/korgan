//! Username value object with alphanumeric and underscore validation.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::domain::errors::DomainError;

/// Minimum allowed username length.
pub const MIN_USERNAME_LENGTH: usize = 3;
/// Maximum allowed username length.
pub const MAX_USERNAME_LENGTH: usize = 30;

/// Validated username value object (alphanumeric and underscore only).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Username(String);

impl Username {
    /// Parses, validates, and constructs a [`Username`].
    ///
    /// The input is trimmed. It must contain between 3 and 30 characters,
    /// and consist exclusively of ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`)
    /// and underscores (`_`).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidUsername`] if length constraints are violated
    /// or illegal characters are present.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        let trimmed = raw.as_ref().trim();
        let len = trimmed.len();

        if len < MIN_USERNAME_LENGTH {
            return Err(DomainError::InvalidUsername {
                reason: format!(
                    "username must be at least {MIN_USERNAME_LENGTH} characters long (was {len})"
                ),
            });
        }

        if len > MAX_USERNAME_LENGTH {
            return Err(DomainError::InvalidUsername {
                reason: format!(
                    "username must be at most {MAX_USERNAME_LENGTH} characters long (was {len})"
                ),
            });
        }

        let is_valid_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
        if !trimmed.chars().all(is_valid_char) {
            return Err(DomainError::InvalidUsername {
                reason: "username must contain only ASCII alphanumeric characters and underscores"
                    .to_owned(),
            });
        }

        Ok(Self(trimmed.to_owned()))
    }

    /// Returns the underlying username string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value object and returns the inner [`String`].
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Username {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Username {
    type Error = DomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for Username {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<Username> for String {
    fn from(username: Username) -> Self {
        username.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn accepts_valid_usernames() -> TestResult {
        let valid = ["alice", "bob_123", "ADMIN_USER", "user99"];
        for name in valid {
            let u = Username::new(name)?;
            assert_eq!(u.as_str(), name);
        }
        Ok(())
    }

    #[test]
    fn trims_whitespace() -> TestResult {
        let u = Username::new("   johndoe_1   \n")?;
        assert_eq!(u.as_str(), "johndoe_1");
        Ok(())
    }

    #[test]
    fn rejects_too_short() {
        assert!(Username::new("ab").is_err());
        assert!(Username::new("").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(31);
        assert!(Username::new(&long).is_err());
    }

    #[test]
    fn rejects_invalid_characters() {
        let invalid = ["user-name", "user.name", "user@home", "user name", "user#1"];
        for name in invalid {
            assert!(
                Username::new(name).is_err(),
                "expected '{name}' to be rejected"
            );
        }
    }

    #[test]
    fn serde_round_trips() -> TestResult {
        let u = Username::new("alice_99")?;
        let json = serde_json::to_string(&u)?;
        assert_eq!(json, "\"alice_99\"");
        let deserialized: Username = serde_json::from_str(&json)?;
        assert_eq!(u, deserialized);
        Ok(())
    }
}
