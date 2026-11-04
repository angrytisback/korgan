//! Self-validating, canonicalized e-mail address value object.
//!
//! Validates against RFC rules using [`validator::validate_email`] and
//! silently normalizes to lowercase upon instantiation.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use validator::ValidateEmail;

use crate::domain::errors::DomainError;

/// Maximum e-mail length permitted by RFC 5321 Section 4.5.3.1.3.
pub const MAX_EMAIL_LENGTH: usize = 254;

/// Strongly-typed, normalized e-mail address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Parses, validates, and normalizes an e-mail address.
    ///
    /// The string is trimmed and silently converted to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidEmail`] if the address is empty, exceeds
    /// 254 characters, or fails standard RFC syntax validation.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        let trimmed = raw.as_ref().trim();

        if trimmed.is_empty() {
            return Err(DomainError::InvalidEmail {
                reason: "e-mail address cannot be empty".to_owned(),
            });
        }

        if trimmed.len() > MAX_EMAIL_LENGTH {
            return Err(DomainError::InvalidEmail {
                reason: format!(
                    "e-mail address exceeds maximum allowed length of {MAX_EMAIL_LENGTH} characters"
                ),
            });
        }

        let normalized = trimmed.to_lowercase();

        if !ValidateEmail::validate_email(&normalized) {
            return Err(DomainError::InvalidEmail {
                reason: "e-mail address format does not comply with RFC standards".to_owned(),
            });
        }

        Ok(Self(normalized))
    }

    /// Returns the underlying normalized e-mail string slice.
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

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for EmailAddress {
    type Error = DomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl FromStr for EmailAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<EmailAddress> for String {
    fn from(email: EmailAddress) -> Self {
        email.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn normalizes_to_lowercase() -> TestResult {
        let email = EmailAddress::parse("John.Doe@EXAMPLE.COM")?;
        assert_eq!(email.as_str(), "john.doe@example.com");
        Ok(())
    }

    #[test]
    fn trims_whitespace() -> TestResult {
        let email = EmailAddress::parse("   jane.doe@example.org   \n")?;
        assert_eq!(email.as_str(), "jane.doe@example.org");
        Ok(())
    }

    #[test]
    fn accepts_valid_emails() -> TestResult {
        let valid = [
            "user@example.com",
            "first.last+tag@sub.domain.co.uk",
            "customer_123@service.io",
            "a@b.ce",
        ];
        for address in valid {
            let email = EmailAddress::parse(address)?;
            assert_eq!(email.as_str(), address.to_lowercase());
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_emails() {
        let invalid = [
            "",
            "   ",
            "not-an-email",
            "@missing-local.com",
            "missing-domain@",
            "spaces in@local.com",
            "user@.invalid.com",
            "user@domain..com",
        ];
        for address in invalid {
            assert!(
                EmailAddress::parse(address).is_err(),
                "expected '{address}' to be rejected"
            );
        }
    }

    #[test]
    fn rejects_oversized_email() {
        let domain = "@example.com";
        let local_part = "a".repeat(MAX_EMAIL_LENGTH - domain.len() + 1);
        let oversized = format!("{local_part}{domain}");
        assert!(EmailAddress::parse(&oversized).is_err());
    }

    #[test]
    fn serde_round_trips() -> TestResult {
        let email = EmailAddress::parse("admin@system.local")?;
        let json = serde_json::to_string(&email)?;
        assert_eq!(json, "\"admin@system.local\"");
        let deserialized: EmailAddress = serde_json::from_str(&json)?;
        assert_eq!(email, deserialized);
        Ok(())
    }
}
