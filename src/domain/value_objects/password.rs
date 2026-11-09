//! Password value objects: [`RawPassword`] with Unicode NFC normalization and
//! memory zeroization, and [`PasswordHash`] for Argon2id PHC hashes.

use std::fmt;
use std::str::FromStr;

use password_hash::phc::PasswordHash as PhcHash;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::errors::DomainError;

/// NIST SP 800-63B minimum password length.
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// NIST SP 800-63B maximum password length.
pub const MAX_PASSWORD_LENGTH: usize = 128;
/// Maximum allowed raw password byte size before Unicode normalization (128 chars * 4 bytes/char).
pub const MAX_PASSWORD_BYTES: usize = MAX_PASSWORD_LENGTH * 4;

/// Plaintext password value object.
///
/// Complies strictly with NIST SP 800-63B:
/// - Enforces length between 8 and 128 Unicode characters.
/// - Normalizes to Unicode NFC (Normalization Form Canonical Composition) upon instantiation.
/// - Automatically zeroizes memory on drop via [`ZeroizeOnDrop`].
/// - Redacts plaintext in both [`fmt::Debug`] and [`fmt::Display`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RawPassword {
    secret: String,
}

impl RawPassword {
    /// Validates, normalizes to Unicode NFC, and creates a [`RawPassword`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::PasswordTooShort`] if fewer than 8 characters,
    /// or [`DomainError::PasswordTooLong`] if more than 512 raw bytes or
    /// more than 128 Unicode characters.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw_ref = raw.as_ref();
        let raw_len = raw_ref.len();

        if raw_len > MAX_PASSWORD_BYTES {
            return Err(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: raw_len,
            });
        }

        let normalized: String = raw_ref.nfc().collect();
        let char_count = normalized.chars().count();

        if char_count < MIN_PASSWORD_LENGTH {
            return Err(DomainError::PasswordTooShort {
                min: MIN_PASSWORD_LENGTH,
                actual: char_count,
            });
        }

        if char_count > MAX_PASSWORD_LENGTH {
            return Err(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: char_count,
            });
        }

        Ok(Self { secret: normalized })
    }

    /// Exposes the inner normalized password string for cryptographic operations.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }

    /// Exposes the inner normalized password as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// Returns the character count of the normalized password.
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.secret.chars().count()
    }
}

impl fmt::Debug for RawPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for RawPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl TryFrom<String> for RawPassword {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for RawPassword {
    type Error = DomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Strongly-typed wrapper for Argon2id PHC password hash strings.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PasswordHash(String);

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PasswordHash {
    /// Validates and constructs a [`PasswordHash`] from a PHC string.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidPasswordHash`] if parsing fails or
    /// the algorithm is not `argon2id`.
    pub fn new(hash: impl Into<String>) -> Result<Self, DomainError> {
        let raw = hash.into();
        let parsed = PhcHash::new(&raw).map_err(|e| DomainError::InvalidPasswordHash {
            reason: format!("failed to parse PHC string: {e}"),
        })?;

        if parsed.algorithm.as_str() != "argon2id" {
            return Err(DomainError::InvalidPasswordHash {
                reason: format!(
                    "expected 'argon2id' algorithm, found '{}'",
                    parsed.algorithm.as_str()
                ),
            });
        }

        Ok(Self(raw))
    }

    /// Returns the hash string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner [`String`].
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for PasswordHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for PasswordHash {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for PasswordHash {
    type Error = DomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for PasswordHash {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl From<PasswordHash> for String {
    fn from(hash: PasswordHash) -> Self {
        hash.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn enforces_minimum_length() {
        let short = "1234567";
        assert_eq!(
            RawPassword::new(short).err(),
            Some(DomainError::PasswordTooShort { min: 8, actual: 7 })
        );

        let valid_min = "12345678";
        assert!(RawPassword::new(valid_min).is_ok());
    }

    #[test]
    fn enforces_maximum_length() {
        let max_str = "a".repeat(128);
        assert!(RawPassword::new(&max_str).is_ok());

        let oversized = "a".repeat(129);
        assert_eq!(
            RawPassword::new(&oversized).err(),
            Some(DomainError::PasswordTooLong {
                max: 128,
                actual: 129
            })
        );
    }

    #[test]
    fn normalizes_unicode_nfc() -> TestResult {
        // "cafe" with acute accent:
        // Composed: 'c', 'a', 'f', '\u{00E9}' (4 chars)
        // Decomposed: 'c', 'a', 'f', 'e', '\u{0301}' (5 chars)
        let composed = "caf\u{00E9}1234";
        let decomposed = "cafe\u{0301}1234";

        let p1 = RawPassword::new(composed)?;
        let p2 = RawPassword::new(decomposed)?;

        assert_eq!(p1.expose_secret(), p2.expose_secret());
        assert_eq!(p1.char_count(), 8);
        assert_eq!(p2.char_count(), 8);
        Ok(())
    }

    #[test]
    fn redacts_in_debug_and_display() -> TestResult {
        let password = RawPassword::new("super-secret-password-123")?;
        assert_eq!(format!("{password:?}"), "[REDACTED]");
        assert_eq!(format!("{password}"), "[REDACTED]");
        Ok(())
    }

    #[test]
    fn allows_spaces_and_emojis() -> TestResult {
        let passphrase = "correct horse battery staple \u{1F680}";
        let password = RawPassword::new(passphrase)?;
        assert_eq!(password.expose_secret(), passphrase);
        Ok(())
    }

    #[test]
    fn password_hash_accepts_valid_argon2id() -> TestResult {
        let valid_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8";
        let hash = PasswordHash::new(valid_hash)?;
        assert_eq!(hash.as_str(), valid_hash);
        Ok(())
    }

    #[test]
    fn password_hash_rejects_non_argon2id() {
        // argon2i hash
        let argon2i_hash =
            "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8";
        assert!(PasswordHash::new(argon2i_hash).is_err());

        // invalid string
        assert!(PasswordHash::new("not-a-hash").is_err());
    }

    #[test]
    fn enforces_pre_normalization_byte_bound_o1() {
        // Massive 100,000-byte payload to verify O(1) fast-rejection without normalization
        let massive = "a".repeat(100_000);
        let start = std::time::Instant::now();
        let res = RawPassword::new(&massive);
        let elapsed = start.elapsed();

        assert_eq!(
            res.err(),
            Some(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: 100_000,
            })
        );
        // Fast-path O(1) rejection must complete in sub-millisecond time (< 1ms)
        assert!(
            elapsed < std::time::Duration::from_millis(1),
            "expected O(1) rejection under 1ms, took {elapsed:?}"
        );
    }

    #[test]
    fn exact_boundary_at_max_password_bytes() {
        // 128 4-byte characters (\u{1F980} = 4 bytes UTF-8) -> exactly 512 bytes, 128 chars
        let max_4byte = "\u{1F980}".repeat(128);
        assert_eq!(max_4byte.len(), MAX_PASSWORD_BYTES);
        assert_eq!(max_4byte.chars().count(), MAX_PASSWORD_LENGTH);
        assert!(RawPassword::new(&max_4byte).is_ok());

        // 129 4-byte characters -> 516 bytes -> rejected at pre-normalization bound
        let over_4byte = "\u{1F980}".repeat(129);
        assert_eq!(over_4byte.len(), 516);
        assert_eq!(
            RawPassword::new(&over_4byte).err(),
            Some(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: 516,
            })
        );

        // 512 1-byte characters -> 512 bytes, but 512 chars (> 128)
        // Passes pre-normalization bound (512 <= 512), caught at post-normalization char check
        let ascii_512 = "a".repeat(512);
        assert_eq!(ascii_512.len(), 512);
        assert_eq!(
            RawPassword::new(&ascii_512).err(),
            Some(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: 512,
            })
        );

        // 513 1-byte characters -> 513 bytes -> caught at pre-normalization bound
        let ascii_513 = "a".repeat(513);
        assert_eq!(ascii_513.len(), 513);
        assert_eq!(
            RawPassword::new(&ascii_513).err(),
            Some(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: 513,
            })
        );
    }

    #[test]
    fn prevents_nfc_dos_with_combining_characters() {
        // Decomposed 'e' + combining acute accent (\u{0301}) is 1 + 2 = 3 bytes per grapheme
        // 200 such characters = 600 bytes (> 512 bytes).
        // Before R8, this would invoke full NFC composition and allocation.
        // With R8, it is immediately rejected in O(1) via the byte bound.
        let zalgo_payload = "e\u{0301}".repeat(200);
        assert_eq!(zalgo_payload.len(), 600);
        assert_eq!(
            RawPassword::new(&zalgo_payload).err(),
            Some(DomainError::PasswordTooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: 600,
            })
        );
    }
}
