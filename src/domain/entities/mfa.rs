//! Multi-Factor Authentication (MFA) domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::domain::value_objects::UserId;

/// MFA configuration and state for a user.
///
/// Encrypted TOTP secret at rest with AES-256-GCM, and SHA-256 hashes of unused
/// backup codes.
/// Maximum backup codes initially issued.
pub const MAX_BACKUP_CODES: usize = 10;
const DUMMY_BACKUP_HASH: &[u8] =
    b"0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMfa {
    /// Owner user identifier.
    pub user_id: UserId,
    /// Symmetric encryption key identifier (version).
    pub key_id: String,
    /// AES-256-GCM ciphertext containing the TOTP secret.
    pub totp_secret_ciphertext: Vec<u8>,
    /// 12-byte nonce used during encryption.
    pub totp_secret_nonce: Vec<u8>,
    /// SHA-256 hex hashes of unused single-use 8-character backup codes.
    pub backup_code_hashes: Vec<String>,
    /// Timestamp when TOTP was successfully verified during initial enrollment.
    pub verified_at: Option<DateTime<Utc>>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for UserMfa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserMfa")
            .field("user_id", &self.user_id)
            .field("key_id", &self.key_id)
            .field("totp_secret_ciphertext", &"[REDACTED]")
            .field("totp_secret_nonce", &"[REDACTED]")
            .field("backup_code_hashes", &"[REDACTED]")
            .field("verified_at", &self.verified_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl UserMfa {
    /// Creates a new unverified MFA enrollment record defaulting to key_id "v1".
    #[must_use]
    pub fn new(
        user_id: UserId,
        totp_secret_ciphertext: Vec<u8>,
        totp_secret_nonce: Vec<u8>,
        backup_code_hashes: Vec<String>,
    ) -> Self {
        Self::new_with_key_id(
            user_id,
            "v1",
            totp_secret_ciphertext,
            totp_secret_nonce,
            backup_code_hashes,
        )
    }

    /// Creates a new unverified MFA enrollment record with an explicit key identifier.
    #[must_use]
    pub fn new_with_key_id(
        user_id: UserId,
        key_id: impl Into<String>,
        totp_secret_ciphertext: Vec<u8>,
        totp_secret_nonce: Vec<u8>,
        backup_code_hashes: Vec<String>,
    ) -> Self {
        Self {
            user_id,
            key_id: key_id.into(),
            totp_secret_ciphertext,
            totp_secret_nonce,
            backup_code_hashes,
            verified_at: None,
            updated_at: Utc::now(),
        }
    }

    /// Returns `true` if this MFA configuration has completed initial verification.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Marks the MFA configuration as verified upon successful TOTP challenge.
    pub fn verify(&mut self, now: DateTime<Utc>) {
        self.verified_at = Some(now);
        self.updated_at = now;
    }

    /// Attempts to consume a hashed backup code in constant time across all 10 indices.
    ///
    /// Even if fewer than 10 backup codes remain, this method always iterates through
    /// exactly 10 comparisons using constant-time equality comparisons to eliminate timing leaks.
    /// If found, the code is removed from the active list and `true` is returned.
    pub fn consume_backup_code(&mut self, candidate_hash: &str) -> bool {
        let candidate_bytes = candidate_hash.as_bytes();
        let mut matched_index = None;

        for i in 0..MAX_BACKUP_CODES {
            let code_bytes = if i < self.backup_code_hashes.len() {
                self.backup_code_hashes[i].as_bytes()
            } else {
                DUMMY_BACKUP_HASH
            };

            let is_match: bool = code_bytes.ct_eq(candidate_bytes).into();
            if is_match && i < self.backup_code_hashes.len() && matched_index.is_none() {
                matched_index = Some(i);
            }
        }

        if let Some(index) = matched_index {
            self.backup_code_hashes.remove(index);
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Returns the number of remaining unused backup codes.
    #[must_use]
    pub fn remaining_backup_codes_count(&self) -> usize {
        self.backup_code_hashes.len()
    }

    /// Replaces active backup code hashes with fresh ones.
    pub fn regenerate_backup_codes(&mut self, new_hashes: Vec<String>, now: DateTime<Utc>) {
        self.backup_code_hashes = new_hashes;
        self.updated_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_verification_and_backup_code_consumption() {
        let user_id = UserId::new();
        let ciphertext = vec![1, 2, 3, 4];
        let nonce = vec![0; 12];
        let backup_hashes = vec![
            "hash_code_1".to_owned(),
            "hash_code_2".to_owned(),
            "hash_code_3".to_owned(),
        ];

        let mut mfa = UserMfa::new(user_id, ciphertext, nonce, backup_hashes);
        assert!(!mfa.is_verified());
        assert_eq!(mfa.remaining_backup_codes_count(), 3);

        let now = Utc::now();
        mfa.verify(now);
        assert!(mfa.is_verified());
        assert_eq!(mfa.verified_at, Some(now));

        // Consume valid backup code
        assert!(mfa.consume_backup_code("hash_code_2"));
        assert_eq!(mfa.remaining_backup_codes_count(), 2);

        // Cannot consume already consumed code
        assert!(!mfa.consume_backup_code("hash_code_2"));
        assert_eq!(mfa.remaining_backup_codes_count(), 2);

        // Consume non-existent code
        assert!(!mfa.consume_backup_code("non_existent"));
        assert_eq!(mfa.remaining_backup_codes_count(), 2);

        // Regenerate backup codes
        mfa.regenerate_backup_codes(vec!["new_1".to_owned()], now);
        assert_eq!(mfa.remaining_backup_codes_count(), 1);
        assert!(mfa.consume_backup_code("new_1"));
        assert_eq!(mfa.remaining_backup_codes_count(), 0);
    }

    #[test]
    fn mfa_key_id_defaults_to_v1_and_supports_explicit_versioning()
    -> Result<(), Box<dyn std::error::Error>> {
        let user_id = UserId::new();
        let ciphertext = vec![1, 2, 3, 4];
        let nonce = vec![0; 12];
        let backup_hashes = vec!["hash_code_1".to_owned()];

        // Default constructor assigns "v1"
        let mfa_v1 = UserMfa::new(
            user_id,
            ciphertext.clone(),
            nonce.clone(),
            backup_hashes.clone(),
        );
        assert_eq!(mfa_v1.key_id, "v1");

        // Explicit constructor assigns specified key_id
        let mfa_v2 = UserMfa::new_with_key_id(
            user_id,
            "v2-2026",
            ciphertext.clone(),
            nonce.clone(),
            backup_hashes.clone(),
        );
        assert_eq!(mfa_v2.key_id, "v2-2026");

        // Serialization & Deserialization preserves key_id
        let json = serde_json::to_string(&mfa_v2)?;
        let deserialized: UserMfa = serde_json::from_str(&json)?;
        assert_eq!(deserialized.key_id, "v2-2026");
        assert_eq!(deserialized.user_id, user_id);
        assert_eq!(deserialized.totp_secret_ciphertext, ciphertext);

        Ok(())
    }
}
