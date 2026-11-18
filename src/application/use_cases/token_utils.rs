//! Cryptographic token utilities for opaque security tokens, Base32 encoding,
//! backup codes, and session blacklist synchronization.

use std::sync::Arc;
use std::time::Duration;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};

use crate::application::error::AppError;
use crate::application::use_cases::shielded;
use crate::domain::value_objects::SessionId;
use crate::ports::cache::TokenStore;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BACKUP_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
const BLACKLIST_SESSION_PREFIX: &[u8; 18] = b"blacklist:session:";

/// Default retention TTL for blacklisted session keys in cache (30 days).
pub const SESSION_BLACKLIST_TTL: Duration = Duration::from_hours(720);

/// Syncs revoked session IDs to the distributed [`TokenStore`] blacklist inside a
/// [`shielded`] task so request cancellation cannot drop the revocation write.
///
/// Short-circuits with zero allocations and zero task spawns when `session_ids` is empty.
///
/// # Errors
///
/// Returns [`AppError`] if the shielded task fails or `token_store` fails after retries.
pub async fn blacklist_sessions(
    token_store: Arc<dyn TokenStore>,
    session_ids: &[SessionId],
    ttl: Duration,
) -> Result<(), AppError> {
    if session_ids.is_empty() {
        return Ok(());
    }

    if let [single] = session_ids {
        let sid = *single;
        return shielded(move || {
            let token_store = token_store.clone();
            async move {
                let mut key_buf = [0u8; 54];
                key_buf[..18].copy_from_slice(BLACKLIST_SESSION_PREFIX);
                let _ = sid.as_uuid().hyphenated().encode_lower(&mut key_buf[18..]);
                let key = std::str::from_utf8(&key_buf).unwrap_or_default();
                token_store.set_token(key, "revoked", ttl).await?;
                Ok(())
            }
        })
        .await;
    }

    let ids: Arc<[SessionId]> = Arc::from(session_ids);
    shielded(move || {
        let token_store = token_store.clone();
        let ids = ids.clone();
        async move {
            let mut buf = vec![0u8; ids.len() * 54];
            let (mut_chunks, _) = buf.as_chunks_mut::<54>();
            for (slot, sid) in mut_chunks.iter_mut().zip(ids.iter()) {
                slot[..18].copy_from_slice(BLACKLIST_SESSION_PREFIX);
                let _ = sid.as_uuid().hyphenated().encode_lower(&mut slot[18..]);
            }
            let (chunks, _) = buf.as_chunks::<54>();
            let borrowed: Vec<(&str, &str, Duration)> = chunks
                .iter()
                .filter_map(|chunk| std::str::from_utf8(chunk).ok())
                .map(|k| (k, "revoked", ttl))
                .collect();
            token_store.set_tokens_batch(&borrowed).await?;
            Ok(())
        }
    })
    .await
}

/// Generates 32 bytes of CSPRNG entropy.
///
/// Returns:
/// - `raw_token`: `Base64URL` unpadded string given to the user/client
/// - `token_hash`: Lowercase hex SHA-256 digest stored in database/cache
#[must_use]
pub fn generate_opaque_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let raw = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&raw);
    (raw, hash)
}

/// Computes the SHA-256 hex digest of a raw token.
#[must_use]
pub fn hash_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for &b in &digest {
        hex.push(char::from(HEX_CHARS[usize::from(b >> 4)]));
        hex.push(char::from(HEX_CHARS[usize::from(b & 0x0F)]));
    }
    hex
}

/// Encodes binary data into an RFC 4648 Base32 unpadded string.
#[must_use]
pub fn encode_base32(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;

    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(char::from(BASE32_ALPHABET[index]));
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(char::from(BASE32_ALPHABET[index]));
    }

    result
}

/// Decodes an RFC 4648 Base32 string into bytes.
#[must_use]
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        let upper = b.to_ascii_uppercase();
        let val = match upper {
            b'A'..=b'Z' => upper - b'A',
            b'2'..=b'7' => upper - b'2' + 26,
            _ => return None,
        };

        buffer = (buffer << 5) | u64::from(val);
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            result.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Some(result)
}

/// Generates 10 single-use 8-character backup codes.
///
/// Returns `(plaintext_codes, sha256_hashes)`.
#[must_use]
pub fn generate_backup_codes(count: usize) -> (Vec<String>, Vec<String>) {
    let mut plaintexts = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    let mut rng = rand::rng();

    for _ in 0..count {
        let mut code = String::with_capacity(8);
        for _ in 0..8 {
            let idx = rng.random_range(0..BACKUP_CODE_ALPHABET.len());
            code.push(char::from(BACKUP_CODE_ALPHABET[idx]));
        }
        hashes.push(hash_token(&code));
        plaintexts.push(code);
    }

    (plaintexts, hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_hash_opaque_token() {
        let (raw, hash) = generate_opaque_token();
        assert_ne!(raw, "");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_token(&raw));
    }

    #[test]
    fn test_base32_roundtrip() {
        let original = b"Hello, TOTP Secret 12345!";
        let encoded = encode_base32(original);
        let decoded = decode_base32(&encoded).unwrap_or_default();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_base32_handles_whitespace_padding_and_invalid() {
        let original = b"Hello!";
        let encoded = encode_base32(original);
        let formatted = format!(" {}== \n", encoded.to_ascii_lowercase());
        assert_eq!(decode_base32(&formatted), Some(original.to_vec()));
        assert_eq!(decode_base32("INVALID!1"), None);
    }

    #[test]
    fn test_generate_backup_codes() {
        let (plain, hashes) = generate_backup_codes(10);
        assert_eq!(plain.len(), 10);
        assert_eq!(hashes.len(), 10);
        for (p, h) in plain.iter().zip(hashes.iter()) {
            assert_eq!(p.len(), 8);
            assert_eq!(&hash_token(p), h);
        }
    }

    #[derive(Default)]
    struct MockBlacklistStore {
        entries: std::sync::Mutex<std::collections::HashMap<String, (String, Duration)>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl TokenStore for MockBlacklistStore {
        async fn set_token(
            &self,
            key: &str,
            token_hash: &str,
            ttl: Duration,
        ) -> Result<(), crate::ports::errors::PortError> {
            if self.fail {
                return Err(crate::ports::errors::PortError::cache("forced failure"));
            }
            self.entries
                .lock()
                .map_err(|e| crate::ports::errors::PortError::cache(e.to_string()))?
                .insert(key.to_owned(), (token_hash.to_owned(), ttl));
            Ok(())
        }
        async fn get_token(
            &self,
            key: &str,
        ) -> Result<Option<String>, crate::ports::errors::PortError> {
            Ok(self
                .entries
                .lock()
                .map_err(|e| crate::ports::errors::PortError::cache(e.to_string()))?
                .get(key)
                .map(|(v, _)| v.clone()))
        }
        async fn delete_token(&self, _key: &str) -> Result<(), crate::ports::errors::PortError> {
            Ok(())
        }
        async fn get_and_delete(
            &self,
            _key: &str,
        ) -> Result<Option<String>, crate::ports::errors::PortError> {
            Ok(None)
        }
        async fn consume_token(
            &self,
            _key: &str,
            _expected: &str,
        ) -> Result<bool, crate::ports::errors::PortError> {
            Ok(true)
        }
        async fn set_if_not_exists(
            &self,
            _key: &str,
            _val: &str,
            _ttl: Duration,
        ) -> Result<bool, crate::ports::errors::PortError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_blacklist_sessions_short_circuits_when_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(MockBlacklistStore {
            fail: true,
            ..Default::default()
        });
        blacklist_sessions(store, &[], SESSION_BLACKLIST_TTL).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_blacklist_sessions_single_and_batch() -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(MockBlacklistStore::default());
        let s1 = SessionId::new();
        let s2 = SessionId::new();
        let s3 = SessionId::new();
        let ttl = Duration::from_mins(5);

        blacklist_sessions(store.clone(), &[s1], ttl).await?;
        assert_eq!(
            store.get_token(&format!("blacklist:session:{s1}")).await?,
            Some("revoked".to_owned())
        );

        blacklist_sessions(store.clone(), &[s2, s3], ttl).await?;
        assert_eq!(
            store.get_token(&format!("blacklist:session:{s2}")).await?,
            Some("revoked".to_owned())
        );
        assert_eq!(
            store.get_token(&format!("blacklist:session:{s3}")).await?,
            Some("revoked".to_owned())
        );
        Ok(())
    }
}
