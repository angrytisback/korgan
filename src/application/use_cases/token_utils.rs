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
use crate::ports::errors::PortError;
use crate::ports::services::SecretCipher;

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
                let (prefix, uuid_part) = key_buf.split_at_mut(18);
                prefix.copy_from_slice(BLACKLIST_SESSION_PREFIX);
                let _ = sid.as_uuid().hyphenated().encode_lower(uuid_part);
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
                let (prefix, uuid_part) = slot.split_at_mut(18);
                prefix.copy_from_slice(BLACKLIST_SESSION_PREFIX);
                let _ = sid.as_uuid().hyphenated().encode_lower(uuid_part);
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

/// Domain-separated AAD binding a pending (not yet activated) TOTP secret to its owner.
fn pending_totp_aad(user_id: &crate::domain::value_objects::UserId) -> Vec<u8> {
    let mut aad = b"KORGAN_PENDING_TOTP_V1\0".to_vec();
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

/// Seals a pending TOTP secret for the cache as `base64url(nonce).base64url(ciphertext)`
/// (AES-256-GCM, AAD bound to the user) so a cache dump never exposes it in clear.
///
/// # Errors
///
/// Returns [`PortError`] if encryption fails.
pub fn seal_pending_totp_secret(
    cipher: &dyn SecretCipher,
    user_id: &crate::domain::value_objects::UserId,
    secret: &[u8],
) -> Result<String, PortError> {
    let (ciphertext, nonce) = cipher.encrypt_with_aad(secret, &pending_totp_aad(user_id))?;
    Ok(format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(nonce),
        BASE64_URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Opens a value produced by [`seal_pending_totp_secret`].
///
/// # Errors
///
/// Returns [`PortError`] if the value is malformed or authentication fails.
pub fn open_pending_totp_secret(
    cipher: &dyn SecretCipher,
    user_id: &crate::domain::value_objects::UserId,
    sealed: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, PortError> {
    let malformed = || PortError::crypto("malformed sealed pending TOTP secret");
    let (nonce_b64, ct_b64) = sealed.split_once('.').ok_or_else(malformed)?;
    let nonce = BASE64_URL_SAFE_NO_PAD
        .decode(nonce_b64)
        .map_err(|_| malformed())?;
    let ciphertext = BASE64_URL_SAFE_NO_PAD
        .decode(ct_b64)
        .map_err(|_| malformed())?;
    let plain = cipher.decrypt_with_aad(&ciphertext, &nonce, &pending_totp_aad(user_id))?;
    Ok(zeroize::Zeroizing::new(plain.as_bytes().to_vec()))
}

/// Derives the RFC 7636 `S256` PKCE `code_challenge` for a `code_verifier`
/// (`BASE64URL(SHA256(verifier))`, unpadded).
#[must_use]
pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

/// Computes the SHA-256 hex digest of a raw token.
#[must_use]
pub fn hash_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for &b in &digest {
        for nibble in [b >> 4, b & 0x0F] {
            hex.push(char::from(
                HEX_CHARS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
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
            if let Some(&c) = BASE32_ALPHABET.get(index) {
                result.push(char::from(c));
            }
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        if let Some(&c) = BASE32_ALPHABET.get(index) {
            result.push(char::from(c));
        }
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
/// Returns `(plaintext_codes, keyed_hashes)`; each hash is computed by
/// [`SecretCipher::backup_code_hash`] (HMAC under a server-side key).
///
/// # Errors
///
/// Returns [`PortError`] if the keyed digest cannot be computed.
pub fn generate_backup_codes(
    count: usize,
    cipher: &dyn SecretCipher,
) -> Result<(Vec<String>, Vec<String>), PortError> {
    let mut plaintexts = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    let mut rng = rand::rng();

    for _ in 0..count {
        let mut code = String::with_capacity(8);
        for _ in 0..8 {
            let idx = rng.random_range(0..BACKUP_CODE_ALPHABET.len());
            if let Some(&c) = BACKUP_CODE_ALPHABET.get(idx) {
                code.push(char::from(c));
            }
        }
        hashes.push(cipher.backup_code_hash(&code)?);
        plaintexts.push(code);
    }

    Ok((plaintexts, hashes))
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
    fn pkce_s256_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
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
    fn test_generate_backup_codes() -> Result<(), PortError> {
        struct PrefixCipher;
        impl SecretCipher for PrefixCipher {
            fn encrypt_with_aad(
                &self,
                _plaintext: &[u8],
                _aad: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), PortError> {
                Err(PortError::crypto("unused"))
            }
            fn decrypt_with_aad(
                &self,
                _ciphertext: &[u8],
                _nonce: &[u8],
                _aad: &[u8],
            ) -> Result<crate::ports::services::DecryptedSecret, PortError> {
                Err(PortError::crypto("unused"))
            }
            fn backup_code_hash(&self, code: &str) -> Result<String, PortError> {
                Ok(format!("keyed:{code}"))
            }
        }

        let (plain, hashes) = generate_backup_codes(10, &PrefixCipher)?;
        assert_eq!(plain.len(), 10);
        assert_eq!(hashes.len(), 10);
        for (p, h) in plain.iter().zip(hashes.iter()) {
            assert_eq!(p.len(), 8);
            assert_eq!(&format!("keyed:{p}"), h);
        }
        Ok(())
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
