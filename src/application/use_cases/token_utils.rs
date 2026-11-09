//! Cryptographic token utilities for opaque security tokens, Base32 encoding,
//! and backup codes.

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BACKUP_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Generates 32 bytes of CSPRNG entropy.
///
/// Returns:
/// - `raw_token`: Base64URL unpadded string given to the user/client
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
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in &digest {
        let _ = write!(hex, "{b:02x}");
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

    for c in input.chars() {
        if c.is_whitespace() || c == '=' {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        let val = match upper {
            'A'..='Z' => (upper as u8) - b'A',
            '2'..='7' => (upper as u8) - b'2' + 26,
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
        assert!(!raw.is_empty());
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
    fn test_generate_backup_codes() {
        let (plain, hashes) = generate_backup_codes(10);
        assert_eq!(plain.len(), 10);
        assert_eq!(hashes.len(), 10);
        for (p, h) in plain.iter().zip(hashes.iter()) {
            assert_eq!(p.len(), 8);
            assert_eq!(&hash_token(p), h);
        }
    }
}
