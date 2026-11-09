//! AES-256-GCM secret vault for encrypting TOTP secrets and sensitive data at rest.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use rand::Rng;
use zeroize::Zeroize;

use crate::ports::errors::PortError;
use crate::ports::services::DecryptedSecret;

/// Nonce length for AES-GCM (96 bits = 12 bytes).
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Key length for AES-256 (256 bits = 32 bytes).
pub const AES_256_KEY_LEN: usize = 32;

/// AES-256-GCM authenticated cipher with automated random nonce generation.
#[derive(Clone)]
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for Aes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmCipher")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

impl Aes256GcmCipher {
    /// Creates a new [`Aes256GcmCipher`] from a 32-byte key slice.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> Result<Self, PortError> {
        if key.len() != AES_256_KEY_LEN {
            return Err(PortError::crypto(format!(
                "AES-256-GCM requires a 32-byte key, provided {} bytes",
                key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            PortError::crypto(format!("failed to initialize AES-256-GCM cipher: {e}"))
        })?;

        Ok(Self { cipher })
    }

    /// Creates an [`Aes256GcmCipher`] by decoding a Base64-encoded 32-byte key string.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if base64 decoding fails or key length is invalid.
    pub fn from_base64(b64_key: &str) -> Result<Self, PortError> {
        let mut key_bytes = BASE64_STANDARD
            .decode(b64_key.trim())
            .map_err(|e| PortError::crypto(format!("invalid AES master key Base64: {e}")))?;

        let cipher_res = Self::new(&key_bytes);
        key_bytes.zeroize();
        cipher_res
    }

    /// Encrypts plaintext using a fresh, CSPRNG-generated 96-bit nonce.
    ///
    /// Returns the combined ciphertext with tag and the 12-byte nonce.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if authenticated encryption fails.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; AES_GCM_NONCE_LEN]), PortError> {
        self.encrypt_with_aad(plaintext, b"")
    }

    /// Encrypts plaintext with associated data (AAD) using a fresh, CSPRNG-generated 96-bit nonce.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if authenticated encryption fails.
    pub fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; AES_GCM_NONCE_LEN]), PortError> {
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from(nonce_bytes);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|e| PortError::crypto(format!("AES-256-GCM encryption failure: {e}")))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypts ciphertext with the supplied 12-byte nonce.
    ///
    /// Returns a [`DecryptedSecret`] which zeroizes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if decryption or authentication tag verification fails.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce_bytes: &[u8; AES_GCM_NONCE_LEN],
    ) -> Result<DecryptedSecret, PortError> {
        self.decrypt_with_aad(ciphertext, nonce_bytes, b"")
    }

    /// Decrypts ciphertext with the supplied 12-byte nonce and associated data (AAD).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if decryption or authentication tag verification fails.
    pub fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce_bytes: &[u8; AES_GCM_NONCE_LEN],
        aad: &[u8],
    ) -> Result<DecryptedSecret, PortError> {
        let nonce = Nonce::from(*nonce_bytes);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        let decrypted = self.cipher.decrypt(&nonce, payload).map_err(|e| {
            PortError::crypto(format!("AES-256-GCM decryption/authentication failed: {e}"))
        })?;

        Ok(DecryptedSecret::new(decrypted))
    }
}

impl crate::ports::services::SecretCipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        let (ct, nonce) = self.encrypt(plaintext)?;
        Ok((ct, nonce.to_vec()))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<DecryptedSecret, PortError> {
        <Self as crate::ports::services::SecretCipher>::decrypt_with_aad(
            self, ciphertext, nonce, b"",
        )
    }

    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        let (ct, nonce) = self.encrypt_with_aad(plaintext, aad)?;
        Ok((ct, nonce.to_vec()))
    }

    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedSecret, PortError> {
        if nonce.len() != AES_GCM_NONCE_LEN {
            return Err(PortError::crypto(format!(
                "invalid AES-GCM nonce length: expected {}, got {}",
                AES_GCM_NONCE_LEN,
                nonce.len()
            )));
        }
        let mut nonce_arr = [0u8; AES_GCM_NONCE_LEN];
        nonce_arr.copy_from_slice(nonce);
        self.decrypt_with_aad(ciphertext, &nonce_arr, aad)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn encrypts_and_decrypts_successfully() -> TestResult {
        let key = [42u8; 32];
        let cipher = Aes256GcmCipher::new(&key)?;

        let plaintext = b"super-secret-totp-key-data-12345";
        let (ciphertext, nonce) = cipher.encrypt(plaintext)?;

        assert_ne!(ciphertext, plaintext);

        let decrypted = cipher.decrypt(&ciphertext, &nonce)?;
        assert_eq!(decrypted.as_bytes(), plaintext);
        Ok(())
    }

    #[test]
    fn generates_unique_nonces_per_encryption() -> TestResult {
        let key = [99u8; 32];
        let cipher = Aes256GcmCipher::new(&key)?;

        let plaintext = b"fixed-plaintext";
        let (_, nonce1) = cipher.encrypt(plaintext)?;
        let (_, nonce2) = cipher.encrypt(plaintext)?;

        assert_ne!(nonce1, nonce2);
        Ok(())
    }

    #[test]
    fn rejects_tampered_ciphertext() -> TestResult {
        let key = [7u8; 32];
        let cipher = Aes256GcmCipher::new(&key)?;

        let (mut ciphertext, nonce) = cipher.encrypt(b"secret")?;
        ciphertext[0] ^= 0xFF; // tamper

        let err = cipher.decrypt(&ciphertext, &nonce);
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn initializes_from_base64() -> TestResult {
        let b64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let cipher = Aes256GcmCipher::from_base64(b64)?;
        let (ct, nonce) = cipher.encrypt(b"data")?;
        let pt = cipher.decrypt(&ct, &nonce)?;
        assert_eq!(pt.as_bytes(), b"data");
        Ok(())
    }

    #[test]
    fn secret_cipher_trait_returns_decrypted_secret() -> TestResult {
        use crate::ports::services::SecretCipher;

        let key = [42u8; 32];
        let cipher: Box<dyn SecretCipher> = Box::new(Aes256GcmCipher::new(&key)?);

        let plaintext = b"secret-payload-to-zeroize";
        let aad = b"user-aad-context";
        let (ciphertext, nonce) = cipher.encrypt_with_aad(plaintext, aad)?;

        let decrypted = cipher.decrypt_with_aad(&ciphertext, &nonce, aad)?;
        assert_eq!(decrypted.as_bytes(), plaintext);
        assert_eq!(format!("{decrypted:?}"), "[REDACTED]");
        Ok(())
    }
}
