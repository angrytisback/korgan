//! Cryptography adapters: Argon2id hashing, Ed25519 JWT signing + JWKS,
//! AES-256-GCM secret encryption and RFC 6238 TOTP.

pub mod aes;
pub mod argon2;
pub mod jwt;
pub mod passkey;
pub mod password;
pub mod totp;

pub use crate::ports::services::DecryptedSecret;
pub use aes::{AES_256_KEY_LEN, AES_GCM_NONCE_LEN, Aes256GcmCipher};
pub use argon2::Argon2PasswordHasher;
pub use jwt::Ed25519JwtService;
pub use passkey::WebauthnRsAdapter;
pub use totp::{DEFAULT_TOTP_SECRET_BYTES, Rfc6238TotpService};
