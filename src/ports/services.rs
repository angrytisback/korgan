//! External capability ports: password hashing, asymmetric JWT signing,
//! mail delivery, breached-password screening, and TOTP.

use std::borrow::Cow;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::entities::{OAuthProvider, Passkey};
use crate::domain::value_objects::{EmailAddress, PasswordHash, RawPassword, SessionId, UserId};
use crate::ports::errors::PortError;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

/// RFC 9068 claims for asymmetric `EdDSA` Access Tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject: user identifier.
    pub sub: UserId,
    /// Session identifier: ties access token directly to the stateful session.
    pub sid: SessionId,
    /// Issuer URL.
    pub iss: Cow<'static, str>,
    /// Audience identifier.
    pub aud: Cow<'static, str>,
    /// Expiration time (seconds since Unix epoch).
    pub exp: i64,
    /// Issued-at time (seconds since Unix epoch).
    pub iat: i64,
    /// Unique JWT identifier (`UUIDv7` string).
    pub jti: String,
    /// Time when the user originally authenticated (RFC 7519 / OIDC Core, seconds since Unix epoch).
    /// Unchanging even across refresh token rotations.
    pub auth_time: i64,
    /// Authentication Methods References (RFC 8176). E.g. `["pwd"]`, `["pwd", "mfa"]`, `["passkey"]`.
    #[serde(default)]
    pub amr: SmallVec<[Cow<'static, str>; 2]>,
}

impl AccessTokenClaims {
    /// Checks if this token is currently expired against `now`.
    #[inline]
    #[must_use]
    pub const fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.exp <= now.timestamp()
    }
}

/// Asynchronous password hashing and constant-time verification port.
///
/// Implementations must offload heavy Argon2id computations to blocking threads.
#[async_trait]
pub trait PasswordHasher: Send + Sync + 'static {
    /// Hashes a plaintext password using Argon2id with configured parameters.
    async fn hash_password(&self, password: &RawPassword) -> Result<PasswordHash, PortError>;

    /// Verifies a plaintext password against an Argon2id hash in constant time.
    async fn verify_password(
        &self,
        password: &RawPassword,
        hash: &PasswordHash,
    ) -> Result<bool, PortError>;

    /// Executes verification against a pre-computed dummy Argon2id hash to mitigate
    /// timing attacks during login attempts for non-existent accounts.
    async fn verify_against_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError>;

    /// Executes a dummy Argon2id hash computation matching real parameter costs to mitigate
    /// timing attacks during registration attempts when an account conflict occurs.
    async fn compute_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError> {
        let _ = self.hash_password(password).await?;
        Ok(())
    }
}

/// Asymmetric Ed25519 (`EdDSA`) JWT signer and verifier port.
pub trait TokenSigner: Send + Sync + 'static {
    /// Issues and signs a JWT access token using the Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if claims serialization or cryptographic signing fails.
    fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, PortError>;

    /// Verifies signature, expiration, and format of an access token, returning its claims.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the token is malformed, expired, or has an invalid signature.
    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, PortError>;

    /// Exports the public key in standard RFC 7517 JWKS JSON format (`/.well-known/jwks.json`).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the public key cannot be serialized into JWKS format.
    fn public_key_jwks(&self) -> Result<serde_json::Value, PortError>;
}

/// Outbound e-mail notification service port.
#[async_trait]
pub trait MailProvider: Send + Sync + 'static {
    /// Dispatches an e-mail with both plaintext and HTML alternatives.
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), PortError>;
}

/// Have I Been Pwned k-Anonymity range API client port.
#[async_trait]
pub trait HibpClient: Send + Sync + 'static {
    /// Checks whether the password has appeared in known public breaches.
    async fn is_password_breached(&self, password: &RawPassword) -> Result<bool, PortError>;
}

/// RFC 6238 compliant TOTP generator, QR code builder, and validator port.
pub trait TotpService: Send + Sync + 'static {
    /// Generates a high-entropy TOTP secret (CSPRNG bytes).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if entropy generation fails.
    fn generate_secret(&self) -> Result<Vec<u8>, PortError>;

    /// Generates an inline SVG QR code for authenticator apps (Google, Microsoft, Authy).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the `otpauth` URI is invalid or QR SVG rendering fails.
    fn generate_qr_code_svg(
        &self,
        email: &EmailAddress,
        secret: &[u8],
        issuer: &str,
    ) -> Result<String, PortError>;

    /// Verifies a 6-digit TOTP code against a secret with +/-1 step clock-drift tolerance.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the secret length or TOTP configuration is invalid.
    fn verify_code(
        &self,
        secret: &[u8],
        code: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, PortError>;
}

/// Secure buffer for decrypted plaintext secrets that zeroizes on drop.
///
/// Complies strictly with zeroization and credential hygiene policies:
/// - Automatically zeroizes memory on drop via [`ZeroizeOnDrop`].
/// - Redacts inner bytes in both [`std::fmt::Debug`] and [`std::fmt::Display`].
/// - Dereferences directly to `&[u8]` for seamless slice operations without copying.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DecryptedSecret {
    bytes: Vec<u8>,
}

impl DecryptedSecret {
    /// Wraps plaintext bytes in a [`DecryptedSecret`].
    #[inline]
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Exposes the inner secret bytes as a slice.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the secret in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the secret buffer is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::ops::Deref for DecryptedSecret {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for DecryptedSecret {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for DecryptedSecret {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Symmetric authenticated cipher port for encrypting and decrypting secrets at rest (e.g. TOTP secrets).
pub trait SecretCipher: Send + Sync + 'static {
    /// Encrypts plaintext bytes using authenticated encryption and a fresh nonce.
    ///
    /// Returns `(ciphertext, nonce)`.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if encryption or nonce generation fails.
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        self.encrypt_with_aad(plaintext, b"")
    }

    /// Decrypts ciphertext bytes using the provided nonce.
    ///
    /// Returns a [`DecryptedSecret`] which zeroizes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if decryption or authentication tag verification fails.
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<DecryptedSecret, PortError> {
        self.decrypt_with_aad(ciphertext, nonce, b"")
    }

    /// Encrypts plaintext bytes using authenticated encryption, a fresh nonce, and associated data (AAD).
    ///
    /// Returns `(ciphertext, nonce)`.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if encryption or nonce generation fails.
    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PortError>;

    /// Decrypts ciphertext bytes using the provided nonce and associated data (AAD).
    ///
    /// Returns a [`DecryptedSecret`] which zeroizes on drop.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if decryption or authentication tag verification fails.
    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedSecret, PortError>;

    /// Computes the keyed, deterministic digest under which an MFA backup code
    /// is stored and looked up (hex-encoded HMAC-SHA256 with a key derived from
    /// the vault master key). A leaked database alone therefore cannot be used
    /// to brute-force the low-entropy backup codes offline (KRG-SEC-06).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the keyed digest cannot be computed.
    fn backup_code_hash(&self, code: &str) -> Result<String, PortError>;
}

/// External user profile fetched from an `OAuth2` / OIDC provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProfile {
    /// Identity provider source.
    pub provider: OAuthProvider,
    /// Provider-unique stable subject identifier (e.g. Google sub, GitHub id).
    pub provider_user_id: String,
    /// User's primary, verified e-mail address from the provider.
    pub email: EmailAddress,
    /// Optional display name or username.
    pub name: Option<String>,
}

/// Outbound adapter port for communicating with external `OAuth2` identity providers.
#[async_trait]
pub trait OAuthProviderPort: Send + Sync + 'static {
    /// Returns the provider type handled by this adapter.
    fn provider(&self) -> OAuthProvider;

    /// Builds the authorization redirect URL with anti-CSRF `state` and the
    /// RFC 7636 `S256` PKCE `code_challenge`.
    fn build_authorization_url(&self, state: &str, code_challenge: &str) -> String;

    /// Exchanges the authorization `code` (proving possession with the RFC 7636
    /// `code_verifier`) for user profile claims.
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuthProfile, PortError>;
}

/// External service port for WebAuthn / FIDO2 Passkey ceremonies.
pub trait WebAuthnService: Send + Sync + 'static {
    /// Generates a WebAuthn registration creation challenge for a user.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if challenge generation fails.
    fn start_registration(
        &self,
        user_id: &UserId,
        username: &str,
        existing_passkeys: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError>;

    /// Completes registration challenge verification, returning the verified passkey credential.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the attestation response is invalid or fails verification.
    fn finish_registration(
        &self,
        reg_response: &RegisterPublicKeyCredential,
        reg_state: &PasskeyRegistration,
    ) -> Result<WebauthnPasskey, PortError>;

    /// Generates a discoverable WebAuthn authentication challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if challenge generation fails.
    fn start_discoverable_login(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PortError>;

    /// Completes discoverable login assertion verification.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if no candidate passkey matches or signature verification fails.
    fn finish_discoverable_login(
        &self,
        auth_response: &PublicKeyCredential,
        auth_state: DiscoverableAuthentication,
        candidate_passkeys: &[Passkey],
    ) -> Result<(AuthenticationResult, WebauthnPasskey), PortError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_secret_redacts_in_debug_and_display() {
        let secret = DecryptedSecret::new(b"sensitive-secret-token".to_vec());
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn decrypted_secret_derefs_and_slices() {
        let secret = DecryptedSecret::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        assert_eq!(&secret[..2], &[1, 2]);
        assert_eq!(secret.as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(&*secret, &[1, 2, 3, 4, 5]);
        assert_eq!(secret.as_ref(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn decrypted_secret_zeroizes_buffer() {
        let mut secret = DecryptedSecret::new(b"wipe-me-now".to_vec());
        assert_eq!(secret.as_bytes(), b"wipe-me-now");
        assert_eq!(secret.len(), 11);
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
        assert_eq!(secret.as_bytes(), &[0u8; 0]);
    }

    #[test]
    fn access_token_claims_wire_format_parity() -> Result<(), Box<dyn std::error::Error>> {
        let sub = UserId::new();
        let sid = SessionId::new();
        let claims = AccessTokenClaims {
            sub,
            sid,
            iss: Cow::Borrowed("https://auth.korgan.local"),
            aud: Cow::Borrowed("korgan"),
            exp: 1_800_000_000,
            iat: 1_799_999_000,
            jti: "0194b1e0-0000-7000-8000-000000000000".to_owned(),
            auth_time: 1_799_998_500,
            amr: smallvec::smallvec![Cow::Borrowed("pwd"), Cow::Borrowed("mfa")],
        };

        let json: serde_json::Value = serde_json::to_value(&claims)?;
        assert_eq!(json["iss"], "https://auth.korgan.local");
        assert_eq!(json["aud"], "korgan");
        assert_eq!(json["amr"], serde_json::json!(["pwd", "mfa"]));

        let roundtrip: AccessTokenClaims = serde_json::from_value(json)?;
        assert_eq!(roundtrip, claims);
        Ok(())
    }
}
