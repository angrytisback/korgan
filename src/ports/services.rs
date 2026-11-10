//! External capability ports: password hashing, asymmetric JWT signing,
//! mail delivery, breached-password screening, and TOTP.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::entities::{OAuthProvider, Passkey};
use crate::domain::value_objects::{EmailAddress, PasswordHash, RawPassword, SessionId, UserId};
use crate::ports::errors::PortError;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

/// RFC 9068 claims for asymmetric EdDSA Access Tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject: user identifier.
    pub sub: UserId,
    /// Session identifier: ties access token directly to the stateful session.
    pub sid: SessionId,
    /// Issuer URL.
    pub iss: String,
    /// Audience identifier.
    pub aud: String,
    /// Expiration time (seconds since Unix epoch).
    pub exp: i64,
    /// Issued-at time (seconds since Unix epoch).
    pub iat: i64,
    /// Unique JWT identifier (UUIDv7 string).
    pub jti: String,
    /// Time when the user originally authenticated (RFC 7519 / OIDC Core, seconds since Unix epoch).
    /// Unchanging even across refresh token rotations.
    pub auth_time: i64,
    /// Authentication Methods References (RFC 8176). E.g. `["pwd"]`, `["pwd", "mfa"]`, `["passkey"]`.
    #[serde(default)]
    pub amr: Vec<String>,
}

impl AccessTokenClaims {
    /// Checks if this token is currently expired against `now`.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
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

/// Asymmetric Ed25519 (EdDSA) JWT signer and verifier port.
pub trait TokenSigner: Send + Sync + 'static {
    /// Issues and signs a JWT access token using the Ed25519 private key.
    fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, PortError>;

    /// Verifies signature, expiration, and format of an access token, returning its claims.
    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, PortError>;

    /// Exports the public key in standard RFC 7517 JWKS JSON format (`/.well-known/jwks.json`).
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
    fn generate_secret(&self) -> Result<Vec<u8>, PortError>;

    /// Generates an inline SVG QR code for authenticator apps (Google, Microsoft, Authy).
    fn generate_qr_code_svg(
        &self,
        email: &EmailAddress,
        secret: &[u8],
        issuer: &str,
    ) -> Result<String, PortError>;

    /// Verifies a 6-digit TOTP code against a secret with +/-1 step clock-drift tolerance.
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
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Exposes the inner secret bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the secret in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the secret buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Clones the inner bytes into an unmanaged [`Vec<u8>`].
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl std::ops::Deref for DecryptedSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for DecryptedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for DecryptedSecret {
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
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        self.encrypt_with_aad(plaintext, b"")
    }

    /// Decrypts ciphertext bytes using the provided nonce.
    ///
    /// Returns a [`DecryptedSecret`] which zeroizes on drop.
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<DecryptedSecret, PortError> {
        self.decrypt_with_aad(ciphertext, nonce, b"")
    }

    /// Encrypts plaintext bytes using authenticated encryption, a fresh nonce, and associated data (AAD).
    ///
    /// Returns `(ciphertext, nonce)`.
    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PortError>;

    /// Decrypts ciphertext bytes using the provided nonce and associated data (AAD).
    ///
    /// Returns a [`DecryptedSecret`] which zeroizes on drop.
    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<DecryptedSecret, PortError>;
}

/// External user profile fetched from an OAuth2 / OIDC provider.
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

/// Outbound adapter port for communicating with external OAuth2 identity providers.
#[async_trait]
pub trait OAuthProviderPort: Send + Sync + 'static {
    /// Returns the provider type handled by this adapter.
    fn provider(&self) -> OAuthProvider;

    /// Builds the authorization redirect URL with anti-CSRF `state`.
    fn build_authorization_url(&self, state: &str) -> String;

    /// Exchanges the authorization `code` for user profile claims.
    async fn exchange_code(&self, code: &str) -> Result<OAuthProfile, PortError>;
}

/// External service port for WebAuthn / FIDO2 Passkey ceremonies.
pub trait WebAuthnService: Send + Sync + 'static {
    /// Generates a WebAuthn registration creation challenge for a user.
    fn start_registration(
        &self,
        user_id: &UserId,
        username: &str,
        existing_passkeys: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError>;

    /// Completes registration challenge verification, returning the verified passkey credential.
    fn finish_registration(
        &self,
        reg_response: &RegisterPublicKeyCredential,
        reg_state: &PasskeyRegistration,
    ) -> Result<WebauthnPasskey, PortError>;

    /// Generates a discoverable WebAuthn authentication challenge.
    fn start_discoverable_login(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PortError>;

    /// Completes discoverable login assertion verification.
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
        assert_eq!(secret.to_vec(), vec![1, 2, 3, 4, 5]);
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
}
