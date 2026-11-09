//! Ed25519 asymmetric JWT signer, verifier, and RFC 7517/8037 JWKS generator.

use std::collections::HashMap;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ports::errors::PortError;
use crate::ports::services::{AccessTokenClaims, TokenSigner};

/// JOSE header for RFC 9068 Access Tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// Asymmetric Ed25519 JWT service implementing [`TokenSigner`].
#[derive(Clone)]
pub struct Ed25519JwtService {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    verifying_keys: HashMap<String, VerifyingKey>,
    kid: String,
}

impl std::fmt::Debug for Ed25519JwtService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519JwtService")
            .field("kid", &self.kid)
            .field("signing_key", &"[REDACTED]")
            .field("verifying_keys_count", &self.verifying_keys.len())
            .finish()
    }
}

impl Ed25519JwtService {
    /// Creates an [`Ed25519JwtService`] with an active signing key and optional additional verifying keys.
    #[must_use]
    pub fn new(
        signing_key: SigningKey,
        kid: Option<String>,
        additional_keys: HashMap<String, VerifyingKey>,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let kid = kid.unwrap_or_else(|| Self::compute_kid(&verifying_key));
        let mut verifying_keys = additional_keys;
        verifying_keys.insert(kid.clone(), verifying_key);

        Self {
            signing_key,
            verifying_key,
            verifying_keys,
            kid,
        }
    }

    /// Loads an [`Ed25519JwtService`] from a PKCS#8 PEM string.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the PEM cannot be decoded as a valid Ed25519 private key.
    pub fn from_pkcs8_pem(pem: &str, kid: Option<String>) -> Result<Self, PortError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| PortError::crypto(format!("failed to parse Ed25519 PKCS#8 PEM: {e}")))?;
        let verifying_key = signing_key.verifying_key();
        let kid = kid.unwrap_or_else(|| Self::compute_kid(&verifying_key));
        let mut verifying_keys = HashMap::new();
        verifying_keys.insert(kid.clone(), verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            verifying_keys,
            kid,
        })
    }

    /// Generates a fresh random Ed25519 key pair (useful for tests and ephemeral environments).
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if key generation fails.
    pub fn generate(kid: Option<String>) -> Result<Self, PortError> {
        let mut rng = rand::rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let kid = kid.unwrap_or_else(|| Self::compute_kid(&verifying_key));
        let mut verifying_keys = HashMap::new();
        verifying_keys.insert(kid.clone(), verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            verifying_keys,
            kid,
        })
    }

    /// Registers an additional verifying public key for key rotation verification.
    pub fn add_verifying_key(&mut self, kid: impl Into<String>, key: VerifyingKey) {
        self.verifying_keys.insert(kid.into(), key);
    }

    /// Builder method to register an additional verifying public key.
    #[must_use]
    pub fn with_verifying_key(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.add_verifying_key(kid, key);
        self
    }

    /// Returns all registered verifying keys.
    #[must_use]
    pub fn verifying_keys(&self) -> &HashMap<String, VerifyingKey> {
        &self.verifying_keys
    }

    /// Computes an RFC 7638 SHA-256 thumbprint as key identifier (`kid`).
    fn compute_kid(verifying_key: &VerifyingKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.to_bytes());
        let digest = hasher.finalize();
        BASE64_URL_SAFE_NO_PAD.encode(&digest[..16])
    }

    /// Returns the active Key Identifier.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the active public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl TokenSigner for Ed25519JwtService {
    fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, PortError> {
        let header = JwtHeader {
            alg: "EdDSA".to_string(),
            typ: Some("at+jwt".to_string()),
            kid: Some(self.kid.clone()),
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| PortError::crypto(format!("failed to serialize JWT header: {e}")))?;
        let payload_json = serde_json::to_vec(claims)
            .map_err(|e| PortError::crypto(format!("failed to serialize JWT claims: {e}")))?;

        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, PortError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(PortError::security(
                "malformed JWT: expected 3 dot-separated segments",
            ));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let sig_b64 = parts[2];

        let header_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| PortError::security(format!("invalid JWT header base64url: {e}")))?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| PortError::security(format!("invalid JWT header JSON: {e}")))?;

        if header.alg != "EdDSA" {
            return Err(PortError::security(format!(
                "unsupported JWT alg '{}', expected 'EdDSA'",
                header.alg
            )));
        }

        match header.typ.as_deref() {
            Some("at+jwt") | Some("application/at+jwt") => {}
            Some(typ) => {
                return Err(PortError::security(format!(
                    "invalid JWT typ '{typ}', expected 'at+jwt'"
                )));
            }
            None => {
                return Err(PortError::security(
                    "missing or empty JWT typ header parameter, expected 'at+jwt'",
                ));
            }
        }

        let kid = match &header.kid {
            Some(k) if !k.trim().is_empty() => k,
            _ => {
                return Err(PortError::security(
                    "missing or empty JWT key identifier ('kid')",
                ));
            }
        };

        let verifying_key = self.verifying_keys.get(kid).ok_or_else(|| {
            PortError::security(format!("unknown JWT key identifier ('kid'): {kid}"))
        })?;

        let sig_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PortError::security(format!("invalid JWT signature base64url: {e}")))?;

        let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
            PortError::security(format!("invalid Ed25519 signature length/format: {e}"))
        })?;

        let signing_input = &token.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];
        verifying_key
            .verify(signing_input, &signature)
            .map_err(|e| PortError::security(format!("JWT signature verification failed: {e}")))?;

        let payload_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| PortError::security(format!("invalid JWT payload base64url: {e}")))?;

        let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| PortError::security(format!("invalid JWT claims payload: {e}")))?;

        if claims.iss.trim().is_empty() {
            return Err(PortError::security("missing or empty JWT issuer ('iss')"));
        }
        if claims.aud.trim().is_empty() {
            return Err(PortError::security("missing or empty JWT audience ('aud')"));
        }
        if claims.jti.trim().is_empty() {
            return Err(PortError::security(
                "missing or empty JWT identifier ('jti')",
            ));
        }
        if claims.exp <= claims.iat {
            return Err(PortError::security(
                "invalid JWT lifetime: exp must be greater than iat",
            ));
        }

        let now = Utc::now();
        if claims.iat > now.timestamp() + 60 {
            return Err(PortError::security(
                "JWT issued in the future (iat clock drift exceeded)",
            ));
        }
        if claims.auth_time <= 0 {
            return Err(PortError::security(
                "missing or invalid JWT auth_time ('auth_time')",
            ));
        }
        if claims.auth_time > now.timestamp() + 60 {
            return Err(PortError::security(
                "JWT auth_time in the future (auth_time clock drift exceeded)",
            ));
        }
        if claims.auth_time > claims.iat + 60 {
            return Err(PortError::security(
                "invalid JWT auth_time: auth_time cannot be greater than iat",
            ));
        }
        for method in &claims.amr {
            if method.trim().is_empty() {
                return Err(PortError::security("invalid empty method in JWT amr claim"));
            }
        }
        if claims.is_expired(now) {
            return Err(PortError::security("access token has expired"));
        }

        Ok(claims)
    }

    fn public_key_jwks(&self) -> Result<serde_json::Value, PortError> {
        let mut sorted_keys: Vec<(&String, &VerifyingKey)> = self.verifying_keys.iter().collect();
        sorted_keys.sort_by(|(k1, _), (k2, _)| {
            if *k1 == &self.kid {
                std::cmp::Ordering::Less
            } else if *k2 == &self.kid {
                std::cmp::Ordering::Greater
            } else {
                k1.cmp(k2)
            }
        });

        let mut keys = Vec::with_capacity(sorted_keys.len());
        for (kid, key) in sorted_keys {
            let x = BASE64_URL_SAFE_NO_PAD.encode(key.to_bytes());
            keys.push(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": x
            }));
        }

        Ok(serde_json::json!({ "keys": keys }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::{SessionId, UserId};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn signs_and_verifies_access_token() -> TestResult {
        let service = Ed25519JwtService::generate(Some("test-key-1".to_string()))?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp() - 10,
            amr: vec!["pwd".to_string(), "mfa".to_string()],
        };

        let token = service.sign_access_token(&claims)?;
        assert_eq!(token.split('.').count(), 3);

        let verified = service.verify_access_token(&token)?;
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.sid, claims.sid);
        assert_eq!(verified.iss, claims.iss);
        assert_eq!(verified.aud, claims.aud);
        assert_eq!(verified.exp, claims.exp);
        assert_eq!(verified.auth_time, claims.auth_time);
        assert_eq!(verified.amr, vec!["pwd", "mfa"]);
        Ok(())
    }

    #[test]
    fn rejects_expired_token() -> TestResult {
        let service = Ed25519JwtService::generate(None)?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() - 60, // already expired
            iat: now.timestamp() - 120,
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp() - 200,
            amr: vec!["pwd".to_string()],
        };

        let token = service.sign_access_token(&claims)?;
        let err = service.verify_access_token(&token);
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn rejects_tampered_token() -> TestResult {
        let service = Ed25519JwtService::generate(None)?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["passkey".to_string()],
        };

        let token = service.sign_access_token(&claims)?;
        let tampered = format!("{token}tampered");
        let err = service.verify_access_token(&tampered);
        assert!(err.is_err());
        Ok(())
    }

    #[test]
    fn rejects_invalid_auth_time() -> TestResult {
        let service = Ed25519JwtService::generate(None)?;
        let now = Utc::now();

        // auth_time <= 0
        let claims_zero = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: 0,
            amr: vec!["pwd".to_string()],
        };
        let token_zero = service.sign_access_token(&claims_zero)?;
        assert!(service.verify_access_token(&token_zero).is_err());

        // auth_time in future
        let claims_future = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp() + 300,
            amr: vec!["pwd".to_string()],
        };
        let token_future = service.sign_access_token(&claims_future)?;
        assert!(service.verify_access_token(&token_future).is_err());

        // auth_time > iat
        let claims_after_iat = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp() - 100,
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };
        let token_after_iat = service.sign_access_token(&claims_after_iat)?;
        assert!(service.verify_access_token(&token_after_iat).is_err());

        Ok(())
    }

    #[test]
    fn rejects_empty_amr_elements() -> TestResult {
        let service = Ed25519JwtService::generate(None)?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["".to_string()],
        };
        let token = service.sign_access_token(&claims)?;
        assert!(service.verify_access_token(&token).is_err());
        Ok(())
    }

    #[test]
    fn generates_standard_jwks() -> TestResult {
        let service = Ed25519JwtService::generate(Some("custom-kid".to_string()))?;
        let jwks = service.public_key_jwks()?;
        assert_eq!(jwks["keys"][0]["kty"], "OKP");
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
        assert_eq!(jwks["keys"][0]["alg"], "EdDSA");
        assert_eq!(jwks["keys"][0]["use"], "sig");
        assert_eq!(jwks["keys"][0]["kid"], "custom-kid");
        assert!(jwks["keys"][0]["x"].as_str().is_some());
        Ok(())
    }

    #[test]
    fn verifies_token_with_rotated_verifying_key() -> TestResult {
        // Generate active service with kid "key-active"
        let mut active_service = Ed25519JwtService::generate(Some("key-active".to_string()))?;

        // Generate older service with kid "key-v1"
        let older_service = Ed25519JwtService::generate(Some("key-v1".to_string()))?;

        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp() - 10,
            amr: vec!["pwd".to_string(), "mfa".to_string()],
        };

        // Token signed with older key
        let token_v1 = older_service.sign_access_token(&claims)?;

        // Active service without older verifying key fails with unknown kid error
        let err = active_service.verify_access_token(&token_v1);
        let err_msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err_msg.contains("unknown JWT key identifier ('kid'): key-v1"));

        // Register older key into active service
        active_service.add_verifying_key("key-v1", *older_service.verifying_key());

        // Active service can now successfully verify the older token
        let verified = active_service.verify_access_token(&token_v1)?;
        assert_eq!(verified.sub, claims.sub);
        assert_eq!(verified.sid, claims.sid);

        // Active service can still sign and verify its own active tokens
        let token_active = active_service.sign_access_token(&claims)?;
        let verified_active = active_service.verify_access_token(&token_active)?;
        assert_eq!(verified_active.sub, claims.sub);

        Ok(())
    }

    #[test]
    fn jwks_exports_all_keys_with_active_first() -> TestResult {
        let service_1 = Ed25519JwtService::generate(Some("active-key".to_string()))?;
        let service_2 = Ed25519JwtService::generate(Some("older-key-a".to_string()))?;
        let service_3 = Ed25519JwtService::generate(Some("older-key-b".to_string()))?;

        let service = service_1
            .with_verifying_key("older-key-a", *service_2.verifying_key())
            .with_verifying_key("older-key-b", *service_3.verifying_key());

        let jwks = service.public_key_jwks()?;
        let keys = match jwks["keys"].as_array() {
            Some(k) => k,
            None => return Err("JWKS 'keys' must be an array".into()),
        };
        assert_eq!(keys.len(), 3);

        // Active key must be at index 0
        assert_eq!(keys[0]["kid"], "active-key");
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["use"], "sig");
        assert!(keys[0]["x"].as_str().is_some());

        // Additional keys sorted deterministically
        assert_eq!(keys[1]["kid"], "older-key-a");
        assert_eq!(keys[2]["kid"], "older-key-b");

        Ok(())
    }

    #[test]
    fn rejects_token_with_missing_or_empty_kid() -> TestResult {
        let service = Ed25519JwtService::generate(Some("key-1".to_string()))?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        // Header without 'kid'
        let header_missing_kid = serde_json::json!({
            "alg": "EdDSA",
            "typ": "at+jwt"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_missing_kid)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = service.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token_missing = format!("{signing_input}.{sig_b64}");

        let err = service.verify_access_token(&token_missing);
        let err_msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err_msg.contains("missing or empty JWT key identifier ('kid')"));

        // Header with empty 'kid'
        let header_empty_kid = serde_json::json!({
            "alg": "EdDSA",
            "typ": "at+jwt",
            "kid": ""
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_empty_kid)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = service.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token_empty = format!("{signing_input}.{sig_b64}");

        let err = service.verify_access_token(&token_empty);
        let err_msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err_msg.contains("missing or empty JWT key identifier ('kid')"));

        Ok(())
    }

    #[test]
    fn rejects_token_with_mismatched_key_signature() -> TestResult {
        let service_a = Ed25519JwtService::generate(Some("key-a".to_string()))?;
        let service_b = Ed25519JwtService::generate(Some("key-b".to_string()))?;

        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        // Header claims kid is "key-a", but signature is created using service_b's private key
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "at+jwt",
            "kid": "key-a"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = service_b.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let spoofed_token = format!("{signing_input}.{sig_b64}");

        // Verification against service_a should fail signature check
        let err = service_a.verify_access_token(&spoofed_token);
        let err_msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err_msg.contains("JWT signature verification failed"));

        Ok(())
    }

    #[test]
    fn rejects_token_with_missing_typ() -> TestResult {
        let service = Ed25519JwtService::generate(Some("test-key-1".to_string()))?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let header = serde_json::json!({
            "alg": "EdDSA",
            "kid": "test-key-1"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = service.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let err = service.verify_access_token(&token);
        let err_msg = match err {
            Err(e) => e.to_string(),
            Ok(_) => return Err("expected error for missing typ".into()),
        };
        assert!(err_msg.contains("missing or empty JWT typ header parameter, expected 'at+jwt'"));
        Ok(())
    }

    #[test]
    fn rejects_token_with_invalid_typ() -> TestResult {
        let service = Ed25519JwtService::generate(Some("test-key-1".to_string()))?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        for invalid_typ in &["JWT", "refresh+jwt", "id+jwt", ""] {
            let header = serde_json::json!({
                "alg": "EdDSA",
                "typ": invalid_typ,
                "kid": "test-key-1"
            });
            let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
            let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signature = service.signing_key.sign(signing_input.as_bytes());
            let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
            let token = format!("{signing_input}.{sig_b64}");

            let err = service.verify_access_token(&token);
            assert!(
                err.is_err(),
                "expected error for invalid typ '{invalid_typ}'"
            );
            let err_msg = match err {
                Err(e) => e.to_string(),
                Ok(_) => return Err("expected error".into()),
            };
            assert!(err_msg.contains("invalid JWT typ"));
        }
        Ok(())
    }

    #[test]
    fn accepts_token_with_application_at_jwt_typ() -> TestResult {
        let service = Ed25519JwtService::generate(Some("test-key-1".to_string()))?;
        let now = Utc::now();
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "https://auth.korgan.local".to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "application/at+jwt",
            "kid": "test-key-1"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = service.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let verified = service.verify_access_token(&token)?;
        assert_eq!(verified.sub, claims.sub);
        Ok(())
    }
}
