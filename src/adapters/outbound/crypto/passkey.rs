//! WebAuthn / FIDO2 Passkey adapter implementation using `webauthn-rs`.

use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::domain::entities::Passkey;
use crate::domain::value_objects::UserId;
use crate::ports::errors::PortError;
use crate::ports::services::WebAuthnService;

/// Outbound adapter wrapping `webauthn-rs` to conduct WebAuthn ceremonies.
#[derive(Clone)]
pub struct WebauthnRsAdapter {
    webauthn: Arc<Webauthn>,
}

impl std::fmt::Debug for WebauthnRsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebauthnRsAdapter").finish_non_exhaustive()
    }
}

impl WebauthnRsAdapter {
    /// Constructs a new [`WebauthnRsAdapter`] from relying party configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PortError::external`] if the origin cannot be parsed or Relying Party setup fails.
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self, PortError> {
        let origin_url = Url::parse(rp_origin).map_err(|e| {
            PortError::external_service(
                "webauthn",
                format!("failed to parse rp_origin '{rp_origin}': {e}"),
                None,
            )
        })?;

        let builder = WebauthnBuilder::new(rp_id, &origin_url).map_err(|e| {
            PortError::external_service(
                "webauthn",
                format!("failed to initialize WebauthnBuilder: {e}"),
                None,
            )
        })?;

        let webauthn = builder.build().map_err(|e| {
            PortError::external_service(
                "webauthn",
                format!("failed to build Webauthn instance: {e}"),
                None,
            )
        })?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
        })
    }
}

impl WebAuthnService for WebauthnRsAdapter {
    fn start_registration(
        &self,
        user_id: &UserId,
        username: &str,
        existing_passkeys: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError> {
        let exclude_credentials = if existing_passkeys.is_empty() {
            None
        } else {
            let ids: Vec<_> = existing_passkeys
                .iter()
                .map(|p| p.credential_id.clone().into())
                .collect();
            Some(ids)
        };

        let user_uuid = user_id.as_uuid();
        self.webauthn
            .start_passkey_registration(user_uuid, username, username, exclude_credentials)
            .map_err(|e| {
                PortError::external_service(
                    "webauthn",
                    format!("failed to start passkey registration: {e}"),
                    None,
                )
            })
    }

    fn finish_registration(
        &self,
        reg_response: &RegisterPublicKeyCredential,
        reg_state: &PasskeyRegistration,
    ) -> Result<WebauthnPasskey, PortError> {
        self.webauthn
            .finish_passkey_registration(reg_response, reg_state)
            .map_err(|e| {
                PortError::external_service(
                    "webauthn",
                    format!("failed to finish passkey registration: {e}"),
                    None,
                )
            })
    }

    fn start_discoverable_login(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PortError> {
        self.webauthn
            .start_discoverable_authentication()
            .map_err(|e| {
                PortError::external_service(
                    "webauthn",
                    format!("failed to start discoverable passkey authentication: {e}"),
                    None,
                )
            })
    }

    fn finish_discoverable_login(
        &self,
        auth_response: &PublicKeyCredential,
        auth_state: DiscoverableAuthentication,
        candidate_passkeys: &[Passkey],
    ) -> Result<(AuthenticationResult, WebauthnPasskey), PortError> {
        let creds: Vec<DiscoverableKey> = candidate_passkeys
            .iter()
            .filter_map(|p| {
                serde_json::from_value::<WebauthnPasskey>(p.passkey_json.clone())
                    .ok()
                    .map(DiscoverableKey::from)
            })
            .collect();

        if creds.is_empty() {
            return Err(PortError::not_found("Passkey"));
        }

        let auth_result = self
            .webauthn
            .finish_discoverable_authentication(auth_response, auth_state, &creds)
            .map_err(|e| {
                PortError::external_service(
                    "webauthn",
                    format!("failed to finish discoverable passkey authentication: {e}"),
                    None,
                )
            })?;

        // Locate and update the matched passkey
        let mut matched = None;
        for pk in candidate_passkeys {
            if let Ok(mut parsed) =
                serde_json::from_value::<WebauthnPasskey>(pk.passkey_json.clone())
                && parsed.cred_id().as_slice() == auth_result.cred_id().as_slice()
            {
                let _ = parsed.update_credential(&auth_result);
                matched = Some(parsed);
                break;
            }
        }

        let passkey = matched.ok_or_else(|| PortError::not_found("Passkey"))?;

        Ok((auth_result, passkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_origin_returns_error() {
        let adapter = WebauthnRsAdapter::new("localhost", "not a url");
        assert!(adapter.is_err());
    }

    #[test]
    fn valid_origin_constructs_adapter() {
        let adapter = WebauthnRsAdapter::new("localhost", "http://localhost:8080");
        assert!(adapter.is_ok());
    }

    #[test]
    fn start_registration_creates_challenge_and_serializes()
    -> Result<(), Box<dyn std::error::Error>> {
        let adapter = WebauthnRsAdapter::new("localhost", "http://localhost:8080")?;
        let user_id = UserId::new();
        let (chal, reg_state) = adapter.start_registration(&user_id, "testuser", &[])?;

        assert!(!chal.public_key.challenge.is_empty());

        // Verify serializability for Redis challenge caching
        let serialized = serde_json::to_string(&reg_state)?;
        let deserialized: PasskeyRegistration = serde_json::from_str(&serialized)?;
        assert_eq!(
            serde_json::to_string(&reg_state)?,
            serde_json::to_string(&deserialized)?
        );
        Ok(())
    }

    #[test]
    fn start_discoverable_login_creates_challenge_and_serializes()
    -> Result<(), Box<dyn std::error::Error>> {
        let adapter = WebauthnRsAdapter::new("localhost", "http://localhost:8080")?;
        let (chal, auth_state) = adapter.start_discoverable_login()?;

        assert!(!chal.public_key.challenge.is_empty());

        // Verify serializability for Redis challenge caching
        let serialized = serde_json::to_string(&auth_state)?;
        let deserialized: DiscoverableAuthentication = serde_json::from_str(&serialized)?;
        assert_eq!(
            serde_json::to_string(&auth_state)?,
            serde_json::to_string(&deserialized)?
        );
        Ok(())
    }

    #[test]
    fn passkey_and_auth_result_roundtrip_from_json() {
        let ser_auth_result = serde_json::json!({
            "cred_id": "uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ",
            "needs_update": false,
            "user_verified": true,
            "backup_state": false,
            "backup_eligible": false,
            "counter": 3,
            "extensions": {}
        });
        let auth_res: Result<AuthenticationResult, _> = serde_json::from_value(ser_auth_result);
        assert!(
            auth_res.is_ok(),
            "failed to parse auth_res: {:?}",
            auth_res.err()
        );

        let ser_passkey = serde_json::json!({
            "cred": {
                "cred_id": "uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ",
                "cred": {
                    "type_": "ES256",
                    "key": {
                        "EC_EC2": {
                            "curve": "SECP256R1",
                            "x": [194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],
                            "y": [143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]
                        }
                    }
                },
                "counter": 2,
                "user_verified": false,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "preferred",
                "extensions": {
                    "cred_protect": "NotRequested",
                    "hmac_create_secret": "NotRequested"
                },
                "attestation": {
                    "data": { "None": null },
                    "metadata": "None"
                },
                "attestation_format": "None"
            }
        });
        let passkey: Result<WebauthnPasskey, _> = serde_json::from_value(ser_passkey);
        assert!(
            passkey.is_ok(),
            "failed to parse passkey: {:?}",
            passkey.err()
        );
    }
}
