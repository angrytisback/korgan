//! DTOs for WebAuthn / Passkeys use cases.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::domain::value_objects::{PasskeyId, RequestId};

/// Result returned when starting passkey registration ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationStartResult {
    /// Opaque challenge identifier used to link finish request to the cached challenge.
    pub challenge_id: Uuid,
    /// WebAuthn creation challenge options for the client authenticator.
    pub options: CreationChallengeResponse,
}

/// Command for finishing passkey registration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PasskeyRegistrationFinishCommand {
    /// Challenge identifier obtained during registration start.
    pub challenge_id: Uuid,
    /// Optional user-provided device label (e.g. "Work MacBook", "YubiKey 5C").
    #[validate(length(
        min = 1,
        max = 100,
        message = "passkey name must be between 1 and 100 characters"
    ))]
    pub name: Option<String>,
    /// WebAuthn public key credential response produced by the authenticator.
    pub credential: RegisterPublicKeyCredential,
}

/// Result returned when passkey registration successfully completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRegistrationFinishResult {
    /// Newly registered passkey identifier.
    pub id: PasskeyId,
    /// Assigned passkey name.
    pub name: String,
    /// Registration timestamp.
    pub created_at: DateTime<Utc>,
}

/// Result returned when starting discoverable passkey login ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyLoginStartResult {
    /// Opaque challenge identifier used to link finish request to the cached challenge.
    pub challenge_id: Uuid,
    /// WebAuthn request challenge options for discoverable passkey assertion.
    pub options: RequestChallengeResponse,
}

/// Command for finishing discoverable passkey login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyLoginFinishCommand {
    /// Challenge identifier obtained during login start.
    pub challenge_id: Uuid,
    /// WebAuthn assertion response produced by the authenticator.
    pub credential: PublicKeyCredential,
    /// Client IP address.
    pub ip_address: IpAddr,
    /// Client User-Agent string.
    pub user_agent: Option<String>,
    /// Client device description.
    pub device_name: Option<String>,
    /// Correlation request identifier.
    pub request_id: RequestId,
}

/// Item representation for listing registered passkeys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyItemResult {
    /// Unique passkey identifier.
    pub id: PasskeyId,
    /// User-friendly label.
    pub name: String,
    /// Timestamp when this passkey was last used, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Timestamp when this passkey was registered.
    pub created_at: DateTime<Utc>,
}
