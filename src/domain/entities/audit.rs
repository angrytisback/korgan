//! Immutable audit trail domain model.

use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::value_objects::{AuditLogId, RequestId, UserId};

/// Status of the audited security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventStatus {
    /// Action succeeded.
    Success,
    /// Action failed (e.g. invalid credentials).
    Failure,
    /// Action was actively blocked by policy or rate limiter.
    Blocked,
}

impl AuditEventStatus {
    /// Returns the static string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for AuditEventStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Well-known audit event types mandated by security standards.
pub mod audit_events {
    /// User registration event.
    pub const REGISTER: &str = "register";
    /// Successful authentication.
    pub const LOGIN_SUCCESS: &str = "login_success";
    /// Failed authentication attempt.
    pub const LOGIN_FAILED: &str = "login_failed";
    /// MFA challenge presented to user.
    pub const MFA_CHALLENGED: &str = "mfa_challenged";
    /// MFA successfully enabled.
    pub const MFA_ENABLED: &str = "mfa_enabled";
    /// MFA disabled.
    pub const MFA_DISABLED: &str = "mfa_disabled";
    /// Password successfully changed.
    pub const PASSWORD_CHANGED: &str = "password_changed";
    /// Forgot password / reset requested.
    pub const PASSWORD_RESET_REQUESTED: &str = "password_reset_requested";
    /// Password reset completed.
    pub const PASSWORD_RESET: &str = "password_reset";
    /// E-mail verification completed.
    pub const EMAIL_VERIFIED: &str = "email_verified";
    /// E-mail address changed.
    pub const EMAIL_CHANGED: &str = "email_changed";
    /// Session explicitly revoked.
    pub const SESSION_REVOKED: &str = "session_revoked";
    /// Replay of an already-rotated refresh token.
    pub const TOKEN_REUSE_DETECTED: &str = "token_reuse_detected";
    /// Account deletion scheduled.
    pub const ACCOUNT_DELETION_SCHEDULED: &str = "account_deletion_scheduled";
    /// Account permanently deleted or purged.
    pub const ACCOUNT_DELETED: &str = "account_deleted";
    /// Passkey successfully registered.
    pub const PASSKEY_REGISTERED: &str = "passkey_registered";
    /// Passkey discoverable authentication success.
    pub const PASSKEY_LOGIN: &str = "passkey_login";
    /// Passkey removed by user.
    pub const PASSKEY_DELETED: &str = "passkey_deleted";
}

/// Immutable security audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLog {
    /// Unique audit log record identifier (UUIDv7).
    pub id: AuditLogId,
    /// Actor user identifier, if authenticated or known.
    pub user_id: Option<UserId>,
    /// Client IP address of the actor.
    pub actor_ip: Option<IpAddr>,
    /// Client `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Correlation request identifier.
    pub request_id: RequestId,
    /// Event type identifier (e.g. `audit_events::LOGIN_SUCCESS`).
    pub event_type: String,
    /// Event outcome status.
    pub event_status: AuditEventStatus,
    /// Structured contextual metadata.
    pub metadata: serde_json::Value,
    /// Cryptographic hash of the previous audit log entry (SHA-256 hex).
    pub prev_hash: Option<String>,
    /// Cryptographic entry hash covering all fields and chaining to `prev_hash` (SHA-256 hex).
    pub entry_hash: Option<String>,
    /// Creation timestamp (TIMESTAMPTZ, UTC).
    pub created_at: DateTime<Utc>,
}

impl AuditLog {
    /// Constructs a fresh audit log entry.
    #[must_use]
    pub fn new(
        user_id: Option<UserId>,
        actor_ip: Option<IpAddr>,
        user_agent: Option<String>,
        request_id: RequestId,
        event_type: impl Into<String>,
        event_status: AuditEventStatus,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: AuditLogId::new(),
            user_id,
            actor_ip,
            user_agent,
            request_id,
            event_type: event_type.into(),
            event_status,
            metadata,
            prev_hash: None,
            entry_hash: None,
            created_at: Utc::now(),
        }
    }

    /// Computes the cryptographic SHA-256 entry hash linking to the optional previous entry hash.
    #[must_use]
    pub fn compute_entry_hash(&self, prev_hash: Option<&str>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.unwrap_or("GENESIS").as_bytes());
        hasher.update(self.id.to_string().as_bytes());
        if let Some(uid) = self.user_id {
            hasher.update(uid.to_string().as_bytes());
        }
        if let Some(ip) = self.actor_ip {
            hasher.update(ip.to_string().as_bytes());
        }
        if let Some(ref ua) = self.user_agent {
            hasher.update(ua.as_bytes());
        }
        hasher.update(self.request_id.to_string().as_bytes());
        hasher.update(self.event_type.as_bytes());
        hasher.update(self.event_status.as_str().as_bytes());
        let meta_str = self.metadata.to_string();
        hasher.update(meta_str.as_bytes());
        hasher.update(self.created_at.timestamp().to_string().as_bytes());

        let digest = hasher.finalize();
        use std::fmt::Write;
        let mut hex = String::with_capacity(64);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// Chains this audit log to the given previous hash by populating `prev_hash` and `entry_hash`.
    pub fn chain_to(&mut self, prev_hash: Option<&str>) {
        self.prev_hash = prev_hash.map(|s| s.to_owned());
        self.entry_hash = Some(self.compute_entry_hash(prev_hash));
    }

    /// Verifies the cryptographic integrity of this audit log entry.
    #[must_use]
    pub fn verify_integrity(&self, expected_prev_hash: Option<&str>) -> bool {
        if self.prev_hash.as_deref() != expected_prev_hash {
            return false;
        }
        match &self.entry_hash {
            Some(entry_hash) => {
                let computed = self.compute_entry_hash(expected_prev_hash);
                subtle::ConstantTimeEq::ct_eq(entry_hash.as_bytes(), computed.as_bytes()).into()
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_creation() {
        let user_id = UserId::new();
        let request_id = RequestId::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

        let log = AuditLog::new(
            Some(user_id),
            Some(ip),
            Some("Firefox".to_owned()),
            request_id,
            audit_events::LOGIN_SUCCESS,
            AuditEventStatus::Success,
            serde_json::json!({ "auth_method": "password" }),
        );

        assert_eq!(log.user_id, Some(user_id));
        assert_eq!(log.actor_ip, Some(ip));
        assert_eq!(log.event_type, "login_success");
        assert_eq!(log.event_status, AuditEventStatus::Success);
        assert_eq!(log.event_status.as_str(), "success");
        assert_eq!(log.request_id, request_id);
    }
}
