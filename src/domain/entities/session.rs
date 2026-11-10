//! Stateful refresh token session domain model.

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::value_objects::{SessionId, TokenFamilyId, UserId};

/// Stateful Session entity backed by the `sessions` table.
///
/// Ties rotated refresh tokens to a device and token family.
/// If an already-replaced session token is presented, the entire family is revoked.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (UUIDv7, embedded as `sid` in Access Tokens).
    pub id: SessionId,
    /// Owner user account.
    pub user_id: UserId,
    /// Groups rotated refresh tokens for reuse detection.
    pub token_family_id: TokenFamilyId,
    /// SHA-256 hash of the opaque refresh token.
    pub refresh_token_hash: String,
    /// Client `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Friendly device name (e.g., "Safari on macOS").
    pub device_name: Option<String>,
    /// Client IP address at time of issue/activity.
    pub ip_address: IpAddr,
    /// Flag indicating whether this session was rotated into a new token.
    pub is_replaced: bool,
    /// Timestamp of most recent activity.
    pub last_active_at: DateTime<Utc>,
    /// Session expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Explicit revocation timestamp, if revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason for revocation (e.g., "user_logout", "token_reuse_detected", "password_reset").
    pub revoke_reason: Option<String>,
    /// Session creation timestamp (initial login time).
    pub created_at: DateTime<Utc>,
    /// Authentication Methods References (RFC 8176). E.g. `["pwd"]`, `["pwd", "mfa"]`, `["passkey"]`.
    #[serde(default)]
    pub amr: Vec<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_family_id", &self.token_family_id)
            .field("refresh_token_hash", &"[REDACTED]")
            .field("user_agent", &self.user_agent)
            .field("device_name", &self.device_name)
            .field("ip_address", &self.ip_address)
            .field("is_replaced", &self.is_replaced)
            .field("last_active_at", &self.last_active_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .field("revoke_reason", &self.revoke_reason)
            .field("created_at", &self.created_at)
            .field("amr", &self.amr)
            .finish()
    }
}

impl Session {
    /// Creates a brand-new session and token family.
    #[must_use]
    pub fn new(
        user_id: UserId,
        refresh_token_hash: String,
        ip_address: IpAddr,
        user_agent: Option<String>,
        device_name: Option<String>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id,
            token_family_id: TokenFamilyId::new(),
            refresh_token_hash,
            user_agent,
            device_name,
            ip_address,
            is_replaced: false,
            last_active_at: now,
            expires_at: now + ttl,
            revoked_at: None,
            revoke_reason: None,
            created_at: now,
            amr: Vec::new(),
        }
    }

    /// Attaches authentication method references (RFC 8176) to this session.
    #[must_use]
    pub fn with_amr(mut self, amr: Vec<String>) -> Self {
        self.amr = amr;
        self
    }

    /// Returns `true` if the session is currently active and can be used/rotated.
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        !self.is_replaced && self.revoked_at.is_none() && self.expires_at > now
    }

    /// Returns `true` if the session has expired.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Returns `true` if the session has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Returns `true` if this session was rotated/replaced within the given `grace_period`.
    ///
    /// Protects against false-positive token family revocation caused by concurrent
    /// browser tab refresh requests presenting the same token before receiving the new cookie.
    #[must_use]
    pub fn is_replaced_within_grace(&self, now: DateTime<Utc>, grace_period: Duration) -> bool {
        if !self.is_replaced {
            return false;
        }
        let elapsed = now.signed_duration_since(self.last_active_at);
        elapsed >= Duration::seconds(-1) && elapsed <= grace_period
    }

    /// Rotates this session into a new child session within the same `token_family_id`.
    ///
    /// The current session is marked as `is_replaced = true`.
    /// The original `created_at` (login timestamp / `auth_time`) and `amr` are preserved
    /// for downstream banking/step-up authorization checks.
    pub fn rotate(
        &mut self,
        new_refresh_token_hash: String,
        ttl: Duration,
        now: DateTime<Utc>,
        ip_address: IpAddr,
        user_agent: Option<String>,
    ) -> Self {
        self.is_replaced = true;
        self.last_active_at = now;

        Self {
            id: SessionId::new(),
            user_id: self.user_id,
            token_family_id: self.token_family_id,
            refresh_token_hash: new_refresh_token_hash,
            user_agent,
            device_name: self.device_name.clone(),
            ip_address,
            is_replaced: false,
            last_active_at: now,
            expires_at: now + ttl,
            revoked_at: None,
            revoke_reason: None,
            created_at: self.created_at,
            amr: self.amr.clone(),
        }
    }

    /// Explicitly revokes this session with a reason.
    pub fn revoke(&mut self, reason: impl Into<String>, now: DateTime<Utc>) {
        self.revoked_at = Some(now);
        self.revoke_reason = Some(reason.into());
    }

    /// Updates the last active timestamp and optionally metadata.
    pub fn update_activity(
        &mut self,
        now: DateTime<Utc>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) {
        self.last_active_at = now;
        if let Some(ip) = ip_address {
            self.ip_address = ip;
        }
        if let Some(ua) = user_agent {
            self.user_agent = Some(ua);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lifecycle_and_rotation() {
        let user_id = UserId::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let ttl = Duration::days(30);

        let mut session = Session::new(
            user_id,
            "hash_1".to_owned(),
            ip,
            Some("Mozilla/5.0".to_owned()),
            Some("MacBook Pro".to_owned()),
            ttl,
        );

        let now = Utc::now();
        assert!(session.is_valid(now));
        assert!(!session.is_expired(now));
        assert!(!session.is_revoked());

        // Rotation
        let next_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let child = session.rotate(
            "hash_2".to_owned(),
            ttl,
            now,
            next_ip,
            Some("Chrome".to_owned()),
        );

        // Parent session is replaced and no longer valid
        assert!(session.is_replaced);
        assert!(!session.is_valid(now));

        // Child session belongs to same family and is valid
        assert_eq!(child.user_id, user_id);
        assert_eq!(child.token_family_id, session.token_family_id);
        assert_ne!(child.id, session.id);
        assert!(child.is_valid(now));
        assert_eq!(child.refresh_token_hash, "hash_2");
        assert_eq!(child.created_at, session.created_at);
        assert_eq!(child.amr, session.amr);

        // Explicit revocation
        let mut child = child;
        child.revoke("user_logout", now);
        assert!(child.is_revoked());
        assert!(!child.is_valid(now));
        assert_eq!(child.revoke_reason.as_deref(), Some("user_logout"));
    }

    #[test]
    fn session_replacement_grace_period() {
        let user_id = UserId::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let ttl = Duration::days(30);

        let mut session = Session::new(
            user_id,
            "hash_1".to_owned(),
            ip,
            Some("Mozilla/5.0".to_owned()),
            Some("MacBook Pro".to_owned()),
            ttl,
        );

        let now = Utc::now();
        let grace = Duration::seconds(10);

        // Not replaced yet: grace check returns false
        assert!(!session.is_replaced_within_grace(now, grace));

        // Rotate session
        let _child = session.rotate(
            "hash_2".to_owned(),
            ttl,
            now,
            ip,
            Some("Mozilla/5.0".to_owned()),
        );
        assert!(session.is_replaced);

        // Immediate check: within grace
        assert!(session.is_replaced_within_grace(now, grace));

        // 5 seconds later: within grace
        let five_sec_later = now + Duration::seconds(5);
        assert!(session.is_replaced_within_grace(five_sec_later, grace));

        // Exactly 10 seconds later: within grace
        let ten_sec_later = now + Duration::seconds(10);
        assert!(session.is_replaced_within_grace(ten_sec_later, grace));

        // 11 seconds later: expired grace window
        let eleven_sec_later = now + Duration::seconds(11);
        assert!(!session.is_replaced_within_grace(eleven_sec_later, grace));

        // Clock skew tolerance: up to -1 second is accepted
        let skew_half_sec_earlier = now - Duration::milliseconds(500);
        assert!(session.is_replaced_within_grace(skew_half_sec_earlier, grace));

        let skew_exact_one_sec_earlier = now - Duration::seconds(1);
        assert!(session.is_replaced_within_grace(skew_exact_one_sec_earlier, grace));

        // Clock skew beyond -1 second rejected
        let skew_too_early = now - Duration::seconds(2);
        assert!(!session.is_replaced_within_grace(skew_too_early, grace));
    }
}
