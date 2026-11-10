//! User account entity, account status, and password history domain models.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::errors::DomainError;
use crate::domain::value_objects::{EmailAddress, PasswordHash, UserId, Username};

/// Lifecycle status of an account, matching the `account_status` PostgreSQL enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// E-mail not yet confirmed.
    Unverified,
    /// Active and fully operational.
    Active,
    /// Administratively suspended.
    Suspended,
    /// Self-deactivated by user.
    Deactivated,
    /// Marked for permanent deletion after a grace period.
    PendingDeletion,
}

impl AccountStatus {
    /// Returns the static string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
            Self::PendingDeletion => "pending_deletion",
        }
    }
}

impl fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Role assigned to a user for role-based access control (RBAC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    /// Standard end-user.
    #[default]
    User,
    /// Administrative user with backoffice access.
    Admin,
    /// Super administrator with complete management capabilities.
    Superadmin,
}

impl UserRole {
    /// Returns the static string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Superadmin => "superadmin",
        }
    }

    /// Returns true if this role has administrative privileges.
    #[must_use]
    pub const fn is_admin(&self) -> bool {
        matches!(self, Self::Admin | Self::Superadmin)
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Core User entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier (always UUIDv7 upon creation).
    pub id: UserId,
    /// Canonical lowercase e-mail address.
    pub email: EmailAddress,
    /// Optional alphanumeric username.
    pub username: Option<Username>,
    /// Current Argon2id password hash, or None if user authenticated via OAuth only.
    pub password_hash: Option<PasswordHash>,
    /// Assigned authorization role.
    pub role: UserRole,
    /// Current account status.
    pub status: AccountStatus,
    /// Timestamp when e-mail was confirmed, if any.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Whether Multi-Factor Authentication is currently enforced.
    pub mfa_enabled: bool,
    /// Consecutive failed login counter for temporary lockout.
    pub failed_login_attempts: u16,
    /// Lockout expiration timestamp, if account is temporarily locked.
    pub locked_until: Option<DateTime<Utc>>,
    /// Deletion timestamp if account is pending deletion.
    pub deletion_scheduled_at: Option<DateTime<Utc>>,
    /// Creation timestamp (TIMESTAMPTZ, UTC).
    pub created_at: DateTime<Utc>,
    /// Last update timestamp (TIMESTAMPTZ, UTC).
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Creates a new user entity upon initial registration (password or OAuth).
    #[must_use]
    pub fn new(
        email: EmailAddress,
        username: Option<Username>,
        password_hash: impl Into<Option<PasswordHash>>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            email,
            username,
            password_hash: password_hash.into(),
            role: UserRole::User,
            status: AccountStatus::Unverified,
            email_verified_at: None,
            mfa_enabled: false,
            failed_login_attempts: 0,
            locked_until: None,
            deletion_scheduled_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a new user entity with a password hash.
    #[must_use]
    pub fn with_password(
        email: EmailAddress,
        username: Option<Username>,
        password_hash: PasswordHash,
    ) -> Self {
        Self::new(email, username, Some(password_hash))
    }

    /// Checks if the account is currently locked out against `now`.
    #[must_use]
    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until.is_some_and(|until| until > now)
    }

    /// Validates whether the account is eligible to log in.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::AccountLocked`] if temporarily locked, or
    /// [`DomainError::AccountNotActive`] if status is not `Active`.
    pub fn can_login(&self, now: DateTime<Utc>) -> Result<(), DomainError> {
        if let Some(until) = self.locked_until
            && until > now
        {
            return Err(DomainError::AccountLocked { until });
        }

        match self.status {
            AccountStatus::Active => Ok(()),
            other => Err(DomainError::AccountNotActive {
                status: other.to_string(),
            }),
        }
    }

    /// Records a failed login attempt, applying a lockout if threshold is exceeded.
    pub fn record_failed_login(
        &mut self,
        max_attempts: u16,
        lockout_duration: Duration,
        now: DateTime<Utc>,
    ) {
        self.failed_login_attempts = self.failed_login_attempts.saturating_add(1);
        if self.failed_login_attempts >= max_attempts {
            self.locked_until = Some(now + lockout_duration);
        }
        self.updated_at = now;
    }

    /// Resets failed login counters and lockout upon successful login.
    pub fn record_successful_login(&mut self, now: DateTime<Utc>) {
        self.failed_login_attempts = 0;
        self.locked_until = None;
        self.updated_at = now;
    }

    /// Confirms the user's e-mail address and activates the account if unverified.
    pub fn verify_email(&mut self, now: DateTime<Utc>) {
        self.email_verified_at = Some(now);
        if self.status == AccountStatus::Unverified {
            self.status = AccountStatus::Active;
        }
        self.updated_at = now;
    }

    /// Enables MFA on the account.
    pub fn enable_mfa(&mut self, now: DateTime<Utc>) {
        self.mfa_enabled = true;
        self.updated_at = now;
    }

    /// Disables MFA on the account.
    pub fn disable_mfa(&mut self, now: DateTime<Utc>) {
        self.mfa_enabled = false;
        self.updated_at = now;
    }

    /// Updates password hash and updates `updated_at`.
    pub fn change_password(&mut self, new_hash: PasswordHash, now: DateTime<Utc>) {
        self.password_hash = Some(new_hash);
        self.failed_login_attempts = 0;
        self.locked_until = None;
        self.updated_at = now;
    }

    /// Schedules account deletion after a grace period.
    pub fn schedule_deletion(&mut self, grace_period: Duration, now: DateTime<Utc>) {
        self.status = AccountStatus::PendingDeletion;
        self.deletion_scheduled_at = Some(now + grace_period);
        self.updated_at = now;
    }

    /// Cancels scheduled deletion and restores active status.
    pub fn cancel_deletion(&mut self, now: DateTime<Utc>) {
        if self.status == AccountStatus::PendingDeletion {
            self.status = AccountStatus::Active;
            self.deletion_scheduled_at = None;
            self.updated_at = now;
        }
    }

    /// Administratively bans the account, marking its status as Suspended.
    pub fn ban(&mut self, now: DateTime<Utc>) {
        self.status = AccountStatus::Suspended;
        self.updated_at = now;
    }

    /// Restores a suspended account to Active status.
    pub fn unban(&mut self, now: DateTime<Utc>) {
        self.status = AccountStatus::Active;
        self.updated_at = now;
    }
}

/// Historical password entry to prevent reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistory {
    /// Primary key.
    pub id: Uuid,
    /// Owner user identifier.
    pub user_id: UserId,
    /// Archived Argon2id password hash.
    pub password_hash: PasswordHash,
    /// Timestamp when this password was created/retired.
    pub created_at: DateTime<Utc>,
}

impl PasswordHistory {
    /// Creates a new password history entry.
    #[must_use]
    pub fn new(user_id: UserId, password_hash: PasswordHash) -> Self {
        Self {
            id: Uuid::now_v7(),
            user_id,
            password_hash,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8";

    #[test]
    fn user_lifecycle_and_login_checks() -> TestResult {
        let email = EmailAddress::parse("user@example.com")?;
        let username = Some(Username::new("user_1")?);
        let hash = PasswordHash::new(TEST_HASH)?;

        let mut user = User::with_password(email, username, hash);
        assert_eq!(user.status, AccountStatus::Unverified);
        assert!(!user.mfa_enabled);

        let now = Utc::now();
        assert!(user.can_login(now).is_err());

        // Verify email activates account
        user.verify_email(now);
        assert_eq!(user.status, AccountStatus::Active);
        assert_eq!(user.email_verified_at, Some(now));
        assert!(user.can_login(now).is_ok());

        // MFA toggles
        user.enable_mfa(now);
        assert!(user.mfa_enabled);
        user.disable_mfa(now);
        assert!(!user.mfa_enabled);

        // Failed logins triggering lockout
        let lockout_dur = Duration::minutes(15);
        for _ in 0..4 {
            user.record_failed_login(5, lockout_dur, now);
            assert!(!user.is_locked(now));
            assert!(user.can_login(now).is_ok());
        }

        user.record_failed_login(5, lockout_dur, now);
        assert!(user.is_locked(now));
        assert!(matches!(
            user.can_login(now),
            Err(DomainError::AccountLocked { .. })
        ));

        // Successful login resets lockout
        user.record_successful_login(now);
        assert!(!user.is_locked(now));
        assert_eq!(user.failed_login_attempts, 0);

        // Deletion scheduling
        let grace = Duration::days(30);
        user.schedule_deletion(grace, now);
        assert_eq!(user.status, AccountStatus::PendingDeletion);
        assert!(matches!(
            user.can_login(now),
            Err(DomainError::AccountNotActive { .. })
        ));

        // Cancellation of deletion
        user.cancel_deletion(now);
        assert_eq!(user.status, AccountStatus::Active);
        assert!(user.can_login(now).is_ok());

        Ok(())
    }
}
