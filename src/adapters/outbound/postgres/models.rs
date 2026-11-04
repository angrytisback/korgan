//! Database row conversions and PostgreSQL custom type mappings.

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::domain::entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User,
    UserMfa, UserRole,
};
use crate::domain::value_objects::{
    AuditLogId, EmailAddress, OAuthAccountId, PasskeyId, PasswordHash, RequestId, SessionId,
    TokenFamilyId, UserId, Username,
};
use crate::ports::errors::PortError;

/// PostgreSQL `account_status` ENUM mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "account_status", rename_all = "snake_case")]
pub enum PgAccountStatus {
    Unverified,
    Active,
    Suspended,
    Deactivated,
    PendingDeletion,
}

impl From<AccountStatus> for PgAccountStatus {
    fn from(status: AccountStatus) -> Self {
        match status {
            AccountStatus::Unverified => Self::Unverified,
            AccountStatus::Active => Self::Active,
            AccountStatus::Suspended => Self::Suspended,
            AccountStatus::Deactivated => Self::Deactivated,
            AccountStatus::PendingDeletion => Self::PendingDeletion,
        }
    }
}

impl From<PgAccountStatus> for AccountStatus {
    fn from(status: PgAccountStatus) -> Self {
        match status {
            PgAccountStatus::Unverified => Self::Unverified,
            PgAccountStatus::Active => Self::Active,
            PgAccountStatus::Suspended => Self::Suspended,
            PgAccountStatus::Deactivated => Self::Deactivated,
            PgAccountStatus::PendingDeletion => Self::PendingDeletion,
        }
    }
}

/// Raw record from the `users` table with explicitly named columns.
#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    pub status: PgAccountStatus,
    pub role: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    pub failed_login_attempts: i16,
    pub locked_until: Option<DateTime<Utc>>,
    pub deletion_scheduled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<UserRow> for User {
    type Error = PortError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        let id = UserId::from_uuid(row.id)
            .map_err(|e| PortError::database(format!("invalid user ID in database: {e}")))?;

        let email = EmailAddress::parse(&row.email)
            .map_err(|e| PortError::database(format!("invalid email address in database: {e}")))?;

        let username = row
            .username
            .map(|u| Username::new(&u))
            .transpose()
            .map_err(|e| PortError::database(format!("invalid username in database: {e}")))?;

        let password_hash = row
            .password_hash
            .map(PasswordHash::new)
            .transpose()
            .map_err(|e| PortError::database(format!("invalid password hash in database: {e}")))?;

        let role = match row.role.as_str() {
            "superadmin" => UserRole::Superadmin,
            "admin" => UserRole::Admin,
            _ => UserRole::User,
        };

        let failed_login_attempts =
            u16::try_from(row.failed_login_attempts.max(0)).unwrap_or(u16::MAX);

        Ok(User {
            id,
            email,
            username,
            password_hash,
            role,
            status: row.status.into(),
            email_verified_at: row.email_verified_at,
            mfa_enabled: row.mfa_enabled,
            failed_login_attempts,
            locked_until: row.locked_until,
            deletion_scheduled_at: row.deletion_scheduled_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// Raw record from the `oauth_accounts` table.
#[derive(Debug, sqlx::FromRow)]
pub struct OAuthAccountRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<OAuthAccountRow> for OAuthAccount {
    type Error = PortError;

    fn try_from(row: OAuthAccountRow) -> Result<Self, Self::Error> {
        let id = OAuthAccountId::from_uuid(row.id).map_err(|e| {
            PortError::database(format!("invalid oauth account ID in database: {e}"))
        })?;

        let user_id = UserId::from_uuid(row.user_id)
            .map_err(|e| PortError::database(format!("invalid user ID in database: {e}")))?;

        let provider = OAuthProvider::parse(&row.provider)
            .map_err(|e| PortError::database(format!("invalid oauth provider in database: {e}")))?;

        Ok(OAuthAccount {
            id,
            user_id,
            provider,
            provider_user_id: row.provider_user_id,
            created_at: row.created_at,
        })
    }
}

/// Raw record from the `sessions` table with explicitly named columns.
#[derive(Debug, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_family_id: Uuid,
    pub refresh_token_hash: String,
    pub user_agent: Option<String>,
    pub device_name: Option<String>,
    pub ip_address: IpNetwork,
    pub is_replaced: bool,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoke_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<SessionRow> for Session {
    type Error = PortError;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        let id = SessionId::from_uuid(row.id)
            .map_err(|e| PortError::database(format!("invalid session ID in database: {e}")))?;

        let user_id = UserId::from_uuid(row.user_id)
            .map_err(|e| PortError::database(format!("invalid user ID in session: {e}")))?;

        let token_family_id = TokenFamilyId::from_uuid(row.token_family_id)
            .map_err(|e| PortError::database(format!("invalid token family ID in session: {e}")))?;

        Ok(Session {
            id,
            user_id,
            token_family_id,
            refresh_token_hash: row.refresh_token_hash,
            user_agent: row.user_agent,
            device_name: row.device_name,
            ip_address: row.ip_address.ip(),
            is_replaced: row.is_replaced,
            last_active_at: row.last_active_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            revoke_reason: row.revoke_reason,
            created_at: row.created_at,
            amr: Vec::new(),
        })
    }
}

/// Raw record from the `user_mfa` table.
#[derive(Debug, sqlx::FromRow)]
pub struct UserMfaRow {
    pub user_id: Uuid,
    pub key_id: String,
    pub totp_secret_ciphertext: Vec<u8>,
    pub totp_secret_nonce: Vec<u8>,
    pub backup_code_hashes: Vec<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<UserMfaRow> for UserMfa {
    type Error = PortError;

    fn try_from(row: UserMfaRow) -> Result<Self, Self::Error> {
        let user_id = UserId::from_uuid(row.user_id)
            .map_err(|e| PortError::database(format!("invalid user ID in MFA: {e}")))?;

        Ok(UserMfa {
            user_id,
            key_id: row.key_id,
            totp_secret_ciphertext: row.totp_secret_ciphertext,
            totp_secret_nonce: row.totp_secret_nonce,
            backup_code_hashes: row.backup_code_hashes,
            verified_at: row.verified_at,
            updated_at: row.updated_at,
        })
    }
}

/// Raw record from the `audit_logs` table.
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub actor_ip: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub request_id: Uuid,
    pub event_type: String,
    pub event_status: String,
    pub metadata: serde_json::Value,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<AuditLogRow> for AuditLog {
    type Error = PortError;

    fn try_from(row: AuditLogRow) -> Result<Self, Self::Error> {
        let id = AuditLogId::from_uuid(row.id)
            .map_err(|e| PortError::database(format!("invalid audit log ID: {e}")))?;

        let user_id = row
            .user_id
            .map(UserId::from_uuid)
            .transpose()
            .map_err(|e| PortError::database(format!("invalid user ID in audit log: {e}")))?;

        let request_id = RequestId::from_uuid(row.request_id)
            .map_err(|e| PortError::database(format!("invalid request ID in audit log: {e}")))?;

        let event_status = match row.event_status.as_str() {
            "success" => AuditEventStatus::Success,
            "failure" => AuditEventStatus::Failure,
            "blocked" => AuditEventStatus::Blocked,
            other => {
                return Err(PortError::database(format!(
                    "unknown audit event status '{other}'"
                )));
            }
        };

        Ok(AuditLog {
            id,
            user_id,
            actor_ip: row.actor_ip.map(|n| n.ip()),
            user_agent: row.user_agent,
            request_id,
            event_type: row.event_type,
            event_status,
            metadata: row.metadata,
            prev_hash: row.prev_hash,
            entry_hash: row.entry_hash,
            created_at: row.created_at,
        })
    }
}

/// Raw record from the `passkeys` table.
#[derive(Debug, sqlx::FromRow)]
pub struct PasskeyRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey_json: serde_json::Value,
    pub name: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<PasskeyRow> for Passkey {
    type Error = PortError;

    fn try_from(row: PasskeyRow) -> Result<Self, Self::Error> {
        let id = PasskeyId::from_uuid(row.id)
            .map_err(|e| PortError::database(format!("invalid passkey ID in database: {e}")))?;
        let user_id = UserId::from_uuid(row.user_id)
            .map_err(|e| PortError::database(format!("invalid user ID in passkey: {e}")))?;

        Ok(Passkey {
            id,
            user_id,
            credential_id: row.credential_id,
            passkey_json: row.passkey_json,
            name: row.name,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
        })
    }
}
