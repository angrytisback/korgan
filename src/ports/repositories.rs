//! Persistence repository port interfaces for Hexagonal Architecture.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::domain::entities::{
    AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa,
};
use crate::domain::value_objects::{
    EmailAddress, PasskeyId, PasswordHash, SessionId, TokenFamilyId, UserId, Username,
};
pub use crate::ports::cache::{TokenStore, WsTicketPayload};
use crate::ports::errors::PortError;

/// Persistence operations for [`User`] accounts, password histories, and MFA.
#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    /// Retrieves a user by their unique [`UserId`].
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError>;

    /// Retrieves a user by their unique canonical [`EmailAddress`].
    async fn find_by_email(&self, email: &EmailAddress) -> Result<Option<User>, PortError>;

    /// Retrieves a user by their unique [`Username`].
    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, PortError>;

    /// Inserts a new user record.
    async fn create(&self, user: &User) -> Result<(), PortError>;

    /// Updates existing user attributes (status, verification, failed attempts, etc.).
    async fn update(&self, user: &User) -> Result<(), PortError>;

    /// Granularly updates a user's username attribute without mutating other user fields
    /// (such as account status, lockout timestamps, failed attempts, or roles).
    async fn update_username(
        &self,
        user_id: &UserId,
        new_username: Option<&Username>,
    ) -> Result<(), PortError> {
        let _ = (user_id, new_username);
        Err(PortError::not_found("update_username not implemented"))
    }

    /// Atomically updates a user's password and records the previous hash into
    /// `password_history`, pruning history older than `history_depth`.
    async fn update_password(
        &self,
        user_id: &UserId,
        new_hash: &PasswordHash,
        history_depth: u16,
    ) -> Result<(), PortError>;

    /// Retrieves recent password hashes from history for password reuse checks.
    async fn get_password_history(
        &self,
        user_id: &UserId,
        limit: u32,
    ) -> Result<Vec<PasswordHash>, PortError>;

    /// Retrieves MFA configuration for a user.
    async fn find_mfa(&self, user_id: &UserId) -> Result<Option<UserMfa>, PortError>;

    /// Creates or updates MFA configuration for a user.
    async fn save_mfa(&self, mfa: &UserMfa) -> Result<(), PortError>;

    /// Atomically persists or updates MFA configuration in `user_mfa` and marks `users.mfa_enabled = true`
    /// within a single PostgreSQL transaction (`BEGIN ... COMMIT`).
    ///
    /// If either operation fails or the user does not exist, the entire transaction rolls back.
    async fn enable_mfa(&self, mfa: &UserMfa) -> Result<(), PortError> {
        self.save_mfa(mfa).await?;
        if let Some(mut user) = self.find_by_id(&mfa.user_id).await? {
            user.mfa_enabled = true;
            user.updated_at = Utc::now();
            self.update(&user).await?;
        }
        Ok(())
    }

    /// Removes MFA configuration and disables MFA on the user record.
    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError>;

    /// Atomically consumes a single-use backup code hash from the user's active backup code list.
    ///
    /// If `code_hash` is present in `backup_code_hashes`, removes it and returns `Ok(true)`.
    /// If not present, returns `Ok(false)`.
    async fn consume_backup_code(
        &self,
        user_id: &UserId,
        code_hash: &str,
    ) -> Result<bool, PortError>;

    /// Atomically increments the failed login attempt counter for a user in a single atomic SQL query,
    /// setting `locked_until` if the incremented counter reaches or exceeds `max_attempts`.
    ///
    /// Returns the updated `(failed_login_attempts, locked_until)`.
    async fn record_failed_login_atomic(
        &self,
        user_id: &UserId,
        max_attempts: u16,
        lockout_until: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<chrono::Utc>>), PortError>;

    /// Atomically resets failed login attempts and clears lockout for a user upon successful login,
    /// without mutating any other user fields (such as account status).
    async fn reset_failed_logins(
        &self,
        user_id: &UserId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError>;

    /// Retrieves a paginated list of users ordered by creation time descending.
    async fn list_paginated(&self, limit: u32, offset: u64) -> Result<Vec<User>, PortError>;

    /// Counts the total number of registered users.
    async fn count_all(&self) -> Result<u64, PortError>;

    /// Purges unverified user accounts created before `created_before`, up to `max_purge` records.
    async fn purge_expired_unverified(
        &self,
        created_before: chrono::DateTime<chrono::Utc>,
        max_purge: u32,
    ) -> Result<u64, PortError> {
        let _ = (created_before, max_purge);
        Ok(0)
    }

    /// Checks whether an administrative user (`admin` or `superadmin`) already exists.
    async fn has_admin_user(&self) -> Result<bool, PortError> {
        Ok(false)
    }
}

/// Persistence operations for stateful rotating refresh token sessions.
#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    /// Inserts a newly issued session.
    async fn create(&self, session: &Session) -> Result<(), PortError>;

    /// Retrieves a session by its unique [`SessionId`].
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError>;

    /// Retrieves a session by its refresh token SHA-256 hash.
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, PortError>;

    /// Lists active sessions for a user, ordered by `last_active_at DESC`.
    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<Session>, PortError>;

    /// Atomically marks a session as replaced using a Single-Query CAS update.
    ///
    /// If an active session with `token_hash` exists, `is_replaced == false`, is not revoked,
    /// and `expires_at > NOW()`, marks it as replaced and returns the updated [`Session`]. Otherwise returns `None`.
    async fn replace_atomic(&self, token_hash: &str) -> Result<Option<Session>, PortError>;

    /// Atomically marks the old session as replaced AND inserts the new rotated session
    /// in a single atomic SQL CTE or transaction.
    ///
    /// Validates that the old session exists, is not replaced, is not revoked,
    /// and has not expired (`expires_at > NOW()`). If valid, marks the old session
    /// as replaced and inserts `new_session` in one atomic operation, returning the
    /// updated old [`Session`]. If invalid or expired, returns `None`.
    async fn rotate_atomic(
        &self,
        old_token_hash: &str,
        new_session: &Session,
    ) -> Result<Option<Session>, PortError>;

    /// Updates an existing session (e.g. `is_replaced`, `last_active_at`, revocation).
    async fn update(&self, session: &Session) -> Result<(), PortError>;

    /// Revokes a single session by its identifier alone.
    async fn revoke_by_id(&self, id: &SessionId, reason: &str) -> Result<(), PortError>;

    /// Revokes a single session by its identifier and owner user ID (defense-in-depth against IDOR/BOLA).
    async fn revoke_by_id_and_user_id(
        &self,
        id: &SessionId,
        user_id: &UserId,
        reason: &str,
    ) -> Result<Option<SessionId>, PortError>;

    /// Revokes an entire family of rotated refresh tokens (used upon replay detection)
    /// and returns the revoked session identifiers.
    async fn revoke_family(
        &self,
        family_id: &TokenFamilyId,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError>;

    /// Revokes all sessions belonging to a user, optionally exempting one current session,
    /// and returns the revoked session identifiers.
    async fn revoke_all_user_sessions(
        &self,
        user_id: &UserId,
        except_session: Option<&SessionId>,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError>;

    /// Purges expired sessions older than the retention threshold.
    async fn purge_expired(&self, max_purge: u32) -> Result<u64, PortError>;

    /// Counts the current number of active (unrevoked, unreplaced, non-expired) sessions.
    async fn count_active(&self) -> Result<u64, PortError> {
        Ok(0)
    }
}

/// Persistence operations for immutable security audit logs.
#[async_trait]
pub trait AuditLogRepository: Send + Sync + 'static {
    /// Appends a new immutable audit record.
    async fn append(&self, entry: &AuditLog) -> Result<(), PortError>;

    /// Lists audit logs for a specific user, ordered by `created_at DESC`.
    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<AuditLog>, PortError>;

    /// Lists recent audit logs across all users, ordered by `created_at DESC`.
    async fn list_recent(&self, limit: u32, offset: u64) -> Result<Vec<AuditLog>, PortError>;

    /// Returns the latest audit log entry hash, if any, for cryptographic chaining.
    async fn find_latest_entry_hash(&self) -> Result<Option<String>, PortError> {
        Ok(None)
    }

    /// Atomically chains this audit log to the latest entry and persists it.
    ///
    /// Implementations backed by relational databases MUST serialize this operation
    /// (e.g. via an advisory transaction lock) to prevent concurrent chain forks.
    async fn append_and_chain(&self, entry: &mut AuditLog) -> Result<(), PortError> {
        let prev_hash = self.find_latest_entry_hash().await?;
        entry.chain_with_timestamp(prev_hash.as_deref(), Utc::now());
        self.append(entry).await
    }

    /// Lists all audit logs chronologically ordered by `created_at ASC, id ASC` for chain verification.
    async fn list_all_chronological(&self) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }

    /// Counts the total number of audit log entries.
    async fn count_all(&self) -> Result<u64, PortError> {
        Ok(0)
    }
}

/// Persistence operations for external [`OAuthAccount`] links.
#[async_trait]
pub trait OAuthAccountRepository: Send + Sync + 'static {
    /// Retrieves an OAuth account link by its external provider and provider-specific user ID.
    async fn find_by_provider_and_id(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError>;

    /// Inserts a new OAuth account linkage.
    async fn create(&self, account: &OAuthAccount) -> Result<(), PortError>;

    /// Atomically links an OAuth account to a user, creating the user record if `user` is `Some`.
    /// Both operations execute within a single explicit PostgreSQL transaction (`BEGIN ... COMMIT`).
    async fn link_oauth_account(
        &self,
        user: Option<&User>,
        account: &OAuthAccount,
    ) -> Result<(), PortError> {
        let _ = user;
        self.create(account).await
    }

    /// Retrieves all OAuth accounts linked to a given [`UserId`].
    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError>;
}

/// Persistence operations for WebAuthn [`Passkey`] credentials.
#[async_trait]
pub trait PasskeyRepository: Send + Sync + 'static {
    /// Inserts or updates a passkey credential record.
    async fn save(&self, passkey: &Passkey) -> Result<(), PortError>;

    /// Retrieves a passkey by its raw credential ID.
    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, PortError>;

    /// Retrieves a passkey by its unique [`PasskeyId`].
    async fn find_by_id(&self, id: &PasskeyId) -> Result<Option<Passkey>, PortError>;

    /// Retrieves all passkeys registered for a given [`UserId`].
    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<Passkey>, PortError>;

    /// Deletes a passkey by its [`PasskeyId`].
    async fn delete_by_id(&self, id: &PasskeyId) -> Result<(), PortError>;

    /// Deletes a passkey credential ensuring strict user ownership (defense-in-depth against IDOR/BOLA).
    async fn delete_by_id_and_user_id(
        &self,
        id: &PasskeyId,
        user_id: &UserId,
    ) -> Result<bool, PortError>;

    /// Atomically updates the passkey's serialized credential state (`passkey_json` counter/sign_count)
    /// and `last_used_at` timestamp upon successful authentication ceremony to prevent hardware key cloning.
    async fn update_credential_state(
        &self,
        id: &PasskeyId,
        passkey_json: &serde_json::Value,
        last_used_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        if let Some(mut pk) = self.find_by_id(id).await? {
            let old_counter = pk
                .passkey_json
                .get("cred")
                .and_then(|c| c.get("counter"))
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                })
                .unwrap_or(0);
            let new_counter = passkey_json
                .get("cred")
                .and_then(|c| c.get("counter"))
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                })
                .unwrap_or(0);

            let allowed = (old_counter == 0 && new_counter == 0) || (new_counter > old_counter);
            if !allowed {
                return Err(PortError::conflict(
                    "passkey counter state conflict or replay detected",
                ));
            }

            pk.passkey_json = passkey_json.clone();
            pk.last_used_at = Some(last_used_at);
            self.save(&pk).await
        } else {
            Err(PortError::not_found("Passkey"))
        }
    }
}
