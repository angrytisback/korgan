//! End-to-end integration tests for OAuth2 Social Login (Google & GitHub).
//!
//! Validates:
//! 1. Authorization URL generation with anti-CSRF state token stored in Redis/TokenStore.
//! 2. New user signup via OAuth: User created (Active, verified email, passwordless),
//!    OAuthAccount created, Session created, tokens and cookies issued.
//! 3. Existing user linking: User with matching email is linked to external OAuth account,
//!    email verified if unverified, no duplicate user created.
//! 4. Anti-CSRF protection: Tampered or consumed state rejected with 403 Forbidden.
//! 5. Passwordless security: Standard password login on OAuth-only account fails with
//!    401 Unauthorized via constant-time dummy hash verification.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use chrono::Utc;
use http::header::{CONTENT_TYPE, SET_COOKIE};
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::handlers::oauth::OAuthUrlResponse;
use korgan::adapters::inbound::http::{AppState, ProblemDetails, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::application::workers::{EventBus, EventWorker};
use korgan::config::Settings;
use korgan::domain::entities::{
    AccountStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{OAuthProfile, OAuthProviderPort, WebAuthnService};
use secrecy::ExposeSecret;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ===========================================================================
// In-Memory Test Repositories & Mock Adapters
// ===========================================================================

#[derive(Default, Debug)]
struct OAuthTestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for OAuthTestUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, email: &EmailAddress) -> Result<Option<User>, PortError> {
        let emails = self
            .emails
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(id) = emails.get(email.as_str()) {
            Ok(users.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, PortError> {
        let usernames = self
            .usernames
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(id) = usernames.get(username.as_str()) {
            Ok(users.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn create(&self, user: &User) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut emails = self
            .emails
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut usernames = self
            .usernames
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        emails.insert(user.email.as_str().to_owned(), user.id);
        if let Some(ref u) = user.username {
            usernames.insert(u.as_str().to_owned(), user.id);
        }
        users.insert(user.id, user.clone());
        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        users.insert(user.id, user.clone());
        Ok(())
    }

    async fn update_password(
        &self,
        user_id: &UserId,
        new_hash: &PasswordHash,
        history_depth: u16,
    ) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut history = self
            .history
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(user) = users.get_mut(user_id) {
            let user_history = history.entry(*user_id).or_default();
            if let Some(ref current_hash) = user.password_hash {
                user_history.insert(0, current_hash.clone());
            }
            user_history.truncate(history_depth as usize);
            user.password_hash = Some(new_hash.clone());
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn get_password_history(
        &self,
        user_id: &UserId,
        limit: u32,
    ) -> Result<Vec<PasswordHash>, PortError> {
        let history = self
            .history
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(history
            .get(user_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(limit as usize)
            .collect())
    }

    async fn save_mfa(&self, mfa: &UserMfa) -> Result<(), PortError> {
        let mut mfas = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        mfas.insert(mfa.user_id, mfa.clone());
        Ok(())
    }

    async fn find_mfa(&self, user_id: &UserId) -> Result<Option<UserMfa>, PortError> {
        let mfas = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(mfas.get(user_id).cloned())
    }

    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError> {
        let mut mfas = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        mfas.remove(user_id);
        Ok(())
    }

    async fn consume_backup_code(
        &self,
        user_id: &UserId,
        code_hash: &str,
    ) -> Result<bool, PortError> {
        let mut mfas = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(mfa) = mfas.get_mut(user_id) {
            Ok(mfa.consume_backup_code(code_hash))
        } else {
            Ok(false)
        }
    }

    async fn list_paginated(&self, limit: u32, offset: u64) -> Result<Vec<User>, PortError> {
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list: Vec<User> = users.values().cloned().collect();
        list.sort_by_key(|u| u.created_at);
        Ok(list
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(users.len() as u64)
    }

    async fn record_failed_login_atomic(
        &self,
        user_id: &UserId,
        max_attempts: u16,
        lockout_until: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<chrono::Utc>>), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| PortError::not_found("user"))?;
        user.failed_login_attempts = user.failed_login_attempts.saturating_add(1);
        if user.failed_login_attempts >= max_attempts {
            user.locked_until = Some(lockout_until);
        }
        user.updated_at = now;
        Ok((user.failed_login_attempts, user.locked_until))
    }

    async fn reset_failed_logins(
        &self,
        user_id: &UserId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            user.failed_login_attempts = 0;
            user.locked_until = None;
            user.updated_at = now;
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct OAuthTestSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
}

#[async_trait]
impl SessionRepository for OAuthTestSessionRepo {
    async fn create(&self, session: &Session) -> Result<(), PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut by_hash = self
            .by_token_hash
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        by_hash.insert(session.refresh_token_hash.clone(), session.id);
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(sessions.get(id).cloned())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, PortError> {
        let by_hash = self
            .by_token_hash
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        match by_hash.get(token_hash) {
            Some(id) => Ok(sessions.get(id).cloned()),
            None => Ok(None),
        }
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut user_sessions: Vec<Session> = sessions
            .values()
            .filter(|s| s.user_id == *user_id && !s.is_revoked())
            .cloned()
            .collect();
        user_sessions.sort_by_key(|a| std::cmp::Reverse(a.last_active_at));
        Ok(user_sessions
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn update(&self, session: &Session) -> Result<(), PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn replace_atomic(&self, token_hash: &str) -> Result<Option<Session>, PortError> {
        let by_hash = self
            .by_token_hash
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(id) = by_hash.get(token_hash)
            && let Some(session) = sessions.get_mut(id)
            && !session.is_replaced
            && !session.is_revoked()
            && !session.is_expired(Utc::now())
        {
            session.is_replaced = true;
            session.last_active_at = Utc::now();
            return Ok(Some(session.clone()));
        }
        Ok(None)
    }

    async fn rotate_atomic(
        &self,
        old_token_hash: &str,
        new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
        let mut by_hash = self
            .by_token_hash
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(id) = by_hash.get(old_token_hash)
            && let Some(session) = sessions.get_mut(id)
            && !session.is_replaced
            && !session.is_revoked()
            && !session.is_expired(Utc::now())
        {
            session.is_replaced = true;
            session.last_active_at = Utc::now();
            let old = session.clone();

            by_hash.insert(new_session.refresh_token_hash.clone(), new_session.id);
            sessions.insert(new_session.id, new_session.clone());

            return Ok(Some(old));
        }
        Ok(None)
    }

    async fn revoke_by_id(&self, id: &SessionId, reason: &str) -> Result<(), PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(session) = sessions.get_mut(id) {
            session.revoke(reason, Utc::now());
        }
        Ok(())
    }

    async fn revoke_by_id_and_user_id(
        &self,
        id: &SessionId,
        user_id: &UserId,
        reason: &str,
    ) -> Result<Option<SessionId>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(session) = sessions.get_mut(id)
            && session.user_id == *user_id
            && !session.is_revoked()
        {
            session.revoke(reason, Utc::now());
            return Ok(Some(*id));
        }
        Ok(None)
    }

    async fn revoke_family(
        &self,
        family_id: &TokenFamilyId,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let now = Utc::now();
        let mut revoked = Vec::new();
        for session in sessions.values_mut() {
            if session.token_family_id == *family_id && !session.is_revoked() {
                session.revoke(reason, now);
                revoked.push(session.id);
            }
        }
        Ok(revoked)
    }

    async fn revoke_all_user_sessions(
        &self,
        user_id: &UserId,
        except_session: Option<&SessionId>,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let now = Utc::now();
        let mut revoked = Vec::new();
        for session in sessions.values_mut() {
            if session.user_id == *user_id {
                if let Some(exempt) = except_session
                    && session.id == *exempt
                {
                    continue;
                }
                if !session.is_revoked() {
                    session.revoke(reason, now);
                    revoked.push(session.id);
                }
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct OAuthTestAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for OAuthTestAuditRepo {
    async fn append(&self, entry: &AuditLog) -> Result<(), PortError> {
        let mut logs = self
            .logs
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        logs.push(entry.clone());
        Ok(())
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        let logs = self
            .logs
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(logs
            .iter()
            .filter(|l| l.user_id == Some(*user_id))
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn list_recent(&self, limit: u32, offset: u64) -> Result<Vec<AuditLog>, PortError> {
        let logs = self
            .logs
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(logs
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }
}

#[derive(Default, Debug)]
struct OAuthTestAccountRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
}

#[async_trait]
impl OAuthAccountRepository for OAuthTestAccountRepo {
    async fn find_by_provider_and_id(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        let accounts = self
            .accounts
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(accounts
            .values()
            .find(|a| a.provider == provider && a.provider_user_id == provider_user_id)
            .cloned())
    }

    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        let accounts = self
            .accounts
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(accounts
            .values()
            .filter(|a| &a.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn create(&self, account: &OAuthAccount) -> Result<(), PortError> {
        let mut accounts = self
            .accounts
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        accounts.insert(account.id, account.clone());
        Ok(())
    }
}

#[derive(Default, Debug)]
struct OAuthPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for OAuthPasskeyRepo {
    async fn save(&self, passkey: &Passkey) -> Result<(), PortError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        passkeys.insert(passkey.id, passkey.clone());
        Ok(())
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, PortError> {
        let passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(passkeys
            .values()
            .find(|p| p.credential_id == credential_id)
            .cloned())
    }

    async fn find_by_id(&self, id: &PasskeyId) -> Result<Option<Passkey>, PortError> {
        let passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(passkeys.get(id).cloned())
    }

    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<Passkey>, PortError> {
        let passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list: Vec<_> = passkeys
            .values()
            .filter(|p| &p.user_id == user_id)
            .cloned()
            .collect();
        list.sort_by_key(|p| p.created_at);
        Ok(list)
    }

    async fn delete_by_id(&self, id: &PasskeyId) -> Result<(), PortError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        passkeys.remove(id);
        Ok(())
    }

    async fn delete_by_id_and_user_id(
        &self,
        id: &PasskeyId,
        user_id: &UserId,
    ) -> Result<bool, PortError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(pk) = passkeys.get(id)
            && pk.user_id == *user_id
        {
            passkeys.remove(id);
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(Default, Debug)]
struct OAuthTestTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for OAuthTestTokenStore {
    async fn set_token(&self, key: &str, value: &str, _ttl: Duration) -> Result<(), PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        tokens.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn get_token(&self, key: &str) -> Result<Option<String>, PortError> {
        let tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(tokens.get(key).cloned())
    }

    async fn delete_token(&self, key: &str) -> Result<(), PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        tokens.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(tokens.remove(key))
    }

    async fn consume_token(&self, key: &str, expected_token_hash: &str) -> Result<bool, PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if let Some(val) = tokens.get(key)
            && val == expected_token_hash
        {
            tokens.remove(key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn set_if_not_exists(
        &self,
        key: &str,
        value: &str,
        _ttl: Duration,
    ) -> Result<bool, PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if tokens.contains_key(key) {
            return Ok(false);
        }
        tokens.insert(key.to_owned(), value.to_owned());
        Ok(true)
    }
}

#[derive(Default, Debug)]
struct OAuthTestRateLimiter;

#[async_trait]
impl RateLimiterPort for OAuthTestRateLimiter {
    async fn check_and_increment(
        &self,
        _key: &str,
        limit: u32,
        _window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        Ok(RateLimitStatus {
            allowed: true,
            limit,
            remaining: limit.saturating_sub(1),
            reset_epoch_secs: Utc::now().timestamp() as u64 + 60,
            retry_after_secs: None,
        })
    }

    async fn reset(&self, _key: &str) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Debug)]
struct MockOAuthProvider {
    provider: OAuthProvider,
    auth_base_url: String,
    responses: Mutex<HashMap<String, Result<OAuthProfile, PortError>>>,
}

impl MockOAuthProvider {
    fn new(provider: OAuthProvider, auth_base_url: &str) -> Self {
        Self {
            provider,
            auth_base_url: auth_base_url.to_owned(),
            responses: Mutex::new(HashMap::new()),
        }
    }

    fn register_profile(
        &self,
        code: &str,
        profile: OAuthProfile,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut responses = self
            .responses
            .lock()
            .map_err(|e| format!("mock provider mutex poisoned: {e}"))?;
        responses.insert(code.to_owned(), Ok(profile));
        Ok(())
    }

    #[allow(dead_code)]
    fn register_error(
        &self,
        code: &str,
        error: PortError,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut responses = self
            .responses
            .lock()
            .map_err(|e| format!("mock provider mutex poisoned: {e}"))?;
        responses.insert(code.to_owned(), Err(error));
        Ok(())
    }
}

#[async_trait]
impl OAuthProviderPort for MockOAuthProvider {
    fn provider(&self) -> OAuthProvider {
        self.provider
    }

    fn build_authorization_url(&self, state: &str) -> String {
        format!(
            "{}?client_id=test_client&state={}&scope=openid+email",
            self.auth_base_url, state
        )
    }

    async fn exchange_code(&self, code: &str) -> Result<OAuthProfile, PortError> {
        let responses = self.responses.lock().map_err(|e| {
            PortError::external_service(self.provider.as_str(), e.to_string(), None)
        })?;

        match responses.get(code) {
            Some(Ok(profile)) => Ok(profile.clone()),
            Some(Err(err)) => Err(match err {
                PortError::NotFound { resource } => PortError::NotFound { resource },
                PortError::Conflict { message } => PortError::Conflict {
                    message: message.clone(),
                },
                PortError::Cryptography(b) => PortError::security(b.to_string()),
                other => PortError::security(other.to_string()),
            }),
            None => Err(PortError::external_service(
                self.provider.as_str(),
                format!("unrecognized authorization code: `{code}`"),
                None,
            )),
        }
    }
}

#[allow(dead_code)]
struct TestContext {
    app: Router,
    user_repo: Arc<OAuthTestUserRepo>,
    session_repo: Arc<OAuthTestSessionRepo>,
    oauth_repo: Arc<OAuthTestAccountRepo>,
    token_store: Arc<OAuthTestTokenStore>,
    google_provider: Arc<MockOAuthProvider>,
    github_provider: Arc<MockOAuthProvider>,
}

async fn setup_app() -> TestResult<TestContext> {
    let env = HashMap::from([
        (
            "DATABASE_URL".to_owned(),
            "postgres://u:p@localhost:5432/db".to_owned(),
        ),
        ("REDIS_URL".to_owned(), "redis://localhost:6379".to_owned()),
        (
            "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
            TEST_PEM.to_owned(),
        ),
        (
            "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
            TEST_AES.to_owned(),
        ),
        (
            "KORGAN__OAUTH__GOOGLE__ENABLED".to_owned(),
            "true".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GOOGLE__CLIENT_ID".to_owned(),
            "google-client-id".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GOOGLE__CLIENT_SECRET".to_owned(),
            "google-client-secret".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GOOGLE__REDIRECT_URI".to_owned(),
            "http://localhost:8080/api/v1/auth/oauth/google/callback".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GITHUB__ENABLED".to_owned(),
            "true".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GITHUB__CLIENT_ID".to_owned(),
            "github-client-id".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GITHUB__CLIENT_SECRET".to_owned(),
            "github-client-secret".to_owned(),
        ),
        (
            "KORGAN__OAUTH__GITHUB__REDIRECT_URI".to_owned(),
            "http://localhost:8080/api/v1/auth/oauth/github/callback".to_owned(),
        ),
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);

    let user_repo = Arc::new(OAuthTestUserRepo::default());
    let session_repo = Arc::new(OAuthTestSessionRepo::default());
    let audit_repo = Arc::new(OAuthTestAuditRepo::default());
    let oauth_repo = Arc::new(OAuthTestAccountRepo::default());
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(OAuthPasskeyRepo::default());
    let token_store = Arc::new(OAuthTestTokenStore::default());
    let rate_limiter = Arc::new(OAuthTestRateLimiter);

    let google_provider = Arc::new(MockOAuthProvider::new(
        OAuthProvider::Google,
        "https://accounts.google.com/o/oauth2/v2/auth",
    ));
    let github_provider = Arc::new(MockOAuthProvider::new(
        OAuthProvider::GitHub,
        "https://github.com/login/oauth/authorize",
    ));
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebauthnRsAdapter::new(
        "localhost",
        "http://localhost:8080",
    )?);

    let password_hasher = Arc::new(Argon2PasswordHasher::new(1024, 1, 1)?);
    let token_signer = Arc::new(Ed25519JwtService::from_pkcs8_pem(
        settings.crypto.normalized_ed25519_pem().expose_secret(),
        Some(settings.crypto.ed25519_key_id.clone()),
    )?);
    let secret_cipher = Arc::new(Aes256GcmCipher::from_base64(
        settings.crypto.aes_master_key.expose_secret(),
    )?);
    let totp_service = Arc::new(Rfc6238TotpService::new());
    let hibp_client = Arc::new(NoopHibpClient);
    let mail_provider = Arc::new(ConsoleMailProvider::new("no-reply@example.com"));

    let (event_bus, receiver) = EventBus::new(256);
    let worker = EventWorker::new(
        receiver,
        mail_provider.clone(),
        audit_repo.clone(),
        settings.server.public_base_url.clone(),
    );
    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(worker.run(stop_rx));

    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_cfg = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        user_repo.clone(),
        session_repo.clone(),
        audit_repo,
        oauth_repo.clone(),
        passkey_repo,
        token_store.clone(),
        rate_limiter,
        password_hasher,
        token_signer,
        secret_cipher,
        totp_service,
        hibp_client,
        mail_provider,
        google_provider.clone(),
        github_provider.clone(),
        webauthn_service,
        event_bus,
        pg_pool,
        redis_pool,
    );

    let app = build_router(state)?;
    Ok(TestContext {
        app,
        user_repo,
        session_repo,
        oauth_repo,
        token_store,
        google_provider,
        github_provider,
    })
}

async fn send_request(app: &Router, req: Request<Body>) -> TestResult<Response> {
    Ok(app.clone().oneshot(req).await?)
}

async fn json_body<T: serde::de::DeserializeOwned>(response: Response) -> TestResult<T> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ===========================================================================
// Test Cases
// ===========================================================================

#[tokio::test]
async fn test_oauth_authorization_url_generation() -> TestResult {
    let ctx = setup_app().await?;

    // 1. Google OAuth URL Generation
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let body: OAuthUrlResponse = json_body(res).await?;
    assert!(
        body.url
            .starts_with("https://accounts.google.com/o/oauth2/v2/auth")
    );
    assert!(body.url.contains(&format!("state={}", body.state)));

    // Verify state was saved to TokenStore
    let state_key = format!("oauth:state:google:{}", body.state);
    let stored = ctx.token_store.get_token(&state_key).await?;
    assert_eq!(stored.as_deref(), Some("valid"));

    // 2. GitHub OAuth URL Generation
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/github/url")
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let body: OAuthUrlResponse = json_body(res).await?;
    assert!(
        body.url
            .starts_with("https://github.com/login/oauth/authorize")
    );
    assert!(body.url.contains(&format!("state={}", body.state)));

    let state_key = format!("oauth:state:github:{}", body.state);
    let stored = ctx.token_store.get_token(&state_key).await?;
    assert_eq!(stored.as_deref(), Some("valid"));

    // 3. Unsupported Provider returns 422 Unprocessable Entity
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/facebook/url")
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let problem: ProblemDetails = json_body(res).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");

    Ok(())
}

#[tokio::test]
async fn test_oauth_new_user_signup_and_cookie_issuance() -> TestResult {
    let ctx = setup_app().await?;

    // 1. Generate CSRF state via URL endpoint
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    let url_resp: OAuthUrlResponse = json_body(res).await?;

    // 2. Mock external Google profile
    let auth_code = "google_test_auth_code_123";
    let profile_email = EmailAddress::parse("newuser@gmail.com")?;
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "google-sub-98765".to_owned(),
            email: profile_email.clone(),
            name: Some("Google New User".to_owned()),
        },
    )?;

    // 3. Callback invocation with web client type
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .header("X-Client-Type", "web")
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Verify Set-Cookie headers for access and refresh tokens
    let cookies: Vec<_> = res
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    assert!(cookies.iter().any(|c| c.starts_with("access_token=")));
    assert!(cookies.iter().any(|c| c.contains("refresh_token=")));

    // Verify tokens in JSON body
    let tokens: serde_json::Value = json_body(res).await?;
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(
        tokens["access_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert!(
        tokens["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );

    // 4. Verify user record in repository
    let user = ctx
        .user_repo
        .find_by_email(&profile_email)
        .await?
        .ok_or("user record not created")?;
    assert_eq!(user.status, AccountStatus::Active);
    assert!(user.email_verified_at.is_some());
    assert!(user.password_hash.is_none()); // Passwordless OAuth user

    // 5. Verify OAuthAccount linking
    let account = ctx
        .oauth_repo
        .find_by_provider_and_id(OAuthProvider::Google, "google-sub-98765")
        .await?
        .ok_or("oauth account link not created")?;
    assert_eq!(account.user_id, user.id);
    assert_eq!(account.provider, OAuthProvider::Google);
    assert_eq!(account.provider_user_id, "google-sub-98765");

    // 6. Verify state was consumed (cannot be replayed)
    let state_key = format!("oauth:state:google:{}", url_resp.state);
    let state_val = ctx.token_store.get_token(&state_key).await?;
    assert_eq!(state_val, None);

    Ok(())
}

#[tokio::test]
async fn test_oauth_existing_user_linking() -> TestResult {
    let ctx = setup_app().await?;

    // 1. Create existing user with a password
    let existing_email = EmailAddress::parse("existing.developer@github.com")?;
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8",
    )?;
    let mut existing_user = User::new(existing_email.clone(), None, dummy_hash);
    existing_user.status = AccountStatus::Unverified; // Should become Active upon verified OAuth login
    ctx.user_repo.create(&existing_user).await?;

    // 2. Generate anti-CSRF state for GitHub
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/github/url")
        .body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    let url_resp: OAuthUrlResponse = json_body(res).await?;

    // 3. Register GitHub profile matching existing user's email
    let auth_code = "github_code_555";
    ctx.github_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::GitHub,
            provider_user_id: "github-id-443322".to_owned(),
            email: existing_email.clone(),
            name: Some("Existing Dev".to_owned()),
        },
    )?;

    // 4. Callback invocation
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/github/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Verify existing user was NOT duplicated
    assert_eq!(ctx.user_repo.count_all().await?, 1);

    // Verify user status was upgraded to Active and email verified
    let updated_user = ctx
        .user_repo
        .find_by_email(&existing_email)
        .await?
        .ok_or("user record not found")?;
    assert_eq!(updated_user.id, existing_user.id);
    assert_eq!(updated_user.status, AccountStatus::Active);
    assert!(updated_user.email_verified_at.is_some());
    // Password hash was cleared to prevent pre-account takeover on unverified account (R1.4)
    assert!(updated_user.password_hash.is_none());

    // Verify login with previous password via /api/v1/auth/login is rejected
    let login_payload = serde_json::json!({
        "email": existing_email.as_str(),
        "password": "Password123!"
    });
    let req_login = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;
    let res_login = send_request(&ctx.app, req_login).await?;
    assert_eq!(res_login.status(), StatusCode::UNAUTHORIZED);
    let problem: ProblemDetails = json_body(res_login).await?;
    assert_eq!(problem.code, "AUTH_INVALID_CREDENTIALS");

    // Verify OAuthAccount is linked to this user
    let account = ctx
        .oauth_repo
        .find_by_provider_and_id(OAuthProvider::GitHub, "github-id-443322")
        .await?
        .ok_or("oauth link not found")?;
    assert_eq!(account.user_id, existing_user.id);

    // 5. Subsequent OAuth login with the same external account
    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/github/url")
        .body(Body::empty())?;
    let res2 = send_request(&ctx.app, req2).await?;
    let url_resp2: OAuthUrlResponse = json_body(res2).await?;

    let auth_code2 = "github_code_subsequent";
    ctx.github_provider.register_profile(
        auth_code2,
        OAuthProfile {
            provider: OAuthProvider::GitHub,
            provider_user_id: "github-id-443322".to_owned(),
            email: existing_email.clone(),
            name: Some("Existing Dev".to_owned()),
        },
    )?;

    let req_login = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/github/callback?code={}&state={}",
            auth_code2, url_resp2.state
        ))
        .body(Body::empty())?;
    let res_login = send_request(&ctx.app, req_login).await?;
    assert_eq!(res_login.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_oauth_anti_csrf_state_validation_failure() -> TestResult {
    let ctx = setup_app().await?;

    // 1. Invocation with an unregistered/tampered state
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/callback?code=fake_code&state=forged_state_token")
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let problem: ProblemDetails = json_body(res).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");

    // 2. Replay attack: State is valid once, but rejected on second use
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_request(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = json_body(res_url).await?;

    let auth_code = "replay_code_1";
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "replay-sub-1".to_owned(),
            email: EmailAddress::parse("replay@example.com")?,
            name: None,
        },
    )?;

    // First attempt succeeds
    let req_first = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;
    let res_first = send_request(&ctx.app, req_first).await?;
    assert_eq!(res_first.status(), StatusCode::OK);

    // Second attempt with exact same state fails with 403 Forbidden
    let req_second = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;
    let res_second = send_request(&ctx.app, req_second).await?;
    assert_eq!(res_second.status(), StatusCode::FORBIDDEN);

    let problem: ProblemDetails = json_body(res_second).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");

    Ok(())
}

#[tokio::test]
async fn test_oauth_password_login_denial_on_passwordless_account() -> TestResult {
    let ctx = setup_app().await?;

    // 1. Create passwordless user via OAuth
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_request(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = json_body(res_url).await?;

    let auth_code = "oauth_code_only";
    let user_email = "passwordless@example.com";
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "google-pwdless-1".to_owned(),
            email: EmailAddress::parse(user_email)?,
            name: None,
        },
    )?;

    let req_callback = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;
    let res_callback = send_request(&ctx.app, req_callback).await?;
    assert_eq!(res_callback.status(), StatusCode::OK);

    // 2. Attempt standard password login against this user
    let login_payload = serde_json::json!({
        "email": user_email,
        "password": "ValidPassword123!"
    });
    let req_login = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let start = std::time::Instant::now();
    let res_login = send_request(&ctx.app, req_login).await?;
    let duration = start.elapsed();

    assert_eq!(res_login.status(), StatusCode::UNAUTHORIZED);
    let problem: ProblemDetails = json_body(res_login).await?;
    assert_eq!(problem.code, "AUTH_INVALID_CREDENTIALS");

    // Verify timing attack mitigation: Dummy hash verification occurred
    // Dummy hash Argon2 verification takes >= 1ms
    assert!(duration.as_millis() >= 1);

    Ok(())
}

#[tokio::test]
async fn test_oauth_pre_account_takeover_prevention() -> TestResult {
    let ctx = setup_app().await?;

    let victim_email = EmailAddress::parse("victim.pretakeover@example.com")?;
    let attacker_password = "AttackerSecretPassword999!";
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8",
    )?;

    // 1. Attacker pre-registers account with victim's email (Unverified status, password set)
    let mut attacker_user = User::new(victim_email.clone(), None, dummy_hash);
    attacker_user.status = AccountStatus::Unverified;
    attacker_user.failed_login_attempts = 2;
    attacker_user.locked_until = None;
    ctx.user_repo.create(&attacker_user).await?;

    // Pre-create an active session for the attacker
    let pre_existing_session = Session::new(
        attacker_user.id,
        "attacker_stale_refresh_token_hash".to_owned(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
        Some("AttackerBrowser/1.0".to_owned()),
        Some("AttackerDevice".to_owned()),
        chrono::Duration::days(7),
    );
    ctx.session_repo.create(&pre_existing_session).await?;

    // Verify pre-existing session is currently active
    let initial_sessions = ctx
        .session_repo
        .list_by_user_id(&attacker_user.id, 10, 0)
        .await?;
    assert_eq!(initial_sessions.len(), 1);
    assert!(!initial_sessions[0].is_revoked());

    // 2. Legitimate victim logs in via Google OAuth
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_request(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = json_body(res_url).await?;

    let auth_code = "google_victim_auth_code_123";
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "google-victim-sub-123".to_owned(),
            email: victim_email.clone(),
            name: Some("Victim Legitimate".to_owned()),
        },
    )?;

    let req_callback = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;
    let res_callback = send_request(&ctx.app, req_callback).await?;
    assert_eq!(res_callback.status(), StatusCode::OK);

    // 3. Verify user account state post-linking
    let updated_user = ctx
        .user_repo
        .find_by_email(&victim_email)
        .await?
        .ok_or("user record missing")?;

    // - Account is verified and active
    assert_eq!(updated_user.status, AccountStatus::Active);
    assert!(updated_user.email_verified_at.is_some());

    // - Attacker password hash is completely purged (None)
    assert!(updated_user.password_hash.is_none());

    // - Lockout counters reset
    assert_eq!(updated_user.failed_login_attempts, 0);
    assert!(updated_user.locked_until.is_none());

    // 4. Verify attacker's pre-existing session was revoked
    let check_pre_session = ctx
        .session_repo
        .find_by_id(&pre_existing_session.id)
        .await?
        .ok_or("session missing")?;
    assert!(check_pre_session.is_revoked());

    // 5. Verify attacker cannot log in with previous password
    let login_payload = serde_json::json!({
        "email": "victim.pretakeover@example.com",
        "password": attacker_password,
    });
    let req_login = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;
    let res_login = send_request(&ctx.app, req_login).await?;
    assert_eq!(res_login.status(), StatusCode::UNAUTHORIZED);
    let problem: ProblemDetails = json_body(res_login).await?;
    assert_eq!(problem.code, "AUTH_INVALID_CREDENTIALS");

    // 6. Verify victim can continue to authenticate via OAuth seamlessly
    let req_url2 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url2 = send_request(&ctx.app, req_url2).await?;
    let url_resp2: OAuthUrlResponse = json_body(res_url2).await?;

    let auth_code2 = "google_victim_auth_code_subsequent";
    ctx.google_provider.register_profile(
        auth_code2,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "google-victim-sub-123".to_owned(),
            email: victim_email.clone(),
            name: Some("Victim Legitimate".to_owned()),
        },
    )?;

    let req_callback2 = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code2, url_resp2.state
        ))
        .body(Body::empty())?;
    let res_callback2 = send_request(&ctx.app, req_callback2).await?;
    assert_eq!(res_callback2.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_oauth_google_rejects_unverified_email() -> TestResult {
    // Part 1: Direct GoogleOAuthAdapter test with local mock HTTP server
    let mock_google = Router::new()
        .route(
            "/token",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "access_token": "google_test_token_123"
                }))
            }),
        )
        .route(
            "/userinfo_unverified",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "sub": "google-unverified-sub",
                    "email": "unverified.user@gmail.com",
                    "email_verified": false,
                    "name": "Unverified User"
                }))
            }),
        )
        .route(
            "/userinfo_missing_verified",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "sub": "google-missing-sub",
                    "email": "missing.verified@gmail.com",
                    "name": "Missing Verified Field"
                }))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_google).await;
    });

    let adapter_unverified = korgan::adapters::outbound::oauth::GoogleOAuthAdapter::with_endpoints(
        "test-client-id",
        secrecy::SecretString::new("test-secret".into()),
        "http://localhost:8080/callback",
        "http://localhost:8080/auth",
        format!("http://127.0.0.1:{port}/token"),
        format!("http://127.0.0.1:{port}/userinfo_unverified"),
    );

    let err1 = match adapter_unverified.exchange_code("code_unverified").await {
        Err(e) => e,
        Ok(_) => {
            return Err(
                "expected exchange_code to fail with unverified email, but succeeded".into(),
            );
        }
    };
    assert!(
        err1.to_string()
            .contains("google account email is not verified"),
        "expected unverified email security error, got: {err1}"
    );

    let adapter_missing = korgan::adapters::outbound::oauth::GoogleOAuthAdapter::with_endpoints(
        "test-client-id",
        secrecy::SecretString::new("test-secret".into()),
        "http://localhost:8080/callback",
        "http://localhost:8080/auth",
        format!("http://127.0.0.1:{port}/token"),
        format!("http://127.0.0.1:{port}/userinfo_missing_verified"),
    );

    let err2 = match adapter_missing.exchange_code("code_missing").await {
        Err(e) => e,
        Ok(_) => {
            return Err(
                "expected exchange_code to fail with missing email_verified, but succeeded".into(),
            );
        }
    };
    assert!(
        err2.to_string()
            .contains("google account email is not verified"),
        "expected unverified email security error, got: {err2}"
    );

    // Part 2: E2E Callback invocation with security error rejection
    let ctx = setup_app().await?;

    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_request(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = json_body(res_url).await?;

    let bad_code = "google_code_unverified_email";
    ctx.google_provider.register_error(
        bad_code,
        PortError::security("google account email is not verified"),
    )?;

    let req_callback = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            bad_code, url_resp.state
        ))
        .body(Body::empty())?;

    let res_callback = send_request(&ctx.app, req_callback).await?;
    assert!(
        res_callback.status() == StatusCode::FORBIDDEN
            || res_callback.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "expected security error rejection status (403 or 500), got: {}",
        res_callback.status()
    );

    // Verify no user was created
    assert_eq!(ctx.user_repo.count_all().await?, 0);

    Ok(())
}

#[tokio::test]
async fn test_oauth_github_ignores_public_bio_email() -> TestResult {
    // Part 1: Direct GithubOAuthAdapter test with local mock HTTP server
    let mock_github = Router::new()
        .route(
            "/login/oauth/access_token",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "access_token": "gh_test_token_456"
                }))
            }),
        )
        // Public bio profile contains unverified bio email
        .route(
            "/user",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "id": 987654,
                    "login": "attacker-dev",
                    "name": "Attacker Dev",
                    "email": "unverified_bio_public@attacker-controlled.com"
                }))
            }),
        )
        // Case A: /user/emails returns no verified emails
        .route(
            "/user/emails_unverified",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!([
                    {
                        "email": "unverified_bio_public@attacker-controlled.com",
                        "primary": true,
                        "verified": false
                    }
                ]))
            }),
        )
        // Case B: /user/emails returns legitimate verified primary email
        .route(
            "/user/emails_verified",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!([
                    {
                        "email": "unverified_bio_public@attacker-controlled.com",
                        "primary": false,
                        "verified": false
                    },
                    {
                        "email": "verified_primary@legit-company.org",
                        "primary": true,
                        "verified": true
                    }
                ]))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_github).await;
    });

    // Subcase A: Unverified bio email + no verified emails in /user/emails -> REJECT
    let adapter_unverified = korgan::adapters::outbound::oauth::GithubOAuthAdapter::with_endpoints(
        "gh-client-id",
        secrecy::SecretString::new("gh-secret".into()),
        "http://localhost:8080/callback",
        "http://localhost:8080/auth",
        format!("http://127.0.0.1:{port}/login/oauth/access_token"),
        format!("http://127.0.0.1:{port}/user"),
        format!("http://127.0.0.1:{port}/user/emails_unverified"),
    );

    let err = match adapter_unverified.exchange_code("code_unverified").await {
        Err(e) => e,
        Ok(_) => {
            return Err(
                "expected exchange_code to fail with unverified bio email, but succeeded".into(),
            );
        }
    };
    assert!(
        err.to_string()
            .contains("no verified email found on github account")
            || err
                .to_string()
                .contains("github account has no verified email"),
        "expected no verified email error, got: {err}"
    );

    // Subcase B: Unverified bio email + verified primary in /user/emails -> ACCEPTS VERIFIED PRIMARY
    let adapter_verified = korgan::adapters::outbound::oauth::GithubOAuthAdapter::with_endpoints(
        "gh-client-id",
        secrecy::SecretString::new("gh-secret".into()),
        "http://localhost:8080/callback",
        "http://localhost:8080/auth",
        format!("http://127.0.0.1:{port}/login/oauth/access_token"),
        format!("http://127.0.0.1:{port}/user"),
        format!("http://127.0.0.1:{port}/user/emails_verified"),
    );

    let profile = adapter_verified.exchange_code("code_verified").await?;

    // Bio email was strictly ignored
    assert_ne!(
        profile.email.as_str(),
        "unverified_bio_public@attacker-controlled.com"
    );
    // Verified primary email was chosen
    assert_eq!(profile.email.as_str(), "verified_primary@legit-company.org");

    // Part 2: E2E Callback invocation with verified primary email
    let ctx = setup_app().await?;

    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/github/url")
        .body(Body::empty())?;
    let res_url = send_request(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = json_body(res_url).await?;

    let auth_code = "github_code_legit_verified";
    ctx.github_provider
        .register_profile(auth_code, profile.clone())?;

    let req_callback = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/github/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .body(Body::empty())?;

    let res_callback = send_request(&ctx.app, req_callback).await?;
    assert_eq!(res_callback.status(), StatusCode::OK);

    // Verify user created with verified email, NOT unverified bio email
    let user = ctx
        .user_repo
        .find_by_email(&profile.email)
        .await?
        .ok_or("user record not found")?;
    assert_eq!(user.email.as_str(), "verified_primary@legit-company.org");

    let bio_email = EmailAddress::parse("unverified_bio_public@attacker-controlled.com")?;
    let bio_user = ctx.user_repo.find_by_email(&bio_email).await?;
    assert!(
        bio_user.is_none(),
        "unverified bio email must not exist in user repository"
    );

    Ok(())
}
