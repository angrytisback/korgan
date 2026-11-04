//! Comprehensive integration tests for Phase 5 Inbound HTTP Layer.
//!
//! Verifies:
//! - Health probes (`/health/live`)
//! - JWKS RFC 7517 discovery (`/.well-known/jwks.json`)
//! - OpenAPI 3.1 & Scalar documentation (`/openapi.json`, `/docs`)
//! - Registration (`POST /api/v1/auth/register`) and validation error responses (RFC 9457)
//! - Dual-mode login (`POST /api/v1/auth/login`) with cookies for Web and JSON body for Mobile
//! - Dual-mode auth extractor (`AuthUser`) via Bearer token and via Cookie
//! - Refresh token rotation (`POST /api/v1/auth/refresh`)
//! - Session management (`GET /api/v1/sessions`, `DELETE /api/v1/sessions/:id`, `DELETE /api/v1/sessions`)
//! - Logout (`POST /api/v1/auth/logout`) with cookie clearing
//! - MFA workflow (`POST /api/v1/mfa/setup`, `/enable`, `/disable`)
//! - Password management (`POST /api/v1/password/forgot`, `/change`)
//! - User profile (`GET /api/v1/users/me`, `PATCH /api/v1/users/me`)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use chrono::Utc;
use http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::{AppState, ProblemDetails, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::workers::EventBus;
use korgan::config::Settings;
use korgan::domain::entities::{
    AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{OAuthProviderPort, PasswordHasher, WebAuthnService};
use secrecy::ExposeSecret;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Throwaway test crypto material
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ---------------------------------------------------------------------------
// In-Memory Test Fixtures
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct TestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for TestUserRepo {
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
        match emails.get(email.as_str()) {
            Some(id) => Ok(users.get(id).cloned()),
            None => Ok(None),
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
        match usernames.get(username.as_str()) {
            Some(id) => Ok(users.get(id).cloned()),
            None => Ok(None),
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

        if emails.contains_key(user.email.as_str()) {
            return Err(PortError::conflict("email already exists"));
        }
        emails.insert(user.email.to_string(), user.id);
        if let Some(ref u) = user.username {
            usernames.insert(u.to_string(), user.id);
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
        match history.get(user_id) {
            Some(h) => Ok(h.iter().take(limit as usize).cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    async fn find_mfa(&self, user_id: &UserId) -> Result<Option<UserMfa>, PortError> {
        let mfa = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(mfa.get(user_id).cloned())
    }

    async fn save_mfa(&self, mfa: &UserMfa) -> Result<(), PortError> {
        let mut store = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        store.insert(mfa.user_id, mfa.clone());
        Ok(())
    }

    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError> {
        let mut store = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        store.remove(user_id);
        Ok(())
    }

    async fn consume_backup_code(
        &self,
        user_id: &UserId,
        code_hash: &str,
    ) -> Result<bool, PortError> {
        let mut store = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(mfa) = store.get_mut(user_id) {
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
        list.sort_by_key(|a| std::cmp::Reverse(a.created_at));
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
struct TestSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
}

#[async_trait]
impl SessionRepository for TestSessionRepo {
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
struct TestAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for TestAuditRepo {
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
struct TestTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for TestTokenStore {
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
            return Ok(true);
        }
        Ok(false)
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
struct TestRateLimiter;

#[async_trait]
impl RateLimiterPort for TestRateLimiter {
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

#[derive(Default, Debug)]
struct TestOAuthAccountRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
}

#[async_trait]
impl OAuthAccountRepository for TestOAuthAccountRepo {
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
struct TestPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for TestPasskeyRepo {
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

// ---------------------------------------------------------------------------
// Test App Assembly
// ---------------------------------------------------------------------------

struct TestContext {
    app: Router,
    user_repo: Arc<TestUserRepo>,
    session_repo: Arc<TestSessionRepo>,
    token_signer: Arc<Ed25519JwtService>,
}

fn setup_test_app() -> Result<TestContext, Box<dyn std::error::Error>> {
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
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);

    let user_repo = Arc::new(TestUserRepo::default());
    let session_repo = Arc::new(TestSessionRepo::default());
    let audit_repo = Arc::new(TestAuditRepo::default());
    let token_store = Arc::new(TestTokenStore::default());
    let rate_limiter = Arc::new(TestRateLimiter);
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> =
        Arc::new(TestOAuthAccountRepo::default());
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(TestPasskeyRepo::default());
    let google_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
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

    let (event_bus, event_rx) = EventBus::new(100);
    let event_worker = korgan::application::workers::EventWorker::new(
        event_rx,
        mail_provider.clone(),
        audit_repo.clone(),
        settings.server.public_base_url.clone(),
    );

    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(event_worker.run(stop_rx));

    // Lazy pools for tests
    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_cfg = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        user_repo.clone(),
        session_repo.clone(),
        audit_repo,
        oauth_account_repo,
        passkey_repo,
        token_store,
        rate_limiter,
        password_hasher,
        token_signer.clone(),
        secret_cipher,
        totp_service,
        hibp_client,
        mail_provider,
        google_oauth,
        github_oauth,
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
        token_signer,
    })
}

async fn send_request(
    app: &Router,
    req: Request<Body>,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app.clone().oneshot(req).await?)
}

async fn json_body<T: serde::de::DeserializeOwned>(
    response: Response,
) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = to_bytes(response.into_body(), 64 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ---------------------------------------------------------------------------
// Phase 5 Integration Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_and_jwks_and_docs_endpoints() -> TestResult {
    let ctx = setup_test_app()?;

    // 1. Health Live
    let req = Request::builder().uri("/health/live").body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let val: serde_json::Value = json_body(res).await?;
    assert_eq!(val["status"], "ok");

    let req = Request::builder().uri("/health").body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let val: serde_json::Value = json_body(res).await?;
    assert_eq!(val["status"], "ok");

    // 2. JWKS
    let req = Request::builder()
        .uri("/.well-known/jwks.json")
        .body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let jwks: serde_json::Value = json_body(res).await?;
    assert!(jwks["keys"].is_array());
    assert_eq!(jwks["keys"][0]["kty"], "OKP");
    assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
    assert_eq!(jwks["keys"][0]["alg"], "EdDSA");

    // 3. OpenAPI 3.1 Document
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let openapi: serde_json::Value = json_body(res).await?;
    assert!(openapi["paths"]["/api/v1/auth/register"].is_object());
    assert!(openapi["paths"]["/api/v1/auth/login"].is_object());
    assert!(openapi["paths"]["/api/v1/sessions"].is_object());
    assert!(openapi["paths"]["/api/v1/users/me"].is_object());

    // 4. Scalar UI
    let req = Request::builder().uri("/docs").body(Body::empty())?;
    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_registration_validation_and_success() -> TestResult {
    let ctx = setup_test_app()?;

    // 1. Validation failure: short password & invalid email
    let bad_body = serde_json::json!({
        "email": "invalid-email",
        "password": "short"
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/register")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&bad_body)?))?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        res.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json")
    );
    let problem: ProblemDetails = json_body(res).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");
    assert!(!problem.errors.is_empty());

    // 2. Successful registration
    let good_body = serde_json::json!({
        "email": "NewUser@Example.com",
        "password": "SecurePassword123!",
        "username": "newuser"
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/register")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&good_body)?))?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::CREATED);
    let val: serde_json::Value = json_body(res).await?;
    assert_eq!(val["email"], "newuser@example.com"); // normalized lowercase
    assert_eq!(val["status"], "unverified");
    assert_eq!(val["verification_required"], true);

    Ok(())
}

#[tokio::test]
async fn test_dual_mode_login_and_auth_extractor() -> TestResult {
    let ctx = setup_test_app()?;

    // Seed active user in mock repo
    let email = EmailAddress::parse("alice@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let raw_pass = RawPassword::new("CorrectPassword123!")?;
    let hash = hasher.hash_password(&raw_pass).await?;
    let mut user = User::new(email, Some(Username::new("alice")?), hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    // 1. WEB CLIENT LOGIN: Expects Set-Cookie headers
    let login_payload = serde_json::json!({
        "email": "alice@example.com",
        "password": "CorrectPassword123!"
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "web")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Verify Set-Cookie headers contain access_token and refresh_token
    let cookies: Vec<String> = res
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok().map(ToOwned::to_owned))
        .collect();

    assert!(cookies.iter().any(|c| c.contains("access_token=")
        && c.contains("HttpOnly")
        && c.contains("SameSite=Strict")));
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("refresh_token=") && c.contains("HttpOnly"))
    );

    let body_tokens: serde_json::Value = json_body(res).await?;
    let access_token = body_tokens["access_token"]
        .as_str()
        .ok_or("missing access token")?;
    let session_id_str = body_tokens["session_id"]
        .as_str()
        .ok_or("missing session id")?;

    // 2. MOBILE CLIENT LOGIN: No Set-Cookie headers
    let req_mobile = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "mobile")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let res_mobile = send_request(&ctx.app, req_mobile).await?;
    assert_eq!(res_mobile.status(), StatusCode::OK);
    assert!(res_mobile.headers().get(SET_COOKIE).is_none());

    // 3. PROTECTED ROUTE via Authorization: Bearer <token>
    let req_auth_header = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())?;

    let res_profile = send_request(&ctx.app, req_auth_header).await?;
    assert_eq!(res_profile.status(), StatusCode::OK);
    let profile: serde_json::Value = json_body(res_profile).await?;
    assert_eq!(profile["email"], "alice@example.com");
    assert_eq!(profile["username"], "alice");

    // 4. PROTECTED ROUTE via Cookie: access_token=<token>
    let req_auth_cookie = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(COOKIE, format!("access_token={access_token}"))
        .body(Body::empty())?;

    let res_cookie_profile = send_request(&ctx.app, req_auth_cookie).await?;
    assert_eq!(res_cookie_profile.status(), StatusCode::OK);

    // 5. PROTECTED ROUTE UNCREDENTIALED: 401 ProblemDetails
    let req_no_auth = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .body(Body::empty())?;

    let res_unauth = send_request(&ctx.app, req_no_auth).await?;
    assert_eq!(res_unauth.status(), StatusCode::UNAUTHORIZED);
    let problem: ProblemDetails = json_body(res_unauth).await?;
    assert_eq!(problem.code, "AUTH_UNAUTHENTICATED");

    // 6. SESSIONS LIST
    let req_sessions = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())?;

    let res_sessions = send_request(&ctx.app, req_sessions).await?;
    assert_eq!(res_sessions.status(), StatusCode::OK);
    let sessions: Vec<serde_json::Value> = json_body(res_sessions).await?;
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .any(|s| s["id"] == session_id_str && s["is_current"] == true)
    );

    // 7. LOGOUT (Web mode): Revokes session and clears cookies
    let req_logout = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-Client-Type", "web")
        .body(Body::empty())?;

    let res_logout = send_request(&ctx.app, req_logout).await?;
    assert_eq!(res_logout.status(), StatusCode::NO_CONTENT);

    // Check Set-Cookie headers expire cookies (Max-Age=0)
    let logout_cookies: Vec<String> = res_logout
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok().map(ToOwned::to_owned))
        .collect();

    assert!(
        logout_cookies
            .iter()
            .any(|c| c.contains("access_token=") && c.contains("Max-Age=0"))
    );
    assert!(
        logout_cookies
            .iter()
            .any(|c| c.contains("refresh_token=") && c.contains("Max-Age=0"))
    );

    // After logout, accessing protected route with that token returns 401 (session revoked)
    let req_post_logout = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())?;

    let res_after_logout = send_request(&ctx.app, req_post_logout).await?;
    assert_eq!(res_after_logout.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn test_mfa_workflow_and_profile_updates() -> TestResult {
    let ctx = setup_test_app()?;

    // Seed active user
    let email = EmailAddress::parse("bob@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let raw_pass = RawPassword::new("CorrectPassword123!")?;
    let hash = hasher.hash_password(&raw_pass).await?;
    let mut user = User::new(email, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    // Create session & access token
    let session = Session::new(
        user.id,
        "dummy_refresh_hash".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("TestRunner".to_owned()),
        Some("Linux".to_owned()),
        chrono::Duration::days(1),
    );
    let session_id = session.id;
    ctx.session_repo.create(&session).await?;

    let claims = korgan::ports::services::AccessTokenClaims {
        sub: user.id,
        sid: session_id,
        iss: "https://auth.korgan.local".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };
    use korgan::ports::services::TokenSigner;
    let token = ctx.token_signer.sign_access_token(&claims)?;

    // 1. MFA Setup: POST /api/v1/mfa/setup
    let req_mfa_setup = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/mfa/setup")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res_setup = send_request(&ctx.app, req_mfa_setup).await?;
    assert_eq!(res_setup.status(), StatusCode::OK);
    let setup_val: serde_json::Value = json_body(res_setup).await?;
    assert!(setup_val["secret"].is_string());
    assert!(
        setup_val["qr_code_svg"]
            .as_str()
            .ok_or("missing svg")?
            .contains("<svg")
    );

    // 2. Profile Update: PATCH /api/v1/users/me
    let update_body = serde_json::json!({
        "username": "bobsmith"
    });
    let req_update = Request::builder()
        .method(Method::PATCH)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&update_body)?))?;

    let res_update = send_request(&ctx.app, req_update).await?;
    assert_eq!(res_update.status(), StatusCode::OK);
    let updated_profile: serde_json::Value = json_body(res_update).await?;
    assert_eq!(updated_profile["username"], "bobsmith");

    // 3. Password Forgot: POST /api/v1/password/forgot
    let forgot_body = serde_json::json!({
        "email": "bob@example.com"
    });
    let req_forgot = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/password/forgot")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&forgot_body)?))?;

    let res_forgot = send_request(&ctx.app, req_forgot).await?;
    assert_eq!(res_forgot.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn test_refresh_ambiguous_token_injection_rejected() -> TestResult {
    let ctx = setup_test_app()?;

    // Seed active user in mock repo
    let email = EmailAddress::parse("charlie@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let raw_pass = RawPassword::new("CorrectPassword123!")?;
    let hash = hasher.hash_password(&raw_pass).await?;
    let mut user = User::new(email, Some(Username::new("charlie")?), hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    // Perform web login to obtain initial valid tokens and cookies
    let login_payload = serde_json::json!({
        "email": "charlie@example.com",
        "password": "CorrectPassword123!"
    });
    let req_login = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "web")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let res_login = send_request(&ctx.app, req_login).await?;
    assert_eq!(res_login.status(), StatusCode::OK);

    let body_tokens: serde_json::Value = json_body(res_login).await?;
    let access_token = body_tokens["access_token"]
        .as_str()
        .ok_or("missing access token")?;
    let refresh_token = body_tokens["refresh_token"]
        .as_str()
        .ok_or("missing refresh token")?;

    // 1. REFRESH: Ambiguous Token Injection (Web client sending both cookie and JSON body) -> 422
    let ambiguous_payload = serde_json::json!({ "refresh_token": refresh_token });
    let req_ambiguous_web = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "web")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .body(Body::from(serde_json::to_vec(&ambiguous_payload)?))?;

    let res_ambiguous_web = send_request(&ctx.app, req_ambiguous_web).await?;
    assert_eq!(res_ambiguous_web.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem: ProblemDetails = json_body(res_ambiguous_web).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");
    assert!(
        problem
            .errors
            .iter()
            .any(|e| e.field == "refresh_token" && e.reason.contains("ambiguous"))
    );

    // 2. REFRESH: Ambiguous Token Injection (CLI client sending both cookie and JSON body) -> 422
    let req_ambiguous_cli = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "cli")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .body(Body::from(serde_json::to_vec(&ambiguous_payload)?))?;

    let res_ambiguous_cli = send_request(&ctx.app, req_ambiguous_cli).await?;
    assert_eq!(res_ambiguous_cli.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem: ProblemDetails = json_body(res_ambiguous_cli).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");

    // 3. REFRESH: Strict Channel Separation (Web client sending JSON body only) -> 422
    let req_web_body_only = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "web")
        .body(Body::from(serde_json::to_vec(&ambiguous_payload)?))?;

    let res_web_body_only = send_request(&ctx.app, req_web_body_only).await?;
    assert_eq!(res_web_body_only.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem: ProblemDetails = json_body(res_web_body_only).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");

    // 4. REFRESH: Strict Channel Separation (Mobile client sending Cookie only) -> 403 Forbidden
    let req_mobile_cookie_only = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header("X-Client-Type", "mobile")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .body(Body::empty())?;

    let res_mobile_cookie_only = send_request(&ctx.app, req_mobile_cookie_only).await?;
    assert_eq!(res_mobile_cookie_only.status(), StatusCode::FORBIDDEN);
    let problem: ProblemDetails = json_body(res_mobile_cookie_only).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");

    // 5. REFRESH: Strict Channel Separation (CLI client default sending Cookie only) -> 403 Forbidden
    // (Explicitly verifies that metadata extractor no longer coerces CLI to Web on cookie presence)
    let req_cli_cookie_only = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .body(Body::empty())?;

    let res_cli_cookie_only = send_request(&ctx.app, req_cli_cookie_only).await?;
    assert_eq!(res_cli_cookie_only.status(), StatusCode::FORBIDDEN);
    let problem: ProblemDetails = json_body(res_cli_cookie_only).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");

    // 6. LOGOUT: Ambiguous Token Injection (Both cookie and JSON body) -> 422
    let req_logout_ambiguous = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-Client-Type", "web")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ambiguous_payload)?))?;

    let res_logout_ambiguous = send_request(&ctx.app, req_logout_ambiguous).await?;
    assert_eq!(
        res_logout_ambiguous.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let problem: ProblemDetails = json_body(res_logout_ambiguous).await?;
    assert_eq!(problem.code, "VALIDATION_FAILED");

    // 7. LOGOUT: Strict Channel Separation (Web client sending JSON body) -> 422
    let req_logout_web_body = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-Client-Type", "web")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&ambiguous_payload)?))?;

    let res_logout_web_body = send_request(&ctx.app, req_logout_web_body).await?;
    assert_eq!(
        res_logout_web_body.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // 8. LOGOUT: Strict Channel Separation (Mobile client sending Cookie) -> 403
    let req_logout_mobile_cookie = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header("X-Client-Type", "mobile")
        .header(COOKIE, format!("refresh_token={refresh_token}"))
        .body(Body::empty())?;

    let res_logout_mobile_cookie = send_request(&ctx.app, req_logout_mobile_cookie).await?;
    assert_eq!(res_logout_mobile_cookie.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn test_r3_exhaustive_channel_separation_matrix() -> TestResult {
    let ctx = setup_test_app()?;

    // Seed active user
    let email = EmailAddress::parse("adversary@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let raw_pass = RawPassword::new("AdversaryPass123!")?;
    let hash = hasher.hash_password(&raw_pass).await?;
    let mut user = User::new(email, Some(Username::new("adversary")?), hash.clone());
    user.status = korgan::domain::entities::AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    let login_payload = serde_json::json!({
        "email": "adversary@example.com",
        "password": "AdversaryPass123!"
    });
    let req_login = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "web")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let res_login = send_request(&ctx.app, req_login).await?;
    assert_eq!(res_login.status(), StatusCode::OK);
    let body_tokens: serde_json::Value = json_body(res_login).await?;
    let _access_token = body_tokens["access_token"]
        .as_str()
        .ok_or("missing access")?;
    let refresh_token = body_tokens["refresh_token"]
        .as_str()
        .ok_or("missing refresh")?;

    let client_types = [
        Some("web"),
        Some("Web"),
        Some("WEB"),
        Some("mobile"),
        Some("Mobile"),
        Some("cli"),
        Some("CLI"),
        None, // missing header -> defaults to CLI
    ];

    // --- REFRESH ENDPOINT MATRIX ---
    for client_hdr in client_types {
        let is_web = match client_hdr {
            Some(h) => h.eq_ignore_ascii_case("web"),
            None => false,
        };

        // 1. Ambiguous: Cookie + Body (refresh_token field) -> MUST BE 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(CONTENT_TYPE, "application/json")
                .header(COOKIE, format!("refresh_token={refresh_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "refresh_token": refresh_token
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            assert_eq!(
                res.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Ambiguous refresh (cookie+body) must be 422 for {client_hdr:?}"
            );
        }

        // 2. Ambiguous: __Host- Cookie + Body ("token" alias field) -> MUST BE 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(CONTENT_TYPE, "application/json")
                .header(COOKIE, format!("__Host-refresh_token={refresh_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "token": refresh_token
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            assert_eq!(
                res.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Ambiguous refresh (__Host-+alias) must be 422 for {client_hdr:?}"
            );
        }

        // 3. Body only: Web MUST BE 422; Mobile/CLI must NOT be 403 or 422-channel rejection
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(CONTENT_TYPE, "application/json");
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "refresh_token": refresh_token
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            if is_web {
                assert_eq!(
                    res.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Web client must reject body token with 422"
                );
            } else {
                assert_ne!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must not get 403 on body token"
                );
            }
        }

        // 4. Cookie only: Web accepts; Mobile/CLI MUST BE 403 FORBIDDEN
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(COOKIE, format!("refresh_token={refresh_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::empty())?;
            let res = send_request(&ctx.app, req).await?;
            if is_web {
                assert_ne!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Web client must not get 403 on cookie token"
                );
            } else {
                assert_eq!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must get 403 on cookie token for {client_hdr:?}"
                );
                let prob: ProblemDetails = json_body(res).await?;
                assert_eq!(prob.code, "AUTH_FORBIDDEN");
            }
        }

        // 5. __Host- Cookie only: Mobile/CLI MUST BE 403 FORBIDDEN
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(COOKIE, format!("__Host-refresh_token={refresh_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::empty())?;
            let res = send_request(&ctx.app, req).await?;
            if is_web {
                assert_ne!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Web client must not get 403 on __Host- cookie token"
                );
            } else {
                assert_eq!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must get 403 on __Host- cookie token for {client_hdr:?}"
                );
            }
        }

        // 6. Neither Cookie nor Body: All clients MUST BE 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh");
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::empty())?;
            let res = send_request(&ctx.app, req).await?;
            assert_eq!(
                res.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Missing token in both channels must be 422 for {client_hdr:?}"
            );
        }
    }

    // --- LOGOUT ENDPOINT MATRIX ---
    for (i, &client_hdr) in client_types.iter().enumerate() {
        let is_web = match client_hdr {
            Some(h) => h.eq_ignore_ascii_case("web"),
            None => false,
        };

        // Create fresh user & session for each logout iteration
        let email_str = format!(
            "logout_{i}_{}@example.com",
            client_hdr.unwrap_or("none").to_lowercase()
        );
        let email_iter = EmailAddress::parse(&email_str)?;
        let mut user_iter = User::new(
            email_iter,
            Some(Username::new(format!("logoutuser{i}"))?),
            hash.clone(),
        );
        user_iter.status = korgan::domain::entities::AccountStatus::Active;
        ctx.user_repo.create(&user_iter).await?;

        let login_payload_iter = serde_json::json!({
            "email": email_str,
            "password": "AdversaryPass123!"
        });
        let req_login_iter = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(CONTENT_TYPE, "application/json")
            .header("X-Client-Type", "web")
            .body(Body::from(serde_json::to_vec(&login_payload_iter)?))?;

        let res_login_iter = send_request(&ctx.app, req_login_iter).await?;
        assert_eq!(res_login_iter.status(), StatusCode::OK);
        let body_tokens_iter: serde_json::Value = json_body(res_login_iter).await?;
        let access_token = body_tokens_iter["access_token"]
            .as_str()
            .ok_or("missing access")?;
        let refresh_token = body_tokens_iter["refresh_token"]
            .as_str()
            .ok_or("missing refresh")?;

        // 1. Ambiguous: Cookie + Body -> MUST BE 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(AUTHORIZATION, format!("Bearer {access_token}"))
                .header(CONTENT_TYPE, "application/json")
                .header(COOKIE, format!("refresh_token={refresh_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "refresh_token": refresh_token
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            assert_eq!(
                res.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Ambiguous logout must be 422 for {client_hdr:?}"
            );
        }

        // 2. Ambiguous: access_token Cookie + Body ("token" alias) -> MUST BE 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(AUTHORIZATION, format!("Bearer {access_token}"))
                .header(CONTENT_TYPE, "application/json")
                .header(COOKIE, format!("access_token={access_token}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "token": "some_token"
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            assert_eq!(
                res.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Ambiguous logout with access_token cookie must be 422 for {client_hdr:?}"
            );
        }

        // 3. Body only: Web MUST BE 422; Mobile/CLI must NOT be 403 or 422
        {
            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(AUTHORIZATION, format!("Bearer {access_token}"))
                .header(CONTENT_TYPE, "application/json");
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::from(serde_json::to_vec(&serde_json::json!({
                "refresh_token": refresh_token
            }))?))?;
            let res = send_request(&ctx.app, req).await?;
            if is_web {
                assert_eq!(
                    res.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Web client must reject body token with 422 on logout"
                );
            } else {
                assert_ne!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must not get 403 on body token"
                );
                assert_ne!(
                    res.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Mobile/CLI client must not get 422 on body token"
                );
            }
        }

        // 4. Cookie only: Web accepts; Mobile/CLI MUST BE 403
        {
            let res_login = send_request(
                &ctx.app,
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Client-Type", "web")
                    .body(Body::from(serde_json::to_vec(&login_payload_iter)?))?,
            )
            .await?;
            let body_tokens: serde_json::Value = json_body(res_login).await?;
            let at = body_tokens["access_token"]
                .as_str()
                .ok_or("missing access")?;
            let rt = body_tokens["refresh_token"]
                .as_str()
                .ok_or("missing refresh")?;

            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(AUTHORIZATION, format!("Bearer {at}"))
                .header(COOKIE, format!("refresh_token={rt}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::empty())?;
            let res = send_request(&ctx.app, req).await?;
            if is_web {
                assert_ne!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Web client must not get 403 on cookie token"
                );
            } else {
                assert_eq!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must get 403 on cookie token on logout for {client_hdr:?}"
                );
            }
        }

        // 5. __Host- Cookie only: Mobile/CLI MUST BE 403
        {
            let res_login = send_request(
                &ctx.app,
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Client-Type", "web")
                    .body(Body::from(serde_json::to_vec(&login_payload_iter)?))?,
            )
            .await?;
            let body_tokens: serde_json::Value = json_body(res_login).await?;
            let at = body_tokens["access_token"]
                .as_str()
                .ok_or("missing access")?;
            let rt = body_tokens["refresh_token"]
                .as_str()
                .ok_or("missing refresh")?;

            let mut req_b = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(AUTHORIZATION, format!("Bearer {at}"))
                .header(COOKIE, format!("__Host-refresh_token={rt}"));
            if let Some(ch) = client_hdr {
                req_b = req_b.header("X-Client-Type", ch);
            }
            let req = req_b.body(Body::empty())?;
            let res = send_request(&ctx.app, req).await?;
            if !is_web {
                assert_eq!(
                    res.status(),
                    StatusCode::FORBIDDEN,
                    "Mobile/CLI client must get 403 on __Host- cookie token on logout for {client_hdr:?}"
                );
            }
        }
    }

    Ok(())
}

fn setup_test_app_with_rate_limiter(
    rate_limiter: Arc<dyn RateLimiterPort>,
    trust_proxy: bool,
) -> Result<Router, Box<dyn std::error::Error>> {
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
            "KORGAN__RATE_LIMIT__TRUST_PROXY_HEADERS".to_owned(),
            trust_proxy.to_string(),
        ),
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);

    let user_repo = Arc::new(TestUserRepo::default());
    let session_repo = Arc::new(TestSessionRepo::default());
    let audit_repo = Arc::new(TestAuditRepo::default());
    let token_store = Arc::new(TestTokenStore::default());
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> =
        Arc::new(TestOAuthAccountRepo::default());
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(TestPasskeyRepo::default());
    let google_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
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
    let (event_bus, _rx) = EventBus::new(100);

    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_cfg = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        user_repo,
        session_repo,
        audit_repo,
        oauth_account_repo,
        passkey_repo,
        token_store,
        rate_limiter,
        password_hasher,
        token_signer,
        secret_cipher,
        totp_service,
        hibp_client,
        mail_provider,
        google_oauth,
        github_oauth,
        webauthn_service,
        event_bus,
        pg_pool,
        redis_pool,
    );

    Ok(build_router(state)?)
}

#[tokio::test]
async fn test_rate_limit_ip_spoofing_via_x_forwarded_for() -> TestResult {
    #[derive(Default)]
    struct SpyRateLimiter {
        keys: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl RateLimiterPort for SpyRateLimiter {
        async fn check_and_increment(
            &self,
            key: &str,
            limit: u32,
            _window: Duration,
        ) -> Result<RateLimitStatus, PortError> {
            self.keys
                .lock()
                .map_err(|e| PortError::cache(e.to_string()))?
                .push(key.to_string());
            Ok(RateLimitStatus {
                allowed: true,
                limit,
                remaining: limit.saturating_sub(1),
                reset_epoch_secs: 0,
                retry_after_secs: None,
            })
        }
        async fn reset(&self, _key: &str) -> Result<(), PortError> {
            Ok(())
        }
    }

    let spy = Arc::new(SpyRateLimiter::default());
    let app = setup_test_app_with_rate_limiter(spy.clone(), true)?;

    // Spoofed X-Forwarded-For: leftmost is untrusted client IP (1.1.1.1),
    // intermediate proxy (2.2.2.2), rightmost is trusted reverse proxy client IP (198.51.100.42)
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health/live")
        .header("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 198.51.100.42")
        .body(Body::empty())?;

    let res = send_request(&app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let recorded = spy.keys.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0], "http_rl:198.51.100.42");

    Ok(())
}

#[tokio::test]
async fn test_rate_limit_fail_closed_on_redis_error() -> TestResult {
    struct FailingRateLimiter;
    #[async_trait]
    impl RateLimiterPort for FailingRateLimiter {
        async fn check_and_increment(
            &self,
            _key: &str,
            _limit: u32,
            _window: Duration,
        ) -> Result<RateLimitStatus, PortError> {
            Err(PortError::cache("redis connection timed out"))
        }
        async fn reset(&self, _key: &str) -> Result<(), PortError> {
            Ok(())
        }
    }

    let app = setup_test_app_with_rate_limiter(Arc::new(FailingRateLimiter), false)?;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health/live")
        .body(Body::empty())?;

    let res = send_request(&app, req).await?;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    let bytes = to_bytes(res.into_body(), 64 * 1024).await?;
    let problem: ProblemDetails = serde_json::from_slice(&bytes)?;
    assert_eq!(problem.status, 503);

    Ok(())
}
