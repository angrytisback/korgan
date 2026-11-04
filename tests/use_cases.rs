//! Comprehensive unit tests for application layer use cases.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use korgan::adapters::outbound::crypto::Argon2PasswordHasher;
use korgan::application::dto::*;
use korgan::application::error::AppError;
use korgan::application::use_cases::*;
use korgan::application::workers::{AppEvent, EventBus};
use korgan::domain::entities::{AuditLog, Session, User, UserMfa};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{AuditLogRepository, SessionRepository, UserRepository};
use korgan::ports::services::{
    AccessTokenClaims, DecryptedSecret, HibpClient, MailProvider, PasswordHasher, SecretCipher,
    TokenSigner, TotpService,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// In-Memory Mocks for All Ports
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct MockUserRepository {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    password_history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for MockUserRepository {
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
            .password_history
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(user) = users.get_mut(user_id) {
            let hist = history.entry(*user_id).or_default();
            if let Some(ref current_hash) = user.password_hash {
                hist.insert(0, current_hash.clone());
            }
            hist.truncate(history_depth as usize);

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
            .password_history
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
        let mut map = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        map.insert(mfa.user_id, mfa.clone());
        Ok(())
    }

    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError> {
        let mut map = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        map.remove(user_id);
        Ok(())
    }

    async fn consume_backup_code(
        &self,
        user_id: &UserId,
        code_hash: &str,
    ) -> Result<bool, PortError> {
        let mut map = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(mfa) = map.get_mut(user_id) {
            Ok(mfa.consume_backup_code(code_hash))
        } else {
            Ok(false)
        }
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
}

#[derive(Default, Debug)]
struct MockSessionRepository {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
    user_repo: Mutex<Option<Arc<MockUserRepository>>>,
}

impl MockSessionRepository {
    #[allow(dead_code)]
    fn set_user_repo(&self, user_repo: Arc<MockUserRepository>) {
        if let Ok(mut lock) = self.user_repo.lock() {
            *lock = Some(user_repo);
        }
    }
}

#[async_trait]
impl SessionRepository for MockSessionRepository {
    async fn create(&self, session: &Session) -> Result<(), PortError> {
        let user_repo_opt = self
            .user_repo
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?
            .clone();
        if let Some(ur) = user_repo_opt {
            if let Ok(Some(u)) = ur.find_by_id(&session.user_id).await {
                if u.status != korgan::domain::entities::AccountStatus::Active
                    || u.is_locked(session.created_at)
                {
                    return Err(PortError::conflict(
                        "user account is not active or is locked",
                    ));
                }
            } else {
                return Err(PortError::conflict(
                    "user account is not active or is locked",
                ));
            }
        }

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
        let user_repo_opt = self
            .user_repo
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?
            .clone();
        if let Some(ur) = user_repo_opt {
            if let Ok(Some(u)) = ur.find_by_id(&new_session.user_id).await {
                if u.status != korgan::domain::entities::AccountStatus::Active
                    || u.is_locked(new_session.last_active_at)
                {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

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
            session.last_active_at = new_session.last_active_at;
            let old_session = session.clone();

            by_hash.insert(new_session.refresh_token_hash.clone(), new_session.id);
            sessions.insert(new_session.id, new_session.clone());

            return Ok(Some(old_session));
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
struct MockAuditLogRepository {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for MockAuditLogRepository {
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
struct MockTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for MockTokenStore {
    async fn set_token(
        &self,
        key: &str,
        token_hash: &str,
        _ttl: Duration,
    ) -> Result<(), PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        tokens.insert(key.to_owned(), token_hash.to_owned());
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
struct MockRateLimiter {
    counts: Mutex<HashMap<String, u32>>,
}

#[async_trait]
impl RateLimiterPort for MockRateLimiter {
    async fn check_and_increment(
        &self,
        key: &str,
        limit: u32,
        _window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        let mut counts = self
            .counts
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        let count = counts.entry(key.to_owned()).or_insert(0);
        *count += 1;
        let allowed = *count <= limit;
        Ok(RateLimitStatus {
            allowed,
            limit,
            remaining: limit.saturating_sub(*count),
            reset_epoch_secs: Utc::now().timestamp() as u64 + 60,
            retry_after_secs: if allowed { None } else { Some(60) },
        })
    }

    async fn reset(&self, key: &str) -> Result<(), PortError> {
        let mut counts = self
            .counts
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        counts.remove(key);
        Ok(())
    }
}

#[derive(Debug)]
struct MockPasswordHasherWrapper {
    inner: Argon2PasswordHasher,
    dummy_calls: AtomicUsize,
}

impl MockPasswordHasherWrapper {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let inner = Argon2PasswordHasher::new(1024, 1, 1)?;
        Ok(Self {
            inner,
            dummy_calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl PasswordHasher for MockPasswordHasherWrapper {
    async fn hash_password(&self, password: &RawPassword) -> Result<PasswordHash, PortError> {
        self.inner.hash_password(password).await
    }

    async fn verify_password(
        &self,
        password: &RawPassword,
        hash: &PasswordHash,
    ) -> Result<bool, PortError> {
        self.inner.verify_password(password, hash).await
    }

    async fn verify_against_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError> {
        self.dummy_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.verify_against_dummy_hash(password).await
    }
}

#[derive(Default, Debug)]
struct MockTokenSigner;

impl TokenSigner for MockTokenSigner {
    fn sign_access_token(&self, _claims: &AccessTokenClaims) -> Result<String, PortError> {
        Ok("mock.jwt.token".to_owned())
    }

    fn verify_access_token(&self, _token: &str) -> Result<AccessTokenClaims, PortError> {
        Ok(AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "mock".to_owned(),
            aud: "mock".to_owned(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: "mock-jti".to_owned(),
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_string()],
        })
    }

    fn public_key_jwks(&self) -> Result<serde_json::Value, PortError> {
        Ok(serde_json::json!({ "keys": [] }))
    }
}

#[derive(Default, Debug)]
struct MockHibpClient {
    breached: Mutex<HashSet<String>>,
}

#[async_trait]
impl HibpClient for MockHibpClient {
    async fn is_password_breached(&self, password: &RawPassword) -> Result<bool, PortError> {
        let breached = self
            .breached
            .lock()
            .map_err(|e| PortError::crypto(e.to_string()))?;
        Ok(breached.contains(password.expose_secret()))
    }
}

#[derive(Default, Debug)]
struct MockMailProvider {
    sent: Mutex<Vec<(EmailAddress, String)>>,
}

#[async_trait]
impl MailProvider for MockMailProvider {
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        _text_body: &str,
        _html_body: &str,
    ) -> Result<(), PortError> {
        let mut sent = self
            .sent
            .lock()
            .map_err(|e| PortError::crypto(e.to_string()))?;
        sent.push((to.clone(), subject.to_owned()));
        Ok(())
    }
}

#[derive(Default, Debug)]
struct MockSecretCipher;

impl SecretCipher for MockSecretCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        Ok((plaintext.to_vec(), vec![0u8; 12]))
    }

    fn decrypt(&self, ciphertext: &[u8], _nonce: &[u8]) -> Result<DecryptedSecret, PortError> {
        Ok(DecryptedSecret::new(ciphertext.to_vec()))
    }

    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        _aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        Ok((plaintext.to_vec(), vec![0u8; 12]))
    }

    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<DecryptedSecret, PortError> {
        Ok(DecryptedSecret::new(ciphertext.to_vec()))
    }
}

#[derive(Default, Debug)]
struct MockTotpService;

impl TotpService for MockTotpService {
    fn generate_secret(&self) -> Result<Vec<u8>, PortError> {
        Ok(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
    }

    fn generate_qr_code_svg(
        &self,
        _email: &EmailAddress,
        _secret: &[u8],
        _issuer: &str,
    ) -> Result<String, PortError> {
        Ok("<svg>mock_qr</svg>".to_owned())
    }

    fn verify_code(
        &self,
        _secret: &[u8],
        code: &str,
        _now_epoch_secs: u64,
    ) -> Result<bool, PortError> {
        Ok(code == "123456")
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_refresh_session_token_reuse_detection_revokes_entire_family() -> TestResult {
    let session_repo = Arc::new(MockSessionRepository::default());
    let user_repo = Arc::new(MockUserRepository::default());
    let token_signer = Arc::new(MockTokenSigner);
    let (event_bus, mut event_rx) = EventBus::new(100);

    let email = EmailAddress::parse("user@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("DummyPassword123!")?)
        .await?;
    let mut user = User::new(email, None, dummy_hash);

    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    let token_store: Arc<dyn TokenStore> = Arc::new(MockTokenStore::default());
    let use_case = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
    );

    // 1. Create an initial session
    let token_1_raw = "token_alpha_12345";
    let token_1_hash = token_utils::hash_token(token_1_raw);
    let initial_session = Session::new(
        user.id,
        token_1_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Safari".to_owned()),
        Some("MacBook".to_owned()),
        chrono::Duration::days(7),
    );
    let family_id = initial_session.token_family_id;
    session_repo.create(&initial_session).await?;

    // 2. Rotate once: token_1 is consumed, token_2 is issued
    let rotate_cmd = RefreshTokenCommand {
        refresh_token: token_1_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Safari".to_owned()),
        request_id: RequestId::new(),
    };
    let token_2 = use_case.execute(rotate_cmd).await?;
    assert_eq!(token_2.access_token, "mock.jwt.token");
    assert!(!token_2.refresh_token.is_empty());

    // Verify session 1 is now marked is_replaced = true
    let s1 = session_repo.find_by_id(&initial_session.id).await?;
    let s1 = match s1 {
        Some(s) => s,
        None => return Err("session 1 missing".into()),
    };
    assert!(s1.is_replaced);

    // 3. REPLAY ATTACK: Present token_1 AGAIN!
    let replay_cmd = RefreshTokenCommand {
        refresh_token: token_1_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        user_agent: Some("HackerBot".to_owned()),
        request_id: RequestId::new(),
    };
    let replay_err = use_case.execute(replay_cmd).await;

    // Must return TokenReuseDetected!
    match replay_err {
        Err(AppError::TokenReuseDetected) => {}
        other => return Err(format!("expected TokenReuseDetected, got {other:?}").into()),
    }

    // 4. Verify ALL sessions in the token family were revoked!
    let s1_after = session_repo.find_by_id(&initial_session.id).await?;
    let s1_after = match s1_after {
        Some(s) => s,
        None => return Err("session 1 missing".into()),
    };
    assert!(s1_after.is_revoked());
    assert_eq!(
        s1_after.revoke_reason.as_deref(),
        Some("token_reuse_detected")
    );

    let s2_after = session_repo.find_by_id(&token_2.session_id).await?;
    let s2_after = match s2_after {
        Some(s) => s,
        None => return Err("session 2 missing".into()),
    };
    assert!(s2_after.is_revoked());
    assert_eq!(
        s2_after.revoke_reason.as_deref(),
        Some("token_reuse_detected")
    );

    // 5. Verify audit event was logged
    let mut audit_found = false;
    while let Ok(event) = event_rx.try_recv() {
        if let AppEvent::LogAudit(log) = event
            && log.event_type == "token_reuse_detected"
        {
            assert_eq!(log.event_status.as_str(), "blocked");
            assert_eq!(log.metadata["token_family_id"], family_id.to_string());
            audit_found = true;
        }
    }
    assert!(audit_found);

    Ok(())
}

#[tokio::test]
async fn test_register_user_flow() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_store = Arc::new(MockTokenStore::default());
    let hibp_client = Arc::new(MockHibpClient::default());
    let (event_bus, mut event_rx) = EventBus::new(100);

    // Register "pwned_password123" into mock HIBP
    {
        let mut breached = hibp_client.breached.lock().map_err(|e| e.to_string())?;
        breached.insert("pwned_password123".to_owned());
    }

    let use_case = RegisterUserUseCase::new(
        user_repo.clone(),
        password_hasher.clone(),
        token_store.clone(),
        hibp_client.clone(),
        event_bus,
        Duration::from_secs(86400),
    );

    // 1. Rejected if password breached
    let breached_cmd = RegisterCommand {
        email: "alice@example.com".to_owned(),
        password: "pwned_password123".to_owned(),
        username: Some("alice".to_owned()),
        ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        user_agent: Some("Firefox".to_owned()),
        request_id: RequestId::new(),
    };
    let res = use_case.execute(breached_cmd).await;
    match res {
        Err(AppError::Validation(violations)) => {
            assert!(violations.iter().any(|v| v.field == "password"));
        }
        other => return Err(format!("expected Validation error, got {other:?}").into()),
    }

    // 2. Successful registration
    let valid_cmd = RegisterCommand {
        email: "alice@example.com".to_owned(),
        password: "SuperSecretPassword123!".to_owned(),
        username: Some("alice".to_owned()),
        ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        user_agent: Some("Firefox".to_owned()),
        request_id: RequestId::new(),
    };
    let res = use_case.execute(valid_cmd).await?;
    assert_eq!(res.email, "alice@example.com");
    assert!(res.verification_required);

    // User is in repository
    let created = user_repo.find_by_id(&res.user_id).await?;
    assert!(created.is_some());

    // 3. Email verification token created
    let mut email_dispatched = false;
    while let Ok(event) = event_rx.try_recv() {
        if let AppEvent::SendVerificationEmail { to, token } = event {
            assert_eq!(to.as_str(), "alice@example.com");
            assert!(!token.is_empty());
            email_dispatched = true;
        }
    }
    assert!(email_dispatched);

    // 4. Duplicate registration rejected with Conflict
    let dup_cmd = RegisterCommand {
        email: "alice@example.com".to_owned(),
        password: "AnotherPassword123!".to_owned(),
        username: Some("alice2".to_owned()),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    match use_case.execute(dup_cmd).await {
        Err(AppError::Conflict) => {}
        other => return Err(format!("expected Conflict error, got {other:?}").into()),
    }

    Ok(())
}

#[tokio::test]
async fn test_login_timing_mitigation_and_lockout() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let config = LoginConfig {
        max_failed_attempts: 3,
        lockout_duration: Duration::from_secs(900),
        ..Default::default()
    };

    let use_case = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus,
        config,
    );

    // 1. Non-existent user: verifies dummy hash to prevent timing attacks
    let unknown_cmd = LoginCommand {
        email: "ghost@example.com".to_owned(),
        password: "SomePassword123!".to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };
    match use_case.execute(unknown_cmd).await {
        Err(AppError::InvalidCredentials) => {}
        other => return Err(format!("expected InvalidCredentials, got {other:?}").into()),
    }
    assert_eq!(password_hasher.dummy_calls.load(Ordering::SeqCst), 1);

    // 2. Create existing active user
    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(EmailAddress::parse("bob@example.com")?, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    // 3. Failed attempts count up to lockout
    for _ in 0..3 {
        let wrong_cmd = LoginCommand {
            email: "bob@example.com".to_owned(),
            password: "WrongPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        };
        match use_case.execute(wrong_cmd).await {
            Err(AppError::InvalidCredentials) => {}
            other => return Err(format!("expected InvalidCredentials, got {other:?}").into()),
        }
    }

    // 4. 4th attempt: account is locked, returns Forbidden
    let attempt_4 = LoginCommand {
        email: "bob@example.com".to_owned(),
        password: "CorrectPassword123!".to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };
    match use_case.execute(attempt_4).await {
        Err(AppError::Forbidden) => {}
        other => return Err(format!("expected Forbidden (locked), got {other:?}").into()),
    }

    Ok(())
}

#[tokio::test]
async fn test_mfa_setup_enable_and_verify_login() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let totp_service = Arc::new(MockTotpService);
    let secret_cipher = Arc::new(MockSecretCipher);
    let (event_bus, _event_rx) = EventBus::new(100);

    // Create user
    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(EmailAddress::parse("charlie@example.com")?, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    // 1. Setup TOTP
    let setup_uc = SetupTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        token_store.clone(),
        "Korgan".to_owned(),
        Duration::from_secs(900),
    );
    let setup_res = setup_uc
        .execute(SetupTotpCommand {
            user_id: user.id,
            request_id: RequestId::new(),
        })
        .await?;
    assert!(!setup_res.secret.is_empty());
    assert_eq!(setup_res.qr_code_svg, "<svg>mock_qr</svg>");

    // 2. Enable TOTP with code 123456
    let enable_uc = EnableTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_store.clone(),
        event_bus.clone(),
    );
    let enable_res = enable_uc
        .execute(EnableTotpCommand {
            user_id: user.id,
            code: "123456".to_owned(),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;
    assert_eq!(enable_res.backup_codes.len(), 10);

    // Verify user now has mfa_enabled = true
    let updated_user = user_repo.find_by_id(&user.id).await?;
    let updated_user = match updated_user {
        Some(u) => u,
        None => return Err("user missing".into()),
    };
    assert!(updated_user.mfa_enabled);

    // 3. Login now returns MfaRequired
    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    let login_res = login_uc
        .execute(LoginCommand {
            email: "charlie@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;

    let ticket = match login_res {
        LoginOutcome::MfaRequired(challenge) => challenge.mfa_ticket,
        other => return Err(format!("expected MfaRequired, got {other:?}").into()),
    };

    // 4. Verify login using one of the backup codes
    let backup_code = enable_res.backup_codes[0].clone();
    let verify_mfa_uc = VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
        5,
        Duration::from_secs(900),
    );

    let auth_tokens = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket,
            code: backup_code.clone(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    assert_eq!(auth_tokens.access_token, "mock.jwt.token");

    // 5. Verify the backup code was consumed (remaining count = 9)
    let mfa_record = user_repo.find_mfa(&user.id).await?;
    let mfa_record = match mfa_record {
        Some(m) => m,
        None => return Err("mfa record missing".into()),
    };
    assert_eq!(mfa_record.remaining_backup_codes_count(), 9);

    Ok(())
}

#[tokio::test]
async fn test_reset_password_history_depth_prevention() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_store = Arc::new(MockTokenStore::default());
    let hibp_client = Arc::new(MockHibpClient::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let raw_pw = RawPassword::new("InitialPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(EmailAddress::parse("dave@example.com")?, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    let reset_uc = ResetPasswordUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_store.clone(),
        hibp_client.clone(),
        event_bus.clone(),
        5,
    );

    // Issue reset token
    let raw_token = "reset_token_secret_12345";
    let token_hash = token_utils::hash_token(raw_token);
    token_store
        .set_token(
            &format!("reset_password:{token_hash}"),
            &user.id.to_string(),
            Duration::from_secs(3600),
        )
        .await?;

    // Attempt to reset to identical password: rejected
    let same_pw_cmd = ResetPasswordCommand {
        token: raw_token.to_owned(),
        new_password: "InitialPassword123!".to_owned(),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    match reset_uc.execute(same_pw_cmd).await {
        Err(AppError::Validation(violations)) => {
            assert!(violations.iter().any(|v| v.field == "new_password"));
        }
        other => return Err(format!("expected Validation error, got {other:?}").into()),
    }

    // Put token back in token_store since the previous call consumed it
    token_store
        .set_token(
            &format!("reset_password:{token_hash}"),
            &user.id.to_string(),
            Duration::from_secs(3600),
        )
        .await?;

    // Reset to brand new password: succeeds
    let new_pw_cmd = ResetPasswordCommand {
        token: raw_token.to_owned(),
        new_password: "BrandNewPassword123!".to_owned(),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    reset_uc.execute(new_pw_cmd).await?;

    // Verify history now contains InitialPassword123!
    let history = user_repo.get_password_history(&user.id, 5).await?;
    assert_eq!(history.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_session_management_flow() -> TestResult {
    let session_repo = Arc::new(MockSessionRepository::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let user_id = UserId::new();
    let s1 = Session::new(
        user_id,
        "hash1".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Chrome".to_owned()),
        Some("MacBook".to_owned()),
        chrono::Duration::days(7),
    );
    let s2 = Session::new(
        user_id,
        "hash2".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Safari".to_owned()),
        Some("iPhone".to_owned()),
        chrono::Duration::days(7),
    );
    let s1_id = s1.id;
    let s2_id = s2.id;
    session_repo.create(&s1).await?;
    session_repo.create(&s2).await?;

    // List sessions
    let list_uc = ListSessionsUseCase::new(session_repo.clone());
    let summaries = list_uc
        .execute(ListSessionsQuery {
            user_id,
            current_session_id: Some(s1_id),
            limit: 10,
            offset: 0,
        })
        .await?;
    assert_eq!(summaries.len(), 2);
    let curr = summaries.iter().find(|s| s.is_current);
    assert_eq!(curr.map(|s| s.id), Some(s1_id));

    // Revoke single session s2
    let token_store: Arc<dyn TokenStore> = Arc::new(MockTokenStore::default());
    let revoke_uc =
        RevokeSessionUseCase::new(session_repo.clone(), token_store.clone(), event_bus.clone());
    revoke_uc
        .execute(RevokeSessionCommand {
            user_id,
            session_id: s2_id,
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;

    let s2_check = session_repo.find_by_id(&s2_id).await?;
    let s2_check = match s2_check {
        Some(s) => s,
        None => return Err("session 2 missing".into()),
    };
    assert!(s2_check.is_revoked());

    // Revoke all remaining sessions
    let revoke_all_uc =
        RevokeAllSessionsUseCase::new(session_repo.clone(), token_store.clone(), event_bus);
    revoke_all_uc
        .execute(RevokeAllSessionsCommand {
            user_id,
            except_session_id: None,
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;

    let s1_check = session_repo.find_by_id(&s1_id).await?;
    let s1_check = match s1_check {
        Some(s) => s,
        None => return Err("session 1 missing".into()),
    };
    assert!(s1_check.is_revoked());

    Ok(())
}

#[tokio::test]
async fn test_user_profile_use_cases() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);

    let raw_pw = RawPassword::new("InitialPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let user = User::new(EmailAddress::parse("eve@example.com")?, None, hash);
    let user_id = user.id;
    user_repo.create(&user).await?;

    let get_profile = GetProfileUseCase::new(user_repo.clone());
    let profile = get_profile.execute(GetProfileQuery { user_id }).await?;
    assert_eq!(profile.email, "eve@example.com");
    assert_eq!(profile.username, None);

    let update_profile = UpdateProfileUseCase::new(user_repo.clone());
    let updated = update_profile
        .execute(UpdateProfileCommand {
            user_id,
            username: Some("eve_online".to_owned()),
            request_id: RequestId::new(),
        })
        .await?;
    assert_eq!(updated.username.as_deref(), Some("eve_online"));

    // Verify retrieval reflects update
    let profile2 = get_profile.execute(GetProfileQuery { user_id }).await?;
    assert_eq!(profile2.username.as_deref(), Some("eve_online"));

    Ok(())
}

#[tokio::test]
async fn test_event_worker_execution() -> TestResult {
    let (event_bus, event_rx) = EventBus::new(10);
    let mail_provider = Arc::new(MockMailProvider::default());
    let audit_repo = Arc::new(MockAuditLogRepository::default());

    let worker = korgan::application::workers::EventWorker::new(
        event_rx,
        mail_provider.clone(),
        audit_repo.clone(),
        "https://example.com".to_owned(),
    );

    // Dispatch verification email
    event_bus.dispatch(AppEvent::SendVerificationEmail {
        to: EmailAddress::parse("test@example.com")?,
        token: "tok123".to_owned(),
    });

    // Dispatch audit log
    event_bus.dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "test_event",
        korgan::domain::entities::AuditEventStatus::Success,
        serde_json::json!({}),
    ))));

    // Run worker for single batch then stop
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker_handle = tokio::spawn(async move {
        worker.run(shutdown_rx).await;
    });

    // Give worker time to process both events
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(true);
    let _ = worker_handle.await;

    // Verify email was sent
    let sent = mail_provider.sent.lock().map_err(|e| e.to_string())?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0.as_str(), "test@example.com");

    // Verify audit log was recorded
    let logs = audit_repo.logs.lock().map_err(|e| e.to_string())?;
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event_type, "test_event");

    Ok(())
}

#[tokio::test]
async fn test_refresh_session_concurrent_cas_race_condition() -> TestResult {
    let session_repo = Arc::new(MockSessionRepository::default());
    let user_repo = Arc::new(MockUserRepository::default());
    let token_signer = Arc::new(MockTokenSigner);
    let (event_bus, _event_rx) = EventBus::new(100);

    let email = EmailAddress::parse("concurrent@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("DummyPassword123!")?)
        .await?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    let token_store: Arc<dyn TokenStore> = Arc::new(MockTokenStore::default());
    let use_case = Arc::new(RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
    ));

    // Create session
    let token_raw = "concurrent_token_xyz";
    let token_hash = token_utils::hash_token(token_raw);
    let session = Session::new(
        user.id,
        token_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Chrome".to_owned()),
        Some("Linux".to_owned()),
        chrono::Duration::days(7),
    );
    let session_id = session.id;
    session_repo.create(&session).await?;

    // Launch two concurrent refresh requests for the same token
    let uc1 = use_case.clone();
    let uc2 = use_case.clone();
    let cmd1 = RefreshTokenCommand {
        refresh_token: token_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Worker1".to_owned()),
        request_id: RequestId::new(),
    };
    let cmd2 = RefreshTokenCommand {
        refresh_token: token_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Worker2".to_owned()),
        request_id: RequestId::new(),
    };

    let (res1, res2) = tokio::join!(async move { uc1.execute(cmd1).await }, async move {
        uc2.execute(cmd2).await
    },);

    // Exactly one must succeed and one must fail (due to atomic CAS replace)
    let (success, failure) = match (res1, res2) {
        (Ok(s), Err(e)) => (s, e),
        (Err(e), Ok(s)) => (s, e),
        (Ok(_), Ok(_)) => return Err("race condition: both concurrent refreshes succeeded!".into()),
        (Err(e1), Err(e2)) => return Err(format!("both failed: e1={e1:?}, e2={e2:?}").into()),
    };

    assert!(!success.access_token.is_empty());
    // The failed one detected reuse and revoked
    match failure {
        AppError::TokenReuseDetected => {}
        other => return Err(format!("expected TokenReuseDetected, got {other:?}").into()),
    }

    // Verify session was blacklisted in Redis token store
    assert!(
        token_store
            .get_token(&format!("blacklist:session:{session_id}"))
            .await?
            .is_some()
    );

    // Verify phantom session was prevented: the newly created session was also revoked by family revocation
    let success_session = session_repo
        .find_by_id(&success.session_id)
        .await?
        .ok_or("new session missing")?;
    assert!(
        success_session.is_revoked(),
        "Winning session must be revoked when replay triggers family revocation"
    );
    assert_eq!(
        success_session.revoke_reason.as_deref(),
        Some("token_reuse_detected")
    );

    // Verify all sessions for this family/user are now revoked
    let all_sessions = session_repo.list_by_user_id(&user.id, 10, 0).await?;
    assert!(
        all_sessions.iter().all(|s| s.is_revoked()),
        "No active phantom session may exist in the revoked family!"
    );

    Ok(())
}

#[tokio::test]
async fn test_totp_replay_prevention_and_ticket_single_use() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let totp_service = Arc::new(MockTotpService);
    let secret_cipher = Arc::new(MockSecretCipher);
    let (event_bus, _event_rx) = EventBus::new(100);

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(EmailAddress::parse("totp_user@example.com")?, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    // Setup and Enable TOTP
    let setup_uc = SetupTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        token_store.clone(),
        "Korgan".to_owned(),
        Duration::from_secs(900),
    );
    setup_uc
        .execute(SetupTotpCommand {
            user_id: user.id,
            request_id: RequestId::new(),
        })
        .await?;

    let enable_uc = EnableTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_store.clone(),
        event_bus.clone(),
    );
    enable_uc
        .execute(EnableTotpCommand {
            user_id: user.id,
            code: "123456".to_owned(),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    let verify_mfa_uc = VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
        5,
        Duration::from_secs(900),
    );

    // Login #1 to get MFA ticket #1
    let login_res = login_uc
        .execute(LoginCommand {
            email: "totp_user@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;

    let ticket_1 = match login_res {
        LoginOutcome::MfaRequired(challenge) => challenge.mfa_ticket,
        other => return Err(format!("expected MfaRequired, got {other:?}").into()),
    };

    // First verification with code "123456" succeeds
    let verify_res = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket_1.clone(),
            code: "123456".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    assert_eq!(verify_res.access_token, "mock.jwt.token");

    // 1. Replay of ticket_1 MUST FAIL (ticket consumed via get_and_delete)
    let ticket_replay = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket_1,
            code: "123456".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    match ticket_replay {
        Err(AppError::TokenInvalid) => {}
        other => {
            return Err(format!("expected TokenInvalid for consumed ticket, got {other:?}").into());
        }
    }

    // Login #2 to get fresh ticket #2
    let login_res2 = login_uc
        .execute(LoginCommand {
            email: "totp_user@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket_2 = match login_res2 {
        LoginOutcome::MfaRequired(challenge) => challenge.mfa_ticket,
        other => return Err(format!("expected MfaRequired, got {other:?}").into()),
    };

    // 2. Replay of TOTP code "123456" MUST FAIL (code replay lock within 120s)
    let code_replay = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket_2,
            code: "123456".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    match code_replay {
        Err(AppError::InvalidCredentials) => {}
        other => {
            return Err(format!(
                "expected InvalidCredentials for replayed TOTP code, got {other:?}"
            )
            .into());
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_account_status_gating_blocks_suspended_deactivated_pending_deletion() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let refresh_uc = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
    );

    let verify_email_uc =
        VerifyEmailUseCase::new(user_repo.clone(), token_store.clone(), event_bus.clone());

    let statuses = [
        korgan::domain::entities::AccountStatus::Suspended,
        korgan::domain::entities::AccountStatus::Deactivated,
        korgan::domain::entities::AccountStatus::PendingDeletion,
    ];

    for status in statuses {
        let email_str = format!("user_{:?}@example.com", status).to_lowercase();
        let email = EmailAddress::parse(&email_str)?;
        let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
        let dummy_hash = hasher
            .hash_password(&RawPassword::new("DummyPassword123!")?)
            .await?;
        let mut user = User::new(email, None, dummy_hash);
        user.status = status;
        user_repo.create(&user).await?;

        // 1. Session Refresh must be blocked
        let token_raw = format!("token_{:?}", status);
        let token_hash = token_utils::hash_token(&token_raw);
        let session = Session::new(
            user.id,
            token_hash,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            None,
            chrono::Duration::days(7),
        );
        session_repo.create(&session).await?;

        let res = refresh_uc
            .execute(RefreshTokenCommand {
                refresh_token: token_raw,
                ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                user_agent: None,
                request_id: RequestId::new(),
            })
            .await;

        match res {
            Err(AppError::Forbidden) => {}
            other => {
                return Err(
                    format!("expected Forbidden for status {status:?}, got {other:?}").into(),
                );
            }
        }

        // 2. Email verification must be blocked
        let verify_token = format!("verify_tok_{:?}", status);
        let verify_hash = token_utils::hash_token(&verify_token);
        token_store
            .set_token(
                &format!("verify_email:{verify_hash}"),
                &user.id.to_string(),
                Duration::from_secs(300),
            )
            .await?;
        let verify_res = verify_email_uc
            .execute(VerifyEmailCommand {
                token: verify_token,
                ip_address: None,
                user_agent: None,
                request_id: RequestId::new(),
            })
            .await;

        match verify_res {
            Err(AppError::Forbidden) => {}
            other => {
                return Err(format!(
                    "expected Forbidden for email verify status {status:?}, got {other:?}"
                )
                .into());
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_totp_concurrent_replay_race_condition() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let totp_service = Arc::new(MockTotpService);
    let secret_cipher = Arc::new(MockSecretCipher);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(100);
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);

    let email = EmailAddress::parse("totp_concurrent@example.com")?;
    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(email, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    // Setup and enable TOTP
    let setup_uc = SetupTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        token_store.clone(),
        "Korgan".to_owned(),
        Duration::from_secs(900),
    );
    setup_uc
        .execute(SetupTotpCommand {
            user_id: user.id,
            request_id: RequestId::new(),
        })
        .await?;

    let enable_uc = EnableTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_store.clone(),
        event_bus.clone(),
    );
    enable_uc
        .execute(EnableTotpCommand {
            user_id: user.id,
            code: "123456".to_owned(),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    let verify_mfa_uc = Arc::new(VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
        5,
        Duration::from_secs(900),
    ));

    // Obtain ticket 1 and ticket 2 via two separate login challenges
    let login1 = login_uc
        .execute(LoginCommand {
            email: "totp_concurrent@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;

    let ticket_1 = match login1 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    let login2 = login_uc
        .execute(LoginCommand {
            email: "totp_concurrent@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;

    let ticket_2 = match login2 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    // Both concurrent requests attempt to consume the SAME TOTP code "123456"
    let uc1 = verify_mfa_uc.clone();
    let uc2 = verify_mfa_uc.clone();
    let cmd1 = VerifyMfaLoginCommand {
        mfa_ticket: ticket_1,
        code: "123456".to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };
    let cmd2 = VerifyMfaLoginCommand {
        mfa_ticket: ticket_2,
        code: "123456".to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };

    let (res1, res2) = tokio::join!(async move { uc1.execute(cmd1).await }, async move {
        uc2.execute(cmd2).await
    },);

    // Exactly one must succeed and one must fail with InvalidCredentials (replay lock collision)
    match (res1, res2) {
        (Ok(_), Err(AppError::InvalidCredentials)) | (Err(AppError::InvalidCredentials), Ok(_)) => {
            // Success: concurrent replay was prevented!
        }
        (Ok(_), Ok(_)) => {
            return Err(
                "RACE CONDITION: Both concurrent TOTP verifications succeeded with the same code!"
                    .into(),
            );
        }
        (Err(e1), Err(e2)) => {
            return Err(format!("Both failed unexpectedly: e1={e1:?}, e2={e2:?}").into());
        }
        (Ok(_), Err(other)) | (Err(other), Ok(_)) => {
            return Err(
                format!("Expected InvalidCredentials for losing task, got {other:?}").into(),
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_backup_code_concurrent_consumption_race_condition() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let totp_service = Arc::new(MockTotpService);
    let secret_cipher = Arc::new(MockSecretCipher);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(100);
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);

    let email = EmailAddress::parse("backup_concurrent@example.com")?;
    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let mut user = User::new(email, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    // Setup and enable TOTP to generate 10 backup codes
    let setup_uc = SetupTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        token_store.clone(),
        "Korgan".to_owned(),
        Duration::from_secs(900),
    );
    setup_uc
        .execute(SetupTotpCommand {
            user_id: user.id,
            request_id: RequestId::new(),
        })
        .await?;

    let enable_uc = EnableTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_store.clone(),
        event_bus.clone(),
    );
    let enable_res = enable_uc
        .execute(EnableTotpCommand {
            user_id: user.id,
            code: "123456".to_owned(),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await?;

    let target_backup_code = enable_res.backup_codes[0].clone();

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    let verify_mfa_uc = Arc::new(VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
        5,
        Duration::from_secs(900),
    ));

    // Obtain ticket 1 and ticket 2
    let login1 = login_uc
        .execute(LoginCommand {
            email: "backup_concurrent@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket_1 = match login1 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    let login2 = login_uc
        .execute(LoginCommand {
            email: "backup_concurrent@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket_2 = match login2 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    // Both concurrent tasks submit the EXACT SAME backup code
    let uc1 = verify_mfa_uc.clone();
    let uc2 = verify_mfa_uc.clone();
    let code_str = target_backup_code.clone();
    let cmd1 = VerifyMfaLoginCommand {
        mfa_ticket: ticket_1,
        code: code_str.clone(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };
    let cmd2 = VerifyMfaLoginCommand {
        mfa_ticket: ticket_2,
        code: code_str,
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: None,
        device_name: None,
        request_id: RequestId::new(),
    };

    let (res1, res2) = tokio::join!(async move { uc1.execute(cmd1).await }, async move {
        uc2.execute(cmd2).await
    },);

    // Exactly one must succeed and one must fail
    match (res1, res2) {
        (Ok(_), Err(AppError::InvalidCredentials)) | (Err(AppError::InvalidCredentials), Ok(_)) => {
            // Success: concurrent backup code double-spend was blocked!
        }
        (Ok(_), Ok(_)) => {
            return Err(
                "DOUBLE-SPEND RACE: Both concurrent tasks consumed the same backup code!".into(),
            );
        }
        (Err(e1), Err(e2)) => {
            return Err(format!("Both failed unexpectedly: e1={e1:?}, e2={e2:?}").into());
        }
        (Ok(_), Err(other)) | (Err(other), Ok(_)) => {
            return Err(
                format!("Expected InvalidCredentials for losing task, got {other:?}").into(),
            );
        }
    }

    // Confirm that only 9 backup codes remain in storage
    let updated_mfa = user_repo.find_mfa(&user.id).await?.ok_or("MFA not found")?;
    assert_eq!(updated_mfa.remaining_backup_codes_count(), 9);

    Ok(())
}

#[test]
fn test_debug_redaction_secrets() -> TestResult {
    let raw = RawPassword::new("SuperSecretPassword123!")?;
    let debug_raw = format!("{raw:?}");
    assert_eq!(debug_raw, "[REDACTED]");

    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let debug_hash = format!("{hash:?}");
    assert_eq!(debug_hash, "[REDACTED]");

    let mfa = UserMfa::new(
        UserId::new(),
        vec![1, 2, 3, 4],
        vec![0; 12],
        vec!["hash1_secret_backup".to_owned()],
    );
    let debug_mfa = format!("{mfa:?}");
    assert!(!debug_mfa.contains("hash1_secret_backup"));
    assert!(debug_mfa.contains("[REDACTED]"));

    let session = Session::new(
        UserId::new(),
        "my_secret_token_hash_value".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(1),
    );
    let debug_session = format!("{session:?}");
    assert!(!debug_session.contains("my_secret_token_hash_value"));
    assert!(debug_session.contains("[REDACTED]"));

    let decrypted = DecryptedSecret::new(b"sensitive_totp_key".to_vec());
    let debug_decrypted = format!("{decrypted:?}");
    assert_eq!(debug_decrypted, "[REDACTED]");
    let display_decrypted = format!("{decrypted}");
    assert_eq!(display_decrypted, "[REDACTED]");

    Ok(())
}

#[test]
fn test_backup_code_treads_all_10_indices_constant_time() -> TestResult {
    let mut mfa = UserMfa::new(
        UserId::new(),
        vec![1, 2, 3],
        vec![0; 12],
        vec!["code_hash_1".to_owned()],
    );
    // Only 1 code in list, but consume_backup_code safely iterates through all 10 indices
    assert!(mfa.consume_backup_code("code_hash_1"));
    assert_eq!(mfa.remaining_backup_codes_count(), 0);

    // List is now empty (0 codes), still safely iterates 10 times and returns false
    assert!(!mfa.consume_backup_code("code_hash_1"));
    assert!(!mfa.consume_backup_code("non_existent_code"));

    Ok(())
}

#[tokio::test]
async fn test_expired_refresh_token_does_not_trigger_token_family_revocation() -> TestResult {
    let session_repo = Arc::new(MockSessionRepository::default());
    let user_repo = Arc::new(MockUserRepository::default());
    let token_signer = Arc::new(MockTokenSigner);
    let (event_bus, _event_rx) = EventBus::new(100);

    let email = EmailAddress::parse("expired_test@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("DummyPassword123!")?)
        .await?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    let token_store: Arc<dyn TokenStore> = Arc::new(MockTokenStore::default());
    let use_case = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
    );

    // 1. Create an expired session
    let token_raw = "expired_token_raw";
    let token_hash = token_utils::hash_token(token_raw);
    let session = Session::new(
        user.id,
        token_hash.clone(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Browser".to_owned()),
        Some("Laptop".to_owned()),
        chrono::Duration::seconds(-60), // Expired 60s ago
    );
    let family_id = session.token_family_id;
    let expired_id = session.id;
    session_repo.create(&session).await?;

    // 2. Also create an active sibling session in the same token family
    let sibling_token_raw = "sibling_token_raw";
    let sibling_token_hash = token_utils::hash_token(sibling_token_raw);
    let sibling_session = Session {
        id: SessionId::new(),
        user_id: user.id,
        token_family_id: family_id,
        refresh_token_hash: sibling_token_hash,
        user_agent: Some("Mobile".to_owned()),
        device_name: Some("Phone".to_owned()),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        is_replaced: false,
        last_active_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(24),
        revoked_at: None,
        revoke_reason: None,
        created_at: Utc::now(),
        amr: vec!["pwd".to_string()],
    };
    let sibling_id = sibling_session.id;
    session_repo.create(&sibling_session).await?;

    // 3. Attempt to refresh with the expired token
    let cmd1 = RefreshTokenCommand {
        refresh_token: token_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Browser".to_owned()),
        request_id: RequestId::new(),
    };
    let res1 = use_case.execute(cmd1).await;
    match res1 {
        Err(AppError::TokenExpired) => {}
        other => return Err(format!("Expected TokenExpired, got {other:?}").into()),
    }

    // 4. Verify session is NOT marked as replaced
    let s_after = session_repo
        .find_by_id(&expired_id)
        .await?
        .ok_or("session missing")?;
    assert!(
        !s_after.is_replaced,
        "Expired session must NOT be marked is_replaced = true"
    );

    // 5. Present the expired token a SECOND time
    let cmd2 = RefreshTokenCommand {
        refresh_token: token_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Browser".to_owned()),
        request_id: RequestId::new(),
    };
    let res2 = use_case.execute(cmd2).await;
    match res2 {
        Err(AppError::TokenExpired) => {}
        other => return Err(format!("Expected TokenExpired on second try, got {other:?}").into()),
    }

    // 6. Verify the active sibling session in the same family was NOT revoked!
    let sibling_after = session_repo
        .find_by_id(&sibling_id)
        .await?
        .ok_or("sibling session missing")?;
    assert!(
        !sibling_after.is_revoked(),
        "Active sibling session must NOT be revoked by expired token replay!"
    );

    Ok(())
}

#[tokio::test]
async fn test_mfa_verify_brute_force_lockout_and_login_does_not_reset_attempts() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let totp_service = Arc::new(MockTotpService);
    let secret_cipher = Arc::new(MockSecretCipher);
    let (event_bus, _event_rx) = EventBus::new(100);

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let pw_hash = password_hasher.hash_password(&raw_pw).await?;
    let email = EmailAddress::parse("mfa_bruteforce@example.com")?;
    let mut user = User::new(email, None, pw_hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user.mfa_enabled = true;
    user_repo.create(&user).await?;

    let mut mfa = UserMfa::new(
        user.id,
        vec![10, 20, 30],
        vec![0; 12],
        vec![token_utils::hash_token("backup_123")],
    );
    mfa.verify(Utc::now());
    user_repo.save_mfa(&mfa).await?;

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig {
            max_failed_attempts: 3,
            lockout_duration: Duration::from_secs(900),
            ..Default::default()
        },
    );

    let verify_mfa_uc = VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
        3,                        // max_failed_attempts = 3
        Duration::from_secs(900), // lockout 15 mins
    );

    // Step 1: Login #1 returns MFA ticket
    let l1 = login_uc
        .execute(LoginCommand {
            email: "mfa_bruteforce@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket1 = match l1 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    // Failed MFA attempt 1
    let res1 = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket1,
            code: "000000".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    assert!(matches!(res1, Err(AppError::InvalidCredentials)));

    let u_check1 = user_repo
        .find_by_id(&user.id)
        .await?
        .ok_or("user missing")?;
    assert_eq!(u_check1.failed_login_attempts, 1);
    // Invalid TOTP code must NOT pollute Redis with replay locks
    assert!(
        token_store
            .get_token(&format!("totp_used:{}:000000", user.id))
            .await?
            .is_none()
    );

    // Step 2: Attacker logs in again with correct password
    // CRITICAL CHECK: login MUST NOT reset failed_login_attempts when mfa_enabled = true!
    let l2 = login_uc
        .execute(LoginCommand {
            email: "mfa_bruteforce@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket2 = match l2 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    let u_check2 = user_repo
        .find_by_id(&user.id)
        .await?
        .ok_or("user missing")?;
    assert_eq!(
        u_check2.failed_login_attempts, 1,
        "Password login must NOT reset failed attempts while MFA is pending!"
    );

    // Failed MFA attempt 2
    let res2 = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket2,
            code: "111111".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    assert!(matches!(res2, Err(AppError::InvalidCredentials)));

    let u_check3 = user_repo
        .find_by_id(&user.id)
        .await?
        .ok_or("user missing")?;
    assert_eq!(u_check3.failed_login_attempts, 2);

    // Login #3
    let l3 = login_uc
        .execute(LoginCommand {
            email: "mfa_bruteforce@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await?;
    let ticket3 = match l3 {
        LoginOutcome::MfaRequired(c) => c.mfa_ticket,
        _ => return Err("expected MfaRequired".into()),
    };

    // Failed MFA attempt 3 (reaches threshold of 3!)
    let res3 = verify_mfa_uc
        .execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket3,
            code: "222222".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    assert!(matches!(res3, Err(AppError::InvalidCredentials)));

    let u_check4 = user_repo
        .find_by_id(&user.id)
        .await?
        .ok_or("user missing")?;
    assert_eq!(u_check4.failed_login_attempts, 3);
    assert!(
        u_check4.is_locked(Utc::now()),
        "Account must be locked after 3 failed MFA attempts!"
    );

    // Step 3: Now any further login attempt must be rejected with Forbidden (locked)!
    let l4 = login_uc
        .execute(LoginCommand {
            email: "mfa_bruteforce@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    assert!(
        matches!(l4, Err(AppError::Forbidden)),
        "Locked account cannot initiate new logins!"
    );

    Ok(())
}

#[tokio::test]
async fn test_future_cancellation_safety_ensures_redis_blacklisting() -> TestResult {
    let session_repo = Arc::new(MockSessionRepository::default());
    let token_store = Arc::new(MockTokenStore::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let user_id = UserId::new();
    let session = Session::new(
        user_id,
        token_utils::hash_token("test_cancellation_token"),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    let session_id = session.id;
    session_repo.create(&session).await?;

    let use_case = RevokeSessionUseCase::new(session_repo.clone(), token_store.clone(), event_bus);

    let cmd = RevokeSessionCommand {
        session_id,
        user_id,
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };

    use_case.execute(cmd).await?;

    // Verify session is blacklisted in token_store
    let key = format!("blacklist:session:{session_id}");
    assert!(
        token_store.get_token(&key).await?.is_some(),
        "Session MUST be blacklisted in Redis!"
    );

    // Direct cancellation proof:
    // When a shielded task's outer future is dropped mid-flight, the spawned background task completes!
    let ts_clone = token_store.clone();
    let cancel_session_id = SessionId::new();
    let cancel_sid_str = cancel_session_id.to_string();

    // Simulate Future Cancellation by letting a timeout abort the awaiting future mid-flight
    let _ = tokio::time::timeout(Duration::from_millis(1), async {
        shielded(move || {
            let ts_clone = ts_clone.clone();
            let cancel_sid_str = cancel_sid_str.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                ts_clone
                    .set_token(
                        &format!("blacklist:session:{cancel_sid_str}"),
                        "revoked",
                        Duration::from_secs(3600),
                    )
                    .await?;
                Ok::<(), AppError>(())
            }
        })
        .await
    })
    .await;

    // Wait for detached Tokio task to finish
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Shielded task MUST have completed despite caller being dropped
    let cancel_key = format!("blacklist:session:{cancel_session_id}");
    assert_eq!(
        token_store.get_token(&cancel_key).await?,
        Some("revoked".to_owned()),
        "Shielded Redis blacklist task must complete even when parent future is cancelled/dropped!"
    );

    Ok(())
}

#[tokio::test]
async fn test_ban_user_concurrent_with_login_race_condition() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    session_repo.set_user_repo(user_repo.clone());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let pw_hash = password_hasher.hash_password(&raw_pw).await?;
    let email = EmailAddress::parse("concurrent_ban@example.com")?;
    let mut user = User::new(email, None, pw_hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;

    let user_id = user.id;

    // Create existing session
    let existing_session = Session::new(
        user_id,
        token_utils::hash_token("pre_ban_token"),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    let existing_session_id = existing_session.id;
    session_repo.create(&existing_session).await?;

    let ban_uc = BanUserUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        token_store.clone(),
        event_bus.clone(),
    );

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    // Ban the user
    let ban_res = ban_uc
        .execute(BanUserCommand {
            user_id,
            actor_id: UserId::new(),
            reason: Some("Violation of ToS".to_owned()),
        })
        .await?;
    assert!(ban_res.banned);

    // Existing session must be revoked
    let s_after = session_repo
        .find_by_id(&existing_session_id)
        .await?
        .ok_or("session missing")?;
    assert!(s_after.is_revoked());
    assert!(
        token_store
            .get_token(&format!("blacklist:session:{existing_session_id}"))
            .await?
            .is_some()
    );

    // Attempt concurrent login with correct credentials
    let login_res = login_uc
        .execute(LoginCommand {
            email: "concurrent_ban@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;

    // Login must fail with Forbidden because user is Suspended
    assert!(matches!(login_res, Err(AppError::Forbidden)));

    // User status in DB must remain Suspended (not overwritten by stale login object!)
    let u_after = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user missing")?;
    assert_eq!(
        u_after.status,
        korgan::domain::entities::AccountStatus::Suspended
    );

    // No new active sessions can exist for the banned user
    let sessions = session_repo.list_by_user_id(&user_id, 10, 0).await?;
    assert!(sessions.iter().all(|s| s.is_revoked()));

    Ok(())
}

#[tokio::test]
async fn test_ban_user_concurrent_with_refresh_race_condition() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    session_repo.set_user_repo(user_repo.clone());
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let email = EmailAddress::parse("concurrent_ban_refresh@example.com")?;
    let mut user = User::new(email, None, None);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;
    let user_id = user.id;

    // Create session 1 (to be revoked by ban)
    let raw_token = "pre_ban_refresh_token";
    let token_hash = token_utils::hash_token(raw_token);
    let session = Session::new(
        user_id,
        token_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Browser".to_owned()),
        Some("PC".to_owned()),
        chrono::Duration::days(7),
    );
    let session_id = session.id;
    session_repo.create(&session).await?;

    // Create session 2 while user is still Active (simulates active session during race window)
    let unrevoked_raw = "unrevoked_token";
    let unrevoked_session = Session::new(
        user_id,
        token_utils::hash_token(unrevoked_raw),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    session_repo.create(&unrevoked_session).await?;

    let ban_uc = BanUserUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        token_store.clone(),
        event_bus.clone(),
    );

    let refresh_uc = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus.clone(),
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "https://api.iam.dev".to_owned(),
        "api".to_owned(),
    );

    // Ban the user
    let ban_res = ban_uc
        .execute(BanUserCommand {
            user_id,
            actor_id: UserId::new(),
            reason: Some("Compromised account".to_owned()),
        })
        .await?;
    assert!(ban_res.banned);

    // Existing session must be revoked in DB and blacklisted in Redis
    let s_after = session_repo
        .find_by_id(&session_id)
        .await?
        .ok_or("session missing")?;
    assert!(s_after.is_revoked());
    assert!(
        token_store
            .get_token(&format!("blacklist:session:{session_id}"))
            .await?
            .is_some()
    );

    // Part A: Presenting the revoked token fails immediately with TokenInvalid
    let refresh_res1 = refresh_uc
        .execute(RefreshTokenCommand {
            refresh_token: raw_token.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: Some("Browser".to_owned()),
            request_id: RequestId::new(),
        })
        .await;
    assert!(matches!(refresh_res1, Err(AppError::TokenInvalid)));

    // Part B: Even if an active session existed during the race window, user status check blocks refresh with Forbidden
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.update(&user).await?;

    let unrevoked_raw = "unrevoked_token";
    let unrevoked_session = Session::new(
        user_id,
        token_utils::hash_token(unrevoked_raw),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    session_repo.create(&unrevoked_session).await?;

    // Now ban the user (simulates concurrent ban during the active session's lifecycle)
    user.status = korgan::domain::entities::AccountStatus::Suspended;
    user_repo.update(&user).await?;

    let refresh_res2 = refresh_uc
        .execute(RefreshTokenCommand {
            refresh_token: unrevoked_raw.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: Some("Browser".to_owned()),
            request_id: RequestId::new(),
        })
        .await;
    assert!(matches!(refresh_res2, Err(AppError::Forbidden)));

    // Verify refresh was blocked and no new child session was created
    let after_sessions = session_repo.list_by_user_id(&user_id, 10, 0).await?;
    assert!(
        !after_sessions.iter().any(|s| s.is_replaced),
        "No session was rotated!"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_failed_logins_atomic_counter_and_lockout() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(200);

    let config = LoginConfig {
        max_failed_attempts: 5,
        lockout_duration: Duration::from_secs(900),
        max_attempts_per_ip: 50,
        ..Default::default()
    };

    let login_uc = Arc::new(LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus,
        config,
    ));

    // Create an active user with known credentials
    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let email = EmailAddress::parse("victim@example.com")?;
    let mut user = User::new(email, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;
    let user_id = user.id;

    // Helper to execute a failed login attempt with wrong password
    let make_attempt = |uc: Arc<LoginUseCase>| async move {
        uc.execute(LoginCommand {
            email: "victim@example.com".to_owned(),
            password: "WrongPassword999!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await
    };

    // Execute 10 parallel failed login requests simultaneously via tokio::join!
    let (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10) = tokio::join!(
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
        make_attempt(login_uc.clone()),
    );

    // All 10 parallel failed attempts must return InvalidCredentials (not Forbidden)
    let results = [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10];
    for (i, res) in results.iter().enumerate() {
        assert!(
            matches!(res, Err(AppError::InvalidCredentials)),
            "Attempt {i} produced unexpected result: {res:?}"
        );
    }

    // Verify atomic counter in persistence: exactly 10 failed login attempts (NO lost updates!)
    let u_after = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user not found")?;
    assert_eq!(
        u_after.failed_login_attempts, 10,
        "Expected exactly 10 failed login attempts, got {}",
        u_after.failed_login_attempts
    );

    // Account MUST be locked
    assert!(
        u_after.is_locked(Utc::now()),
        "Account must be locked after 10 failed attempts exceeding max_failed_attempts = 5"
    );

    // Subsequent 11th login attempt must be rejected with Forbidden due to account lockout
    let r11 = login_uc
        .execute(LoginCommand {
            email: "victim@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;
    assert!(
        matches!(r11, Err(AppError::Forbidden)),
        "Locked account must reject subsequent login attempts with Forbidden, but got {r11:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_failed_mfa_verifications_atomic_counter_and_lockout() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let secret_cipher = Arc::new(MockSecretCipher);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let totp_service = Arc::new(MockTotpService);
    let (event_bus, _event_rx) = EventBus::new(200);

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;
    let email = EmailAddress::parse("mfa_victim@example.com")?;
    let mut user = User::new(email, None, hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user.mfa_enabled = true;
    user_repo.create(&user).await?;
    let user_id = user.id;

    // Set up verified MFA record
    let mut mfa = UserMfa::new(user_id, vec![], vec![], vec![]);
    mfa.verify(Utc::now());
    user_repo.save_mfa(&mfa).await?;

    let verify_uc = Arc::new(VerifyMfaLoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400 * 7),
        "test_issuer".to_owned(),
        "test_audience".to_owned(),
        10,
        Duration::from_secs(900),
    ));

    // Store 10 valid single-use tickets in token_store (one for each attempt)
    let mut tickets = Vec::new();
    for i in 0..10 {
        let ticket = format!("valid_mfa_ticket_{i}");
        let ticket_hash = token_utils::hash_token(&ticket);
        token_store
            .set_token(
                &format!("mfa_ticket:{ticket_hash}"),
                &user_id.to_string(),
                Duration::from_secs(300),
            )
            .await?;
        tickets.push(ticket);
    }

    // Helper to execute an invalid MFA verification with a specific ticket
    let make_mfa_attempt = |uc: Arc<VerifyMfaLoginUseCase>, ticket: String| async move {
        uc.execute(VerifyMfaLoginCommand {
            mfa_ticket: ticket,
            code: "999999".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await
    };

    // Run 10 parallel invalid MFA code verifications via tokio::join!
    let (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10) = tokio::join!(
        make_mfa_attempt(verify_uc.clone(), tickets[0].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[1].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[2].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[3].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[4].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[5].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[6].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[7].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[8].clone()),
        make_mfa_attempt(verify_uc.clone(), tickets[9].clone()),
    );

    let results = [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10];
    for (i, res) in results.iter().enumerate() {
        assert!(
            matches!(
                res,
                Err(AppError::InvalidCredentials) | Err(AppError::Forbidden)
            ),
            "MFA attempt {i} produced unexpected result: {res:?}"
        );
    }

    // Verify counter is exactly 10 in persistence
    let u_after = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user not found")?;
    assert_eq!(
        u_after.failed_login_attempts, 10,
        "Expected exactly 10 failed MFA attempts, got {}",
        u_after.failed_login_attempts
    );
    assert!(
        u_after.is_locked(Utc::now()),
        "Account must be locked after 10 failed MFA attempts"
    );

    Ok(())
}

#[tokio::test]
#[allow(clippy::panic)]
async fn test_shielded_propagates_redis_failures_fail_closed() -> TestResult {
    // 1. Direct unit verification of shielded error propagation
    let fail_result = shielded(|| async move {
        Err::<(), AppError>(AppError::internal(
            "redis_offline",
            std::io::Error::other("connection refused"),
        ))
    })
    .await;

    assert!(
        matches!(fail_result, Err(AppError::Internal { context, .. }) if context == "redis_offline"),
        "shielded must propagate AppError when the inner future fails!"
    );

    // 2. Direct verification of shielded JoinError on panic
    let panic_result = shielded(|| async move {
        panic!("simulated panic in background task");
        #[allow(unreachable_code)]
        Ok::<(), AppError>(())
    })
    .await;

    assert!(
        matches!(panic_result, Err(AppError::Internal { context, .. }) if context == "shielded background task failed"),
        "shielded must convert JoinError to AppError::Internal upon task panic!"
    );

    // 3. Fail-Closed use-case test: FailingTokenStore causes RevokeSessionUseCase to fail closed
    #[derive(Debug, Default)]
    struct FailingTokenStore;

    #[async_trait]
    impl TokenStore for FailingTokenStore {
        async fn set_token(&self, _key: &str, _val: &str, _ttl: Duration) -> Result<(), PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
        async fn get_token(&self, _key: &str) -> Result<Option<String>, PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
        async fn delete_token(&self, _key: &str) -> Result<(), PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
        async fn get_and_delete(&self, _key: &str) -> Result<Option<String>, PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
        async fn set_if_not_exists(
            &self,
            _key: &str,
            _val: &str,
            _ttl: Duration,
        ) -> Result<bool, PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
        async fn consume_token(&self, _key: &str, _val: &str) -> Result<bool, PortError> {
            Err(PortError::cache("Redis cluster unavailable"))
        }
    }

    let user_id = UserId::new();
    let session_repo = Arc::new(MockSessionRepository::default());
    let failing_token_store = Arc::new(FailingTokenStore);
    let (event_bus, _event_rx) = EventBus::new(10);

    let session = Session::new(
        user_id,
        token_utils::hash_token("test_token"),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    let session_id = session.id;
    session_repo.create(&session).await?;

    let revoke_uc = RevokeSessionUseCase::new(session_repo.clone(), failing_token_store, event_bus);

    let revoke_res = revoke_uc
        .execute(RevokeSessionCommand {
            session_id,
            user_id,
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await;

    assert!(
        matches!(revoke_res, Err(AppError::Internal { .. })),
        "RevokeSessionUseCase MUST fail closed when Redis blacklisting fails, but got {revoke_res:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_orphan_session_creation_blocked_for_banned_or_locked_user() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    session_repo.set_user_repo(user_repo.clone());

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let hash = password_hasher.hash_password(&raw_pw).await?;

    // 1. Create a suspended user
    let email = EmailAddress::parse("banned_orphan@example.com")?;
    let mut user = User::new(email, None, hash.clone());
    user.status = korgan::domain::entities::AccountStatus::Suspended;
    user_repo.create(&user).await?;

    // Attempting to create a session for suspended user must fail
    let orphan_session = Session::new(
        user.id,
        token_utils::hash_token("orphan_token"),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    let create_res = session_repo.create(&orphan_session).await;
    assert!(
        matches!(create_res, Err(PortError::Conflict { .. })),
        "Session creation must be blocked for suspended user"
    );

    // 2. Create a locked user
    let email2 = EmailAddress::parse("locked_orphan@example.com")?;
    let mut user2 = User::new(email2, None, hash.clone());
    user2.status = korgan::domain::entities::AccountStatus::Active;
    user2.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
    user_repo.create(&user2).await?;

    let orphan_session2 = Session::new(
        user2.id,
        token_utils::hash_token("orphan_token_2"),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    let create_res2 = session_repo.create(&orphan_session2).await;
    assert!(
        matches!(create_res2, Err(PortError::Conflict { .. })),
        "Session creation must be blocked for locked user"
    );

    // 3. rotate_atomic must be blocked for suspended user
    let email3 = EmailAddress::parse("suspended_rotate@example.com")?;
    let mut user3 = User::new(email3, None, hash.clone());
    user3.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user3).await?;

    let raw_token_3 = "rotate_token_3";
    let token_hash_3 = token_utils::hash_token(raw_token_3);
    let session3 = Session::new(
        user3.id,
        token_hash_3.clone(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    session_repo.create(&session3).await?;

    // Suspend user3
    user3.status = korgan::domain::entities::AccountStatus::Suspended;
    user_repo.update(&user3).await?;

    let mut rot_session3 = session3.clone();
    let next_session3 = rot_session3.rotate(
        token_utils::hash_token("next_token_3"),
        chrono::Duration::days(7),
        Utc::now(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
    );
    let rot_res3 = session_repo
        .rotate_atomic(&token_hash_3, &next_session3)
        .await?;
    assert!(
        rot_res3.is_none(),
        "rotate_atomic must return None for suspended user"
    );

    // 4. rotate_atomic must be blocked for locked user
    let email4 = EmailAddress::parse("locked_rotate@example.com")?;
    let mut user4 = User::new(email4, None, hash);
    user4.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user4).await?;

    let raw_token_4 = "rotate_token_4";
    let token_hash_4 = token_utils::hash_token(raw_token_4);
    let session4 = Session::new(
        user4.id,
        token_hash_4.clone(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::days(7),
    );
    session_repo.create(&session4).await?;

    // Lock user4
    user4.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
    user_repo.update(&user4).await?;

    let mut rot_session4 = session4.clone();
    let next_session4 = rot_session4.rotate(
        token_utils::hash_token("next_token_4"),
        chrono::Duration::days(7),
        Utc::now(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
    );
    let rot_res4 = session_repo
        .rotate_atomic(&token_hash_4, &next_session4)
        .await?;
    assert!(
        rot_res4.is_none(),
        "rotate_atomic must return None for locked user"
    );

    Ok(())
}

#[tokio::test]
async fn test_orphan_session_and_unban_race_prevented() -> TestResult {
    let user_repo = Arc::new(MockUserRepository::default());
    let session_repo = Arc::new(MockSessionRepository::default());
    session_repo.set_user_repo(user_repo.clone());
    let password_hasher = Arc::new(MockPasswordHasherWrapper::new()?);
    let token_signer = Arc::new(MockTokenSigner);
    let token_store = Arc::new(MockTokenStore::default());
    let rate_limiter = Arc::new(MockRateLimiter::default());
    let (event_bus, _event_rx) = EventBus::new(100);

    let raw_pw = RawPassword::new("CorrectPassword123!")?;
    let pw_hash = password_hasher.hash_password(&raw_pw).await?;
    let email = EmailAddress::parse("race_victim@example.com")?;
    let mut user = User::new(email, None, pw_hash);
    user.status = korgan::domain::entities::AccountStatus::Active;
    user_repo.create(&user).await?;
    let user_id = user.id;

    let login_uc = LoginUseCase::new(
        user_repo.clone(),
        session_repo.clone(),
        password_hasher.clone(),
        token_signer.clone(),
        token_store.clone(),
        rate_limiter.clone(),
        event_bus.clone(),
        LoginConfig::default(),
    );

    // Concurrently ban the user right after can_login passed but before session_repo.create:
    // We simulate this exact race by suspending the user in user_repo.
    let mut banned_user = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user not found")?;
    banned_user.status = korgan::domain::entities::AccountStatus::Suspended;
    user_repo.update(&banned_user).await?;

    // Attempt login: session creation must be blocked atomically, and error must be Forbidden (not Conflict or Ok)
    let login_res = login_uc
        .execute(LoginCommand {
            email: "race_victim@example.com".to_owned(),
            password: "CorrectPassword123!".to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            device_name: None,
            request_id: RequestId::new(),
        })
        .await;

    assert!(
        matches!(login_res, Err(AppError::Forbidden)),
        "Concurrent ban must cause login to fail with Forbidden, got {login_res:?}"
    );

    // Verify user status remains Suspended in database (NOT reverted by record_successful_login / update)
    let u_check = user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user not found")?;
    assert_eq!(
        u_check.status,
        korgan::domain::entities::AccountStatus::Suspended,
        "User status must remain Suspended and must not be overwritten by login!"
    );

    // Verify no orphan session exists in the repository
    let sessions = session_repo.list_by_user_id(&user_id, 10, 0).await?;
    assert_eq!(
        sessions.len(),
        0,
        "No orphan session may exist for a banned user!"
    );

    Ok(())
}

#[tokio::test]
async fn test_shielded_exponential_backoff_retry_success() -> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();

    let start = Instant::now();
    let result = shielded(move || {
        let attempts = attempts_clone.clone();
        async move {
            let count = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if count < 3 {
                Err(AppError::internal(
                    "transient_network_error",
                    std::io::Error::other("connection reset by peer"),
                ))
            } else {
                Ok("retry_recovered")
            }
        }
    })
    .await?;

    let elapsed = start.elapsed();
    assert_eq!(result, "retry_recovered");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(
        elapsed >= Duration::from_millis(70),
        "Elapsed duration should reflect 25ms + 50ms backoff delays: {elapsed:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_shielded_exponential_backoff_retry_exhausted() -> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();

    let start = Instant::now();
    let result = shielded(move || {
        let attempts = attempts_clone.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), AppError>(AppError::internal(
                "redis_down",
                std::io::Error::other("connection refused"),
            ))
        }
    })
    .await;

    let elapsed = start.elapsed();
    assert!(
        matches!(result, Err(AppError::Internal { context, .. }) if context == "redis_down"),
        "Must propagate error after 3 failed attempts: {result:?}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(
        elapsed >= Duration::from_millis(70),
        "Elapsed duration should reflect 25ms + 50ms backoff delays: {elapsed:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_argon2_semaphore_queue_timeout() -> TestResult {
    let hasher = Arc::new(Argon2PasswordHasher::new_with_concurrency(1024, 1, 1, 1)?);
    let pwd = RawPassword::new("TestPassword123!")?;

    // 1. Acquire and hold the single available concurrency permit
    let held_permit = hasher.semaphore_for_test().acquire_owned().await?;

    // 2. Fill queue to capacity (32 tasks)
    let mut handles = Vec::new();
    for _ in 0..32 {
        let hasher_clone = hasher.clone();
        let pwd_clone = pwd.clone();
        handles.push(tokio::spawn(async move {
            hasher_clone.hash_password(&pwd_clone).await
        }));
    }

    // Allow spawned tasks to enter waiting queue
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Next request must be rejected with ServiceUnavailable due to queue bounding
    let res = hasher.hash_password(&pwd).await;
    match res {
        Err(PortError::ServiceUnavailable { message }) => {
            assert!(
                message.contains("queue capacity exceeded"),
                "Expected queue capacity exceeded, got: {message}"
            );
        }
        other => return Err(format!("Expected ServiceUnavailable, got {other:?}").into()),
    }

    // 4. Release permit so queued tasks can complete cleanly
    drop(held_permit);
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}
