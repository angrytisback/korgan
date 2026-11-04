//! End-to-End User Lifecycle & Replay-Attack Integration Test.
//!
//! Validates the full IAM lifecycle through Axum HTTP transport in-memory:
//! 1. Register new account -> 201 Created (status: unverified)
//! 2. Intercept asynchronous verification email and extract one-time verification token
//! 3. Verify email -> 200 OK (status becomes active)
//! 4. Primary login -> 200 OK with AuthTokensResponse
//! 5. Setup TOTP MFA -> 200 OK with Base32 secret & SVG QR code
//! 6. Enable MFA -> 200 OK with 10 single-use backup codes
//! 7. Logout -> 204 No Content
//! 8. Login with MFA -> returns 200 OK MfaChallengeResponse (mfa_ticket)
//! 9. Complete MFA login -> exchange ticket + TOTP code for fresh tokens
//! 10. Rotate refresh token -> issues new token pair; marks previous token as replaced
//! 11. Replay attack: present stale refresh token -> 401 Unauthorized (AUTH_TOKEN_REUSE_DETECTED)
//! 12. Family revocation: verify both stale and active tokens from that session family are revoked

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use chrono::Utc;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::{AppState, ProblemDetails, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::workers::{EventBus, EventWorker};
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
use korgan::ports::services::{MailProvider, OAuthProviderPort, TokenSigner, WebAuthnService};
use secrecy::ExposeSecret;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use totp_rs::{Algorithm, Totp};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ---------------------------------------------------------------------------
// Intercepted Mail Adapter & In-Memory Repositories
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct InterceptedMailProvider {
    sender: UnboundedSender<(EmailAddress, String, String)>,
}

#[async_trait]
impl MailProvider for InterceptedMailProvider {
    async fn send_email(
        &self,
        to: &EmailAddress,
        subject: &str,
        text_body: &str,
        _html_body: &str,
    ) -> Result<(), PortError> {
        let _ = self
            .sender
            .send((to.clone(), subject.to_owned(), text_body.to_owned()));
        Ok(())
    }
}

#[derive(Default, Debug)]
struct E2eUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for E2eUserRepo {
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
struct E2eSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
}

#[async_trait]
impl SessionRepository for E2eSessionRepo {
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
struct E2eAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for E2eAuditRepo {
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
struct E2eOAuthAccountRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
}

#[async_trait]
impl OAuthAccountRepository for E2eOAuthAccountRepo {
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
struct E2ePasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for E2ePasskeyRepo {
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
struct E2eTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for E2eTokenStore {
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
struct E2eRateLimiter;

#[async_trait]
impl RateLimiterPort for E2eRateLimiter {
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

// ---------------------------------------------------------------------------
// E2E Test Fixture Builder
// ---------------------------------------------------------------------------

struct E2eTestContext {
    app: Router,
    mail_rx: UnboundedReceiver<(EmailAddress, String, String)>,
    token_signer: Arc<dyn TokenSigner>,
}

fn setup_e2e_app() -> Result<E2eTestContext, Box<dyn std::error::Error>> {
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

    let user_repo = Arc::new(E2eUserRepo::default());
    let session_repo = Arc::new(E2eSessionRepo::default());
    let audit_repo = Arc::new(E2eAuditRepo::default());
    let token_store = Arc::new(E2eTokenStore::default());
    let rate_limiter = Arc::new(E2eRateLimiter);

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

    let (mail_tx, mail_rx) = unbounded_channel();
    let mail_provider: Arc<dyn MailProvider> =
        Arc::new(InterceptedMailProvider { sender: mail_tx });

    let (event_bus, event_rx) = EventBus::new(100);
    let event_worker = EventWorker::new(
        event_rx,
        mail_provider.clone(),
        audit_repo.clone(),
        settings.server.public_base_url.clone(),
    );

    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(event_worker.run(stop_rx));

    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_cfg = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let oauth_account_repo: Arc<dyn OAuthAccountRepository> =
        Arc::new(E2eOAuthAccountRepo::default());
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(E2ePasskeyRepo::default());
    let google_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebauthnRsAdapter::new(
        "localhost",
        "http://localhost:8080",
    )?);

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

    Ok(E2eTestContext {
        app,
        mail_rx,
        token_signer: token_signer.clone(),
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
// E2E User Lifecycle & Replay Detection Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_user_lifecycle_and_replay_detection() -> TestResult {
    let mut ctx = setup_e2e_app()?;

    // =======================================================================
    // 1. REGISTER
    // =======================================================================
    let register_payload = serde_json::json!({
        "email": "carol@example.com",
        "password": "CarolPassword123!",
        "username": "carol"
    });
    let reg_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/register")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&register_payload)?))?;

    let reg_res = send_request(&ctx.app, reg_req).await?;
    assert_eq!(reg_res.status(), StatusCode::CREATED);
    let reg_val: serde_json::Value = json_body(reg_res).await?;
    assert_eq!(reg_val["email"], "carol@example.com");
    assert_eq!(reg_val["status"], "unverified");
    assert_eq!(reg_val["verification_required"], true);

    // =======================================================================
    // 2. EXTRACT VERIFICATION TOKEN FROM INTERCEPTED EMAIL
    // =======================================================================
    let (_to, subject, text_body) =
        tokio::time::timeout(Duration::from_secs(3), ctx.mail_rx.recv())
            .await?
            .ok_or("no verification email received")?;

    assert!(subject.contains("Verify your email"));
    let token = text_body
        .split("token=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .ok_or("failed to parse verification token from email body")?;

    // =======================================================================
    // 3. VERIFY EMAIL
    // =======================================================================
    let verify_payload = serde_json::json!({ "token": token });
    let verify_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/verify-email")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&verify_payload)?))?;

    let verify_res = send_request(&ctx.app, verify_req).await?;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // =======================================================================
    // 4. PRIMARY LOGIN (Active Account)
    // =======================================================================
    let login_payload = serde_json::json!({
        "email": "carol@example.com",
        "password": "CarolPassword123!"
    });
    let login_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Client-Type", "mobile")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let login_res = send_request(&ctx.app, login_req).await?;
    assert_eq!(login_res.status(), StatusCode::OK);
    let tokens_1: serde_json::Value = json_body(login_res).await?;
    let access_token_1 = tokens_1["access_token"]
        .as_str()
        .ok_or("missing access token 1")?;
    let claims_1 = ctx.token_signer.verify_access_token(access_token_1)?;
    assert_eq!(claims_1.amr, vec!["pwd"]);
    assert!(claims_1.auth_time > 0);

    // =======================================================================
    // 5. SETUP MFA (TOTP)
    // =======================================================================
    let mfa_setup_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/mfa/setup")
        .header(AUTHORIZATION, format!("Bearer {access_token_1}"))
        .body(Body::empty())?;

    let mfa_setup_res = send_request(&ctx.app, mfa_setup_req).await?;
    assert_eq!(mfa_setup_res.status(), StatusCode::OK);
    let mfa_setup_val: serde_json::Value = json_body(mfa_setup_res).await?;
    let totp_b32_secret = mfa_setup_val["secret"]
        .as_str()
        .ok_or("missing totp secret")?;

    // Decode Base32 secret and compute current valid 6-digit TOTP code
    let raw_secret = korgan::application::use_cases::token_utils::decode_base32(totp_b32_secret)
        .ok_or("failed to decode base32 secret")?;
    #[allow(deprecated)]
    let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, raw_secret, None, String::new())
        .map_err(|e| format!("failed to construct TOTP: {e}"))?;
    let totp_code = totp.generate_current().to_string();

    // =======================================================================
    // 6. ENABLE MFA
    // =======================================================================
    let mfa_enable_payload = serde_json::json!({ "code": totp_code });
    let mfa_enable_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/mfa/enable")
        .header(AUTHORIZATION, format!("Bearer {access_token_1}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&mfa_enable_payload)?))?;

    let mfa_enable_res = send_request(&ctx.app, mfa_enable_req).await?;
    assert_eq!(mfa_enable_res.status(), StatusCode::OK);
    let mfa_enable_val: serde_json::Value = json_body(mfa_enable_res).await?;
    let backup_codes = mfa_enable_val["backup_codes"]
        .as_array()
        .ok_or("missing backup codes")?;
    assert_eq!(backup_codes.len(), 10);

    // =======================================================================
    // 7. LOGOUT
    // =======================================================================
    let logout_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/logout")
        .header(AUTHORIZATION, format!("Bearer {access_token_1}"))
        .body(Body::empty())?;

    let logout_res = send_request(&ctx.app, logout_req).await?;
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);

    // =======================================================================
    // 8. LOGIN WITH MFA CHALLENGE
    // =======================================================================
    let login_mfa_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_payload)?))?;

    let login_mfa_res = send_request(&ctx.app, login_mfa_req).await?;
    assert_eq!(login_mfa_res.status(), StatusCode::OK);
    let mfa_challenge_val: serde_json::Value = json_body(login_mfa_res).await?;
    let mfa_ticket = mfa_challenge_val["mfa_ticket"]
        .as_str()
        .ok_or("missing mfa ticket")?;

    // Generate fresh TOTP code
    let fresh_totp_code = totp.generate_current().to_string();

    // Complete MFA Verification: POST /api/v1/auth/mfa/verify
    let verify_mfa_payload = serde_json::json!({
        "mfa_ticket": mfa_ticket,
        "code": fresh_totp_code
    });
    let verify_mfa_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/mfa/verify")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&verify_mfa_payload)?))?;

    let verify_mfa_res = send_request(&ctx.app, verify_mfa_req).await?;
    assert_eq!(verify_mfa_res.status(), StatusCode::OK);
    let tokens_2: serde_json::Value = json_body(verify_mfa_res).await?;
    let access_token_2 = tokens_2["access_token"]
        .as_str()
        .ok_or("missing access token 2")?;
    let claims_2 = ctx.token_signer.verify_access_token(access_token_2)?;
    assert_eq!(claims_2.amr, vec!["pwd", "mfa"]);
    let initial_auth_time = claims_2.auth_time;
    assert!(initial_auth_time > 0);

    let refresh_token_2 = tokens_2["refresh_token"]
        .as_str()
        .ok_or("missing refresh token 2")?
        .to_owned();

    // =======================================================================
    // 9. REFRESH TOKEN ROTATION
    // =======================================================================
    let refresh_payload = serde_json::json!({ "refresh_token": refresh_token_2 });
    let refresh_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&refresh_payload)?))?;

    let refresh_res = send_request(&ctx.app, refresh_req).await?;
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let tokens_3: serde_json::Value = json_body(refresh_res).await?;
    let access_token_3 = tokens_3["access_token"]
        .as_str()
        .ok_or("missing access token 3")?;
    let claims_3 = ctx.token_signer.verify_access_token(access_token_3)?;
    assert_eq!(claims_3.amr, vec!["pwd", "mfa"]);
    // Original authentication time (auth_time) remains unchanged even after token rotation!
    assert_eq!(claims_3.auth_time, initial_auth_time);

    let refresh_token_3 = tokens_3["refresh_token"]
        .as_str()
        .ok_or("missing refresh token 3")?
        .to_owned();

    // Verify access token 3 works
    let me_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {access_token_3}"))
        .body(Body::empty())?;

    let me_res = send_request(&ctx.app, me_req).await?;
    assert_eq!(me_res.status(), StatusCode::OK);

    // =======================================================================
    // 10. REPLAY ATTACK: PRESENT STALE REFRESH TOKEN 2 AGAIN
    // =======================================================================
    let replay_payload = serde_json::json!({ "refresh_token": refresh_token_2 });
    let replay_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&replay_payload)?))?;

    let replay_res = send_request(&ctx.app, replay_req).await?;
    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);
    let replay_problem: ProblemDetails = json_body(replay_res).await?;
    assert_eq!(replay_problem.code, "AUTH_TOKEN_REUSE_DETECTED");

    // =======================================================================
    // 11. VERIFY FULL FAMILY REVOCATION
    // =======================================================================
    // The newly issued refresh token 3 must also fail now because the entire token family was revoked!
    let stale_family_payload = serde_json::json!({ "refresh_token": refresh_token_3 });
    let stale_family_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/refresh")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&stale_family_payload)?))?;

    let stale_family_res = send_request(&ctx.app, stale_family_req).await?;
    assert_eq!(stale_family_res.status(), StatusCode::UNAUTHORIZED);

    // Access token from that session is also rejected on next API call
    let me_revoked_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {access_token_3}"))
        .body(Body::empty())?;

    let me_revoked_res = send_request(&ctx.app, me_revoked_req).await?;
    assert_eq!(me_revoked_res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
