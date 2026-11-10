//! Empirical Adversarial Verification Harness:
//! - OAuth state unconditional consumption & anti-replay
//! - OAuth cookie clearing (`Max-Age=0`) on ALL error pathways (401, 403, 422, 500)
//! - OAuth Account Linking Transaction Atomicity: Rollback on link failure (no orphaned users)
//! - Concurrency stress testing: profile update vs admin suspension and brute-force lockout

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use http::header::SET_COOKIE;
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::error::{ApiError, ErrorKind, ProblemDetails};
use korgan::adapters::inbound::http::handlers::oauth::OAuthUrlResponse;
use korgan::adapters::inbound::http::{AppState, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::application::dto::UpdateProfileCommand;
use korgan::application::use_cases::user::UpdateProfileUseCase;
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

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ===========================================================================
// In-Memory Test Repositories & Mock Adapters
// ===========================================================================

#[derive(Default, Debug)]
struct ChallengerUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for ChallengerUserRepo {
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

    async fn update_username(
        &self,
        user_id: &UserId,
        new_username: Option<&Username>,
    ) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut usernames = self
            .usernames
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| PortError::not_found("user"))?;

        if let Some(ref old) = user.username {
            usernames.remove(old.as_str());
        }
        if let Some(new_u) = new_username {
            if let Some(existing_id) = usernames.get(new_u.as_str())
                && existing_id != user_id
            {
                return Err(PortError::conflict("username taken"));
            }
            usernames.insert(new_u.to_string(), *user_id);
            user.username = Some(new_u.clone());
        } else {
            user.username = None;
        }
        user.updated_at = Utc::now();
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
struct ChallengerSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
}

#[async_trait]
impl SessionRepository for ChallengerSessionRepo {
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
struct ChallengerAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for ChallengerAuditRepo {
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
struct ChallengerAccountRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
    user_repo: Mutex<Option<Arc<ChallengerUserRepo>>>,
    fail_link: Mutex<bool>,
    fail_lookup: Mutex<bool>,
}

#[async_trait]
impl OAuthAccountRepository for ChallengerAccountRepo {
    async fn find_by_provider_and_id(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        let fail = *self
            .fail_lookup
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if fail {
            return Err(PortError::database(
                "simulated database failure on oauth account lookup",
            ));
        }

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

    async fn link_oauth_account(
        &self,
        user: Option<&User>,
        account: &OAuthAccount,
    ) -> Result<(), PortError> {
        let should_fail = *self
            .fail_link
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if should_fail {
            // Transaction aborts!
            return Err(PortError::conflict(
                "simulated unique constraint collision on oauth account",
            ));
        }

        if let Some(user) = user {
            let user_repo = self
                .user_repo
                .lock()
                .map_err(|e| PortError::database(e.to_string()))?
                .clone();
            if let Some(repo) = user_repo {
                repo.create(user).await?;
            }
        }

        self.create(account).await
    }
}

#[derive(Default, Debug)]
struct ChallengerPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for ChallengerPasskeyRepo {
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
struct ChallengerTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for ChallengerTokenStore {
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
struct ChallengerRateLimiter;

#[async_trait]
impl RateLimiterPort for ChallengerRateLimiter {
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
struct ChallengerOAuthProvider {
    provider: OAuthProvider,
    auth_base_url: String,
    responses: Mutex<HashMap<String, Result<OAuthProfile, PortError>>>,
}

impl ChallengerOAuthProvider {
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
            .map_err(|e| format!("mutex poisoned: {e}"))?;
        responses.insert(code.to_owned(), Ok(profile));
        Ok(())
    }

    fn register_error(
        &self,
        code: &str,
        error: PortError,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut responses = self
            .responses
            .lock()
            .map_err(|e| format!("mutex poisoned: {e}"))?;
        responses.insert(code.to_owned(), Err(error));
        Ok(())
    }
}

#[async_trait]
impl OAuthProviderPort for ChallengerOAuthProvider {
    fn provider(&self) -> OAuthProvider {
        self.provider
    }

    fn build_authorization_url(&self, state: &str) -> String {
        format!(
            "{}?client_id=challenger_client&state={}&scope=openid+email",
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

struct TestContext {
    app: Router,
    user_repo: Arc<ChallengerUserRepo>,
    oauth_repo: Arc<ChallengerAccountRepo>,
    token_store: Arc<ChallengerTokenStore>,
    google_provider: Arc<ChallengerOAuthProvider>,
}

async fn setup_test_context() -> TestResult<TestContext> {
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

    let user_repo = Arc::new(ChallengerUserRepo::default());
    let session_repo = Arc::new(ChallengerSessionRepo::default());
    let audit_repo = Arc::new(ChallengerAuditRepo::default());
    let oauth_repo = Arc::new(ChallengerAccountRepo::default());
    if let Ok(mut guard) = oauth_repo.user_repo.lock() {
        *guard = Some(user_repo.clone());
    }
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(ChallengerPasskeyRepo::default());
    let token_store = Arc::new(ChallengerTokenStore::default());
    let rate_limiter = Arc::new(ChallengerRateLimiter);

    let google_provider = Arc::new(ChallengerOAuthProvider::new(
        OAuthProvider::Google,
        "https://accounts.google.com/o/oauth2/v2/auth",
    ));
    let github_provider = Arc::new(ChallengerOAuthProvider::new(
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
        oauth_repo,
        token_store,
        google_provider,
    })
}

async fn send_req(app: &Router, req: Request<Body>) -> TestResult<Response> {
    Ok(app.clone().oneshot(req).await?)
}

async fn parse_json<T: serde::de::DeserializeOwned>(res: Response) -> TestResult<T> {
    let bytes = to_bytes(res.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ===========================================================================
// CHALLENGE 1: OAuth State Lifecycle & Anti-Replay
// ===========================================================================

#[tokio::test]
async fn test_adversarial_oauth_state_burned_on_cookie_mismatch_blocks_replay() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Generate authorization URL and anti-CSRF state token in TokenStore
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_req(&ctx.app, req_url).await?;
    assert_eq!(res_url.status(), StatusCode::OK);
    let url_resp: OAuthUrlResponse = parse_json(res_url).await?;

    let state_key = format!("oauth:state:google:{}", url_resp.state);
    assert_eq!(
        ctx.token_store.get_token(&state_key).await?.as_deref(),
        Some("valid"),
        "State token must initially exist in TokenStore"
    );

    let auth_code = "adversarial_code_1";
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "adv-sub-1".to_owned(),
            email: EmailAddress::parse("adversary@example.com")?,
            name: Some("Adversary One".to_owned()),
        },
    )?;

    // 2. Attack: Callback with valid state in query parameter but spoofed/mismatched cookie
    let req_mismatch = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .header("Cookie", "__Host-oauth_state=spoofed_cookie_value")
        .body(Body::empty())?;
    let res_mismatch = send_req(&ctx.app, req_mismatch).await?;
    assert_eq!(
        res_mismatch.status(),
        StatusCode::FORBIDDEN,
        "Cookie mismatch must be rejected with 403 Forbidden"
    );

    // 3. INVARIANT: State in TokenStore MUST be burned unconditionally!
    let token_after_mismatch = ctx.token_store.get_token(&state_key).await?;
    assert_eq!(
        token_after_mismatch, None,
        "CRITICAL STATE FAILURE: State token was NOT burned in TokenStore after cookie mismatch!"
    );

    // 4. Attack Replay: Attacker/victim attempts to replay with the valid matching cookie
    let req_replay = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .header("Cookie", format!("__Host-oauth_state={}", url_resp.state))
        .body(Body::empty())?;
    let res_replay = send_req(&ctx.app, req_replay).await?;
    assert_eq!(
        res_replay.status(),
        StatusCode::FORBIDDEN,
        "CRITICAL ANTI-REPLAY FAILURE: Replay attempt with burned state was not rejected with 403!"
    );

    let problem: ProblemDetails = parse_json(res_replay).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");

    Ok(())
}

#[tokio::test]
async fn test_adversarial_oauth_state_burned_on_failed_code_exchange_blocks_replay() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Generate authorization URL and anti-CSRF state token in TokenStore
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_req(&ctx.app, req_url).await?;
    assert_eq!(res_url.status(), StatusCode::OK);
    let url_resp: OAuthUrlResponse = parse_json(res_url).await?;

    let state_key = format!("oauth:state:google:{}", url_resp.state);
    assert_eq!(
        ctx.token_store.get_token(&state_key).await?.as_deref(),
        Some("valid")
    );

    // 2. Configure provider so that code exchange for "invalid_code_xyz" returns an error
    let invalid_code = "invalid_code_xyz";
    ctx.google_provider.register_error(
        invalid_code,
        PortError::external_service("google", "invalid authorization code", None),
    )?;

    // 3. Callback with valid state, matching cookie, but failing code exchange
    let req_failed_exchange = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            invalid_code, url_resp.state
        ))
        .header("Cookie", format!("__Host-oauth_state={}", url_resp.state))
        .body(Body::empty())?;
    let res_failed_exchange = send_req(&ctx.app, req_failed_exchange).await?;

    assert!(
        res_failed_exchange.status().is_client_error()
            || res_failed_exchange.status().is_server_error(),
        "Failed code exchange must return error status"
    );

    // 4. INVARIANT: State token MUST be burned even when code exchange fails!
    let token_after_failure = ctx.token_store.get_token(&state_key).await?;
    assert_eq!(
        token_after_failure, None,
        "CRITICAL STATE FAILURE: State token was NOT consumed before or during code exchange failure!"
    );

    // 5. Attack Replay: Now register a valid profile for "valid_code_now", but replay with the previously used state
    let valid_code = "valid_code_now";
    ctx.google_provider.register_profile(
        valid_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "adv-sub-replay".to_owned(),
            email: EmailAddress::parse("replay_victim@example.com")?,
            name: Some("Replay Victim".to_owned()),
        },
    )?;

    let req_replay = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            valid_code, url_resp.state
        ))
        .header("Cookie", format!("__Host-oauth_state={}", url_resp.state))
        .body(Body::empty())?;
    let res_replay = send_req(&ctx.app, req_replay).await?;
    assert_eq!(
        res_replay.status(),
        StatusCode::FORBIDDEN,
        "CRITICAL ANTI-REPLAY FAILURE: State token from failed code exchange was replayed successfully!"
    );

    Ok(())
}

// ===========================================================================
// CHALLENGE 2: Cookie Clearing on ALL Error Pathways (401, 403, 422, 500)
// ===========================================================================

fn assert_cookie_cleared(res: &Response, scenario: &str) {
    let cookies: Vec<String> = res
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();

    let host_cleared = cookies.iter().any(|c| {
        c.contains("__Host-oauth_state=")
            && (c.contains("Max-Age=0") || c.contains("max-age=0"))
            && c.contains("HttpOnly")
            && c.contains("Secure")
    });
    assert!(
        host_cleared,
        "[{scenario}] __Host-oauth_state cookie was not cleared with Max-Age=0. Cookies found: {cookies:?}"
    );

    let fallback_cleared = cookies.iter().any(|c| {
        c.contains("oauth_state=")
            && (c.contains("Max-Age=0") || c.contains("max-age=0"))
            && c.contains("HttpOnly")
            && c.contains("Secure")
    });
    assert!(
        fallback_cleared,
        "[{scenario}] fallback oauth_state cookie was not cleared with Max-Age=0. Cookies found: {cookies:?}"
    );
}

#[tokio::test]
async fn test_adversarial_cookie_cleared_on_all_error_status_codes() -> TestResult {
    let ctx = setup_test_context().await?;

    // --- Scenario A: 422 Unprocessable Entity (Unsupported OAuth Provider) ---
    let req_422 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/unsupported_provider_xyz/callback?code=foo&state=bar")
        .header("Cookie", "__Host-oauth_state=bar; oauth_state=bar")
        .body(Body::empty())?;
    let res_422 = send_req(&ctx.app, req_422).await?;
    assert_eq!(res_422.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_cookie_cleared(&res_422, "Status 422 Unprocessable Entity");

    // --- Scenario B: 403 Forbidden (Tampered or Expired Anti-CSRF State) ---
    let req_403 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/callback?code=foo&state=tampered_state_999")
        .header(
            "Cookie",
            "__Host-oauth_state=tampered_state_999; oauth_state=tampered_state_999",
        )
        .body(Body::empty())?;
    let res_403 = send_req(&ctx.app, req_403).await?;
    assert_eq!(res_403.status(), StatusCode::FORBIDDEN);
    assert_cookie_cleared(&res_403, "Status 403 Forbidden");

    // --- Scenario C: 500 Internal Server Error (Database Lookup Failure) ---
    // Generate valid CSRF state first
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_req(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = parse_json(res_url).await?;

    // Register valid profile for code "db_fail_code"
    let code_500 = "db_fail_code";
    ctx.google_provider.register_profile(
        code_500,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "db-fail-sub".to_owned(),
            email: EmailAddress::parse("dbfail@example.com")?,
            name: Some("DB Fail".to_owned()),
        },
    )?;

    // Enable database failure simulation in OAuthAccountRepository
    *ctx.oauth_repo
        .fail_lookup
        .lock()
        .map_err(|e| format!("mutex poisoned: {e}"))? = true;

    let req_500 = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            code_500, url_resp.state
        ))
        .header(
            "Cookie",
            format!(
                "__Host-oauth_state={}; oauth_state={}",
                url_resp.state, url_resp.state
            ),
        )
        .body(Body::empty())?;
    let res_500 = send_req(&ctx.app, req_500).await?;
    assert_eq!(res_500.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_cookie_cleared(&res_500, "Status 500 Internal Server Error");

    // Reset database failure simulation
    *ctx.oauth_repo
        .fail_lookup
        .lock()
        .map_err(|e| format!("mutex poisoned: {e}"))? = false;

    // --- Scenario D: 401 Unauthorized (ApiError response mapping invariant) ---
    // Verify that when execute_result yields ApiError with 401 (e.g. Unauthenticated / InvalidCredentials),
    // (cleared_jar, err.into_response()) produces StatusCode::UNAUTHORIZED and includes the Max-Age=0 cookies
    let jar = CookieJar::new();
    let clear_host_cookie = axum_extra::extract::cookie::Cookie::build(("__Host-oauth_state", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0))
        .build();
    let clear_fallback_cookie = axum_extra::extract::cookie::Cookie::build(("oauth_state", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0))
        .build();
    let cleared_jar = jar.add(clear_host_cookie).add(clear_fallback_cookie);

    let err_401 = ApiError::new(ErrorKind::Unauthenticated);
    let mapped_response: Response = (cleared_jar, err_401.into_response()).into_response();
    assert_eq!(mapped_response.status(), StatusCode::UNAUTHORIZED);
    assert_cookie_cleared(&mapped_response, "Status 401 Unauthorized Response Mapping");

    Ok(())
}

// ===========================================================================
// CHALLENGE 3: Atomic Account Linking Transaction (No Orphaned Users)
// ===========================================================================

#[tokio::test]
async fn test_adversarial_account_linking_rollback_prevents_orphaned_users() -> TestResult {
    let ctx = setup_test_context().await?;

    // Configure OAuth account repo to simulate a database failure / unique conflict during link
    *ctx.oauth_repo
        .fail_link
        .lock()
        .map_err(|e| format!("mutex poisoned: {e}"))? = true;

    // Generate CSRF state
    let req_url = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/oauth/google/url")
        .body(Body::empty())?;
    let res_url = send_req(&ctx.app, req_url).await?;
    let url_resp: OAuthUrlResponse = parse_json(res_url).await?;

    // Mock profile for a new user
    let auth_code = "atomic_check_code";
    let target_email = EmailAddress::parse("uncommitted_user@example.com")?;
    ctx.google_provider.register_profile(
        auth_code,
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "atomic-sub-fail".to_owned(),
            email: target_email.clone(),
            name: Some("Uncommitted User".to_owned()),
        },
    )?;

    // Send callback
    let req_callback = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oauth/google/callback?code={}&state={}",
            auth_code, url_resp.state
        ))
        .header("Cookie", format!("__Host-oauth_state={}", url_resp.state))
        .body(Body::empty())?;
    let res_callback = send_req(&ctx.app, req_callback).await?;

    assert!(
        res_callback.status().is_client_error() || res_callback.status().is_server_error(),
        "Failed link must return an error status"
    );

    // CRITICAL ATOMICITY CHECK 1: User record must NOT exist in UserRepository
    let user_in_db = ctx.user_repo.find_by_email(&target_email).await?;
    assert!(
        user_in_db.is_none(),
        "CRITICAL TRANSACTION FAILURE: Orphaned User record exists despite failed account link!"
    );

    // CRITICAL ATOMICITY CHECK 2: OAuth link must NOT exist in OAuthAccountRepository
    let account_in_db = ctx
        .oauth_repo
        .find_by_provider_and_id(OAuthProvider::Google, "atomic-sub-fail")
        .await?;
    assert!(
        account_in_db.is_none(),
        "CRITICAL TRANSACTION FAILURE: OAuth account was created despite failed linking transaction!"
    );

    Ok(())
}

// ===========================================================================
// CHALLENGE 4: Concurrency Stress Testing
// Profile Updates vs Admin Suspension and Brute-Force Lockout
// ===========================================================================

#[tokio::test]
async fn test_adversarial_concurrency_stress_profile_update_vs_admin_suspend() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Create active user
    let email = EmailAddress::parse("suspend_victim@example.com")?;
    let hash = PasswordHash::new(
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8",
    )?;
    let mut user = User::new(email, Some(Username::new("initial_uname")?), hash);
    user.status = AccountStatus::Active;
    let user_id = user.id;
    ctx.user_repo.create(&user).await?;

    let update_uc = UpdateProfileUseCase::new(ctx.user_repo.clone());
    let user_repo_clone = ctx.user_repo.clone();

    // 2. Concurrently fire 40 tasks:
    //    - 20 tasks: User submitting rapid profile updates with different usernames
    //    - 20 tasks: Admin administratively suspending the user
    let mut handles = Vec::new();

    for i in 0..40 {
        let uc = update_uc.clone();
        let repo = user_repo_clone.clone();

        if i % 2 == 0 {
            // Profile update task
            handles.push(tokio::spawn(async move {
                let uname_str = format!("name_seq_{i}");
                let _ = uc
                    .execute(UpdateProfileCommand {
                        user_id,
                        username: Some(uname_str),
                        request_id: RequestId::new(),
                    })
                    .await;
            }));
        } else {
            // Admin suspension task
            handles.push(tokio::spawn(async move {
                if let Ok(Some(mut u)) = repo.find_by_id(&user_id).await {
                    u.ban(Utc::now());
                    let _ = repo.update(&u).await;
                }
            }));
        }
    }

    for h in handles {
        h.await?;
    }

    // 3. Final verification:
    // Because Admin suspended the user, and profile updates use granular `update_username`
    // (which NEVER touches `status`), `status` MUST be `Suspended`!
    let final_user = ctx
        .user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user missing from repository")?;

    assert_eq!(
        final_user.status,
        AccountStatus::Suspended,
        "CONCURRENCY REGRESSION: Granular profile update overwrote admin suspension back to Active!"
    );

    Ok(())
}

#[tokio::test]
async fn test_adversarial_concurrency_stress_profile_update_vs_brute_force_lockout() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Create active user with initial lockout set
    let email = EmailAddress::parse("lockout_victim@example.com")?;
    let hash = PasswordHash::new(
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$MhP2+71y6FpS2z+Gz2f8rW9N2A7mJ1t8y9A4dK0b6L8",
    )?;
    let mut user = User::new(email, Some(Username::new("lock_uname")?), hash);
    user.status = AccountStatus::Active;
    let expected_lockout = Utc::now() + chrono::Duration::minutes(30);
    user.locked_until = Some(expected_lockout);
    user.failed_login_attempts = 5;
    let user_id = user.id;
    ctx.user_repo.create(&user).await?;

    let update_uc = UpdateProfileUseCase::new(ctx.user_repo.clone());
    let user_repo_clone = ctx.user_repo.clone();

    // 2. Concurrently fire 40 tasks:
    //    - 20 tasks: User submitting rapid profile updates
    //    - 20 tasks: Failed login attempts recording atomic failures
    let mut handles = Vec::new();

    for i in 0..40 {
        let uc = update_uc.clone();
        let repo = user_repo_clone.clone();

        if i % 2 == 0 {
            // Profile update task
            handles.push(tokio::spawn(async move {
                let uname_str = format!("uname_burst_{i}");
                let _ = uc
                    .execute(UpdateProfileCommand {
                        user_id,
                        username: Some(uname_str),
                        request_id: RequestId::new(),
                    })
                    .await;
            }));
        } else {
            // Brute force failed login atomic attempt
            handles.push(tokio::spawn(async move {
                let lock_until = Utc::now() + chrono::Duration::minutes(30);
                let _ = repo
                    .record_failed_login_atomic(&user_id, 5, lock_until, Utc::now())
                    .await;
            }));
        }
    }

    for h in handles {
        h.await?;
    }

    // 3. Final verification:
    // `locked_until` MUST be preserved and MUST NOT be reset to None.
    // `failed_login_attempts` MUST NOT be wiped out to 0 by profile updates.
    let final_user = ctx
        .user_repo
        .find_by_id(&user_id)
        .await?
        .ok_or("user missing from repository")?;

    assert!(
        final_user.locked_until.is_some(),
        "CONCURRENCY REGRESSION: Granular profile update cleared user locked_until timestamp!"
    );
    assert!(
        final_user.failed_login_attempts >= 5,
        "CONCURRENCY REGRESSION: Granular profile update wiped user failed_login_attempts!"
    );

    Ok(())
}
