//! Comprehensive 4-Tier Opaque-Box E2E Behavioral Invariants Test Suite.
//!
//! Validates the external API behavioral contracts, invariant preservation,
//! concurrency safety, zero panics, and regression avoidance for Korgan IAM.
//!
//! Architecture:
//! - Tier 1: Feature Coverage (auth, sessions, MFA, passkeys, ws-ticket, rate limits)
//! - Tier 2: Boundary & Corner Cases (input bounds, RFC 9457 errors, token tampering/expiry, replay attacks, account gating, payload limits)
//! - Tier 3: Cross-Feature Combinations (step-up auth with MFA/passkeys, cross-session invalidation on password change, OAuth takeover prevention, concurrent bursts & CAS races)
//! - Tier 4: Real-World Application Scenarios (multi-device user lifecycle, password recovery & history depth, brute force lockout & backup code consumption)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use chrono::{DateTime, Utc};
use http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use http::{HeaderMap, Method, Request, StatusCode};
use korgan::adapters::inbound::http::{AppState, ProblemDetails, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::application::use_cases::token_utils::decode_base32;
use korgan::application::workers::{EventBus, EventWorker};
use korgan::config::Settings;
use korgan::domain::entities::{
    AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa, UserRole,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{
    AccessTokenClaims, MailProvider, OAuthProfile, OAuthProviderPort, TokenSigner, WebAuthnService,
};
use secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use totp_rs::{Algorithm, Totp};
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

const TEST_CRED_ID_STR: &str =
    "uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ";

// ===========================================================================
// WebAuthn Mock Helpers
// ===========================================================================

fn make_sample_webauthn_passkey() -> Result<WebauthnPasskey, PortError> {
    let ser_passkey = json!({
        "cred": {
            "cred_id": TEST_CRED_ID_STR,
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": [194,126,127,109,252,23,131,21,252,6,223,99,44,254,140,27,230,17,94,5,133,28,104,41,144,69,171,149,161,26,200,243],
                        "y": [143,123,183,156,24,178,21,248,117,159,162,69,171,52,188,252,26,59,6,47,103,92,19,58,117,103,249,0,219,8,95,196]
                    }
                }
            },
            "counter": 0,
            "user_verified": true,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "preferred",
            "extensions": {
                "cred_protect": "NotRequested",
                "hmac_create_secret": "NotRequested"
            },
            "attestation": {
                "data": { "None": null },
                "metadata": "None"
            },
            "attestation_format": "None"
        }
    });
    serde_json::from_value(ser_passkey).map_err(|e| PortError::serialization(e.to_string()))
}

fn make_sample_auth_result() -> Result<AuthenticationResult, PortError> {
    let ser_auth_result = json!({
        "cred_id": TEST_CRED_ID_STR,
        "needs_update": false,
        "user_verified": true,
        "backup_state": false,
        "backup_eligible": false,
        "counter": 0,
        "extensions": {}
    });
    serde_json::from_value(ser_auth_result).map_err(|e| PortError::serialization(e.to_string()))
}

#[derive(Clone)]
struct MockWebAuthnService {
    real: WebauthnRsAdapter,
}

impl MockWebAuthnService {
    fn new() -> Result<Self, PortError> {
        Ok(Self {
            real: WebauthnRsAdapter::new("localhost", "http://localhost:8080")?,
        })
    }
}

impl WebAuthnService for MockWebAuthnService {
    fn start_registration(
        &self,
        user_id: &UserId,
        username: &str,
        existing_passkeys: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError> {
        self.real
            .start_registration(user_id, username, existing_passkeys)
    }

    fn finish_registration(
        &self,
        _reg_response: &RegisterPublicKeyCredential,
        _reg_state: &PasskeyRegistration,
    ) -> Result<WebauthnPasskey, PortError> {
        make_sample_webauthn_passkey()
    }

    fn start_discoverable_login(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PortError> {
        self.real.start_discoverable_login()
    }

    fn finish_discoverable_login(
        &self,
        _auth_response: &PublicKeyCredential,
        _auth_state: DiscoverableAuthentication,
        candidate_passkeys: &[Passkey],
    ) -> Result<(AuthenticationResult, WebauthnPasskey), PortError> {
        let sample_pk = make_sample_webauthn_passkey()?;
        let matched = candidate_passkeys
            .iter()
            .find(|pk| pk.credential_id == sample_pk.cred_id().as_slice());

        if let Some(_pk) = matched {
            let auth_res = make_sample_auth_result()?;
            Ok((auth_res, sample_pk))
        } else {
            Err(PortError::not_found("Passkey"))
        }
    }
}

// ===========================================================================
// In-Memory Test Repositories & Ports
// ===========================================================================

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
struct InMemUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    history: Mutex<HashMap<UserId, Vec<PasswordHash>>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for InMemUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
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
        Ok(emails
            .get(email.as_str())
            .and_then(|id| users.get(id))
            .cloned())
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
        Ok(usernames
            .get(username.as_str())
            .and_then(|id| users.get(id))
            .cloned())
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
        if let Some(ref u) = user.username
            && usernames.contains_key(u.as_str())
        {
            return Err(PortError::conflict("username already exists"));
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
            let h = history.entry(*user_id).or_default();
            if let Some(ref current) = user.password_hash {
                h.insert(0, current.clone());
            }
            h.truncate(history_depth as usize);
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
            .map(|h| h.iter().take(limit as usize).cloned().collect())
            .unwrap_or_default())
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
        lockout_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(u16, Option<DateTime<Utc>>), PortError> {
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
        now: DateTime<Utc>,
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

        if let Some(u) = new_username
            && let Some(&existing_id) = usernames.get(u.as_str())
            && existing_id != *user_id
        {
            return Err(PortError::conflict("username already taken"));
        }

        if let Some(user) = users.get_mut(user_id) {
            if let Some(ref old_u) = user.username {
                usernames.remove(old_u.as_str());
            }
            if let Some(u) = new_username {
                usernames.insert(u.to_string(), *user_id);
                user.username = Some(u.clone());
            } else {
                user.username = None;
            }
            user.updated_at = Utc::now();
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct InMemSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
}

#[async_trait]
impl SessionRepository for InMemSessionRepo {
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
        Ok(by_hash
            .get(token_hash)
            .and_then(|id| sessions.get(id))
            .cloned())
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
        let mut list: Vec<Session> = sessions
            .values()
            .filter(|s| s.user_id == *user_id && !s.is_revoked())
            .cloned()
            .collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.last_active_at));
        Ok(list
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
struct InMemAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for InMemAuditRepo {
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
struct InMemOAuthRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
    user_repo: Option<Arc<InMemUserRepo>>,
}

#[async_trait]
impl OAuthAccountRepository for InMemOAuthRepo {
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

    async fn link_oauth_account(
        &self,
        user: Option<&User>,
        account: &OAuthAccount,
    ) -> Result<(), PortError> {
        if let Some(user) = user
            && let Some(ref repo) = self.user_repo
        {
            repo.create(user).await?;
        }
        self.create(account).await
    }
}

#[derive(Default, Debug)]
struct InMemPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for InMemPasskeyRepo {
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

    async fn update_credential_state(
        &self,
        id: &PasskeyId,
        passkey_json: &serde_json::Value,
        last_used_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        let mut passkeys = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(pk) = passkeys.get_mut(id) {
            pk.passkey_json = passkey_json.clone();
            pk.last_used_at = Some(last_used_at);
            Ok(())
        } else {
            Err(PortError::not_found("Passkey"))
        }
    }
}

#[derive(Default, Debug)]
struct InMemTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for InMemTokenStore {
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
struct InMemRateLimiter {
    counts: Mutex<HashMap<String, (u32, i64)>>,
}

#[async_trait]
impl RateLimiterPort for InMemRateLimiter {
    async fn check_and_increment(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        let mut map = self
            .counts
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        let now = Utc::now().timestamp();
        let entry = map
            .entry(key.to_string())
            .or_insert((0, now + window.as_secs() as i64));

        if now > entry.1 {
            entry.0 = 0;
            entry.1 = now + window.as_secs() as i64;
        }

        entry.0 += 1;
        let allowed = entry.0 <= limit;
        let remaining = limit.saturating_sub(entry.0);
        let reset_epoch_secs = entry.1 as u64;
        let retry_after_secs = if allowed {
            None
        } else {
            Some((entry.1 - now).max(1) as u64)
        };

        Ok(RateLimitStatus {
            allowed,
            limit,
            remaining,
            reset_epoch_secs,
            retry_after_secs,
        })
    }

    async fn reset(&self, key: &str) -> Result<(), PortError> {
        let mut map = self
            .counts
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        map.remove(key);
        Ok(())
    }
}

#[derive(Clone)]
struct MockOAuthProvider {
    provider: OAuthProvider,
    profiles: Arc<Mutex<HashMap<String, OAuthProfile>>>,
}

impl MockOAuthProvider {
    fn new(provider: OAuthProvider) -> Self {
        Self {
            provider,
            profiles: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register_profile(&self, code: &str, profile: OAuthProfile) {
        if let Ok(mut lock) = self.profiles.lock() {
            lock.insert(code.to_owned(), profile);
        }
    }
}

#[async_trait]
impl OAuthProviderPort for MockOAuthProvider {
    fn provider(&self) -> OAuthProvider {
        self.provider
    }

    fn build_authorization_url(&self, state: &str, _code_challenge: &str) -> String {
        format!(
            "https://{}.oauth.local/auth?state={state}",
            self.provider.as_str()
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        _code_verifier: &str,
    ) -> Result<OAuthProfile, PortError> {
        let profiles = self
            .profiles
            .lock()
            .map_err(|e| PortError::external_service("oauth", e.to_string(), None))?;
        if let Some(p) = profiles.get(code) {
            Ok(p.clone())
        } else {
            // Default deterministic profile fallback
            Ok(OAuthProfile {
                provider: self.provider,
                provider_user_id: format!("{}_sub_{code}", self.provider.as_str()),
                email: EmailAddress::parse(format!("oauth_{code}@example.com"))
                    .map_err(|e| PortError::serialization(e.to_string()))?,
                name: Some(format!("OAuth User {code}")),
            })
        }
    }
}

// ===========================================================================
// Test Context Fixture
// ===========================================================================

struct TestContext {
    app: Router,
    mail_rx: UnboundedReceiver<(EmailAddress, String, String)>,
    token_signer: Arc<dyn TokenSigner>,
    user_repo: Arc<InMemUserRepo>,
    session_repo: Arc<InMemSessionRepo>,
    google_oauth: Arc<MockOAuthProvider>,
}

fn setup_test_context() -> Result<TestContext, Box<dyn std::error::Error + Send + Sync>> {
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
            "true".to_owned(),
        ),
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);

    let user_repo = Arc::new(InMemUserRepo::default());
    let session_repo = Arc::new(InMemSessionRepo::default());
    let audit_repo = Arc::new(InMemAuditRepo::default());
    let token_store = Arc::new(InMemTokenStore::default());
    let rate_limiter = Arc::new(InMemRateLimiter::default());
    let passkey_repo = Arc::new(InMemPasskeyRepo::default());
    let oauth_repo = Arc::new(InMemOAuthRepo {
        accounts: Mutex::new(HashMap::new()),
        user_repo: Some(user_repo.clone()),
    });

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

    let google_oauth = Arc::new(MockOAuthProvider::new(OAuthProvider::Google));
    let github_oauth = Arc::new(MockOAuthProvider::new(OAuthProvider::GitHub));
    let webauthn_service = Arc::new(MockWebAuthnService::new()?);

    let state = AppState::with_ports(
        settings,
        user_repo.clone(),
        session_repo.clone(),
        audit_repo,
        oauth_repo,
        passkey_repo,
        token_store,
        rate_limiter,
        password_hasher,
        token_signer.clone(),
        secret_cipher,
        totp_service,
        hibp_client,
        mail_provider,
        google_oauth.clone(),
        github_oauth,
        webauthn_service,
        event_bus,
        pg_pool,
        redis_pool,
    );

    let app = build_router(state)?;

    Ok(TestContext {
        app,
        mail_rx,
        token_signer,
        user_repo,
        session_repo,
        google_oauth,
    })
}

// Request helpers
async fn send_request(
    app: &Router,
    method: Method,
    uri: &str,
    headers: Option<HeaderMap>,
    body: Option<Value>,
) -> TestResult<Response> {
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(hdrs) = headers {
        for (name, val) in &hdrs {
            builder = builder.header(name, val);
        }
    }

    let body_bytes = match body {
        Some(v) => {
            if builder
                .headers_ref()
                .and_then(|h| h.get(CONTENT_TYPE))
                .is_none()
            {
                builder = builder.header(CONTENT_TYPE, "application/json");
            }
            serde_json::to_vec(&v)?
        }
        None => Vec::new(),
    };

    let req = builder.body(Body::from(body_bytes))?;
    let resp = match app.clone().oneshot(req).await {
        Ok(r) => r,
        Err(inf) => match inf {},
    };
    Ok(resp)
}

async fn json_body<T: DeserializeOwned>(response: Response) -> TestResult<T> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Helper to register a user, intercept email token, and verify account.
async fn register_and_verify(
    ctx: &mut TestContext,
    email: &str,
    password: &str,
    username: &str,
) -> TestResult<UserId> {
    let reg_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "email": email,
            "password": password,
            "username": username
        })),
    )
    .await?;
    assert_eq!(reg_res.status(), StatusCode::CREATED);
    let reg_val: Value = json_body(reg_res).await?;
    let user_id: UserId = reg_val["user_id"]
        .as_str()
        .ok_or("missing user_id")?
        .parse()?;

    // Intercept verification token
    let (_to, _subject, text) = ctx.mail_rx.recv().await.ok_or("did not receive email")?;
    let token = text
        .split("token=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .ok_or("could not parse email verification token")?;

    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/verify-email",
        None,
        Some(json!({ "token": token })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);

    Ok(user_id)
}

/// Helper to login user and extract (access_token, refresh_token).
async fn login_mobile(
    ctx: &TestContext,
    email: &str,
    password: &str,
) -> TestResult<(String, String)> {
    let mut headers = HeaderMap::new();
    headers.insert("x-client-type", "mobile".parse()?);

    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        Some(headers),
        Some(json!({
            "email": email,
            "password": password
        })),
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);
    let val: Value = json_body(res).await?;
    let access = val["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_owned();
    let refresh = val["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?
        .to_owned();
    Ok((access, refresh))
}

// ===========================================================================
// TIER 1: Feature Coverage Tests
// ===========================================================================

#[tokio::test]
async fn tier1_auth_registration_and_email_verification_flow() -> TestResult {
    let mut ctx = setup_test_context()?;

    // 1. Registration produces 201 Created and unverified status
    let reg_payload = json!({
        "email": "t1_flow@example.com",
        "password": "ValidPassword123!",
        "username": "t1_flow"
    });
    let reg_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(reg_payload),
    )
    .await?;
    assert_eq!(reg_res.status(), StatusCode::CREATED);
    let reg_body: Value = json_body(reg_res).await?;
    assert_eq!(reg_body["email"], "t1_flow@example.com");
    assert_eq!(reg_body["status"], "unverified");
    assert!(reg_body["user_id"].is_string());

    // 2. Login before email verification is rejected with 403 Forbidden
    let pre_login = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "t1_flow@example.com",
            "password": "ValidPassword123!"
        })),
    )
    .await?;
    assert_eq!(pre_login.status(), StatusCode::FORBIDDEN);
    let prob: ProblemDetails = json_body(pre_login).await?;
    assert_eq!(prob.code, "AUTH_FORBIDDEN");

    // 3. Intercept one-time email token
    let (_to, _sub, text) = ctx
        .mail_rx
        .recv()
        .await
        .ok_or("verification mail missing")?;
    let token = text
        .split("token=")
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .ok_or("token not found in email")?;

    // 4. Verify email
    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/verify-email",
        None,
        Some(json!({ "token": token })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // 5. Login after verification succeeds
    let mut login_headers = HeaderMap::new();
    login_headers.insert("x-client-type", "mobile".parse()?);
    let login_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        Some(login_headers),
        Some(json!({
            "email": "t1_flow@example.com",
            "password": "ValidPassword123!"
        })),
    )
    .await?;
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body: Value = json_body(login_res).await?;
    assert!(login_body["access_token"].is_string());
    assert!(login_body["refresh_token"].is_string());

    // 6. Public JWKS discovery returns signing keys
    let jwks_res =
        send_request(&ctx.app, Method::GET, "/.well-known/jwks.json", None, None).await?;
    assert_eq!(jwks_res.status(), StatusCode::OK);
    let jwks_body: Value = json_body(jwks_res).await?;
    let keys = jwks_body["keys"].as_array().ok_or("keys missing")?;
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");

    Ok(())
}

#[tokio::test]
async fn tier1_session_management_and_explicit_revocation() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t1_sess@example.com", "Password123!", "t1_sess").await?;
    let (access, refresh) = login_mobile(&ctx, "t1_sess@example.com", "Password123!").await?;

    // 1. List active sessions
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);

    let list_res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/sessions",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(list_res.status(), StatusCode::OK);
    let sessions: Vec<Value> = json_body(list_res).await?;
    assert_eq!(sessions.len(), 1);
    let session_id = sessions[0]["id"].as_str().ok_or("missing id")?;
    assert_eq!(sessions[0]["is_current"], true);

    // 2. Revoke session explicitly by ID
    let revoke_res = send_request(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/sessions/{session_id}"),
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(revoke_res.status(), StatusCode::NO_CONTENT);

    // 3. Attempt to refresh with the revoked session
    let refresh_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": refresh })),
    )
    .await?;
    assert_eq!(refresh_res.status(), StatusCode::UNAUTHORIZED);
    let prob: ProblemDetails = json_body(refresh_res).await?;
    assert_eq!(prob.code, "AUTH_TOKEN_INVALID");

    Ok(())
}

#[tokio::test]
async fn tier1_mfa_totp_setup_enable_and_challenge_login() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t1_mfa@example.com", "Password123!", "t1_mfa").await?;
    let (access, _refresh) = login_mobile(&ctx, "t1_mfa@example.com", "Password123!").await?;

    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);

    // 1. Setup MFA
    let setup_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/setup",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(setup_res.status(), StatusCode::OK);
    let setup_val: Value = json_body(setup_res).await?;
    let secret = setup_val["secret"].as_str().ok_or("missing secret")?;
    assert!(!secret.is_empty());
    assert!(setup_val["qr_code_svg"].as_str().is_some());

    // 2. Generate TOTP code and Enable MFA
    let raw_secret = decode_base32(secret).ok_or("failed to decode base32 secret")?;
    #[allow(deprecated)]
    let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, raw_secret, None, String::new())
        .map_err(|e| format!("failed to construct TOTP: {e}"))?;
    let code = totp.generate_current().to_string();

    let enable_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/enable",
        Some(auth_headers.clone()),
        Some(json!({ "code": code })),
    )
    .await?;
    assert_eq!(enable_res.status(), StatusCode::OK);
    let enable_val: Value = json_body(enable_res).await?;
    let backup_codes = enable_val["backup_codes"]
        .as_array()
        .ok_or("missing backup codes")?;
    assert_eq!(backup_codes.len(), 10);

    // 3. Primary login now triggers MFA challenge
    let login_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "t1_mfa@example.com",
            "password": "Password123!"
        })),
    )
    .await?;
    assert_eq!(login_res.status(), StatusCode::OK);
    let challenge_val: Value = json_body(login_res).await?;
    assert!(challenge_val["mfa_ticket"].is_string());
    let mfa_ticket = challenge_val["mfa_ticket"]
        .as_str()
        .ok_or("missing ticket")?;
    assert!(challenge_val.get("access_token").is_none());

    // 4. Verify MFA with valid TOTP code
    let fresh_code = totp.generate_current().to_string();
    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/mfa/verify",
        None,
        Some(json!({
            "mfa_ticket": mfa_ticket,
            "code": fresh_code
        })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);
    let mfa_auth: Value = json_body(verify_res).await?;
    assert!(mfa_auth["access_token"].is_string());

    Ok(())
}

#[tokio::test]
async fn tier1_passkey_registration_and_discoverable_login() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t1_pk@example.com", "Password123!", "t1_pk").await?;
    let (access, _refresh) = login_mobile(&ctx, "t1_pk@example.com", "Password123!").await?;

    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);

    // 1. Start passkey registration
    let start_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/start",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(start_res.status(), StatusCode::OK);
    let start_val: Value = json_body(start_res).await?;
    let challenge_id = start_val["challenge_id"]
        .as_str()
        .ok_or("missing challenge_id")?;

    // 2. Finish passkey registration
    let reg_credential = json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZHVtbXkiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ"
        },
        "type": "public-key"
    });
    let finish_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/finish",
        Some(auth_headers.clone()),
        Some(json!({
            "challenge_id": challenge_id,
            "name": "Test Key",
            "credential": reg_credential
        })),
    )
    .await?;
    assert_eq!(finish_res.status(), StatusCode::CREATED);

    // 3. List passkeys
    let list_res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me/passkeys",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(list_res.status(), StatusCode::OK);
    let passkeys: Vec<Value> = json_body(list_res).await?;
    assert_eq!(passkeys.len(), 1);

    // 4. Start discoverable passkey login
    let login_start_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;
    assert_eq!(login_start_res.status(), StatusCode::OK);
    let login_start_val: Value = json_body(login_start_res).await?;
    let login_challenge_id = login_start_val["challenge_id"]
        .as_str()
        .ok_or("missing challenge_id")?;

    // 5. Finish discoverable passkey login
    let login_credential = json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAeQ",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZHVtbXkiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ",
            "signature": "MEQCIF6Nq_tV9x4p15h88H-Yl9A",
            "userHandle": null
        },
        "type": "public-key"
    });
    let mut mobile_headers = HeaderMap::new();
    mobile_headers.insert("x-client-type", "mobile".parse()?);
    let login_finish_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        Some(mobile_headers),
        Some(json!({
            "challenge_id": login_challenge_id,
            "credential": login_credential
        })),
    )
    .await?;
    assert_eq!(login_finish_res.status(), StatusCode::OK);
    let tokens: Value = json_body(login_finish_res).await?;
    assert!(tokens["access_token"].is_string());

    Ok(())
}

#[tokio::test]
async fn tier1_websocket_ticket_issuance_and_single_use() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t1_ws@example.com", "Password123!", "t1_ws").await?;
    let (access, _refresh) = login_mobile(&ctx, "t1_ws@example.com", "Password123!").await?;

    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);

    // 1. Issue WS Ticket
    let issue_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/ws-ticket",
        Some(auth_headers),
        None,
    )
    .await?;
    assert_eq!(issue_res.status(), StatusCode::OK);
    let issue_val: Value = json_body(issue_res).await?;
    let ticket = issue_val["ticket"].as_str().ok_or("missing ticket")?;
    assert!(issue_val["expires_in"].is_number());

    // 2. Verify ticket
    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/ws-ticket/verify",
        None,
        Some(json!({ "ticket": ticket })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);
    let verify_val: Value = json_body(verify_res).await?;
    assert!(verify_val["sub"].is_string() || verify_val["user_id"].is_string());

    // 3. Replay of consumed ticket is strictly rejected
    let replay_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/ws-ticket/verify",
        None,
        Some(json!({ "ticket": ticket })),
    )
    .await?;
    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);
    let prob: ProblemDetails = json_body(replay_res).await?;
    assert_eq!(prob.code, "AUTH_TOKEN_INVALID");

    Ok(())
}

#[tokio::test]
async fn tier1_rate_limiting_headers_and_status() -> TestResult {
    let ctx = setup_test_context()?;

    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "email": "invalid-email-test",
            "password": "short"
        })),
    )
    .await?;

    // Verify rate limit headers exist on response
    let headers = res.headers();
    assert!(headers.contains_key("ratelimit-limit"));
    assert!(headers.contains_key("ratelimit-remaining"));
    assert!(headers.contains_key("ratelimit-reset"));
    assert!(headers.contains_key("x-request-id"));

    Ok(())
}

// ===========================================================================
// TIER 2: Boundary & Corner Cases Tests
// ===========================================================================

#[tokio::test]
async fn tier2_registration_input_boundary_validation_rfc9457() -> TestResult {
    // Boundary cases: invalid email, password too short/long, username invalid
    let cases = vec![
        (
            json!({ "email": "", "password": "Password123!", "username": "user1" }),
            "email",
        ),
        (
            json!({ "email": "missing-at-sign.com", "password": "Password123!", "username": "user2" }),
            "email",
        ),
        (
            json!({ "email": "valid@example.com", "password": "short", "username": "user3" }),
            "password",
        ),
        (
            json!({ "email": "valid@example.com", "password": "a".repeat(129), "username": "user4" }),
            "password",
        ),
        (
            json!({ "email": "valid@example.com", "password": "Password123!", "username": "bad with spaces" }),
            "username",
        ),
        (
            json!({ "email": "valid@example.com", "password": "Password123!", "username": "u".repeat(31) }),
            "username",
        ),
    ];

    for (payload, expected_field) in cases {
        let ctx = setup_test_context()?;
        let res = send_request(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(payload),
        )
        .await?;

        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );

        let prob: ProblemDetails = json_body(res).await?;
        assert_eq!(prob.status, 422);
        assert_eq!(prob.code, "VALIDATION_FAILED");
        assert!(
            prob.errors.iter().any(|e| e.field == expected_field),
            "expected field error for '{expected_field}', got: {:?}",
            prob.errors
        );
    }

    Ok(())
}

#[tokio::test]
async fn tier2_token_boundaries_expired_tampered_and_malformed() -> TestResult {
    let mut ctx = setup_test_context()?;
    let user_id =
        register_and_verify(&mut ctx, "t2_tok@example.com", "Password123!", "t2_tok").await?;
    let (valid_access, _refresh) = login_mobile(&ctx, "t2_tok@example.com", "Password123!").await?;

    // 1. Missing Authorization header
    let res_missing = send_request(&ctx.app, Method::GET, "/api/v1/users/me", None, None).await?;
    assert_eq!(res_missing.status(), StatusCode::UNAUTHORIZED);
    let p1: ProblemDetails = json_body(res_missing).await?;
    assert_eq!(p1.code, "AUTH_UNAUTHENTICATED");

    // 2. Malformed token string
    let mut bad_auth = HeaderMap::new();
    bad_auth.insert(AUTHORIZATION, "Bearer not.a.valid.jwt".parse()?);
    let res_malformed = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me",
        Some(bad_auth),
        None,
    )
    .await?;
    assert_eq!(res_malformed.status(), StatusCode::UNAUTHORIZED);
    let p2: ProblemDetails = json_body(res_malformed).await?;
    assert_eq!(p2.code, "AUTH_TOKEN_INVALID");

    // 3. Tampered token signature
    let mut tampered = valid_access.clone();
    let last_char = tampered.pop().unwrap_or('A');
    let replacement = if last_char == 'A' { 'B' } else { 'A' };
    tampered.push(replacement);

    let mut tampered_auth = HeaderMap::new();
    tampered_auth.insert(AUTHORIZATION, format!("Bearer {tampered}").parse()?);
    let res_tampered = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me",
        Some(tampered_auth),
        None,
    )
    .await?;
    assert_eq!(res_tampered.status(), StatusCode::UNAUTHORIZED);
    let p3: ProblemDetails = json_body(res_tampered).await?;
    assert_eq!(p3.code, "AUTH_TOKEN_INVALID");

    // 4. Expired token
    let now = Utc::now();
    let expired_claims = AccessTokenClaims {
        sub: user_id,
        sid: SessionId::new(),
        iss: std::borrow::Cow::Borrowed("https://auth.korgan.local"),
        aud: std::borrow::Cow::Borrowed("korgan"),
        exp: (now - chrono::Duration::hours(2)).timestamp(),
        iat: (now - chrono::Duration::hours(3)).timestamp(),
        jti: Uuid::now_v7().to_string(),
        auth_time: (now - chrono::Duration::hours(3)).timestamp(),
        amr: smallvec::smallvec![std::borrow::Cow::Borrowed("pwd")],
    };
    let expired_jwt = ctx.token_signer.sign_access_token(&expired_claims)?;

    let mut expired_auth = HeaderMap::new();
    expired_auth.insert(AUTHORIZATION, format!("Bearer {expired_jwt}").parse()?);
    let res_expired = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me",
        Some(expired_auth),
        None,
    )
    .await?;
    assert_eq!(res_expired.status(), StatusCode::UNAUTHORIZED);
    let p4: ProblemDetails = json_body(res_expired).await?;
    assert_eq!(p4.code, "AUTH_TOKEN_EXPIRED");

    // 5. Refresh with non-existent random token
    let res_bad_refresh = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": "random_unregistered_refresh_token" })),
    )
    .await?;
    assert_eq!(res_bad_refresh.status(), StatusCode::UNAUTHORIZED);
    let p5: ProblemDetails = json_body(res_bad_refresh).await?;
    assert_eq!(p5.code, "AUTH_TOKEN_INVALID");

    Ok(())
}

#[tokio::test]
async fn tier2_refresh_token_reuse_replay_detection_revokes_entire_family() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id = register_and_verify(
        &mut ctx,
        "t2_replay@example.com",
        "Password123!",
        "t2_replay",
    )
    .await?;

    // 1. Initial login -> R1
    let (_acc1, r1) = login_mobile(&ctx, "t2_replay@example.com", "Password123!").await?;

    // 2. Rotate R1 -> issues R2; R1 is replaced
    let res_rot1 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": r1 })),
    )
    .await?;
    assert_eq!(res_rot1.status(), StatusCode::OK);
    let val_rot1: Value = json_body(res_rot1).await?;
    let r2 = val_rot1["refresh_token"]
        .as_str()
        .ok_or("missing r2")?
        .to_owned();

    // 3. Rotate R2 -> issues R3; R2 is replaced
    let res_rot2 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": r2 })),
    )
    .await?;
    assert_eq!(res_rot2.status(), StatusCode::OK);
    let val_rot2: Value = json_body(res_rot2).await?;
    let r3 = val_rot2["refresh_token"]
        .as_str()
        .ok_or("missing r3")?
        .to_owned();

    // Age r1's last_active_at beyond the rotation grace period (10s) to trigger actual replay detection
    if let Ok(mut sessions) = ctx.session_repo.sessions.lock() {
        for session in sessions.values_mut() {
            if session.is_replaced {
                session.last_active_at = Utc::now() - chrono::Duration::seconds(30);
            }
        }
    }

    // 4. Adversary replays stale R1!
    let res_replay = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": r1 })),
    )
    .await?;
    assert_eq!(res_replay.status(), StatusCode::UNAUTHORIZED);
    let replay_prob: ProblemDetails = json_body(res_replay).await?;
    assert_eq!(replay_prob.code, "AUTH_TOKEN_REUSE_DETECTED");

    // 5. Invariant: Entire family is revoked. R3 must now also be rejected!
    let res_r3 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": r3 })),
    )
    .await?;
    assert_eq!(res_r3.status(), StatusCode::UNAUTHORIZED);
    let r3_prob: ProblemDetails = json_body(res_r3).await?;
    assert_eq!(r3_prob.code, "AUTH_TOKEN_INVALID");

    Ok(())
}

#[tokio::test]
async fn tier2_account_status_gating_boundaries() -> TestResult {
    let mut ctx = setup_test_context()?;

    // Register admin user
    let admin_id = register_and_verify(
        &mut ctx,
        "admin@example.com",
        "AdminPassword123!",
        "admin_user",
    )
    .await?;
    // Elevate admin role
    {
        let mut users = ctx.user_repo.users.lock().map_err(|e| e.to_string())?;
        if let Some(admin) = users.get_mut(&admin_id) {
            admin.role = UserRole::Admin;
        }
    }
    let (admin_access, _) = login_mobile(&ctx, "admin@example.com", "AdminPassword123!").await?;

    // Register normal target user
    let target_id = register_and_verify(
        &mut ctx,
        "target@example.com",
        "TargetPassword123!",
        "target_user",
    )
    .await?;
    let (_target_acc, target_ref) =
        login_mobile(&ctx, "target@example.com", "TargetPassword123!").await?;

    // 1. Admin bans target user -> status becomes Suspended
    let mut admin_auth = HeaderMap::new();
    admin_auth.insert(AUTHORIZATION, format!("Bearer {admin_access}").parse()?);
    let ban_res = send_request(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/admin/users/{target_id}/ban"),
        Some(admin_auth.clone()),
        Some(json!({ "reason": "Violating terms of service" })),
    )
    .await?;
    assert_eq!(ban_res.status(), StatusCode::OK);

    // 2. Suspended target attempts login -> 403 Forbidden
    let login_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "target@example.com",
            "password": "TargetPassword123!"
        })),
    )
    .await?;
    assert_eq!(login_res.status(), StatusCode::FORBIDDEN);
    let prob: ProblemDetails = json_body(login_res).await?;
    assert_eq!(prob.code, "AUTH_FORBIDDEN");

    // 3. Suspended target attempts refresh -> 403 Forbidden
    let ref_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": target_ref })),
    )
    .await?;
    assert!(
        ref_res.status() == StatusCode::FORBIDDEN || ref_res.status() == StatusCode::UNAUTHORIZED
    );

    // 4. Admin unbans target user -> status becomes Active
    let unban_res = send_request(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/admin/users/{target_id}/unban"),
        Some(admin_auth),
        None,
    )
    .await?;
    assert_eq!(unban_res.status(), StatusCode::OK);

    // 5. Target can now login again
    let (new_acc, _) = login_mobile(&ctx, "target@example.com", "TargetPassword123!").await?;
    assert!(!new_acc.is_empty());

    Ok(())
}

#[tokio::test]
async fn tier2_brute_force_lockout_boundary() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id = register_and_verify(
        &mut ctx,
        "t2_lock@example.com",
        "CorrectPassword123!",
        "t2_lock",
    )
    .await?;

    // Execute 5 consecutive failed logins
    for _ in 0..5 {
        let res = send_request(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": "t2_lock@example.com",
                "password": "WrongPassword999!"
            })),
        )
        .await?;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // 6th attempt with CORRECT password must be rejected with 403 Forbidden (AccountLocked)
    let locked_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "t2_lock@example.com",
            "password": "CorrectPassword123!"
        })),
    )
    .await?;
    assert_eq!(locked_res.status(), StatusCode::FORBIDDEN);
    let prob: ProblemDetails = json_body(locked_res).await?;
    assert_eq!(prob.code, "AUTH_FORBIDDEN");

    Ok(())
}

#[tokio::test]
async fn tier2_payload_limit_and_unsupported_media_type() -> TestResult {
    let ctx = setup_test_context()?;

    // 1. Oversized body exceeding request limit (configured default: 1MB = 1048576)
    let huge_payload = "A".repeat(1024 * 1024 + 100);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse()?);

    let huge_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/register",
        Some(headers),
        Some(json!({ "huge": huge_payload })),
    )
    .await?;
    assert_eq!(huge_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 2. Malformed JSON syntax returns 400 Bad Request
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/register")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{ this is invalid json syntax }"))?;
    let resp = match ctx.app.clone().oneshot(req).await {
        Ok(r) => r,
        Err(inf) => match inf {},
    };
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

// ===========================================================================
// TIER 3: Cross-Feature Combinations Tests
// ===========================================================================

#[tokio::test]
async fn tier3_step_up_authentication_enforcement_with_mfa_and_passkey() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t3_step@example.com", "Password123!", "t3_step").await?;

    // 1. Login with password only -> amr = ["pwd"]
    let (pwd_access, _) = login_mobile(&ctx, "t3_step@example.com", "Password123!").await?;
    let mut pwd_headers = HeaderMap::new();
    pwd_headers.insert(AUTHORIZATION, format!("Bearer {pwd_access}").parse()?);

    // 2. User has no MFA yet -> StepUpUser accepts fresh password token
    let sessions_pre = send_request(
        &ctx.app,
        Method::DELETE,
        "/api/v1/sessions",
        Some(pwd_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(sessions_pre.status(), StatusCode::NO_CONTENT);

    // 3. User sets up and enables MFA
    let setup_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/setup",
        Some(pwd_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(setup_res.status(), StatusCode::OK);
    let setup_val: Value = json_body(setup_res).await?;
    let secret = setup_val["secret"].as_str().ok_or("missing secret")?;

    let raw_secret = decode_base32(secret).ok_or("failed to decode base32 secret")?;
    #[allow(deprecated)]
    let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, raw_secret, None, String::new())
        .map_err(|e| format!("failed to construct TOTP: {e}"))?;
    let code = totp.generate_current().to_string();
    let enable_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/enable",
        Some(pwd_headers.clone()),
        Some(json!({ "code": code })),
    )
    .await?;
    assert_eq!(enable_res.status(), StatusCode::OK);

    // 4. Now that MFA is enabled: attempts to perform StepUp actions with password-only token are REJECTED!
    let blocked_res = send_request(
        &ctx.app,
        Method::DELETE,
        "/api/v1/sessions",
        Some(pwd_headers),
        None,
    )
    .await?;
    assert_eq!(blocked_res.status(), StatusCode::FORBIDDEN);
    let prob: ProblemDetails = json_body(blocked_res).await?;
    assert!(prob.detail.contains("step-up authentication required"));

    // 5. Authenticate via MFA challenge -> produces token with amr = ["pwd", "mfa"]
    let login_mfa = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "t3_step@example.com",
            "password": "Password123!"
        })),
    )
    .await?;
    let chal_val: Value = json_body(login_mfa).await?;
    let ticket = chal_val["mfa_ticket"].as_str().ok_or("missing ticket")?;

    let code2 = totp.generate_current().to_string();
    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/mfa/verify",
        None,
        Some(json!({
            "mfa_ticket": ticket,
            "code": code2
        })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);
    let mfa_tokens: Value = json_body(verify_res).await?;
    let mfa_access = mfa_tokens["access_token"].as_str().ok_or("missing token")?;

    // 6. With MFA-stepped-up token: sensitive operation SUCCEEDS!
    let mut mfa_headers = HeaderMap::new();
    mfa_headers.insert(AUTHORIZATION, format!("Bearer {mfa_access}").parse()?);
    let stepup_ok = send_request(
        &ctx.app,
        Method::DELETE,
        "/api/v1/sessions",
        Some(mfa_headers),
        None,
    )
    .await?;
    assert_eq!(stepup_ok.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn tier3_password_change_cross_session_invalidation() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id = register_and_verify(
        &mut ctx,
        "t3_pwchange@example.com",
        "OldPassword123!",
        "t3_pwchange",
    )
    .await?;

    // Device A login
    let (access_a, _ref_a) =
        login_mobile(&ctx, "t3_pwchange@example.com", "OldPassword123!").await?;
    // Device B login
    let (access_b, ref_b) =
        login_mobile(&ctx, "t3_pwchange@example.com", "OldPassword123!").await?;

    // Device A changes password
    let mut headers_a = HeaderMap::new();
    headers_a.insert(AUTHORIZATION, format!("Bearer {access_a}").parse()?);
    let change_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/password/change",
        Some(headers_a),
        Some(json!({
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!"
        })),
    )
    .await?;
    assert_eq!(change_res.status(), StatusCode::OK);

    // Invariant: Device B session is immediately revoked!
    // 1. Device B cannot refresh its session
    let refresh_b_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": ref_b })),
    )
    .await?;
    assert_eq!(refresh_b_res.status(), StatusCode::UNAUTHORIZED);

    // 2. Device B cannot access protected endpoints
    let mut headers_b = HeaderMap::new();
    headers_b.insert(AUTHORIZATION, format!("Bearer {access_b}").parse()?);
    let me_b_res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me",
        Some(headers_b),
        None,
    )
    .await?;
    assert_eq!(me_b_res.status(), StatusCode::UNAUTHORIZED);

    // 3. User can login with new password
    let (new_access, _) = login_mobile(&ctx, "t3_pwchange@example.com", "NewPassword123!").await?;
    assert!(!new_access.is_empty());

    Ok(())
}

#[tokio::test]
async fn tier3_oauth_account_takeover_prevention() -> TestResult {
    let mut ctx = setup_test_context()?;

    // 1. Create a user via normal registration and verify
    let _user_id = register_and_verify(
        &mut ctx,
        "victim_oauth@example.com",
        "VictimPassword123!",
        "victim_oauth",
    )
    .await?;

    // 2. Generate OAuth URL and intercept state cookie
    let url_res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/auth/oauth/google/url",
        None,
        None,
    )
    .await?;
    assert_eq!(url_res.status(), StatusCode::OK);
    let url_val: Value = json_body(url_res).await?;
    let state = url_val["state"].as_str().ok_or("missing state")?;

    // 3. Attacker tries OAuth callback with unverified cookie or wrong state -> 403 Forbidden
    let mut bad_cookie_headers = HeaderMap::new();
    bad_cookie_headers.insert(COOKIE, "oauth_state=tampered_state".parse()?);
    let tampered_callback = send_request(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/auth/oauth/google/callback?state={state}&code=oauth_code_1"),
        Some(bad_cookie_headers),
        None,
    )
    .await?;
    assert_eq!(tampered_callback.status(), StatusCode::FORBIDDEN);

    // Note: State token was consumed during the attempted attack. Generate fresh state for valid link.
    let url_res2 = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/auth/oauth/google/url",
        None,
        None,
    )
    .await?;
    assert_eq!(url_res2.status(), StatusCode::OK);
    let state_cookie2 = url_res2
        .headers()
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing state cookie")?
        .to_owned();
    let url_val2: Value = json_body(url_res2).await?;
    let state2 = url_val2["state"].as_str().ok_or("missing state 2")?;

    // 4. Register mock profile matching victim's email
    ctx.google_oauth.register_profile(
        "oauth_code_valid",
        OAuthProfile {
            provider: OAuthProvider::Google,
            provider_user_id: "google_victim_id_1".to_string(),
            email: EmailAddress::parse("victim_oauth@example.com")?,
            name: Some("Victim Google Profile".to_string()),
        },
    );

    // 5. Callback with valid state cookie links the account
    let mut valid_cookie_headers = HeaderMap::new();
    let raw_cookie = state_cookie2.split(';').next().unwrap_or("");
    valid_cookie_headers.insert(COOKIE, raw_cookie.parse()?);

    let valid_callback = send_request(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/auth/oauth/google/callback?state={state2}&code=oauth_code_valid"),
        Some(valid_cookie_headers),
        None,
    )
    .await?;
    assert_eq!(valid_callback.status(), StatusCode::OK);

    // Invariant: No duplicate user is created; the existing user is linked
    let count = ctx.user_repo.count_all().await?;
    assert_eq!(count, 1);

    Ok(())
}

#[tokio::test]
async fn tier3_rate_limiter_under_concurrent_burst() -> TestResult {
    let ctx = setup_test_context()?;

    // Send a burst of 25 concurrent requests to /api/v1/auth/register
    // Endpoint limit for Register is 5 per window
    let mut handles = Vec::new();
    for i in 0..25 {
        let app = ctx.app.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/register")
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "192.0.2.1")
                .body(Body::from(
                    json!({
                        "email": format!("burst_{i}@example.com"),
                        "password": "Password123!",
                        "username": format!("burst_{i}")
                    })
                    .to_string(),
                ))
                .map_err(|e| e.to_string())?;

            let res = match app.oneshot(req).await {
                Ok(r) => r,
                Err(inf) => match inf {},
            };
            Ok::<_, String>(res.status())
        }));
    }

    let mut success_count = 0;
    let mut rate_limited_count = 0;

    for handle in handles {
        let status = handle.await.map_err(|e| e.to_string())??;
        if status == StatusCode::CREATED {
            success_count += 1;
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            rate_limited_count += 1;
        }
    }

    // First N requests succeed, remaining requests are cleanly rate-limited (429)
    assert!(success_count > 0, "expected some successes");
    assert!(
        rate_limited_count > 0,
        "expected excess requests to be rate-limited"
    );
    assert_eq!(success_count + rate_limited_count, 25);

    Ok(())
}

#[tokio::test]
async fn tier3_concurrent_backup_code_consumption_race() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t3_race@example.com", "Password123!", "t3_race").await?;
    let (access, _) = login_mobile(&ctx, "t3_race@example.com", "Password123!").await?;

    // Setup & enable MFA
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);
    let setup_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/setup",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    let setup_val: Value = json_body(setup_res).await?;
    let secret = setup_val["secret"].as_str().ok_or("missing secret")?;

    let raw_secret = decode_base32(secret).ok_or("failed to decode base32 secret")?;
    #[allow(deprecated)]
    let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, raw_secret, None, String::new())
        .map_err(|e| format!("failed to construct TOTP: {e}"))?;
    let code = totp.generate_current().to_string();
    let enable_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/enable",
        Some(auth_headers),
        Some(json!({ "code": code })),
    )
    .await?;
    let enable_val: Value = json_body(enable_res).await?;
    let backup_codes = enable_val["backup_codes"]
        .as_array()
        .ok_or("missing backup codes")?;
    let single_backup_code = backup_codes[0].as_str().ok_or("missing code")?.to_owned();

    // Pre-issue all 8 MFA tickets before launching concurrent redemption tasks
    let mut tickets = Vec::new();
    for i in 0..8 {
        let mut ip_headers = HeaderMap::new();
        ip_headers.insert("x-forwarded-for", format!("192.168.1.{}", i + 1).parse()?);
        let login_res = send_request(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/login",
            Some(ip_headers),
            Some(json!({
                "email": "t3_race@example.com",
                "password": "Password123!"
            })),
        )
        .await?;
        let chal: Value = json_body(login_res).await?;
        let ticket = chal["mfa_ticket"]
            .as_str()
            .ok_or("missing ticket")?
            .to_owned();
        tickets.push(ticket);
    }

    // Spawn 8 concurrent requests trying to redeem the SAME backup code
    let mut handles = Vec::new();
    for ticket in tickets {
        let app = ctx.app.clone();
        let code_clone = single_backup_code.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/mfa/verify")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "mfa_ticket": ticket,
                        "code": code_clone
                    })
                    .to_string(),
                ))
                .map_err(|e| e.to_string())?;

            let res = match app.oneshot(req).await {
                Ok(r) => r,
                Err(inf) => match inf {},
            };
            Ok::<_, String>(res.status())
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for handle in handles {
        let status = handle.await.map_err(|e| e.to_string())??;
        if status == StatusCode::OK {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    // Invariant: Atomic CAS ensures EXACTLY ONE request consumes the backup code
    assert_eq!(
        successes, 1,
        "exactly 1 request should succeed in consuming the backup code"
    );
    assert_eq!(failures, 7, "7 parallel requests should fail");

    Ok(())
}

#[tokio::test]
async fn tier3_concurrent_refresh_token_cas_race() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id =
        register_and_verify(&mut ctx, "t3_cas@example.com", "Password123!", "t3_cas").await?;
    let (_acc, initial_refresh) = login_mobile(&ctx, "t3_cas@example.com", "Password123!").await?;

    // Spawn 6 concurrent refresh calls with the same refresh token
    let mut handles = Vec::new();
    for _ in 0..6 {
        let app = ctx.app.clone();
        let r_clone = initial_refresh.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/refresh")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "refresh_token": r_clone }).to_string()))
                .map_err(|e| e.to_string())?;

            let res = match app.oneshot(req).await {
                Ok(r) => r,
                Err(inf) => match inf {},
            };
            Ok::<_, String>(res.status())
        }));
    }

    let mut ok_count = 0;
    let mut client_error_count = 0;
    for handle in handles {
        let status = handle.await.map_err(|e| e.to_string())??;
        if status == StatusCode::OK {
            ok_count += 1;
        } else if status == StatusCode::CONFLICT || status == StatusCode::UNAUTHORIZED {
            client_error_count += 1;
        }
    }

    // Zero 500 internal errors; safe atomic execution
    assert!(ok_count >= 1, "at least 1 refresh must succeed");
    assert_eq!(ok_count + client_error_count, 6);

    Ok(())
}

// ===========================================================================
// TIER 4: Real-World Application Scenarios
// ===========================================================================

#[tokio::test]
async fn tier4_full_user_lifecycle_multi_device_mfa_and_passkey() -> TestResult {
    let mut ctx = setup_test_context()?;

    // Step 1: User Registration
    let reg_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "email": "alice_lifecycle@example.com",
            "password": "AlicePassword123!",
            "username": "alice_life"
        })),
    )
    .await?;
    assert_eq!(reg_res.status(), StatusCode::CREATED);

    // Step 2: Email Verification
    let (_to, _sub, text) = ctx.mail_rx.recv().await.ok_or("no verification mail")?;
    let token = text
        .split("token=")
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .ok_or("no token")?;

    let verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/verify-email",
        None,
        Some(json!({ "token": token })),
    )
    .await?;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // Step 3: Login on Mobile Device (Device A)
    let mut mobile_headers = HeaderMap::new();
    mobile_headers.insert("x-client-type", "mobile".parse()?);
    mobile_headers.insert("x-device-name", "iPhone 15 Pro".parse()?);
    let login_mobile_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        Some(mobile_headers),
        Some(json!({
            "email": "alice_lifecycle@example.com",
            "password": "AlicePassword123!"
        })),
    )
    .await?;
    assert_eq!(login_mobile_res.status(), StatusCode::OK);
    let mobile_tokens: Value = json_body(login_mobile_res).await?;
    let mobile_access = mobile_tokens["access_token"]
        .as_str()
        .ok_or("missing token")?;
    let mobile_refresh = mobile_tokens["refresh_token"]
        .as_str()
        .ok_or("missing token")?;

    // Step 4: Update Profile (change username)
    let mut auth_mobile = HeaderMap::new();
    auth_mobile.insert(AUTHORIZATION, format!("Bearer {mobile_access}").parse()?);
    let update_res = send_request(
        &ctx.app,
        Method::PATCH,
        "/api/v1/users/me",
        Some(auth_mobile.clone()),
        Some(json!({ "username": "alice_updated" })),
    )
    .await?;
    assert_eq!(update_res.status(), StatusCode::OK);
    let updated_user: Value = json_body(update_res).await?;
    assert_eq!(updated_user["username"], "alice_updated");

    // Step 5: Register WebAuthn Passkey for Laptop (performed with fresh primary auth token)
    let pk_start = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/start",
        Some(auth_mobile.clone()),
        None,
    )
    .await?;
    assert_eq!(pk_start.status(), StatusCode::OK);
    let pk_start_val: Value = json_body(pk_start).await?;
    let challenge_id = pk_start_val["challenge_id"]
        .as_str()
        .ok_or("missing challenge_id")?;

    let reg_cred = json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZHVtbXkiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ"
        },
        "type": "public-key"
    });
    let pk_finish = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/finish",
        Some(auth_mobile.clone()),
        Some(json!({
            "challenge_id": challenge_id,
            "name": "MacBook Passkey",
            "credential": reg_cred
        })),
    )
    .await?;
    assert_eq!(pk_finish.status(), StatusCode::CREATED);

    // Step 6: Adding a second factor now needs step-up. The account owns a
    // passkey, so a password-only session (amr = ["pwd"]) is refused for both
    // setup and enable (KRG-SEC-15: no factor changes from a weak session).
    let setup_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/setup",
        Some(auth_mobile.clone()),
        None,
    )
    .await?;
    assert_eq!(setup_res.status(), StatusCode::FORBIDDEN);
    let enable_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/enable",
        Some(auth_mobile.clone()),
        Some(json!({ "code": "123456" })),
    )
    .await?;
    assert_eq!(enable_res.status(), StatusCode::FORBIDDEN);

    // Step 7: Login on Laptop using Passkey (Web mode with Set-Cookie)
    let login_start = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;
    assert_eq!(login_start.status(), StatusCode::OK);
    let login_start_val: Value = json_body(login_start).await?;
    let login_challenge_id = login_start_val["challenge_id"]
        .as_str()
        .ok_or("missing login challenge_id")?;

    let login_credential = json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAeQ",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZHVtbXkiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ",
            "signature": "MEQCIF6Nq_tV9x4p15h88H-Yl9A",
            "userHandle": null
        },
        "type": "public-key"
    });
    let mut web_headers = HeaderMap::new();
    web_headers.insert("x-client-type", "web".parse()?);
    let login_finish = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        Some(web_headers),
        Some(json!({
            "challenge_id": login_challenge_id,
            "credential": login_credential
        })),
    )
    .await?;
    assert_eq!(login_finish.status(), StatusCode::OK);
    // Verify Web mode sets cookies
    assert!(login_finish.headers().contains_key(SET_COOKIE));

    // Step 8: Rotate Mobile Refresh Token
    let rot_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": mobile_refresh })),
    )
    .await?;
    assert_eq!(rot_res.status(), StatusCode::OK);
    let rot_val: Value = json_body(rot_res).await?;
    let fresh_mobile_access = rot_val["access_token"]
        .as_str()
        .ok_or("missing fresh token")?;

    // Step 9: User logs out from Mobile
    let mut fresh_mobile_headers = HeaderMap::new();
    fresh_mobile_headers.insert(
        AUTHORIZATION,
        format!("Bearer {fresh_mobile_access}").parse()?,
    );
    let logout_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/logout",
        Some(fresh_mobile_headers.clone()),
        None,
    )
    .await?;
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);

    // Mobile token can no longer access /users/me
    let post_logout_res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me",
        Some(fresh_mobile_headers),
        None,
    )
    .await?;
    assert_eq!(post_logout_res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn tier4_password_reset_and_history_depth_enforcement_flow() -> TestResult {
    let mut ctx = setup_test_context()?;
    let _user_id = register_and_verify(
        &mut ctx,
        "reset_flow@example.com",
        "OriginalPass123!",
        "reset_flow",
    )
    .await?;
    let (_access, refresh) =
        login_mobile(&ctx, "reset_flow@example.com", "OriginalPass123!").await?;

    // 1. Forgot password request
    let forgot_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/password/forgot",
        None,
        Some(json!({ "email": "reset_flow@example.com" })),
    )
    .await?;
    assert_eq!(forgot_res.status(), StatusCode::OK);

    // 2. Intercept reset token from email
    let (_to, _sub, text) = ctx.mail_rx.recv().await.ok_or("no reset mail")?;
    let reset_token = text
        .split("token=")
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .ok_or("no reset token")?;

    // 3. Attempt reset with the SAME password -> 422 Unprocessable Entity
    let same_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/password/reset",
        None,
        Some(json!({
            "token": reset_token,
            "new_password": "OriginalPass123!"
        })),
    )
    .await?;
    assert_eq!(same_res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Re-issue reset token since single-use consumption consumed the previous one
    let forgot_res2 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/password/forgot",
        None,
        Some(json!({ "email": "reset_flow@example.com" })),
    )
    .await?;
    assert_eq!(forgot_res2.status(), StatusCode::OK);
    let (_to, _sub, text2) = ctx.mail_rx.recv().await.ok_or("no reset mail 2")?;
    let reset_token2 = text2
        .split("token=")
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .ok_or("no reset token 2")?;

    // 4. Reset to a brand new valid password -> 200 OK
    let reset_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/password/reset",
        None,
        Some(json!({
            "token": reset_token2,
            "new_password": "BrandNewPassword999!"
        })),
    )
    .await?;
    assert_eq!(reset_res.status(), StatusCode::OK);

    // 5. Invariant: All previous sessions are revoked upon reset
    let stale_refresh_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": refresh })),
    )
    .await?;
    assert_eq!(stale_refresh_res.status(), StatusCode::UNAUTHORIZED);

    // 6. Login with new password succeeds
    let (new_acc, _) = login_mobile(&ctx, "reset_flow@example.com", "BrandNewPassword999!").await?;
    assert!(!new_acc.is_empty());

    Ok(())
}

#[tokio::test]
async fn tier4_brute_force_lockout_and_mfa_ticket_hijacking_mitigation() -> TestResult {
    let mut ctx = setup_test_context()?;
    let user_id = register_and_verify(
        &mut ctx,
        "victim_bf@example.com",
        "VictimPass123!",
        "victim_bf",
    )
    .await?;
    let (access, _) = login_mobile(&ctx, "victim_bf@example.com", "VictimPass123!").await?;

    // Enable MFA
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(AUTHORIZATION, format!("Bearer {access}").parse()?);
    let setup_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/setup",
        Some(auth_headers.clone()),
        None,
    )
    .await?;
    let setup_val: Value = json_body(setup_res).await?;
    let secret = setup_val["secret"].as_str().ok_or("missing secret")?;
    let raw_secret = decode_base32(secret).ok_or("failed to decode base32 secret")?;
    #[allow(deprecated)]
    let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, raw_secret, None, String::new())
        .map_err(|e| format!("failed to construct TOTP: {e}"))?;
    let code = totp.generate_current().to_string();
    let enable_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/mfa/enable",
        Some(auth_headers),
        Some(json!({ "code": code })),
    )
    .await?;
    let enable_val: Value = json_body(enable_res).await?;
    let backup_codes = enable_val["backup_codes"]
        .as_array()
        .ok_or("missing codes")?;
    let backup_code = backup_codes[0].as_str().ok_or("missing code")?.to_owned();

    // Attacker brute-forces 5 wrong passwords
    for _ in 0..5 {
        let _ = send_request(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": "victim_bf@example.com",
                "password": "WrongPasswordAttempt!"
            })),
        )
        .await?;
    }

    // Account is locked out
    let locked_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "victim_bf@example.com",
            "password": "VictimPass123!"
        })),
    )
    .await?;
    assert_eq!(locked_res.status(), StatusCode::FORBIDDEN);

    // Administrative unlock / reset lockout
    ctx.user_repo
        .reset_failed_logins(&user_id, Utc::now())
        .await?;

    // Legitimate owner logs in -> receives MFA challenge
    let login_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "victim_bf@example.com",
            "password": "VictimPass123!"
        })),
    )
    .await?;
    assert_eq!(login_res.status(), StatusCode::OK);
    let chal: Value = json_body(login_res).await?;
    let mfa_ticket = chal["mfa_ticket"].as_str().ok_or("missing ticket")?;

    // Attacker attempts invalid / brute force TOTP verification
    let bad_mfa_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/mfa/verify",
        None,
        Some(json!({
            "mfa_ticket": mfa_ticket,
            "code": "000000"
        })),
    )
    .await?;
    assert_eq!(bad_mfa_res.status(), StatusCode::UNAUTHORIZED);

    // Legitimate user completes login using one of their emergency backup codes
    // Re-login to get a fresh MFA ticket
    let login_res2 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": "victim_bf@example.com",
            "password": "VictimPass123!"
        })),
    )
    .await?;
    let chal2: Value = json_body(login_res2).await?;
    let mfa_ticket2 = chal2["mfa_ticket"].as_str().ok_or("missing ticket")?;

    let backup_verify_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/mfa/verify",
        None,
        Some(json!({
            "mfa_ticket": mfa_ticket2,
            "code": backup_code
        })),
    )
    .await?;
    assert_eq!(backup_verify_res.status(), StatusCode::OK);
    let auth_tokens: Value = json_body(backup_verify_res).await?;
    assert!(auth_tokens["access_token"].is_string());

    Ok(())
}
