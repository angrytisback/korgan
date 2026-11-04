//! End-to-End Integration Tests for WebAuthn / Passkeys (FIDO2 Standard).
//!
//! Validates:
//! 1. Passkey registration ceremony (start -> challenge caching in Redis -> finish -> persistence)
//! 2. Single-use challenge validation (replay rejection)
//! 3. Discoverable passkey login (start -> challenge caching -> assertion finish -> session creation & dual-mode cookies)
//! 4. Passkey listing (`GET /api/v1/users/me/passkeys`)
//! 5. Passkey deletion with strict authorization (`DELETE /api/v1/users/me/passkeys/{id}`)
//! 6. Unauthenticated access enforcement across protected passkey endpoints
//! 7. Suspended/banned user passkey login rejection

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
use korgan::adapters::inbound::http::handlers::passkeys::{
    PasskeyItemResponse, PasskeyLoginStartResponse, PasskeyRegistrationFinishResponse,
    PasskeyRegistrationStartResponse,
};
use korgan::adapters::inbound::http::{AppState, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::workers::{EventBus, EventWorker};
use korgan::config::Settings;
use korgan::domain::entities::{
    AccountStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa, UserRole,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{AccessTokenClaims, TokenSigner, WebAuthnService};
use secrecy::ExposeSecret;
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// Canonical test credential ID base64url string
const TEST_CRED_ID_STR: &str =
    "uZcVDBVS68E_MtAgeQpElJxldF_6cY9sSvbWqx_qRh8wiu42lyRBRmh5yFeD_r9k130dMbFHBHI9RTFgdJQIzQ";

fn make_sample_webauthn_passkey() -> Result<WebauthnPasskey, PortError> {
    let ser_passkey = serde_json::json!({
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
            "counter": 2,
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
    let ser_auth_result = serde_json::json!({
        "cred_id": TEST_CRED_ID_STR,
        "needs_update": false,
        "user_verified": true,
        "backup_state": false,
        "backup_eligible": false,
        "counter": 3,
        "extensions": {}
    });
    serde_json::from_value(ser_auth_result).map_err(|e| PortError::serialization(e.to_string()))
}

// ---------------------------------------------------------------------------
// Mock WebAuthn Service
// ---------------------------------------------------------------------------

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
        let mut sample_pk = make_sample_webauthn_passkey()?;
        let matched = candidate_passkeys
            .iter()
            .find(|pk| pk.credential_id == sample_pk.cred_id().as_slice());

        if let Some(pk) = matched {
            let stored_counter = pk
                .passkey_json
                .get("cred")
                .and_then(|c| c.get("counter"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            let auth_res = make_sample_auth_result()?;
            if stored_counter > 0 && auth_res.counter() <= stored_counter {
                // Hardware key counter rollback / clone detected (FIDO2 Section 6.1 / WebAuthn standard)
                return Err(PortError::external_service(
                    "webauthn",
                    format!(
                        "CredentialPossibleCompromise: counter rollback detected (stored: {stored_counter}, received: {}); possible cloned hardware token",
                        auth_res.counter()
                    ),
                    None,
                ));
            }

            let _ = sample_pk.update_credential(&auth_res);
            Ok((auth_res, sample_pk))
        } else {
            Err(PortError::not_found("Passkey"))
        }
    }
}

// ---------------------------------------------------------------------------
// In-Memory Test Repositories
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct TestPasskeyUserRepo {
    users: Mutex<HashMap<UserId, User>>,
}

#[async_trait]
impl UserRepository for TestPasskeyUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
    }

    async fn find_by_email(&self, email: &EmailAddress) -> Result<Option<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.values().find(|u| &u.email == email).cloned())
    }

    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock
            .values()
            .find(|u| u.username.as_ref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> Result<(), PortError> {
        let mut lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(user.id, user.clone());
        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), PortError> {
        let mut lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(user.id, user.clone());
        Ok(())
    }

    async fn update_password(
        &self,
        _user_id: &UserId,
        _new_hash: &PasswordHash,
        _history_depth: u16,
    ) -> Result<(), PortError> {
        Ok(())
    }

    async fn get_password_history(
        &self,
        _user_id: &UserId,
        _limit: u32,
    ) -> Result<Vec<PasswordHash>, PortError> {
        Ok(Vec::new())
    }

    async fn find_mfa(&self, _user_id: &UserId) -> Result<Option<UserMfa>, PortError> {
        Ok(None)
    }

    async fn save_mfa(&self, _mfa: &UserMfa) -> Result<(), PortError> {
        Ok(())
    }

    async fn delete_mfa(&self, _user_id: &UserId) -> Result<(), PortError> {
        Ok(())
    }

    async fn consume_backup_code(
        &self,
        _user_id: &UserId,
        _code_hash: &str,
    ) -> Result<bool, PortError> {
        Ok(false)
    }

    async fn list_paginated(&self, limit: u32, offset: u64) -> Result<Vec<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list: Vec<User> = lock.values().cloned().collect();
        list.sort_by_key(|u| u.created_at);
        Ok(list
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.len() as u64)
    }

    async fn record_failed_login_atomic(
        &self,
        user_id: &UserId,
        max_attempts: u16,
        lockout_until: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<chrono::Utc>>), PortError> {
        let mut lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let user = lock
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
        let mut lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(user) = lock.get_mut(user_id) {
            user.failed_login_attempts = 0;
            user.locked_until = None;
            user.updated_at = now;
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct TestPasskeySessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
}

#[async_trait]
impl SessionRepository for TestPasskeySessionRepo {
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError> {
        let lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
    }

    async fn create(&self, session: &Session) -> Result<(), PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(session.id, session.clone());
        Ok(())
    }

    async fn update(&self, session: &Session) -> Result<(), PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(session.id, session.clone());
        Ok(())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, PortError> {
        let lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock
            .values()
            .find(|s| s.refresh_token_hash == token_hash)
            .cloned())
    }

    async fn revoke_by_id(&self, id: &SessionId, reason: &str) -> Result<(), PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(s) = lock.get_mut(id) {
            s.revoke(reason, Utc::now());
        }
        Ok(())
    }

    async fn replace_atomic(&self, _token_hash: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn rotate_atomic(
        &self,
        old_token_hash: &str,
        new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(session) = lock
            .values_mut()
            .find(|s| s.refresh_token_hash == old_token_hash)
            && !session.is_replaced
            && !session.is_revoked()
            && !session.is_expired(Utc::now())
        {
            session.is_replaced = true;
            session.last_active_at = Utc::now();
            let old = session.clone();
            lock.insert(new_session.id, new_session.clone());
            return Ok(Some(old));
        }
        Ok(None)
    }

    async fn revoke_by_id_and_user_id(
        &self,
        id: &SessionId,
        user_id: &UserId,
        reason: &str,
    ) -> Result<Option<SessionId>, PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(s) = lock.get_mut(id)
            && s.user_id == *user_id
            && !s.is_revoked()
        {
            s.revoke(reason, Utc::now());
            return Ok(Some(*id));
        }
        Ok(None)
    }

    async fn revoke_family(
        &self,
        _family_id: &TokenFamilyId,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }

    async fn revoke_all_user_sessions(
        &self,
        user_id: &UserId,
        except_session: Option<&SessionId>,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut revoked = Vec::new();
        for session in lock.values_mut() {
            if session.user_id == *user_id
                && !session.is_revoked()
                && (except_session != Some(&session.id))
            {
                session.revoke(reason, Utc::now());
                revoked.push(session.id);
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        let lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let list: Vec<Session> = lock
            .values()
            .filter(|s| s.user_id == *user_id && !s.is_revoked())
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(list)
    }
}

#[derive(Default, Debug)]
struct TestPasskeyRepoMem {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for TestPasskeyRepoMem {
    async fn save(&self, passkey: &Passkey) -> Result<(), PortError> {
        let mut lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(passkey.id, passkey.clone());
        Ok(())
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>, PortError> {
        let lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock
            .values()
            .find(|p| p.credential_id == credential_id)
            .cloned())
    }

    async fn find_by_id(&self, id: &PasskeyId) -> Result<Option<Passkey>, PortError> {
        let lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
    }

    async fn list_by_user_id(&self, user_id: &UserId) -> Result<Vec<Passkey>, PortError> {
        let lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list: Vec<_> = lock
            .values()
            .filter(|p| &p.user_id == user_id)
            .cloned()
            .collect();
        list.sort_by_key(|p| p.created_at);
        Ok(list)
    }

    async fn delete_by_id(&self, id: &PasskeyId) -> Result<(), PortError> {
        let mut lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.remove(id);
        Ok(())
    }

    async fn delete_by_id_and_user_id(
        &self,
        id: &PasskeyId,
        user_id: &UserId,
    ) -> Result<bool, PortError> {
        let mut lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(pk) = lock.get(id)
            && pk.user_id == *user_id
        {
            lock.remove(id);
            return Ok(true);
        }
        Ok(false)
    }

    async fn update_credential_state(
        &self,
        id: &PasskeyId,
        passkey_json: &serde_json::Value,
        last_used_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError> {
        let mut lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(pk) = lock.get_mut(id) {
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
            Ok(())
        } else {
            Err(PortError::not_found("Passkey"))
        }
    }
}

#[derive(Default, Debug)]
struct TestPasskeyTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for TestPasskeyTokenStore {
    async fn set_token(&self, key: &str, value: &str, _ttl: Duration) -> Result<(), PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        lock.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn get_token(&self, key: &str) -> Result<Option<String>, PortError> {
        let lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(lock.get(key).cloned())
    }

    async fn delete_token(&self, key: &str) -> Result<(), PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        lock.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(lock.remove(key))
    }

    async fn consume_token(&self, key: &str, expected_token_hash: &str) -> Result<bool, PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if let Some(val) = lock.get(key)
            && val == expected_token_hash
        {
            lock.remove(key);
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
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if lock.contains_key(key) {
            return Ok(false);
        }
        lock.insert(key.to_owned(), value.to_owned());
        Ok(true)
    }
}

#[derive(Default, Debug)]
struct TestPasskeyAuditRepo;

#[async_trait]
impl AuditLogRepository for TestPasskeyAuditRepo {
    async fn append(&self, _entry: &AuditLog) -> Result<(), PortError> {
        Ok(())
    }
    async fn list_by_user_id(
        &self,
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }
    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }
}

#[derive(Default, Debug)]
struct TestPasskeyOAuthRepo;

#[async_trait]
impl OAuthAccountRepository for TestPasskeyOAuthRepo {
    async fn find_by_provider_and_id(
        &self,
        _provider: OAuthProvider,
        _provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        Ok(None)
    }
    async fn create(&self, _account: &OAuthAccount) -> Result<(), PortError> {
        Ok(())
    }
    async fn list_by_user_id(&self, _user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        Ok(Vec::new())
    }
}

struct TestPasskeyRateLimiter;

#[async_trait]
impl RateLimiterPort for TestPasskeyRateLimiter {
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
// Test App Assembly & Helpers
// ---------------------------------------------------------------------------

struct PasskeyTestContext {
    app: Router,
    user_repo: Arc<TestPasskeyUserRepo>,
    session_repo: Arc<TestPasskeySessionRepo>,
    passkey_repo: Arc<TestPasskeyRepoMem>,
    token_store: Arc<TestPasskeyTokenStore>,
    token_signer: Arc<Ed25519JwtService>,
}

fn setup_passkey_app() -> TestResult<PasskeyTestContext> {
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

    let user_repo = Arc::new(TestPasskeyUserRepo::default());
    let session_repo = Arc::new(TestPasskeySessionRepo::default());
    let audit_repo = Arc::new(TestPasskeyAuditRepo);
    let oauth_account_repo = Arc::new(TestPasskeyOAuthRepo);
    let passkey_repo = Arc::new(TestPasskeyRepoMem::default());
    let token_store = Arc::new(TestPasskeyTokenStore::default());
    let rate_limiter = Arc::new(TestPasskeyRateLimiter);
    let google_oauth = Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth = Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
    let webauthn_service = Arc::new(MockWebAuthnService::new()?);

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
        oauth_account_repo,
        passkey_repo.clone(),
        token_store.clone(),
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
    Ok(PasskeyTestContext {
        app,
        user_repo,
        session_repo,
        passkey_repo,
        token_store,
        token_signer,
    })
}

async fn create_auth_token(
    ctx: &PasskeyTestContext,
    user_id: UserId,
    _role: UserRole,
) -> TestResult<String> {
    let now = Utc::now();
    let session = Session::new(
        user_id,
        "dummy_token_hash".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    let session_id = session.id;
    ctx.session_repo.create(&session).await?;

    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: (now + chrono::Duration::hours(1)).timestamp(),
        iat: now.timestamp(),
        jti: Uuid::now_v7().to_string(),
        auth_time: session.created_at.timestamp(),
        amr: vec!["passkey".to_string()],
    };
    let token = ctx.token_signer.sign_access_token(&claims)?;
    Ok(token)
}

async fn send_request(
    app: &Router,
    method: Method,
    uri: &str,
    auth_header: Option<&str>,
    body: Option<serde_json::Value>,
) -> TestResult<Response> {
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(auth) = auth_header {
        builder = builder.header(AUTHORIZATION, auth);
    }
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }

    let body_bytes = match body {
        Some(v) => serde_json::to_vec(&v)?,
        None => Vec::new(),
    };

    let req = builder.body(Body::from(body_bytes))?;
    let resp = app.clone().oneshot(req).await?;
    Ok(resp)
}

// Dummy RegisterPublicKeyCredential JSON matching schema
fn dummy_register_credential() -> serde_json::Value {
    serde_json::json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHyX6Jx7F2P3-_4BZldXSOO9wnvvv4NLR4XV1KIeyZjJ9IM4WFLVPWxaqQoEpY48CcRF5I82_tdbpXj2ciNEYskpQECAyYgASFYIE_9awy66uhXZ6hIzPAW2AzIrTMZ7kyC2jtZe0zuH_pOIlggFbNKhOSt8-prIx0snKRqcxULtc2u1rzUUf47g1PxTcU",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidF9XZTEzMU5wd2xseVBMMHgyNmJ6WmdrRjVmX1h2QTdPY2I0Yjk4emx4TSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9"
        },
        "type": "public-key"
    })
}

// Dummy PublicKeyCredential JSON matching schema
fn dummy_login_credential() -> serde_json::Value {
    serde_json::json!({
        "id": TEST_CRED_ID_STR,
        "rawId": TEST_CRED_ID_STR,
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAeQ",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYXNkZGFzZGFzZCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "signature": "MEQCIF6Nq_tV9x4p15h88H-Yl9A",
            "userHandle": null
        },
        "type": "public-key"
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_passkey_registration_flow_and_anti_replay() -> TestResult {
    let ctx = setup_passkey_app()?;
    let user = User::new(
        EmailAddress::parse("passkey.user@example.com")?,
        Some(Username::new("passkeyuser")?),
        None,
    );
    ctx.user_repo.create(&user).await?;

    let token = create_auth_token(&ctx, user.id, UserRole::User).await?;
    let auth_header = format!("Bearer {token}");

    // 1. Start registration
    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/start",
        Some(&auth_header),
        None,
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let start_resp: PasskeyRegistrationStartResponse = serde_json::from_slice(&body)?;
    let challenge_id = start_resp.challenge_id;

    // Verify challenge is stored in TokenStore with 120s TTL
    let cache_key = format!("passkey:reg:{challenge_id}");
    assert!(ctx.token_store.get_token(&cache_key).await?.is_some());

    // 2. Finish registration
    let finish_payload = serde_json::json!({
        "challenge_id": challenge_id,
        "name": "MacBook TouchID",
        "credential": dummy_register_credential()
    });

    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/finish",
        Some(&auth_header),
        Some(finish_payload.clone()),
    )
    .await?;

    assert_eq!(res.status(), StatusCode::CREATED);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let finish_resp: PasskeyRegistrationFinishResponse = serde_json::from_slice(&body)?;
    assert_eq!(finish_resp.name, "MacBook TouchID");

    // Verify passkey is persisted in PasskeyRepository
    let passkeys = ctx.passkey_repo.list_by_user_id(&user.id).await?;
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].name, "MacBook TouchID");

    // 3. Challenge consumption & Anti-Replay Defense
    // The challenge must now be removed from TokenStore
    assert!(ctx.token_store.get_token(&cache_key).await?.is_none());

    // Replaying the exact same finish request must be rejected
    let replay_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/finish",
        Some(&auth_header),
        Some(finish_payload),
    )
    .await?;

    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn test_passkey_discoverable_login_and_cookie_issuance() -> TestResult {
    let ctx = setup_passkey_app()?;
    let user = User::new(
        EmailAddress::parse("login.passkey@example.com")?,
        Some(Username::new("loginpasskey")?),
        None,
    );
    ctx.user_repo.create(&user).await?;

    // Pre-register sample passkey
    let sample_pk = make_sample_webauthn_passkey()?;
    let passkey_entity = Passkey::new(
        user.id,
        sample_pk.cred_id().as_slice().to_vec(),
        serde_json::to_value(&sample_pk)?,
        "YubiKey 5C NFC".to_owned(),
    );
    ctx.passkey_repo.save(&passkey_entity).await?;

    // 1. Start login ceremony (unauthenticated)
    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let start_resp: PasskeyLoginStartResponse = serde_json::from_slice(&body)?;
    let challenge_id = start_resp.challenge_id;

    // Verify challenge in cache
    let cache_key = format!("passkey:login:{challenge_id}");
    assert!(ctx.token_store.get_token(&cache_key).await?.is_some());

    // 2. Finish login ceremony
    let finish_payload = serde_json::json!({
        "challenge_id": challenge_id,
        "credential": dummy_login_credential()
    });

    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        None,
        Some(finish_payload.clone()),
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);

    // Verify dual-mode response body: tokens & Bearer type
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let tokens: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(tokens.get("access_token").is_some());
    assert!(tokens.get("refresh_token").is_some());
    assert_eq!(
        tokens.get("token_type").and_then(|v| v.as_str()),
        Some("Bearer")
    );

    // Verify challenge was consumed
    assert!(ctx.token_store.get_token(&cache_key).await?.is_none());

    // 3. Anti-Replay: Repeating login finish with same challenge must fail
    let replay_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        None,
        Some(finish_payload),
    )
    .await?;

    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);

    // 4. Verify last_used_at and passkey_json (counter / sign_count) were updated in repo
    let stored = ctx
        .passkey_repo
        .find_by_id(&passkey_entity.id)
        .await?
        .ok_or("passkey not found in repo")?;
    assert!(stored.last_used_at.is_some());
    // Counter must have been atomically updated from 2 to 3
    assert_eq!(stored.passkey_json["cred"]["counter"].as_u64(), Some(3));

    // 5. Verify issued Access Token claims: auth_time and amr = ["passkey"]
    let access_token_str = tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("missing access token in response")?;
    let verified_claims = ctx.token_signer.verify_access_token(access_token_str)?;
    assert_eq!(verified_claims.amr, vec!["passkey"]);
    assert!(verified_claims.auth_time > 0);

    // 6. Verify token refresh retains original auth_time and amr = ["passkey"]
    let refresh_token_str = tokens
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or("missing refresh token in response")?;
    let refresh_payload = serde_json::json!({
        "refresh_token": refresh_token_str
    });
    let refresh_res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(refresh_payload),
    )
    .await?;
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body = to_bytes(refresh_res.into_body(), usize::MAX).await?;
    let refreshed_tokens: serde_json::Value = serde_json::from_slice(&refresh_body)?;
    let refreshed_at = refreshed_tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("missing refreshed access token")?;
    let refreshed_claims = ctx.token_signer.verify_access_token(refreshed_at)?;
    assert_eq!(refreshed_claims.amr, vec!["passkey"]);
    assert_eq!(refreshed_claims.auth_time, verified_claims.auth_time);

    Ok(())
}

#[tokio::test]
async fn test_passkey_yubikey_clone_detection_counter_rollback() -> TestResult {
    let ctx = setup_passkey_app()?;
    let user = User::new(
        EmailAddress::parse("yubikey.clone@example.com")?,
        Some(Username::new("yubikeyuser")?),
        None,
    );
    ctx.user_repo.create(&user).await?;

    // Pre-register physical YubiKey with hardware counter = 2
    let sample_pk = make_sample_webauthn_passkey()?;
    let passkey_entity = Passkey::new(
        user.id,
        sample_pk.cred_id().as_slice().to_vec(),
        serde_json::to_value(&sample_pk)?,
        "YubiKey 5C NFC Physical".to_owned(),
    );
    ctx.passkey_repo.save(&passkey_entity).await?;

    // Step 1: Legitimate authentication ceremony (counter advances from 2 to 3)
    let start_res_1 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;
    assert_eq!(start_res_1.status(), StatusCode::OK);
    let body_1 = to_bytes(start_res_1.into_body(), usize::MAX).await?;
    let start_resp_1: PasskeyLoginStartResponse = serde_json::from_slice(&body_1)?;

    let finish_res_1 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        None,
        Some(serde_json::json!({
            "challenge_id": start_resp_1.challenge_id,
            "credential": dummy_login_credential()
        })),
    )
    .await?;
    assert_eq!(finish_res_1.status(), StatusCode::OK);

    // Verify counter updated to 3 in DB
    let stored = ctx
        .passkey_repo
        .find_by_id(&passkey_entity.id)
        .await?
        .ok_or("passkey not found in repo")?;
    assert_eq!(stored.passkey_json["cred"]["counter"].as_u64(), Some(3));

    // Step 2: Attacker presents cloned token (or replay with counter <= 3) on a new valid challenge
    let start_res_2 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;
    assert_eq!(start_res_2.status(), StatusCode::OK);
    let body_2 = to_bytes(start_res_2.into_body(), usize::MAX).await?;
    let start_resp_2: PasskeyLoginStartResponse = serde_json::from_slice(&body_2)?;

    // Attempt finish with the cloned hardware key (presents counter = 3, which is <= stored 3)
    let finish_res_2 = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        None,
        Some(serde_json::json!({
            "challenge_id": start_resp_2.challenge_id,
            "credential": dummy_login_credential()
        })),
    )
    .await?;

    // Must be rejected with 401 UNAUTHORIZED due to clone / counter rollback detection!
    assert_eq!(finish_res_2.status(), StatusCode::UNAUTHORIZED);

    // Counter in DB must remain 3 and not be regressed or altered
    let stored_after_attack = ctx
        .passkey_repo
        .find_by_id(&passkey_entity.id)
        .await?
        .ok_or("passkey not found in repo")?;
    assert_eq!(
        stored_after_attack.passkey_json["cred"]["counter"].as_u64(),
        Some(3)
    );

    Ok(())
}

#[tokio::test]
async fn test_passkey_listing_and_deletion_security() -> TestResult {
    let ctx = setup_passkey_app()?;

    // User A
    let user_a = User::new(
        EmailAddress::parse("usera@example.com")?,
        Some(Username::new("usera")?),
        None,
    );
    ctx.user_repo.create(&user_a).await?;
    let token_a = create_auth_token(&ctx, user_a.id, UserRole::User).await?;
    let auth_a = format!("Bearer {token_a}");

    // User B
    let user_b = User::new(
        EmailAddress::parse("userb@example.com")?,
        Some(Username::new("userb")?),
        None,
    );
    ctx.user_repo.create(&user_b).await?;

    // Register passkeys: 2 for User A, 1 for User B
    let pk_a1 = Passkey::new(
        user_a.id,
        vec![1, 2, 3],
        serde_json::json!({}),
        "User A Passkey 1".to_owned(),
    );
    let pk_a2 = Passkey::new(
        user_a.id,
        vec![4, 5, 6],
        serde_json::json!({}),
        "User A Passkey 2".to_owned(),
    );
    let pk_b = Passkey::new(
        user_b.id,
        vec![7, 8, 9],
        serde_json::json!({}),
        "User B Passkey".to_owned(),
    );

    ctx.passkey_repo.save(&pk_a1).await?;
    ctx.passkey_repo.save(&pk_a2).await?;
    ctx.passkey_repo.save(&pk_b).await?;

    // 1. User A lists passkeys -> sees exactly 2 passkeys
    let res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me/passkeys",
        Some(&auth_a),
        None,
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let list_a: Vec<PasskeyItemResponse> = serde_json::from_slice(&body)?;
    assert_eq!(list_a.len(), 2);
    assert!(list_a.iter().any(|p| p.id == pk_a1.id.to_uuid()));
    assert!(list_a.iter().any(|p| p.id == pk_a2.id.to_uuid()));

    // 2. Cross-tenant authorization: User A attempts to delete User B's passkey
    let cross_delete_uri = format!("/api/v1/users/me/passkeys/{}", pk_b.id.to_uuid());
    let res = send_request(
        &ctx.app,
        Method::DELETE,
        &cross_delete_uri,
        Some(&auth_a),
        None,
    )
    .await?;

    // Expect 403 Forbidden to prevent unauthorized deletion
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // Verify User B's passkey is still intact
    assert!(ctx.passkey_repo.find_by_id(&pk_b.id).await?.is_some());

    // 2b. Attempt to delete non-existent passkey -> Expect 404 Not Found
    let not_found_uri = format!("/api/v1/users/me/passkeys/{}", Uuid::now_v7());
    let res = send_request(
        &ctx.app,
        Method::DELETE,
        &not_found_uri,
        Some(&auth_a),
        None,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 3. User A deletes their own passkey (pk_a1)
    let own_delete_uri = format!("/api/v1/users/me/passkeys/{}", pk_a1.id.to_uuid());
    let res = send_request(
        &ctx.app,
        Method::DELETE,
        &own_delete_uri,
        Some(&auth_a),
        None,
    )
    .await?;

    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Verify pk_a1 is removed from repository
    assert!(ctx.passkey_repo.find_by_id(&pk_a1.id).await?.is_none());

    // 4. User A lists again -> now only sees 1 passkey
    let res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me/passkeys",
        Some(&auth_a),
        None,
    )
    .await?;

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let list_a_after: Vec<PasskeyItemResponse> = serde_json::from_slice(&body)?;
    assert_eq!(list_a_after.len(), 1);
    assert_eq!(list_a_after[0].id, pk_a2.id.to_uuid());

    Ok(())
}

#[tokio::test]
async fn test_unauthenticated_passkey_routes_are_denied() -> TestResult {
    let ctx = setup_passkey_app()?;
    let dummy_id = Uuid::now_v7();

    // GET /api/v1/users/me/passkeys without token -> 401
    let res = send_request(
        &ctx.app,
        Method::GET,
        "/api/v1/users/me/passkeys",
        None,
        None,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // POST /api/v1/auth/passkeys/register/start without token -> 401
    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/start",
        None,
        None,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // POST /api/v1/auth/passkeys/register/finish without token -> 401
    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/register/finish",
        None,
        Some(serde_json::json!({
            "challenge_id": dummy_id,
            "credential": dummy_register_credential()
        })),
    )
    .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // DELETE /api/v1/users/me/passkeys/:id without token -> 401
    let uri = format!("/api/v1/users/me/passkeys/{dummy_id}");
    let res = send_request(&ctx.app, Method::DELETE, &uri, None, None).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn test_passkey_login_fails_for_suspended_user() -> TestResult {
    let ctx = setup_passkey_app()?;
    let mut user = User::new(
        EmailAddress::parse("banned.passkey@example.com")?,
        Some(Username::new("bannedpk")?),
        None,
    );
    user.status = AccountStatus::Suspended;
    ctx.user_repo.create(&user).await?;

    let sample_pk = make_sample_webauthn_passkey()?;
    let passkey_entity = Passkey::new(
        user.id,
        sample_pk.cred_id().as_slice().to_vec(),
        serde_json::to_value(&sample_pk)?,
        "Banned User Key".to_owned(),
    );
    ctx.passkey_repo.save(&passkey_entity).await?;

    // 1. Start login ceremony
    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/start",
        None,
        None,
    )
    .await?;
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let start_resp: PasskeyLoginStartResponse = serde_json::from_slice(&body)?;

    // 2. Finish login ceremony -> must fail with 403 Forbidden because account is suspended
    let finish_payload = serde_json::json!({
        "challenge_id": start_resp.challenge_id,
        "credential": dummy_login_credential()
    });

    let res = send_request(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/passkeys/login/finish",
        None,
        Some(finish_payload),
    )
    .await?;

    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn test_passkey_concurrent_counter_update_optimistic_lock() -> TestResult {
    let ctx = setup_passkey_app()?;
    let user = User::new(
        EmailAddress::parse("optimistic.lock@example.com")?,
        Some(Username::new("optlockuser")?),
        None,
    );
    ctx.user_repo.create(&user).await?;

    // --- Scenario 1: Cloud Passkeys (Counter 0 -> 0) ---
    // Cloud/synced passkeys (iCloud Keychain, 1Password, Google Password Manager)
    // often have counter = 0 and remain at 0 across authentications.
    // Optimistic lock MUST allow 0 -> 0 updates.
    let cloud_pk = make_sample_webauthn_passkey()?;
    let mut cloud_val = serde_json::to_value(&cloud_pk)?;
    cloud_val["cred"]["counter"] = serde_json::json!(0);

    let cloud_passkey = Passkey::new(
        user.id,
        cloud_pk.cred_id().as_slice().to_vec(),
        cloud_val.clone(),
        "Cloud Passkey (1Password)".to_owned(),
    );
    ctx.passkey_repo.save(&cloud_passkey).await?;

    let now = Utc::now();
    let update_cloud_res = ctx
        .passkey_repo
        .update_credential_state(&cloud_passkey.id, &cloud_val, now)
        .await;
    assert!(
        update_cloud_res.is_ok(),
        "0 -> 0 cloud passkey update must succeed"
    );

    // --- Scenario 2: Hardware Passkeys - Counter Advancement (Strict Increase) ---
    // Physical token (e.g. YubiKey) starts with counter = 10
    let mut hw_val_10 = cloud_val.clone();
    hw_val_10["cred"]["counter"] = serde_json::json!(10);
    let hw_id = PasskeyId::new();
    let hw_passkey = Passkey {
        id: hw_id,
        user_id: user.id,
        credential_id: b"hardware_token_cred_id_12345".to_vec(),
        passkey_json: hw_val_10.clone(),
        name: "YubiKey 5C NFC".to_owned(),
        last_used_at: None,
        created_at: now,
    };
    ctx.passkey_repo.save(&hw_passkey).await?;

    // Advancing counter 10 -> 15: must succeed!
    let mut hw_val_15 = hw_val_10.clone();
    hw_val_15["cred"]["counter"] = serde_json::json!(15);
    let advance_res = ctx
        .passkey_repo
        .update_credential_state(&hw_id, &hw_val_15, now)
        .await;
    assert!(
        advance_res.is_ok(),
        "Advancing counter (10 -> 15) must succeed"
    );

    // Verify counter is now 15 in repo
    let stored = ctx
        .passkey_repo
        .find_by_id(&hw_id)
        .await?
        .ok_or("passkey not found")?;
    assert_eq!(stored.passkey_json["cred"]["counter"].as_i64(), Some(15));

    // --- Scenario 3: Counter Replay / Identical Counter Rejection ---
    // Attempting to update with the same counter 15 -> 15 must fail with Conflict!
    let replay_res = ctx
        .passkey_repo
        .update_credential_state(&hw_id, &hw_val_15, now)
        .await;
    assert!(
        matches!(replay_res, Err(PortError::Conflict { .. })),
        "Identical counter (15 -> 15) must return Conflict, got: {:?}",
        replay_res
    );

    // --- Scenario 4: Counter Rollback / Regression Rejection ---
    // Attempting to regress counter from 15 down to 8 (or 0) must fail with Conflict!
    let mut hw_val_8 = hw_val_10.clone();
    hw_val_8["cred"]["counter"] = serde_json::json!(8);
    let rollback_res = ctx
        .passkey_repo
        .update_credential_state(&hw_id, &hw_val_8, now)
        .await;
    assert!(
        matches!(rollback_res, Err(PortError::Conflict { .. })),
        "Counter rollback (15 -> 8) must return Conflict, got: {:?}",
        rollback_res
    );

    let rollback_zero_res = ctx
        .passkey_repo
        .update_credential_state(&hw_id, &cloud_val, now)
        .await;
    assert!(
        matches!(rollback_zero_res, Err(PortError::Conflict { .. })),
        "Counter regression to 0 (15 -> 0) must return Conflict, got: {:?}",
        rollback_zero_res
    );

    // State in repository must remain intact at 15
    let stored_after_attacks = ctx
        .passkey_repo
        .find_by_id(&hw_id)
        .await?
        .ok_or("passkey not found")?;
    assert_eq!(
        stored_after_attacks.passkey_json["cred"]["counter"].as_i64(),
        Some(15)
    );

    // --- Scenario 5: Concurrent Race Condition Simulation ---
    // Two concurrent ceremonies read counter = 15.
    // Both attempt to advance counter to 16.
    // Exactly one must succeed (15 -> 16), and the other must fail with Conflict!
    let mut hw_val_16 = hw_val_10.clone();
    hw_val_16["cred"]["counter"] = serde_json::json!(16);

    let repo1 = ctx.passkey_repo.clone();
    let repo2 = ctx.passkey_repo.clone();
    let val_clone1 = hw_val_16.clone();
    let val_clone2 = hw_val_16.clone();

    let task1 = tokio::spawn(async move {
        repo1
            .update_credential_state(&hw_id, &val_clone1, Utc::now())
            .await
    });
    let task2 = tokio::spawn(async move {
        repo2
            .update_credential_state(&hw_id, &val_clone2, Utc::now())
            .await
    });

    let (res1, res2) = tokio::join!(task1, task2);
    let r1 = res1?;
    let r2 = res2?;

    let successes = [r1.is_ok(), r2.is_ok()].into_iter().filter(|&b| b).count();
    let conflicts = [
        matches!(r1, Err(PortError::Conflict { .. })),
        matches!(r2, Err(PortError::Conflict { .. })),
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    assert_eq!(successes, 1, "Exactly one concurrent update must succeed");
    assert_eq!(
        conflicts, 1,
        "Exactly one concurrent update must fail with Conflict"
    );

    // Final counter must be 16
    let stored_final = ctx
        .passkey_repo
        .find_by_id(&hw_id)
        .await?
        .ok_or("passkey not found")?;
    assert_eq!(
        stored_final.passkey_json["cred"]["counter"].as_i64(),
        Some(16)
    );

    Ok(())
}
