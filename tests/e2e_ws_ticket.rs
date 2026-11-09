//! End-to-end integration tests for WebSocket/WebRTC Ephemeral Ticket and Telemetry.

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
use korgan::adapters::inbound::http::{AppState, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::error::AppError;
use korgan::application::use_cases::auth::{IssueWsTicketUseCase, VerifyWsTicketUseCase};
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
use korgan::ports::services::{
    AccessTokenClaims, OAuthProviderPort, PasswordHasher, TokenSigner, WebAuthnService,
};
use secrecy::ExposeSecret;
use serde_json::Value;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

#[derive(Default, Debug)]
struct WsTestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for WsTestUserRepo {
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
        _depth: u16,
    ) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            user.password_hash = Some(new_hash.clone());
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn get_password_history(
        &self,
        _user_id: &UserId,
        _limit: u32,
    ) -> Result<Vec<PasswordHash>, PortError> {
        Ok(Vec::new())
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

    async fn has_admin_user(&self) -> Result<bool, PortError> {
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(users.values().any(|u| u.role.is_admin()))
    }
}

#[derive(Default, Debug)]
struct WsTestSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
}

#[async_trait]
impl SessionRepository for WsTestSessionRepo {
    async fn create(&self, session: &Session) -> Result<(), PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
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
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(sessions
            .values()
            .find(|s| s.refresh_token_hash == token_hash)
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

    async fn replace_atomic(&self, _token_hash: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn rotate_atomic(
        &self,
        _old_token_hash: &str,
        _new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
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

    async fn count_active(&self) -> Result<u64, PortError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let now = Utc::now();
        Ok(sessions.values().filter(|s| s.is_valid(now)).count() as u64)
    }
}

#[derive(Default, Debug)]
struct WsTestAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for WsTestAuditRepo {
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

    async fn list_all_chronological(&self) -> Result<Vec<AuditLog>, PortError> {
        let logs = self
            .logs
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list = logs.clone();
        list.sort_by_key(|a| a.created_at);
        Ok(list)
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let logs = self
            .logs
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(logs.len() as u64)
    }
}

#[derive(Default, Debug)]
struct WsTestTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for WsTestTokenStore {
    async fn set_token(&self, key: &str, value: &str, _ttl: Duration) -> Result<(), PortError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        tokens.insert(key.to_owned(), value.to_owned());
        Ok(())
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
        match tokens.get(key) {
            Some(stored) if stored == expected_token_hash => {
                tokens.remove(key);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Default, Debug)]
struct WsTestRateLimiter;

#[async_trait]
impl RateLimiterPort for WsTestRateLimiter {
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
struct WsTestOAuthAccountRepo;

#[async_trait]
impl OAuthAccountRepository for WsTestOAuthAccountRepo {
    async fn find_by_provider_and_id(
        &self,
        _provider: OAuthProvider,
        _id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        Ok(None)
    }

    async fn list_by_user_id(&self, _user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        Ok(Vec::new())
    }

    async fn create(&self, _account: &OAuthAccount) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
struct WsTestPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for WsTestPasskeyRepo {
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

struct TestContext {
    app: Router,
    user_repo: Arc<WsTestUserRepo>,
    session_repo: Arc<WsTestSessionRepo>,
    token_store: Arc<WsTestTokenStore>,
    token_signer: Arc<Ed25519JwtService>,
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
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);
    let user_repo = Arc::new(WsTestUserRepo::default());
    let session_repo = Arc::new(WsTestSessionRepo::default());
    let audit_repo = Arc::new(WsTestAuditRepo::default());
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> = Arc::new(WsTestOAuthAccountRepo);
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(WsTestPasskeyRepo::default());
    let token_store = Arc::new(WsTestTokenStore::default());
    let rate_limiter = Arc::new(WsTestRateLimiter);

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
    let google_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebauthnRsAdapter::new(
        "localhost",
        "http://localhost:8080",
    )?);

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
        passkey_repo,
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

    Ok(TestContext {
        app,
        user_repo,
        session_repo,
        token_store,
        token_signer,
    })
}

#[tokio::test]
async fn test_ws_ticket_issuance_and_single_use_verification_lifecycle() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Create active test user and session
    let user_id = UserId::new();
    let email = EmailAddress::parse("wstest@example.com")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("CorrectPassword123!")?)
        .await?;
    let mut user = User::new(email, None, dummy_hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.role = UserRole::User;
    ctx.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "dummy_refresh_hash".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    let session_id = session.id;
    ctx.session_repo.create(&session).await?;

    // Sign valid Access Token
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };
    let access_token = ctx.token_signer.sign_access_token(&claims)?;

    // 2. Unauthenticated POST /api/v1/auth/ws-ticket -> 401 Unauthorized
    let unauth_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::empty())?;

    let unauth_resp: Response = ctx.app.clone().oneshot(unauth_req).await?;
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Authenticated POST /api/v1/auth/ws-ticket -> 200 OK with ticket
    let auth_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::empty())?;

    let auth_resp: Response = ctx.app.clone().oneshot(auth_req).await?;
    assert_eq!(auth_resp.status(), StatusCode::OK);

    let body_bytes = to_bytes(auth_resp.into_body(), usize::MAX).await?;
    let ticket_json: Value = serde_json::from_slice(&body_bytes)?;
    let ticket = ticket_json["ticket"]
        .as_str()
        .ok_or("ticket must be a string")?;
    assert!(!ticket.is_empty(), "ticket must not be empty");
    assert_eq!(
        ticket_json["expires_in"], 15,
        "ticket TTL must be 15 seconds"
    );

    // 4. Verify ticket: POST /api/v1/auth/ws-ticket/verify -> 200 OK with payload
    let verify_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket/verify")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"ticket":"{ticket}"}}"#)))?;

    let verify_resp: Response = ctx.app.clone().oneshot(verify_req).await?;
    assert_eq!(verify_resp.status(), StatusCode::OK);

    let verify_body_bytes = to_bytes(verify_resp.into_body(), usize::MAX).await?;
    let verify_json: Value = serde_json::from_slice(&verify_body_bytes)?;
    assert_eq!(verify_json["sub"], user_id.to_string());
    assert_eq!(verify_json["sid"], session_id.to_string());
    assert_eq!(verify_json["role"], "user");

    // 5. Atomic GETDEL Replay Protection: Second verify with same ticket MUST FAIL (401 Unauthorized)
    let replay_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket/verify")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"ticket":"{ticket}"}}"#)))?;

    let replay_resp: Response = ctx.app.clone().oneshot(replay_req).await?;
    assert_eq!(
        replay_resp.status(),
        StatusCode::UNAUTHORIZED,
        "consumed ticket must be rejected"
    );

    // 6. Session Revocation / Blacklist Check:
    // Issue a second ticket
    let issue_req2 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::empty())?;

    let issue_resp2: Response = ctx.app.clone().oneshot(issue_req2).await?;
    assert_eq!(issue_resp2.status(), StatusCode::OK);
    let body_bytes2 = to_bytes(issue_resp2.into_body(), usize::MAX).await?;
    let ticket_json2: Value = serde_json::from_slice(&body_bytes2)?;
    let ticket2 = ticket_json2["ticket"]
        .as_str()
        .ok_or("ticket2 must be a string")?;

    // Blacklist the session in Redis
    let blacklist_key = format!("blacklist:session:{session_id}");
    ctx.token_store
        .set_token(&blacklist_key, "revoked", Duration::from_secs(3600))
        .await?;

    // Attempt to verify ticket for blacklisted session -> MUST FAIL (401 Unauthorized)
    let verify_blacklisted_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/ws-ticket/verify")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"ticket":"{ticket2}"}}"#)))?;

    let verify_blacklisted_resp: Response = ctx.app.clone().oneshot(verify_blacklisted_req).await?;
    assert_eq!(
        verify_blacklisted_resp.status(),
        StatusCode::UNAUTHORIZED,
        "ticket with blacklisted session must be rejected"
    );

    // 7. Verify Prometheus /metrics endpoint is exposed and operational
    let metrics_req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())?;

    let metrics_resp: Response = ctx.app.oneshot(metrics_req).await?;
    assert_eq!(metrics_resp.status(), StatusCode::OK);
    let metrics_bytes = to_bytes(metrics_resp.into_body(), usize::MAX).await?;
    let metrics_str = String::from_utf8_lossy(&metrics_bytes);
    assert!(
        metrics_str.contains("korgan_auth_attempts_total"),
        "missing korgan_auth_attempts_total in /metrics"
    );
    assert!(
        metrics_str.contains("korgan_token_reuse_events_total"),
        "missing korgan_token_reuse_events_total in /metrics"
    );
    assert!(
        metrics_str.contains("korgan_argon2_semaphore_waiting"),
        "missing korgan_argon2_semaphore_waiting in /metrics"
    );
    assert!(
        metrics_str.contains("korgan_audit_chain_length"),
        "missing korgan_audit_chain_length in /metrics"
    );
    assert!(
        metrics_str.contains("korgan_active_sessions_gauge"),
        "missing korgan_active_sessions_gauge in /metrics"
    );

    Ok(())
}

#[tokio::test]
async fn test_issue_and_verify_ws_ticket_use_cases_unit() -> TestResult {
    let ctx = setup_test_context().await?;
    let issue_uc = IssueWsTicketUseCase::new(ctx.token_store.clone());
    let verify_uc = VerifyWsTicketUseCase::new(ctx.token_store.clone());

    let user_id = UserId::new();
    let session_id = SessionId::new();
    let role = "admin".to_string();

    // 1. Issue ticket: 32 bytes base64url no pad -> 43 characters
    let issue_res = issue_uc.execute(user_id, session_id, role.clone()).await?;
    assert_eq!(
        issue_res.ticket.len(),
        43,
        "32 bytes Base64URL without padding should be 43 chars"
    );
    assert_eq!(issue_res.expires_in, 15, "ticket TTL must be 15 seconds");

    // 2. Verify ticket successfully
    let payload = verify_uc.execute(&issue_res.ticket).await?;
    assert_eq!(payload.sub, user_id.to_string());
    assert_eq!(payload.sid, session_id.to_string());
    assert_eq!(payload.role, role);

    // 3. Second verification MUST fail (atomic GETDEL consumption)
    let replay_res = verify_uc.execute(&issue_res.ticket).await;
    match replay_res {
        Err(AppError::TokenInvalid) => {}
        other => return Err(format!("Expected AppError::TokenInvalid, got {:?}", other).into()),
    }

    // 4. Empty and whitespace ticket must fail
    match verify_uc.execute("").await {
        Err(AppError::TokenInvalid) => {}
        other => {
            return Err(format!(
                "Expected AppError::TokenInvalid for empty ticket, got {:?}",
                other
            )
            .into());
        }
    }
    match verify_uc.execute("   ").await {
        Err(AppError::TokenInvalid) => {}
        other => {
            return Err(format!(
                "Expected AppError::TokenInvalid for whitespace ticket, got {:?}",
                other
            )
            .into());
        }
    }

    // 5. Non-existent ticket must fail
    match verify_uc.execute("non_existent_ticket_12345").await {
        Err(AppError::TokenInvalid) => {}
        other => {
            return Err(format!(
                "Expected AppError::TokenInvalid for non-existent ticket, got {:?}",
                other
            )
            .into());
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_ws_ticket_blacklisted_session_rejected_at_issuance_and_verification() -> TestResult {
    let ctx = setup_test_context().await?;
    let issue_uc = IssueWsTicketUseCase::new(ctx.token_store.clone());
    let verify_uc = VerifyWsTicketUseCase::new(ctx.token_store.clone());

    let user_id = UserId::new();
    let session_id = SessionId::new();
    let role = "user".to_string();

    // 1. Pre-blacklist session in Redis
    let blacklist_key = format!("blacklist:session:{session_id}");
    ctx.token_store
        .set_token(&blacklist_key, "revoked", Duration::from_secs(3600))
        .await?;

    // 2. Issuing a ticket for an already blacklisted session MUST fail
    let issue_err = issue_uc.execute(user_id, session_id, role.clone()).await;
    match issue_err {
        Err(AppError::Unauthenticated) => {}
        other => {
            return Err(format!(
                "Expected AppError::Unauthenticated for blacklisted session, got {:?}",
                other
            )
            .into());
        }
    }

    // 3. Test verification rejection if blacklisted post-issuance
    let active_session_id = SessionId::new();
    let issue_ok = issue_uc.execute(user_id, active_session_id, role).await?;

    // Now blacklist this active session
    let bl_key2 = format!("blacklist:session:{active_session_id}");
    ctx.token_store
        .set_token(&bl_key2, "revoked", Duration::from_secs(3600))
        .await?;

    let verify_err = verify_uc.execute(&issue_ok.ticket).await;
    match verify_err {
        Err(AppError::TokenInvalid) => {}
        other => return Err(format!(
            "Expected AppError::TokenInvalid when session is blacklisted post-issuance, got {:?}",
            other
        )
        .into()),
    }

    Ok(())
}

#[tokio::test]
async fn test_superadmin_role_can_access_admin_api_endpoints() -> TestResult {
    let ctx = setup_test_context().await?;

    // 1. Create a superadmin user
    let superadmin_id = UserId::new();
    let email = EmailAddress::parse("boss@korgan.internal")?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("SuperSecretAdminPass123!")?)
        .await?;
    let mut superadmin = User::new(email, None, dummy_hash);
    superadmin.id = superadmin_id;
    superadmin.role = UserRole::Superadmin;
    superadmin.status = AccountStatus::Active;
    superadmin.email_verified_at = Some(Utc::now());
    ctx.user_repo.create(&superadmin).await?;

    // 2. Create active session for superadmin
    let superadmin_session = Session::new(
        superadmin_id,
        "dummy_superadmin_hash".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("TestAgent".to_string()),
        None,
        chrono::Duration::days(1),
    );
    let session_id = superadmin_session.id;
    ctx.session_repo.create(&superadmin_session).await?;

    // 3. Sign access token
    let claims = AccessTokenClaims {
        sub: superadmin_id,
        sid: session_id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: superadmin_session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };
    let access_token = ctx.token_signer.sign_access_token(&claims)?;

    // 4. Superadmin requests /api/v1/admin/users
    // Must succeed with 200 OK because Superadmin is an admin (is_admin == true)
    let admin_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/admin/users")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .body(Body::empty())?;

    let admin_resp: Response = ctx.app.oneshot(admin_req).await?;
    assert_eq!(
        admin_resp.status(),
        StatusCode::OK,
        "Superadmin must be permitted to access AdminUser endpoints"
    );

    Ok(())
}
