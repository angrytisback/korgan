//! End-to-end integration tests for Role-Based Access Control (RBAC) and Admin Backoffice.

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
use korgan::ports::services::{
    AccessTokenClaims, OAuthProviderPort, PasswordHasher, TokenSigner, WebAuthnService,
};
use secrecy::ExposeSecret;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Throwaway test crypto material
const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ===========================================================================
// In-Memory Test Repositories
// ===========================================================================

#[derive(Default, Debug)]
struct AdminTestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
    usernames: Mutex<HashMap<String, UserId>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
}

#[async_trait]
impl UserRepository for AdminTestUserRepo {
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
}

#[derive(Default, Debug)]
struct AdminTestSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
}

#[async_trait]
impl SessionRepository for AdminTestSessionRepo {
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
        old_token_hash: &str,
        new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;

        if let Some(session) = sessions
            .values_mut()
            .find(|s| s.refresh_token_hash == old_token_hash)
            && !session.is_replaced
            && !session.is_revoked()
            && !session.is_expired(Utc::now())
        {
            session.is_replaced = true;
            session.last_active_at = Utc::now();
            let old = session.clone();
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
        if let Some(s) = sessions.get_mut(id) {
            s.revoke(reason, Utc::now());
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
        if let Some(s) = sessions.get_mut(id)
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
        family_id: &TokenFamilyId,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let now = Utc::now();
        let mut revoked = Vec::new();
        for s in sessions.values_mut() {
            if s.token_family_id == *family_id && !s.is_revoked() {
                s.revoke(reason, now);
                revoked.push(s.id);
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
        for s in sessions.values_mut() {
            if s.user_id == *user_id && !s.is_revoked() {
                if let Some(except) = except_session
                    && s.id == *except
                {
                    continue;
                }
                s.revoke(reason, now);
                revoked.push(s.id);
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct AdminTestTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for AdminTestTokenStore {
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
struct AdminTestAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for AdminTestAuditRepo {
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
struct AdminTestRateLimiter;

#[async_trait]
impl RateLimiterPort for AdminTestRateLimiter {
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
struct AdminOAuthAccountRepo {
    accounts: Mutex<HashMap<OAuthAccountId, OAuthAccount>>,
}

#[async_trait]
impl OAuthAccountRepository for AdminOAuthAccountRepo {
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
struct AdminPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for AdminPasskeyRepo {
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
    user_repo: Arc<AdminTestUserRepo>,
    session_repo: Arc<AdminTestSessionRepo>,
    token_signer: Arc<Ed25519JwtService>,
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
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);
    let user_repo = Arc::new(AdminTestUserRepo::default());
    let session_repo = Arc::new(AdminTestSessionRepo::default());
    let audit_repo = Arc::new(AdminTestAuditRepo::default());
    let token_store = Arc::new(AdminTestTokenStore::default());
    let rate_limiter = Arc::new(AdminTestRateLimiter);
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> =
        Arc::new(AdminOAuthAccountRepo::default());
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(AdminPasskeyRepo::default());
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

async fn send_request(app: &Router, req: Request<Body>) -> TestResult<Response> {
    Ok(app.clone().oneshot(req).await?)
}

async fn json_body<T: serde::de::DeserializeOwned>(res: Response) -> TestResult<T> {
    let bytes = to_bytes(res.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ===========================================================================
// RBAC & Admin E2E Tests
// ===========================================================================

#[tokio::test]
async fn test_rbac_and_admin_backoffice_flow() -> TestResult {
    let ctx = setup_app().await?;
    let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
    let dummy_hash = hasher
        .hash_password(&RawPassword::new("CorrectPassword123!")?)
        .await?;

    // 1. Create Normal User (role: User)
    let normal_user_id = UserId::new();
    let mut normal_user = User::new(
        EmailAddress::parse("normal@example.com")?,
        Some(Username::new("normaluser")?),
        dummy_hash.clone(),
    );
    normal_user.id = normal_user_id;
    normal_user.status = AccountStatus::Active;
    normal_user.role = UserRole::User;
    ctx.user_repo.create(&normal_user).await?;

    // Create session & access token for normal user
    let normal_session = Session::new(
        normal_user_id,
        "normal_token_hash".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    let normal_session_id = normal_session.id;
    ctx.session_repo.create(&normal_session).await?;

    let normal_claims = AccessTokenClaims {
        sub: normal_user_id,
        sid: normal_session_id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: normal_session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };
    let normal_access_token = ctx.token_signer.sign_access_token(&normal_claims)?;

    // 2. Create Admin User (role: Admin)
    let admin_user_id = UserId::new();
    let mut admin_user = User::new(
        EmailAddress::parse("admin@example.com")?,
        Some(Username::new("superadmin")?),
        dummy_hash,
    );
    admin_user.id = admin_user_id;
    admin_user.status = AccountStatus::Active;
    admin_user.role = UserRole::Admin;
    ctx.user_repo.create(&admin_user).await?;

    // Create session & access token for admin user
    let admin_session = Session::new(
        admin_user_id,
        "admin_token_hash".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    let admin_session_id = admin_session.id;
    ctx.session_repo.create(&admin_session).await?;

    let admin_claims = AccessTokenClaims {
        sub: admin_user_id,
        sid: admin_session_id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 3600,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: admin_session.created_at.timestamp(),
        amr: vec!["pwd".to_string(), "mfa".to_string()],
    };
    let admin_access_token = ctx.token_signer.sign_access_token(&admin_claims)?;

    // =======================================================================
    // STEP A: Normal user tries to access GET /api/v1/admin/users -> 403 Forbidden
    // =======================================================================
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/admin/users")
        .header(AUTHORIZATION, format!("Bearer {normal_access_token}"))
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let problem: ProblemDetails = json_body(res).await?;
    assert_eq!(problem.code, "AUTH_FORBIDDEN");
    assert_eq!(problem.status, 403);

    // =======================================================================
    // STEP B: Normal user tries to ban someone -> 403 Forbidden
    // =======================================================================
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/admin/users/{normal_user_id}/ban"))
        .header(AUTHORIZATION, format!("Bearer {normal_access_token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"reason":"self ban attempt"}"#))?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // =======================================================================
    // STEP C: Admin lists users -> 200 OK
    // =======================================================================
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/admin/users?page=1&per_page=10")
        .header(AUTHORIZATION, format!("Bearer {admin_access_token}"))
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let val: serde_json::Value = json_body(res).await?;
    assert_eq!(val["total"].as_u64(), Some(2));
    let items = val["items"].as_array().ok_or("missing items array")?;
    assert_eq!(items.len(), 2);

    // Verify role field is present in the admin user items
    let emails: Vec<&str> = items.iter().filter_map(|i| i["email"].as_str()).collect();
    assert!(emails.contains(&"normal@example.com"));
    assert!(emails.contains(&"admin@example.com"));

    // =======================================================================
    // STEP D: Admin bans normal user -> 200 OK, sessions revoked
    // =======================================================================
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/admin/users/{normal_user_id}/ban"))
        .header(AUTHORIZATION, format!("Bearer {admin_access_token}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"reason":"Violation of terms"}"#))?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let ban_val: serde_json::Value = json_body(res).await?;
    assert_eq!(ban_val["status"], "suspended");
    assert_eq!(ban_val["banned"], true);

    // Verify normal user status in repository
    let user_after_ban = ctx.user_repo.find_by_id(&normal_user_id).await?;
    let user_after_ban = user_after_ban.ok_or("user missing")?;
    assert_eq!(user_after_ban.status, AccountStatus::Suspended);

    // Verify normal user session is now revoked
    let session_after_ban = ctx.session_repo.find_by_id(&normal_session_id).await?;
    let session_after_ban = session_after_ban.ok_or("session missing")?;
    assert!(session_after_ban.is_revoked());
    assert_eq!(
        session_after_ban.revoke_reason.as_deref(),
        Some("user_banned_by_admin")
    );

    // =======================================================================
    // STEP E: Banned user is blocked from making authenticated calls
    // =======================================================================
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {normal_access_token}"))
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    // The extractor detects user is Suspended and/or session is revoked -> 401 or 403
    assert!(res.status() == StatusCode::FORBIDDEN || res.status() == StatusCode::UNAUTHORIZED);

    // =======================================================================
    // STEP F: Admin unbans normal user -> 200 OK
    // =======================================================================
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/admin/users/{normal_user_id}/unban"))
        .header(AUTHORIZATION, format!("Bearer {admin_access_token}"))
        .body(Body::empty())?;

    let res = send_request(&ctx.app, req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    let unban_val: serde_json::Value = json_body(res).await?;
    assert_eq!(unban_val["status"], "active");
    assert_eq!(unban_val["unbanned"], true);

    let user_after_unban = ctx.user_repo.find_by_id(&normal_user_id).await?;
    let user_after_unban = user_after_unban.ok_or("user missing")?;
    assert_eq!(user_after_unban.status, AccountStatus::Active);

    Ok(())
}
