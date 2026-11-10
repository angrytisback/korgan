//! Verification and regression tests for security hardening layers:
//! 1. Step-Up Authentication (auth_time & amr enforcement)
//! 2. Outbound HTTP client 64KB body limit
//! 3. Immutable audit logs & SHA-256 hash chain
//! 4. Shielded task draining mechanism
//! 5. Retention GC worker for expired sessions and unverified users

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header::AUTHORIZATION};
use chrono::{DateTime, Utc};
use korgan::adapters::inbound::http::{AppState, ProblemDetails, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::use_cases::cancellation::{
    active_shielded_tasks, shielded, wait_for_shielded_tasks,
};
use korgan::application::workers::{AppEvent, EventBus, EventWorker, RetentionGcWorker};
use korgan::config::Settings;
use korgan::domain::entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User,
    UserMfa,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::*;
use korgan::ports::services::*;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIK+cT8yvQ5p+zU1L7nU4mHw9sVb6+Qe8b+W0p0m0h1xY\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    purged_unverified_count: AtomicU32,
}

#[async_trait]
impl UserRepository for MockUserRepo {
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
        _depth: u16,
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
        Ok(true)
    }

    async fn record_failed_login_atomic(
        &self,
        _user_id: &UserId,
        _max: u16,
        _lockout: DateTime<Utc>,
        _now: DateTime<Utc>,
    ) -> Result<(u16, Option<DateTime<Utc>>), PortError> {
        Ok((0, None))
    }

    async fn reset_failed_logins(
        &self,
        _user_id: &UserId,
        _now: DateTime<Utc>,
    ) -> Result<(), PortError> {
        Ok(())
    }

    async fn list_paginated(&self, _limit: u32, _offset: u64) -> Result<Vec<User>, PortError> {
        Ok(Vec::new())
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.len() as u64)
    }

    async fn purge_expired_unverified(
        &self,
        _created_before: DateTime<Utc>,
        _max_purge: u32,
    ) -> Result<u64, PortError> {
        self.purged_unverified_count.fetch_add(1, Ordering::SeqCst);
        Ok(42)
    }
}

#[derive(Default)]
struct MockSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    purged_count: AtomicU32,
}

#[async_trait]
impl SessionRepository for MockSessionRepo {
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

    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError> {
        let lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
    }

    async fn find_by_token_hash(&self, _hash: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn list_by_user_id(
        &self,
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        Ok(Vec::new())
    }

    async fn replace_atomic(&self, _hash: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn rotate_atomic(
        &self,
        _old: &str,
        _new: &Session,
    ) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn revoke_by_id(&self, id: &SessionId, reason: &str) -> Result<(), PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(session) = lock.get_mut(id) {
            session.revoke(reason, Utc::now());
        }
        Ok(())
    }

    async fn revoke_by_id_and_user_id(
        &self,
        id: &SessionId,
        uid: &UserId,
        reason: &str,
    ) -> Result<Option<SessionId>, PortError> {
        let mut lock = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(session) = lock.get_mut(id)
            && &session.user_id == uid
        {
            session.revoke(reason, Utc::now());
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
        _user_id: &UserId,
        _except: Option<&SessionId>,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        self.purged_count.fetch_add(1, Ordering::SeqCst);
        Ok(10)
    }
}

#[derive(Default)]
struct MockPasskeyRepo {
    passkeys: Mutex<HashMap<PasskeyId, Passkey>>,
}

#[async_trait]
impl PasskeyRepository for MockPasskeyRepo {
    async fn save(&self, passkey: &Passkey) -> Result<(), PortError> {
        let mut lock = self
            .passkeys
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(passkey.id, passkey.clone());
        Ok(())
    }

    async fn find_by_credential_id(&self, _cid: &[u8]) -> Result<Option<Passkey>, PortError> {
        Ok(None)
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
        Ok(lock
            .values()
            .filter(|p| &p.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_by_id(&self, _id: &PasskeyId) -> Result<(), PortError> {
        Ok(())
    }

    async fn delete_by_id_and_user_id(
        &self,
        _id: &PasskeyId,
        _uid: &UserId,
    ) -> Result<bool, PortError> {
        Ok(true)
    }
}

#[derive(Default)]
struct MockAuditRepo {
    entries: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for MockAuditRepo {
    async fn append(&self, entry: &AuditLog) -> Result<(), PortError> {
        let mut lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.push(entry.clone());
        Ok(())
    }

    async fn append_and_chain(&self, entry: &mut AuditLog) -> Result<(), PortError> {
        let mut lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let prev_hash = lock.last().and_then(|e| e.entry_hash.clone());
        let now = Utc::now();
        let monotonic_created_at = match lock.last() {
            Some(last) if now <= last.created_at => {
                last.created_at + chrono::Duration::microseconds(1)
            }
            _ => now,
        };
        entry.chain_with_timestamp(prev_hash.as_deref(), monotonic_created_at);
        lock.push(entry.clone());
        Ok(())
    }

    async fn list_by_user_id(
        &self,
        _uid: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        let lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.clone())
    }

    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        let lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.clone())
    }

    async fn find_latest_entry_hash(&self) -> Result<Option<String>, PortError> {
        let lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.last().and_then(|e| e.entry_hash.clone()))
    }

    async fn list_all_chronological(&self) -> Result<Vec<AuditLog>, PortError> {
        let lock = self
            .entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut list = lock.clone();
        list.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(list)
    }
}

#[derive(Default)]
struct MockTokenStore;

#[async_trait]
impl TokenStore for MockTokenStore {
    async fn set_token(&self, _k: &str, _v: &str, _ttl: Duration) -> Result<(), PortError> {
        Ok(())
    }

    async fn get_token(&self, _k: &str) -> Result<Option<String>, PortError> {
        Ok(None)
    }

    async fn delete_token(&self, _k: &str) -> Result<(), PortError> {
        Ok(())
    }

    async fn get_and_delete(&self, _k: &str) -> Result<Option<String>, PortError> {
        Ok(None)
    }

    async fn consume_token(&self, _k: &str, _expected: &str) -> Result<bool, PortError> {
        Ok(true)
    }

    async fn set_if_not_exists(
        &self,
        _k: &str,
        _v: &str,
        _ttl: Duration,
    ) -> Result<bool, PortError> {
        Ok(true)
    }
}

#[derive(Default)]
struct MockOAuthRepo;

#[async_trait]
impl OAuthAccountRepository for MockOAuthRepo {
    async fn find_by_provider_and_id(
        &self,
        _p: OAuthProvider,
        _id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        Ok(None)
    }

    async fn list_by_user_id(&self, _uid: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        Ok(Vec::new())
    }

    async fn create(&self, _a: &OAuthAccount) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockRateLimiter;

#[async_trait]
impl RateLimiterPort for MockRateLimiter {
    async fn check_and_increment(
        &self,
        _key: &str,
        _limit: u32,
        _window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        Ok(RateLimitStatus {
            allowed: true,
            limit: 100,
            remaining: 99,
            reset_epoch_secs: 0,
            retry_after_secs: None,
        })
    }

    async fn reset(&self, _key: &str) -> Result<(), PortError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test Harness Setup
// ---------------------------------------------------------------------------

struct TestHarness {
    app: Router,
    user_repo: Arc<MockUserRepo>,
    session_repo: Arc<MockSessionRepo>,
    passkey_repo: Arc<MockPasskeyRepo>,
    token_signer: Arc<Ed25519JwtService>,
    password_hasher: Arc<Argon2PasswordHasher>,
}

fn create_test_harness() -> Result<TestHarness, Box<dyn std::error::Error>> {
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

    let user_repo = Arc::new(MockUserRepo::default());
    let session_repo = Arc::new(MockSessionRepo::default());
    let audit_repo = Arc::new(MockAuditRepo::default());
    let oauth_account_repo = Arc::new(MockOAuthRepo);
    let passkey_repo = Arc::new(MockPasskeyRepo::default());
    let token_store = Arc::new(MockTokenStore);
    let rate_limiter = Arc::new(MockRateLimiter);

    let password_hasher = Arc::new(Argon2PasswordHasher::new(1024, 1, 1)?);
    let token_signer = Arc::new(Ed25519JwtService::from_pkcs8_pem(
        TEST_PEM,
        Some("test-kid".to_string()),
    )?);
    let secret_cipher = Arc::new(Aes256GcmCipher::from_base64(TEST_AES)?);
    let totp_service = Arc::new(Rfc6238TotpService::new());
    let hibp_client = Arc::new(NoopHibpClient);
    let mail_provider = Arc::new(ConsoleMailProvider::new("no-reply@example.com"));
    let google_oauth = Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth = Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
    let (event_bus, _rx) = EventBus::new(100);

    let webauthn_service = Arc::new(korgan::adapters::outbound::crypto::WebauthnRsAdapter::new(
        "localhost",
        "http://localhost:8080",
    )?);

    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_pool = deadpool_redis::Config::from_url("redis://localhost:6379")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        user_repo.clone(),
        session_repo.clone(),
        audit_repo,
        oauth_account_repo,
        passkey_repo.clone(),
        token_store,
        rate_limiter,
        password_hasher.clone(),
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

    Ok(TestHarness {
        app,
        user_repo,
        session_repo,
        passkey_repo,
        token_signer,
        password_hasher,
    })
}

// ---------------------------------------------------------------------------
// 1. Step-Up Authentication Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_step_up_stale_auth_time_rejected_403() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("stale@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("staleuser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_1".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Generate token with auth_time = 16 minutes ago (960 seconds ago)
    let stale_auth_time = Utc::now().timestamp() - 960;
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: stale_auth_time,
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    // DELETE /api/v1/sessions requires StepUpUser
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await?;
    let problem: ProblemDetails = serde_json::from_slice(&bytes)?;
    assert!(problem.detail.contains("recent re-authentication required"));

    Ok(())
}

#[tokio::test]
async fn test_step_up_mfa_user_missing_amr_rejected_403() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("mfauser@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("mfauser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = true; // User has MFA enabled!
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_2".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh auth_time (10 seconds ago), but amr only contains ["pwd"] (no "mfa" or "passkey")
    let fresh_auth_time = Utc::now().timestamp() - 10;
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: fresh_auth_time,
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await?;
    let problem: ProblemDetails = serde_json::from_slice(&bytes)?;
    assert!(problem.detail.contains("step-up authentication required"));

    Ok(())
}

#[tokio::test]
async fn test_step_up_passkey_user_missing_amr_rejected_403() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("pkuser@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("pkuser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = false;
    harness.user_repo.create(&user).await?;

    // Register a passkey for this user
    let passkey = Passkey::new(
        user_id,
        vec![1, 2, 3, 4],
        serde_json::json!({ "cred": { "counter": 0 } }),
        "YubiKey",
    );
    harness.passkey_repo.save(&passkey).await?;

    let session = Session::new(
        user_id,
        "token_hash_3".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh token, but missing passkey/mfa in amr
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn test_step_up_valid_mfa_amr_and_fresh_auth_time_succeeds() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("validstepup@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("validstepup")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = true;
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_4".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh auth_time AND amr contains "mfa"
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 60,
        amr: vec!["pwd".to_owned(), "mfa".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    // Should pass StepUpUser extractor and successfully execute revoke_all (204 No Content)
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn test_step_up_standard_user_without_mfa_succeeds_with_fresh_auth_time() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("standarduser@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("stduser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = false;
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_std".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh auth_time (30s ago), amr only contains ["pwd"] (no MFA/Passkey required for standard user)
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 30,
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn test_step_up_passkey_user_with_passkey_amr_succeeds() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("passkeyuser@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("passkeyuser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = false;
    harness.user_repo.create(&user).await?;

    let passkey = Passkey::new(
        user_id,
        vec![5, 6, 7, 8],
        serde_json::json!({ "cred": { "counter": 1 } }),
        "YubiKey 5C",
    );
    harness.passkey_repo.save(&passkey).await?;

    let session = Session::new(
        user_id,
        "token_hash_pk".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh auth_time (45s ago) and amr contains "passkey"
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 45,
        amr: vec!["passkey".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn test_step_up_first_passkey_register_and_password_change_succeeds_with_pwd() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("firstsetup@example.com")?;
    let raw_pwd = RawPassword::new("InitialSecurePassword123!")?;
    let hash = harness.password_hasher.hash_password(&raw_pwd).await?;
    let mut user = User::new(email, Some(Username::new("firstsetup")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = false; // No MFA enabled yet
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_first_setup".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Fresh auth_time (30s ago) with amr: ["pwd"]
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 30,
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    // 1. POST /api/v1/auth/passkeys/register/start must succeed (200 OK)
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/passkeys/register/start")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // 2. POST /api/v1/password/change must succeed (200 OK)
    let change_payload = serde_json::json!({
        "current_password": "InitialSecurePassword123!",
        "new_password": "NewReplacementPassword456!",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/password/change")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&change_payload)?))?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::OK);

    // Wait for the asynchronous session revocation shielded task to finish
    wait_for_shielded_tasks(Duration::from_secs(2)).await;

    Ok(())
}

#[tokio::test]
async fn test_step_up_user_with_active_mfa_or_passkey_denied_with_pwd_only() -> TestResult {
    let harness = create_test_harness()?;

    // User A: MFA enabled
    let user_a_id = UserId::new();
    let email_a = EmailAddress::parse("mfa_active@example.com")?;
    let raw_pwd = RawPassword::new("InitialSecurePassword123!")?;
    let hash = harness.password_hasher.hash_password(&raw_pwd).await?;
    let mut user_a = User::new(email_a, Some(Username::new("mfa_active")?), hash.clone());
    user_a.id = user_a_id;
    user_a.status = AccountStatus::Active;
    user_a.mfa_enabled = true;
    harness.user_repo.create(&user_a).await?;

    let session_a = Session::new(
        user_a_id,
        "token_hash_a".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_a_id = session_a.id;
    harness.session_repo.create(&session_a).await?;

    // Token for User A with only amr: ["pwd"]
    let claims_a = AccessTokenClaims {
        sub: user_a_id,
        sid: session_a_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 10,
        amr: vec!["pwd".to_owned()],
    };
    let token_a = harness.token_signer.sign_access_token(&claims_a)?;

    // Calling passkeys register start must return 403 Forbidden
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/passkeys/register/start")
        .header(AUTHORIZATION, format!("Bearer {token_a}"))
        .body(Body::empty())?;
    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Calling password change must return 403 Forbidden
    let change_payload = serde_json::json!({
        "current_password": "InitialSecurePassword123!",
        "new_password": "NewReplacementPassword456!",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/password/change")
        .header(AUTHORIZATION, format!("Bearer {token_a}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&change_payload)?))?;
    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // User B: Passkey registered (mfa_enabled = false)
    let user_b_id = UserId::new();
    let email_b = EmailAddress::parse("passkey_active@example.com")?;
    let mut user_b = User::new(email_b, Some(Username::new("pk_active")?), hash);
    user_b.id = user_b_id;
    user_b.status = AccountStatus::Active;
    user_b.mfa_enabled = false;
    harness.user_repo.create(&user_b).await?;

    let passkey = Passkey::new(
        user_b_id,
        vec![10, 11, 12, 13],
        serde_json::json!({ "cred": { "counter": 0 } }),
        "Titan Security Key",
    );
    harness.passkey_repo.save(&passkey).await?;

    let session_b = Session::new(
        user_b_id,
        "token_hash_b".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_b_id = session_b.id;
    harness.session_repo.create(&session_b).await?;

    let claims_b = AccessTokenClaims {
        sub: user_b_id,
        sid: session_b_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 10,
        amr: vec!["pwd".to_owned()],
    };
    let token_b = harness.token_signer.sign_access_token(&claims_b)?;

    // Calling passkeys register start must return 403 Forbidden
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/passkeys/register/start")
        .header(AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())?;
    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Calling password change must return 403 Forbidden
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/password/change")
        .header(AUTHORIZATION, format!("Bearer {token_b}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&change_payload)?))?;
    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn test_step_up_clock_skew_tolerance_and_forward_limit() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("clockuser@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("clockuser")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    user.mfa_enabled = false;
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_clock".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // 1. auth_time = +20s in the future (within 30s clock skew tolerance) -> succeeds
    let claims_tolerated = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() + 20,
        amr: vec!["pwd".to_owned()],
    };
    let token_tolerated = harness.token_signer.sign_access_token(&claims_tolerated)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token_tolerated}"))
        .body(Body::empty())?;
    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // 2. auth_time = +45s in the future (exceeds 30s clock skew tolerance) -> 403 Forbidden
    let claims_exceeded = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() + 45,
        amr: vec!["pwd".to_owned()],
    };
    let token_exceeded = harness.token_signer.sign_access_token(&claims_exceeded)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token_exceeded}"))
        .body(Body::empty())?;
    let res = harness.app.clone().oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await?;
    let problem: ProblemDetails = serde_json::from_slice(&bytes)?;
    assert!(problem.detail.contains("clock skew"));

    // 3. auth_time with empty amr -> 403 Forbidden
    let claims_empty_amr = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: Utc::now().timestamp() - 10,
        amr: vec![],
    };
    let token_empty_amr = harness.token_signer.sign_access_token(&claims_empty_amr)?;

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token_empty_amr}"))
        .body(Body::empty())?;
    let res = harness.app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Shielded Task Draining Mechanism
// ---------------------------------------------------------------------------

static SHIELDED_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn test_shielded_task_draining() -> TestResult {
    let _guard = SHIELDED_TEST_LOCK.lock().await;
    wait_for_shielded_tasks(Duration::from_secs(2)).await;
    assert_eq!(active_shielded_tasks(), 0);

    // Spawn a shielded task with simulated delay
    let handle = tokio::spawn(async {
        let res = shielded(|| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<u32, korgan::application::error::AppError>(42)
        })
        .await;
        assert_eq!(res.unwrap_or(0), 42);
    });

    // Wait for task to drain cleanly
    let drained = wait_for_shielded_tasks(Duration::from_secs(2)).await;
    assert!(drained);
    assert_eq!(active_shielded_tasks(), 0);

    handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_shielded_task_draining_zero_active_returns_immediately() -> TestResult {
    let _guard = SHIELDED_TEST_LOCK.lock().await;
    wait_for_shielded_tasks(Duration::from_secs(2)).await;
    assert_eq!(active_shielded_tasks(), 0);
    let start = std::time::Instant::now();
    let drained = wait_for_shielded_tasks(Duration::from_secs(5)).await;
    assert!(drained);
    assert!(start.elapsed() < Duration::from_millis(100));
    Ok(())
}

#[tokio::test]
async fn test_shielded_tasks_concurrent_drain() -> TestResult {
    let _guard = SHIELDED_TEST_LOCK.lock().await;
    wait_for_shielded_tasks(Duration::from_secs(2)).await;
    assert_eq!(active_shielded_tasks(), 0);

    let mut handles = Vec::new();
    for _ in 0..10 {
        let handle = tokio::spawn(async {
            let res = shielded(|| async {
                tokio::time::sleep(Duration::from_millis(15)).await;
                Ok::<u32, korgan::application::error::AppError>(100)
            })
            .await;
            assert_eq!(res.unwrap_or(0), 100);
        });
        handles.push(handle);
    }

    let drained = wait_for_shielded_tasks(Duration::from_secs(2)).await;
    assert!(drained);
    assert_eq!(active_shielded_tasks(), 0);

    for h in handles {
        h.await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Retention GC Worker
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_retention_gc_worker_execution() -> TestResult {
    let session_repo = Arc::new(MockSessionRepo::default());
    let user_repo = Arc::new(MockUserRepo::default());

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    let worker = RetentionGcWorker::new(
        session_repo.clone(),
        user_repo.clone(),
        Duration::from_millis(20),
        100,
        Duration::from_secs(86400 * 7),
    );

    let handle = tokio::spawn(worker.run(stop_rx));

    // Allow worker to run at least one tick
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Send shutdown signal
    stop_tx.send(true)?;
    handle.await?;

    assert!(session_repo.purged_count.load(Ordering::SeqCst) > 0);
    assert!(user_repo.purged_unverified_count.load(Ordering::SeqCst) > 0);

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Audit Log Cryptographic Hash Chaining & Tamper Detection
// ---------------------------------------------------------------------------

#[test]
fn test_audit_log_hash_chain_tamper_evidence() {
    let mut log1 = AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "account_created",
        AuditEventStatus::Success,
        serde_json::json!({ "user": "alice" }),
    );
    log1.chain_to(None);
    assert!(log1.verify_integrity(None));

    let mut log2 = AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "password_changed",
        AuditEventStatus::Success,
        serde_json::json!({ "method": "self_service" }),
    );
    log2.chain_to(log1.entry_hash.as_deref());
    assert!(log2.verify_integrity(log1.entry_hash.as_deref()));

    // Verify chain link
    assert_eq!(log2.prev_hash, log1.entry_hash);

    // Tampering with log1's metadata or status invalidates integrity
    log1.metadata = serde_json::json!({ "user": "alice_tampered" });
    assert!(!log1.verify_integrity(None));
}

#[tokio::test]
async fn test_event_worker_audit_log_cryptographic_chaining() -> TestResult {
    let audit_repo = Arc::new(MockAuditRepo::default());
    let mail_provider = Arc::new(ConsoleMailProvider::new("noreply@korgan.local"));
    let (event_bus, receiver) = EventBus::new(32);
    let worker = EventWorker::new(
        receiver,
        mail_provider,
        audit_repo.clone(),
        "https://korgan.local".to_string(),
    );

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let worker_handle = tokio::spawn(worker.run(stop_rx));

    // Dispatch Event 1
    let entry1 = AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "login_success",
        AuditEventStatus::Success,
        serde_json::json!({ "user": "alice" }),
    );
    event_bus.dispatch(AppEvent::LogAudit(Box::new(entry1)));

    // Dispatch Event 2
    let entry2 = AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "password_changed",
        AuditEventStatus::Success,
        serde_json::json!({ "user": "alice" }),
    );
    event_bus.dispatch(AppEvent::LogAudit(Box::new(entry2)));

    // Allow worker to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Stop worker
    stop_tx.send(true)?;
    worker_handle.await?;

    let entries = audit_repo.list_recent(10, 0).await?;
    assert_eq!(entries.len(), 2);

    let first = &entries[0];
    let second = &entries[1];

    // First entry has no prev_hash, but has entry_hash
    assert_eq!(first.prev_hash, None);
    assert!(first.entry_hash.is_some());
    assert!(first.verify_integrity(None));

    // Second entry chains to first entry's entry_hash
    assert_eq!(second.prev_hash, first.entry_hash);
    assert!(second.entry_hash.is_some());
    assert!(second.verify_integrity(first.entry_hash.as_deref()));

    Ok(())
}

#[tokio::test]
async fn test_event_worker_drains_buffered_events_on_shutdown() -> TestResult {
    let audit_repo = Arc::new(MockAuditRepo::default());
    let mail_provider = Arc::new(ConsoleMailProvider::new("noreply@korgan.local"));
    let (event_bus, receiver) = EventBus::new(64);
    let worker = EventWorker::new(
        receiver,
        mail_provider,
        audit_repo.clone(),
        "https://korgan.local".to_string(),
    );

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // Queue 5 audit events into the bus BEFORE starting the worker
    for i in 0..5 {
        let entry = AuditLog::new(
            None,
            None,
            None,
            RequestId::new(),
            format!("event_{i}"),
            AuditEventStatus::Success,
            serde_json::json!({ "index": i }),
        );
        event_bus.dispatch(AppEvent::LogAudit(Box::new(entry)));
    }

    // Immediately signal stop before or right as the worker starts
    stop_tx.send(true)?;
    let worker_handle = tokio::spawn(worker.run(stop_rx));
    worker_handle.await?;

    // All 5 events must have been drained cleanly by the drain loop
    let entries = audit_repo.list_recent(10, 0).await?;
    assert_eq!(entries.len(), 5);

    Ok(())
}

#[test]
fn test_process_memory_hardening_execution() {
    korgan::security::harden_process_memory();

    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };
        assert_eq!(ret, 0);
        assert_eq!(rlim.rlim_cur, 0);
    }
}

#[tokio::test]
async fn test_outbound_http_client_64kb_body_limit_enforcement() -> TestResult {
    use korgan::adapters::outbound::http_client::{
        MAX_OUTBOUND_RESPONSE_BYTES, read_response_body_limited,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                // Send 70 KB payload without Content-Length header to test streaming chunk enforcement
                let payload = vec![b'Z'; 70 * 1024];
                let header = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&payload).await;
            });
        }
    });

    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{addr}")).send().await?;
    let res = read_response_body_limited("test", resp, MAX_OUTBOUND_RESPONSE_BYTES).await;
    let Err(err) = res else {
        return Err("expected error from oversized response body".into());
    };
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("response body exceeded maximum allowed limit"),
        "unexpected error: {err_msg}"
    );

    Ok(())
}

#[tokio::test]
async fn test_outbound_http_client_content_length_limit_enforcement() -> TestResult {
    use korgan::adapters::outbound::http_client::{
        MAX_OUTBOUND_RESPONSE_BYTES, read_response_body_limited,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                // Send Content-Length: 1000000 (1 MB) with empty body
                let header =
                    "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(header.as_bytes()).await;
            });
        }
    });

    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{addr}")).send().await?;
    let res = read_response_body_limited("test", resp, MAX_OUTBOUND_RESPONSE_BYTES).await;
    let Err(err) = res else {
        return Err("expected error from oversized declared Content-Length".into());
    };
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Content-Length"),
        "unexpected error: {err_msg}"
    );

    Ok(())
}

#[tokio::test]
async fn test_step_up_revoked_session_returns_401_even_with_stale_auth_time() -> TestResult {
    let harness = create_test_harness()?;

    let user_id = UserId::new();
    let email = EmailAddress::parse("revoked_stale@example.com")?;
    let hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, Some(Username::new("revoked_stale")?), hash);
    user.id = user_id;
    user.status = AccountStatus::Active;
    harness.user_repo.create(&user).await?;

    let session = Session::new(
        user_id,
        "token_hash_revoked".to_string(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::TimeDelta::seconds(3600),
    );
    let session_id = session.id;
    harness.session_repo.create(&session).await?;

    // Now explicitly revoke the session
    harness
        .session_repo
        .revoke_by_id(&session_id, "test revocation")
        .await?;

    // Generate token with stale auth_time (16 minutes ago)
    let stale_auth_time = Utc::now().timestamp() - 960;
    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: "http://localhost:8080".to_owned(),
        aud: "korgan".to_owned(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: stale_auth_time,
        amr: vec!["pwd".to_owned()],
    };
    let token = harness.token_signer.sign_access_token(&claims)?;

    // DELETE /api/v1/sessions requires StepUpUser.
    // MUST return 401 Unauthorized because the session is revoked, NOT 403 Forbidden!
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/sessions")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;

    let res = harness.app.oneshot(req).await?;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "revoked session must yield 401 Unauthorized before checking step-up auth_time"
    );

    Ok(())
}

#[tokio::test]
async fn test_audit_log_concurrent_writers_produce_unforked_cryptographic_chain() -> TestResult {
    let audit_repo = Arc::new(MockAuditRepo::default());
    let mut handles = Vec::new();

    // Spawn 20 concurrent tasks writing audit records via append_and_chain
    for i in 0..20 {
        let repo = audit_repo.clone();
        let handle = tokio::spawn(async move {
            let mut entry = AuditLog::new(
                None,
                None,
                None,
                RequestId::new(),
                format!("concurrent_event_{i}"),
                AuditEventStatus::Success,
                serde_json::json!({ "index": i }),
            );
            repo.append_and_chain(&mut entry).await
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    let entries = audit_repo.list_recent(50, 0).await?;
    assert_eq!(
        entries.len(),
        20,
        "all 20 concurrent entries must be recorded"
    );

    // Verify unbroken, strictly linear cryptographic chain with zero forks
    assert_eq!(
        entries[0].prev_hash, None,
        "genesis entry must have None prev_hash"
    );
    assert!(
        entries[0].verify_integrity(None),
        "genesis entry integrity check failed"
    );

    for idx in 1..entries.len() {
        let prev = &entries[idx - 1];
        let curr = &entries[idx];

        assert_eq!(
            curr.prev_hash, prev.entry_hash,
            "entry at index {idx} has prev_hash {:?}, expected {:?} from prior entry (chain fork detected!)",
            curr.prev_hash, prev.entry_hash
        );
        assert!(
            curr.verify_integrity(prev.entry_hash.as_deref()),
            "entry at index {idx} failed cryptographic integrity verification"
        );
    }

    // Verify that VerifyAuditChainUseCase confirms entire chain is mathematically valid
    let verify_use_case =
        korgan::application::use_cases::admin::VerifyAuditChainUseCase::new(audit_repo);
    let verify_result = verify_use_case.execute().await?;
    assert_eq!(
        verify_result,
        korgan::application::use_cases::admin::AuditVerificationResult::Valid {
            verified_count: 20
        }
    );

    Ok(())
}

#[tokio::test]
async fn test_audit_log_high_concurrency_burst_resequences_out_of_order_events() -> TestResult {
    let audit_repo = Arc::new(MockAuditRepo::default());
    let mut handles = Vec::new();
    let num_events = 50;

    // Spawn 50 concurrent tasks with intentionally inverted/shuffled in-memory timestamps
    for i in 0..num_events {
        let repo = audit_repo.clone();
        let handle = tokio::spawn(async move {
            let mut entry = AuditLog::new(
                None,
                None,
                None,
                RequestId::new(),
                format!("burst_event_{i}"),
                AuditEventStatus::Success,
                serde_json::json!({ "burst_seq": i }),
            );
            // Simulate skewed / inverted in-memory creation timestamp (e.g. earlier for later events)
            entry.created_at = Utc::now() - chrono::Duration::seconds((num_events - i) as i64 * 10);
            repo.append_and_chain(&mut entry).await
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    let entries = audit_repo.list_all_chronological().await?;
    assert_eq!(
        entries.len(),
        num_events,
        "all {num_events} burst entries must be recorded"
    );

    // Verify strict microsecond monotonicity and unbroken hash chain
    for idx in 1..entries.len() {
        let prev = &entries[idx - 1];
        let curr = &entries[idx];

        assert!(
            curr.created_at > prev.created_at,
            "entry at index {idx} timestamp {} not strictly greater than prev timestamp {}",
            curr.created_at,
            prev.created_at
        );
        assert_eq!(
            curr.prev_hash, prev.entry_hash,
            "entry at index {idx} broken link (fork detected)"
        );
        assert!(
            curr.verify_integrity(prev.entry_hash.as_deref()),
            "entry at index {idx} failed cryptographic integrity verification"
        );
    }

    // Verify via VerifyAuditChainUseCase
    let verify_use_case =
        korgan::application::use_cases::admin::VerifyAuditChainUseCase::new(audit_repo);
    let verify_result = verify_use_case.execute().await?;
    assert_eq!(
        verify_result,
        korgan::application::use_cases::admin::AuditVerificationResult::Valid {
            verified_count: num_events
        }
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Audit Delimiter Collision & Anti-Enumeration Hardening Tests
// ---------------------------------------------------------------------------

struct CountingPasswordHasher {
    inner: Argon2PasswordHasher,
    dummy_count: std::sync::atomic::AtomicUsize,
}

impl CountingPasswordHasher {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let inner = Argon2PasswordHasher::new(1024, 1, 1)?;
        Ok(Self {
            inner,
            dummy_count: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl PasswordHasher for CountingPasswordHasher {
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
        self.inner.verify_against_dummy_hash(password).await
    }

    async fn compute_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError> {
        self.dummy_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.compute_dummy_hash(password).await
    }
}

#[test]
fn test_audit_log_hash_canonical_delimiter_collision_resistance() {
    let req_id = RequestId::new();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    let fixed_time = Utc::now();
    let shared_id = AuditLogId::new();

    // Entry 1: actor_ip is None, user_agent is "127.0.0.1"
    let mut entry1 = AuditLog::new(
        None,
        None,
        Some("127.0.0.1".to_string()),
        req_id,
        "test_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry1.id = shared_id;
    entry1.created_at = fixed_time;

    // Entry 2: actor_ip is 127.0.0.1, user_agent is None
    let mut entry2 = AuditLog::new(
        None,
        Some(ip),
        None,
        req_id,
        "test_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry2.id = shared_id;
    entry2.created_at = fixed_time;

    let hash1 = entry1.compute_entry_hash(None);
    let hash2 = entry2.compute_entry_hash(None);

    // Canonical delimiters must guarantee distinct hashes despite identical character sequences
    assert_ne!(
        hash1, hash2,
        "Collision detected: actor_ip and user_agent fields must not produce identical hash!"
    );

    // Entry 3: user_id is None, actor_ip is None, user_agent is None
    let mut entry3 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "test_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry3.id = shared_id;
    entry3.created_at = fixed_time;

    let hash3 = entry3.compute_entry_hash(None);
    assert_ne!(hash1, hash3);
    assert_ne!(hash2, hash3);
}

#[tokio::test]
async fn test_register_conflict_timing_anti_enumeration() -> TestResult {
    use korgan::application::dto::RegisterCommand;
    use korgan::application::error::AppError;
    use korgan::application::use_cases::RegisterUserUseCase;

    let user_repo = Arc::new(MockUserRepo::default());
    let password_hasher = Arc::new(CountingPasswordHasher::new()?);
    let token_store = Arc::new(MockTokenStore);
    let hibp_client = Arc::new(NoopHibpClient);
    let (event_bus, _rx) = EventBus::new(100);

    let use_case = RegisterUserUseCase::new(
        user_repo.clone(),
        password_hasher.clone(),
        token_store.clone(),
        hibp_client.clone(),
        event_bus,
        Duration::from_secs(86400),
    );

    // Initial valid registration
    let cmd1 = RegisterCommand {
        email: "alice_crypto@example.com".to_owned(),
        password: "StrongPassword123!".to_owned(),
        username: Some("alice_crypto".to_owned()),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    use_case.execute(cmd1).await?;
    assert_eq!(
        password_hasher.dummy_count.load(Ordering::SeqCst),
        0,
        "Successful registration must not invoke dummy hash"
    );

    // Conflict 1: Duplicate email must invoke compute_dummy_hash
    let cmd_dup_email = RegisterCommand {
        email: "alice_crypto@example.com".to_owned(),
        password: "StrongPassword123!".to_owned(),
        username: Some("other_user".to_owned()),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    match use_case.execute(cmd_dup_email).await {
        Err(AppError::Conflict) => {}
        other => return Err(format!("expected Conflict, got {other:?}").into()),
    }
    assert_eq!(
        password_hasher.dummy_count.load(Ordering::SeqCst),
        1,
        "Duplicate email conflict must invoke dummy hash calculation"
    );

    // Conflict 2: Duplicate username must invoke compute_dummy_hash
    let cmd_dup_username = RegisterCommand {
        email: "alice_crypto_new@example.com".to_owned(),
        password: "StrongPassword123!".to_owned(),
        username: Some("alice_crypto".to_owned()),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };
    match use_case.execute(cmd_dup_username).await {
        Err(AppError::Conflict) => {}
        other => return Err(format!("expected Conflict, got {other:?}").into()),
    }
    assert_eq!(
        password_hasher.dummy_count.load(Ordering::SeqCst),
        2,
        "Duplicate username conflict must invoke dummy hash calculation"
    );

    Ok(())
}
