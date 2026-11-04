//! Integration tests for CLI management commands: audit chain verification,
//! superadmin bootstrap, and user account unlocking.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use korgan::adapters::inbound::cli::{
    CliError, handle_audit_verify, handle_bootstrap, handle_user_unlock,
};
use korgan::adapters::inbound::http::AppState;
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::error::AppError;
use korgan::application::use_cases::admin::AuditVerificationResult;
use korgan::application::workers::{EventBus, EventWorker};
use korgan::config::Settings;
use korgan::domain::entities::{
    AccountStatus, AuditEventStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User,
    UserMfa, UserRole,
};
use korgan::domain::value_objects::*;
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{OAuthProviderPort, WebAuthnService};
use secrecy::ExposeSecret;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

#[derive(Default, Debug)]
struct CliTestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
    emails: Mutex<HashMap<String, UserId>>,
}

#[async_trait]
impl UserRepository for CliTestUserRepo {
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

    async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, PortError> {
        Ok(None)
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
        emails.insert(user.email.as_str().to_owned(), user.id);
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

    async fn list_paginated(&self, _limit: u32, _offset: u64) -> Result<Vec<User>, PortError> {
        Ok(Vec::new())
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
struct CliTestAuditRepo {
    logs: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for CliTestAuditRepo {
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
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }

    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
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

    async fn append_and_chain(&self, entry: &mut AuditLog) -> Result<(), PortError> {
        let prev = {
            let logs = self
                .logs
                .lock()
                .map_err(|e| PortError::database(e.to_string()))?;
            logs.last().and_then(|l| l.entry_hash.clone())
        };
        entry.chain_to(prev.as_deref());
        self.append(entry).await
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
struct CliTestSessionRepo;

#[async_trait]
impl SessionRepository for CliTestSessionRepo {
    async fn create(&self, _s: &Session) -> Result<(), PortError> {
        Ok(())
    }
    async fn find_by_id(&self, _id: &SessionId) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn find_by_token_hash(&self, _th: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn list_by_user_id(
        &self,
        _uid: &UserId,
        _l: u32,
        _o: u64,
    ) -> Result<Vec<Session>, PortError> {
        Ok(Vec::new())
    }
    async fn update(&self, _s: &Session) -> Result<(), PortError> {
        Ok(())
    }
    async fn replace_atomic(&self, _th: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn rotate_atomic(
        &self,
        _old: &str,
        _new: &Session,
    ) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn revoke_by_id(&self, _id: &SessionId, _r: &str) -> Result<(), PortError> {
        Ok(())
    }
    async fn revoke_by_id_and_user_id(
        &self,
        _id: &SessionId,
        _uid: &UserId,
        _r: &str,
    ) -> Result<Option<SessionId>, PortError> {
        Ok(None)
    }
    async fn revoke_family(
        &self,
        _fid: &TokenFamilyId,
        _r: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }
    async fn revoke_all_user_sessions(
        &self,
        _uid: &UserId,
        _ex: Option<&SessionId>,
        _r: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }
    async fn purge_expired(&self, _m: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct CliTestTokenStore;

#[async_trait]
impl TokenStore for CliTestTokenStore {
    async fn set_token(&self, _k: &str, _v: &str, _t: Duration) -> Result<(), PortError> {
        Ok(())
    }
    async fn set_if_not_exists(&self, _k: &str, _v: &str, _t: Duration) -> Result<bool, PortError> {
        Ok(true)
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
    async fn consume_token(&self, _k: &str, _h: &str) -> Result<bool, PortError> {
        Ok(true)
    }
}

#[derive(Default, Debug)]
struct CliTestRateLimiter;

#[async_trait]
impl RateLimiterPort for CliTestRateLimiter {
    async fn check_and_increment(
        &self,
        _key: &str,
        limit: u32,
        _window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        Ok(RateLimitStatus {
            allowed: true,
            limit,
            remaining: limit,
            reset_epoch_secs: Utc::now().timestamp() as u64 + 60,
            retry_after_secs: None,
        })
    }
    async fn reset(&self, _key: &str) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
struct CliTestOAuthAccountRepo;

#[async_trait]
impl OAuthAccountRepository for CliTestOAuthAccountRepo {
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
struct CliTestPasskeyRepo;

#[async_trait]
impl PasskeyRepository for CliTestPasskeyRepo {
    async fn save(&self, _p: &Passkey) -> Result<(), PortError> {
        Ok(())
    }
    async fn find_by_credential_id(&self, _cid: &[u8]) -> Result<Option<Passkey>, PortError> {
        Ok(None)
    }
    async fn find_by_id(&self, _id: &PasskeyId) -> Result<Option<Passkey>, PortError> {
        Ok(None)
    }
    async fn list_by_user_id(&self, _uid: &UserId) -> Result<Vec<Passkey>, PortError> {
        Ok(Vec::new())
    }
    async fn delete_by_id(&self, _pid: &PasskeyId) -> Result<(), PortError> {
        Ok(())
    }
    async fn delete_by_id_and_user_id(
        &self,
        _pid: &PasskeyId,
        _uid: &UserId,
    ) -> Result<bool, PortError> {
        Ok(true)
    }
}

struct CliHarness {
    state: AppState,
    user_repo: Arc<CliTestUserRepo>,
    audit_repo: Arc<CliTestAuditRepo>,
    worker: EventWorker,
}

async fn setup_cli_harness() -> TestResult<CliHarness> {
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
    let user_repo = Arc::new(CliTestUserRepo::default());
    let session_repo = Arc::new(CliTestSessionRepo);
    let audit_repo = Arc::new(CliTestAuditRepo::default());
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> = Arc::new(CliTestOAuthAccountRepo);
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(CliTestPasskeyRepo);
    let token_store = Arc::new(CliTestTokenStore);
    let rate_limiter = Arc::new(CliTestRateLimiter);

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
    let pg_pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_cfg = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        user_repo.clone(),
        session_repo,
        audit_repo.clone(),
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

    Ok(CliHarness {
        state,
        user_repo,
        audit_repo,
        worker,
    })
}

#[tokio::test]
async fn test_audit_log_cryptographic_verification_and_tamper_detection() -> TestResult {
    let harness = setup_cli_harness().await?;

    // 1. Empty audit log table should report valid with 0 records
    let res = harness.state.verify_audit_chain_use_case.execute().await?;
    assert_eq!(res, AuditVerificationResult::Valid { verified_count: 0 });

    // 2. Build a valid chained sequence of 3 audit logs
    let req_id = RequestId::new();
    let mut entry1 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "test_event_1",
        AuditEventStatus::Success,
        serde_json::json!({"action": "first"}),
    );
    entry1.chain_to(None);
    harness.audit_repo.append(&entry1).await?;

    let mut entry2 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "test_event_2",
        AuditEventStatus::Success,
        serde_json::json!({"action": "second"}),
    );
    entry2.chain_to(entry1.entry_hash.as_deref());
    harness.audit_repo.append(&entry2).await?;

    let mut entry3 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "test_event_3",
        AuditEventStatus::Success,
        serde_json::json!({"action": "third"}),
    );
    entry3.chain_to(entry2.entry_hash.as_deref());
    harness.audit_repo.append(&entry3).await?;

    // Verify valid chain via use case
    let res = harness.state.verify_audit_chain_use_case.execute().await?;
    assert_eq!(res, AuditVerificationResult::Valid { verified_count: 3 });

    // Verify valid chain via CLI handler
    handle_audit_verify(&harness.state).await?;

    // 3. Tamper with entry2 in the repository (e.g. modify metadata)
    {
        let mut logs = harness.audit_repo.logs.lock().map_err(|e| e.to_string())?;
        logs[1].metadata = serde_json::json!({"action": "tampered_by_attacker"});
    }

    // Verify tamper detection via use case
    let res_tampered = harness.state.verify_audit_chain_use_case.execute().await?;
    match res_tampered {
        AuditVerificationResult::Corrupted(broken) => {
            assert_eq!(broken.record_index, 1);
            assert_eq!(broken.log_id, entry2.id.to_string());
            assert!(broken.reason.contains("Hash mismatch"));
        }
        AuditVerificationResult::Valid { .. } => {
            return Err("Expected chain verification to detect tampering in record 1".into());
        }
    }

    // Verify tamper detection via CLI handler returns CliError::AuditCorrupted
    let cli_res = handle_audit_verify(&harness.state).await;
    match cli_res {
        Err(CliError::AuditCorrupted(log_id)) => {
            assert_eq!(log_id, entry2.id.to_string());
        }
        other => {
            return Err(format!("Expected CliError::AuditCorrupted, got {:?}", other).into());
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_superadmin_bootstrap_lifecycle_and_rejection_when_admin_exists() -> TestResult {
    let mut harness = setup_cli_harness().await?;

    // 1. Initial bootstrap should succeed and create a superadmin
    let superadmin = harness
        .state
        .bootstrap_use_case
        .execute("superadmin@korgan.internal", "SuperAdminPassword123!")
        .await?;

    assert_eq!(superadmin.email.as_str(), "superadmin@korgan.internal");
    assert_eq!(superadmin.role, UserRole::Superadmin);
    assert_eq!(superadmin.status, AccountStatus::Active);
    assert!(superadmin.email_verified_at.is_some());

    // Verify audit log was emitted and properly drained
    harness.worker.drain().await;
    {
        let logs = harness.audit_repo.logs.lock().map_err(|e| e.to_string())?;
        assert_eq!(logs.len(), 1, "audit log should be written on bootstrap");
        assert_eq!(logs[0].event_type, "bootstrap_superadmin");
        assert_eq!(logs[0].user_id, Some(superadmin.id));
    }

    // Verify persisted in repo
    let found = harness
        .user_repo
        .find_by_email(&superadmin.email)
        .await?
        .ok_or("superadmin must exist in user repo")?;
    assert_eq!(found.role, UserRole::Superadmin);
    assert_eq!(found.status, AccountStatus::Active);

    // 2. Second bootstrap attempt must be rejected because an admin exists
    let second_attempt = harness
        .state
        .bootstrap_use_case
        .execute("hacker@example.com", "HackerPassword123!")
        .await;

    match second_attempt {
        Err(AppError::Forbidden) => {}
        other => return Err(format!("Expected AppError::Forbidden, got {:?}", other).into()),
    }

    // 3. Test CLI handler rejection
    let cli_err = handle_bootstrap(
        &harness.state,
        "second_super@example.com",
        "SecondSuperPassword123!",
    )
    .await;
    assert!(
        cli_err.is_err(),
        "CLI bootstrap must fail when admin exists"
    );

    Ok(())
}

#[tokio::test]
async fn test_user_unlock_lifecycle() -> TestResult {
    let mut harness = setup_cli_harness().await?;

    // 1. Create locked user with 5 failed login attempts and future lockout
    let email = EmailAddress::parse("locked_user@example.com")?;
    let dummy_hash = harness
        .state
        .password_hasher
        .hash_password(&RawPassword::new("SecretPass123!")?)
        .await?;

    let mut user = User::new(email.clone(), None, dummy_hash);
    user.failed_login_attempts = 5;
    user.locked_until = Some(Utc::now() + chrono::Duration::hours(2));
    harness.user_repo.create(&user).await?;

    // 2. Execute user unlock via use case
    harness
        .state
        .unlock_user_use_case
        .execute("locked_user@example.com")
        .await?;

    // Drain background worker to process audit events
    harness.worker.drain().await;

    // Verify audit log was emitted and properly drained
    {
        let logs = harness.audit_repo.logs.lock().map_err(|e| e.to_string())?;
        assert!(
            logs.iter()
                .any(|l| l.event_type == "user_unlocked" && l.user_id == Some(user.id)),
            "user_unlocked audit log must be recorded"
        );
    }

    // Verify user is unlocked in repository
    let unlocked = harness
        .user_repo
        .find_by_email(&email)
        .await?
        .ok_or("user must exist")?;
    assert_eq!(unlocked.failed_login_attempts, 0);
    assert!(unlocked.locked_until.is_none());

    // 3. Test CLI handler unlocking
    // Lock user again
    {
        let mut users = harness.user_repo.users.lock().map_err(|e| e.to_string())?;
        if let Some(u) = users.get_mut(&user.id) {
            u.failed_login_attempts = 3;
            u.locked_until = Some(Utc::now() + chrono::Duration::minutes(30));
        }
    }
    handle_user_unlock(&harness.state, "locked_user@example.com").await?;
    harness.worker.drain().await;

    let re_unlocked = harness
        .user_repo
        .find_by_email(&email)
        .await?
        .ok_or("user must exist")?;
    assert_eq!(re_unlocked.failed_login_attempts, 0);
    assert!(re_unlocked.locked_until.is_none());

    // 4. Unlocking non-existent user should fail with NotFound
    let non_existent = harness
        .state
        .unlock_user_use_case
        .execute("nobody@example.com")
        .await;
    match non_existent {
        Err(AppError::NotFound) => {}
        other => return Err(format!("Expected AppError::NotFound, got {:?}", other).into()),
    }

    Ok(())
}

#[tokio::test]
async fn test_superadmin_bootstrap_validation_edge_cases() -> TestResult {
    let harness = setup_cli_harness().await?;

    // 1. Password too short (<8 chars) must fail validation
    let short_pw = harness
        .state
        .bootstrap_use_case
        .execute("admin@korgan.internal", "short")
        .await;
    match short_pw {
        Err(AppError::Validation(violations)) => {
            assert!(violations.iter().any(|v| v.field == "password"));
        }
        other => return Err(format!("Expected AppError::Validation, got {:?}", other).into()),
    }

    // 2. Invalid email format must fail validation
    let bad_email = harness
        .state
        .bootstrap_use_case
        .execute("not-an-email", "ValidPassword123!")
        .await;
    assert!(bad_email.is_err(), "Invalid email format must be rejected");

    // 3. Existing regular user conflict: create regular user first
    let email = EmailAddress::parse("regular@example.com")?;
    let dummy_hash = harness
        .state
        .password_hasher
        .hash_password(&RawPassword::new("RegularPass123!")?)
        .await?;
    let reg_user = User::new(email, None, dummy_hash);
    harness.user_repo.create(&reg_user).await?;

    // Attempting bootstrap with the same email must return Conflict
    let conflict_res = harness
        .state
        .bootstrap_use_case
        .execute("regular@example.com", "NewAdminPass123!")
        .await;
    match conflict_res {
        Err(AppError::Conflict) => {}
        other => return Err(format!("Expected AppError::Conflict, got {:?}", other).into()),
    }

    Ok(())
}

#[tokio::test]
async fn test_user_unlock_idempotency_and_invalid_email() -> TestResult {
    let harness = setup_cli_harness().await?;

    // 1. Invalid email format returns validation error
    let bad_email = harness
        .state
        .unlock_user_use_case
        .execute("invalid-email-format")
        .await;
    assert!(
        bad_email.is_err(),
        "Invalid email should return validation error"
    );

    // 2. Unlocking an already active, non-locked user is idempotent
    let email = EmailAddress::parse("active_user@example.com")?;
    let dummy_hash = harness
        .state
        .password_hasher
        .hash_password(&RawPassword::new("Pass1234567!")?)
        .await?;
    let user = User::new(email, None, dummy_hash);
    harness.user_repo.create(&user).await?;

    // Unlock already unlocked user -> Ok(())
    harness
        .state
        .unlock_user_use_case
        .execute("active_user@example.com")
        .await?;

    Ok(())
}
