//! Empirical Adversarial Verification Suite:
//! - AuditLog compute_entry_hash delimiter collision resistance & domain separator isolation
//! - Registration timing anti-enumeration & Argon2id parameter parity
//! - MFA enablement atomicity & rollback under injected failure

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use korgan::adapters::outbound::crypto::Argon2PasswordHasher;
use korgan::application::dto::{EnableTotpCommand, RegisterCommand};
use korgan::application::error::AppError;
use korgan::application::use_cases::RegisterUserUseCase;
use korgan::application::use_cases::mfa::enable::EnableTotpUseCase;
use korgan::application::use_cases::token_utils::encode_base32;
use korgan::application::workers::EventBus;
use korgan::domain::entities::{AuditEventStatus, AuditLog, User, UserMfa};
use korgan::domain::value_objects::*;
use korgan::ports::cache::TokenStore;
use korgan::ports::errors::PortError;
use korgan::ports::repositories::UserRepository;
use korgan::ports::services::{HibpClient, PasswordHasher, SecretCipher, TotpService};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// ===========================================================================
// SECTION 1: Cryptographic Boundary & Domain Separation Stress Tests
// ===========================================================================

#[test]
fn test_vuln07_actor_ip_vs_user_agent_boundary_shifting() {
    let req_id = RequestId::new();
    let fixed_time = Utc::now();
    let shared_id = AuditLogId::new();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // Case 1: actor_ip is None, user_agent is "192.168.1.100"
    let mut entry_a = AuditLog::new(
        None,
        None,
        Some("192.168.1.100".to_string()),
        req_id,
        "auth_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_a.id = shared_id;
    entry_a.created_at = fixed_time;

    // Case 2: actor_ip is 192.168.1.100, user_agent is None
    let mut entry_b = AuditLog::new(
        None,
        Some(ip),
        None,
        req_id,
        "auth_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_b.id = shared_id;
    entry_b.created_at = fixed_time;

    // Case 3: actor_ip is 192.168.1.100, user_agent is "Mozilla/5.0"
    let mut entry_c = AuditLog::new(
        None,
        Some(ip),
        Some("Mozilla/5.0".to_string()),
        req_id,
        "auth_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_c.id = shared_id;
    entry_c.created_at = fixed_time;

    // Case 4: Boundary shift attack: actor_ip is None, user_agent is "192.168.1.100|Mozilla/5.0"
    let mut entry_d = AuditLog::new(
        None,
        None,
        Some("192.168.1.100|Mozilla/5.0".to_string()),
        req_id,
        "auth_event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_d.id = shared_id;
    entry_d.created_at = fixed_time;

    let hash_a = entry_a.compute_entry_hash(None);
    let hash_b = entry_b.compute_entry_hash(None);
    let hash_c = entry_c.compute_entry_hash(None);
    let hash_d = entry_d.compute_entry_hash(None);

    assert_ne!(hash_a, hash_b, "actor_ip vs user_agent collision detected!");
    assert_ne!(
        hash_c, hash_d,
        "Boundary shifting delimiter injection attack succeeded!"
    );
    assert_ne!(hash_a, hash_c);
    assert_ne!(hash_b, hash_d);
}

#[test]
fn test_vuln07_request_id_vs_event_type_boundary_shifting() {
    let fixed_time = Utc::now();
    let shared_id = AuditLogId::new();
    let req_a = RequestId::new();
    let req_b = RequestId::new();

    // Entry A: normal request_id and event_type
    let mut entry_a = AuditLog::new(
        None,
        None,
        None,
        req_a,
        "login_success",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_a.id = shared_id;
    entry_a.created_at = fixed_time;

    // Entry B: attacker crafts event_type with embedded pipe and request_a string
    let mut entry_b = AuditLog::new(
        None,
        None,
        None,
        req_b,
        format!("{req_a}|login_success"),
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_b.id = shared_id;
    entry_b.created_at = fixed_time;

    let hash_a = entry_a.compute_entry_hash(None);
    let hash_b = entry_b.compute_entry_hash(None);

    assert_ne!(
        hash_a, hash_b,
        "Collision between request_id and event_type!"
    );
}

#[test]
fn test_vuln07_none_vs_some_empty_string_semantic_isolation() {
    let req_id = RequestId::new();
    let fixed_time = Utc::now();
    let shared_id = AuditLogId::new();

    // Entry 1: user_agent is None
    let mut entry_none = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_none.id = shared_id;
    entry_none.created_at = fixed_time;

    // Entry 2: user_agent is Some("")
    let mut entry_empty = AuditLog::new(
        None,
        None,
        Some("".to_string()),
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_empty.id = shared_id;
    entry_empty.created_at = fixed_time;

    let hash_none = entry_none.compute_entry_hash(None);
    let hash_empty = entry_empty.compute_entry_hash(None);

    // Verify semantic equivalence: empty string in optional slot behaves identically to absent slot
    assert_eq!(
        hash_none, hash_empty,
        "None and Some(\"\") must evaluate to the same canonical empty slot representation"
    );

    // CRITICAL ADVERSARIAL CHECK: Does Some("") bleed or collide with non-empty user_agents or pipe delimiters?
    let mut entry_pipe = AuditLog::new(
        None,
        None,
        Some("|".to_string()),
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_pipe.id = shared_id;
    entry_pipe.created_at = fixed_time;

    let mut entry_space = AuditLog::new(
        None,
        None,
        Some(" ".to_string()),
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({}),
    );
    entry_space.id = shared_id;
    entry_space.created_at = fixed_time;

    let hash_pipe = entry_pipe.compute_entry_hash(None);
    let hash_space = entry_space.compute_entry_hash(None);

    assert_ne!(
        hash_none, hash_pipe,
        "Empty slot collided with pipe literal!"
    );
    assert_ne!(
        hash_none, hash_space,
        "Empty slot collided with whitespace!"
    );
}

#[test]
fn test_vuln07_domain_separator_isolation_from_generic_sha256() {
    let req_id = RequestId::new();
    let entry = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "test_event",
        AuditEventStatus::Success,
        serde_json::json!({ "key": "val" }),
    );

    let audit_hash = entry.compute_entry_hash(None);

    // Compute generic SHA-256 over exact concatenated fields without domain separator
    let mut generic_hasher = Sha256::new();
    generic_hasher.update(b"GENESIS");
    generic_hasher.update(b"|");
    generic_hasher.update(entry.id.to_string().as_bytes());
    generic_hasher.update(b"|");
    generic_hasher.update(b"|"); // user_id
    generic_hasher.update(b"|"); // actor_ip
    generic_hasher.update(b"|"); // user_agent
    generic_hasher.update(entry.request_id.to_string().as_bytes());
    generic_hasher.update(b"|");
    generic_hasher.update(entry.event_type.as_bytes());
    generic_hasher.update(b"|");
    generic_hasher.update(entry.event_status.as_str().as_bytes());
    generic_hasher.update(b"|");
    generic_hasher.update(entry.created_at.timestamp().to_string().as_bytes());
    generic_hasher.update(b"|");
    generic_hasher.update(entry.metadata.to_string().as_bytes());

    let generic_digest = generic_hasher.finalize();
    use std::fmt::Write;
    let mut generic_hex = String::with_capacity(64);
    for b in generic_digest {
        let _ = write!(generic_hex, "{b:02x}");
    }

    assert_ne!(
        audit_hash, generic_hex,
        "Domain separator b\"KORGAN_AUDIT_V1\\0\" must isolate audit log hashes from generic SHA-256!"
    );

    // Also assert that version change (e.g. V2) produces distinct domain separation
    let mut v2_hasher = Sha256::new();
    v2_hasher.update(b"KORGAN_AUDIT_V2\0");
    v2_hasher.update(b"GENESIS|");
    v2_hasher.update(entry.id.to_string().as_bytes());
    v2_hasher.update(b"||||");
    v2_hasher.update(entry.request_id.to_string().as_bytes());
    v2_hasher.update(b"|");
    v2_hasher.update(entry.event_type.as_bytes());
    v2_hasher.update(b"|");
    v2_hasher.update(entry.event_status.as_str().as_bytes());
    v2_hasher.update(b"|");
    v2_hasher.update(entry.created_at.timestamp().to_string().as_bytes());
    v2_hasher.update(b"|");
    v2_hasher.update(entry.metadata.to_string().as_bytes());
    let v2_digest = v2_hasher.finalize();
    let mut v2_hex = String::with_capacity(64);
    for b in v2_digest {
        let _ = write!(v2_hex, "{b:02x}");
    }

    assert_ne!(
        audit_hash, v2_hex,
        "Domain separator versioning must be strictly distinct!"
    );
}

#[test]
fn test_vuln07_metadata_json_adversarial_pipe_injection() {
    let req_id = RequestId::new();
    let shared_id = AuditLogId::new();
    let fixed_time = Utc::now();

    // Entry 1: metadata contains pipe in key and value
    let mut entry1 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({ "field|pipe": "val|1" }),
    );
    entry1.id = shared_id;
    entry1.created_at = fixed_time;

    // Entry 2: different metadata structure
    let mut entry2 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event",
        AuditEventStatus::Success,
        serde_json::json!({ "field": "pipe|val|1" }),
    );
    entry2.id = shared_id;
    entry2.created_at = fixed_time;

    assert_ne!(
        entry1.compute_entry_hash(None),
        entry2.compute_entry_hash(None),
        "Metadata with embedded pipes must not cause collisions between distinct JSON documents"
    );
}

// ===========================================================================
// SECTION 2: Empirical Anti-Enumeration & Timing Invariants
// ===========================================================================

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<HashMap<UserId, User>>,
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

    async fn update_username(
        &self,
        _user_id: &UserId,
        _new_username: Option<&Username>,
    ) -> Result<(), PortError> {
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

    async fn enable_mfa(&self, _mfa: &UserMfa) -> Result<(), PortError> {
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
        _max_attempts: u16,
        _lockout_until: chrono::DateTime<Utc>,
        _now: chrono::DateTime<Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<Utc>>), PortError> {
        Ok((0, None))
    }

    async fn reset_failed_logins(
        &self,
        _user_id: &UserId,
        _now: chrono::DateTime<Utc>,
    ) -> Result<(), PortError> {
        Ok(())
    }

    async fn list_paginated(&self, _limit: u32, _offset: u64) -> Result<Vec<User>, PortError> {
        Ok(Vec::new())
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        Ok(0)
    }

    async fn purge_expired_unverified(
        &self,
        _created_before: chrono::DateTime<Utc>,
        _max_purge: u32,
    ) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default)]
struct MockTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for MockTokenStore {
    async fn set_token(&self, k: &str, v: &str, _ttl: Duration) -> Result<(), PortError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        map.insert(k.to_string(), v.to_string());
        Ok(())
    }

    async fn get_token(&self, k: &str) -> Result<Option<String>, PortError> {
        let map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(map.get(k).cloned())
    }

    async fn delete_token(&self, k: &str) -> Result<(), PortError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        map.remove(k);
        Ok(())
    }

    async fn get_and_delete(&self, k: &str) -> Result<Option<String>, PortError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(map.remove(k))
    }

    async fn consume_token(&self, k: &str, _expected: &str) -> Result<bool, PortError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        Ok(map.remove(k).is_some())
    }

    async fn set_if_not_exists(&self, k: &str, v: &str, _ttl: Duration) -> Result<bool, PortError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if map.contains_key(k) {
            Ok(false)
        } else {
            map.insert(k.to_string(), v.to_string());
            Ok(true)
        }
    }
}

struct MockHibp;

#[async_trait]
impl HibpClient for MockHibp {
    async fn is_password_breached(&self, _password: &RawPassword) -> Result<bool, PortError> {
        Ok(false)
    }
}

struct AdversarialSpyPasswordHasher {
    inner: Argon2PasswordHasher,
    pub real_hash_count: AtomicUsize,
    pub dummy_hash_count: AtomicUsize,
}

impl AdversarialSpyPasswordHasher {
    fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, PortError> {
        let inner = Argon2PasswordHasher::new(memory_kib, iterations, parallelism)?;
        Ok(Self {
            inner,
            real_hash_count: AtomicUsize::new(0),
            dummy_hash_count: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl PasswordHasher for AdversarialSpyPasswordHasher {
    async fn hash_password(&self, password: &RawPassword) -> Result<PasswordHash, PortError> {
        self.real_hash_count.fetch_add(1, Ordering::SeqCst);
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
        self.dummy_hash_count.fetch_add(1, Ordering::SeqCst);
        self.inner.compute_dummy_hash(password).await
    }
}

#[tokio::test]
async fn test_vuln10_registration_timing_and_execution_invariants() -> TestResult {
    let user_repo = Arc::new(MockUserRepo::default());
    // 2048 KiB, 1 iteration, 1 thread for clear CPU measurement
    let spy_hasher = Arc::new(AdversarialSpyPasswordHasher::new(2048, 1, 1)?);
    let token_store = Arc::new(MockTokenStore::default());
    let hibp_client = Arc::new(MockHibp);
    let (event_bus, _rx) = EventBus::new(10);

    let use_case = RegisterUserUseCase::new(
        user_repo.clone(),
        spy_hasher.clone(),
        token_store.clone(),
        hibp_client.clone(),
        event_bus,
        Duration::from_secs(86400),
    );

    // Baseline: New user registration
    let t0 = Instant::now();
    let res1 = use_case
        .execute(RegisterCommand {
            email: "alice@example.com".to_owned(),
            password: "CorrectHorseBatteryStaple!123".to_owned(),
            username: Some("alice".to_owned()),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await;
    let dur_new = t0.elapsed();
    assert!(res1.is_ok(), "Initial user registration should succeed");
    assert_eq!(spy_hasher.real_hash_count.load(Ordering::SeqCst), 1);
    assert_eq!(spy_hasher.dummy_hash_count.load(Ordering::SeqCst), 0);

    // Adversarial Challenge 1: Registration with existing email
    let t1 = Instant::now();
    let res2 = use_case
        .execute(RegisterCommand {
            email: "alice@example.com".to_owned(),
            password: "CorrectHorseBatteryStaple!123".to_owned(),
            username: Some("alice_other".to_owned()),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await;
    let dur_dup_email = t1.elapsed();
    match res2 {
        Err(AppError::Conflict) => {}
        other => return Err(format!("Expected Conflict, got {other:?}").into()),
    }
    assert_eq!(spy_hasher.real_hash_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        spy_hasher.dummy_hash_count.load(Ordering::SeqCst),
        1,
        "Duplicate email MUST invoke compute_dummy_hash"
    );

    // Adversarial Challenge 2: Registration with existing username
    let t2 = Instant::now();
    let res3 = use_case
        .execute(RegisterCommand {
            email: "alice_brand_new@example.com".to_owned(),
            password: "CorrectHorseBatteryStaple!123".to_owned(),
            username: Some("alice".to_owned()),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await;
    let dur_dup_username = t2.elapsed();
    match res3 {
        Err(AppError::Conflict) => {}
        other => return Err(format!("Expected Conflict, got {other:?}").into()),
    }
    assert_eq!(spy_hasher.real_hash_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        spy_hasher.dummy_hash_count.load(Ordering::SeqCst),
        2,
        "Duplicate username MUST invoke compute_dummy_hash"
    );

    // Adversarial Challenge 3: Registration with BOTH duplicate email and duplicate username
    let t3 = Instant::now();
    let res4 = use_case
        .execute(RegisterCommand {
            email: "alice@example.com".to_owned(),
            password: "CorrectHorseBatteryStaple!123".to_owned(),
            username: Some("alice".to_owned()),
            ip_address: None,
            user_agent: None,
            request_id: RequestId::new(),
        })
        .await;
    let dur_both = t3.elapsed();
    match res4 {
        Err(AppError::Conflict) => {}
        other => return Err(format!("Expected Conflict, got {other:?}").into()),
    }
    assert_eq!(
        spy_hasher.dummy_hash_count.load(Ordering::SeqCst),
        3,
        "Duplicate email+username must execute dummy hash exactly once (no double penalty)"
    );

    println!(
        "TIMING VERIFICATION: new_user={:?}, dup_email={:?}, dup_username={:?}, dup_both={:?}",
        dur_new, dur_dup_email, dur_dup_username, dur_both
    );

    // Assert that no timing shortcut exists (each must take > 1ms because of Argon2id)
    assert!(
        dur_dup_email >= Duration::from_millis(1),
        "Duplicate email returned suspiciously fast ({:?}) - possible timing shortcut!",
        dur_dup_email
    );
    assert!(
        dur_dup_username >= Duration::from_millis(1),
        "Duplicate username returned suspiciously fast ({:?}) - possible timing shortcut!",
        dur_dup_username
    );

    Ok(())
}

// ===========================================================================
// SECTION 3: MFA Enablement Atomicity & Rollback Verification
// ===========================================================================

struct MockTotpServiceValid;

impl TotpService for MockTotpServiceValid {
    fn generate_secret(&self) -> Result<Vec<u8>, PortError> {
        Ok(b"12345678901234567890".to_vec())
    }

    fn generate_qr_code_svg(
        &self,
        _email: &EmailAddress,
        _secret: &[u8],
        _issuer: &str,
    ) -> Result<String, PortError> {
        Ok("<svg></svg>".to_string())
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

struct MockSecretCipherEcho;

impl SecretCipher for MockSecretCipherEcho {
    fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        Ok((secret.to_vec(), vec![0u8; 12]))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        _nonce: &[u8],
    ) -> Result<korgan::ports::services::DecryptedSecret, PortError> {
        Ok(korgan::ports::services::DecryptedSecret::new(
            ciphertext.to_vec(),
        ))
    }

    fn encrypt_with_aad(
        &self,
        secret: &[u8],
        _aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        Ok((secret.to_vec(), vec![0u8; 12]))
    }

    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<korgan::ports::services::DecryptedSecret, PortError> {
        Ok(korgan::ports::services::DecryptedSecret::new(
            ciphertext.to_vec(),
        ))
    }
}

/// Simulated transactional repository with failure injection points
#[derive(Default)]
struct FaultInjectingUserRepository {
    users: Mutex<HashMap<UserId, User>>,
    mfa: Mutex<HashMap<UserId, UserMfa>>,
    fail_during_user_update: std::sync::atomic::AtomicBool,
    fail_during_mfa_upsert: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl UserRepository for FaultInjectingUserRepository {
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

    async fn update_username(
        &self,
        _user_id: &UserId,
        _new_username: Option<&Username>,
    ) -> Result<(), PortError> {
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

    async fn find_mfa(&self, user_id: &UserId) -> Result<Option<UserMfa>, PortError> {
        let lock = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(user_id).cloned())
    }

    async fn save_mfa(&self, _mfa: &UserMfa) -> Result<(), PortError> {
        Err(PortError::database(
            "monolithic save_mfa is deprecated; use enable_mfa",
        ))
    }

    /// Emulates atomic transactional enable_mfa with failure injection
    async fn enable_mfa(&self, mfa: &UserMfa) -> Result<(), PortError> {
        if self.fail_during_mfa_upsert.load(Ordering::SeqCst) {
            return Err(PortError::database(
                "injected failure during user_mfa upsert",
            ));
        }

        // Snapshot state to emulate SQL transaction rollback
        let mut users_guard = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let user = users_guard
            .get_mut(&mfa.user_id)
            .ok_or_else(|| PortError::not_found("user"))?;

        if self.fail_during_user_update.load(Ordering::SeqCst) {
            // Emulate rollback: neither users.mfa_enabled nor user_mfa is modified
            return Err(PortError::database(
                "injected failure during users.mfa_enabled = true update",
            ));
        }

        user.mfa_enabled = true;
        user.updated_at = Utc::now();

        let mut mfa_guard = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        mfa_guard.insert(mfa.user_id, mfa.clone());

        Ok(())
    }

    async fn delete_mfa(&self, user_id: &UserId) -> Result<(), PortError> {
        let mut mfa_guard = self
            .mfa
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        mfa_guard.remove(user_id);
        let mut users_guard = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        if let Some(user) = users_guard.get_mut(user_id) {
            user.mfa_enabled = false;
        }
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
        _max_attempts: u16,
        _lockout_until: chrono::DateTime<Utc>,
        _now: chrono::DateTime<Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<Utc>>), PortError> {
        Ok((0, None))
    }

    async fn reset_failed_logins(
        &self,
        _user_id: &UserId,
        _now: chrono::DateTime<Utc>,
    ) -> Result<(), PortError> {
        Ok(())
    }

    async fn list_paginated(&self, _limit: u32, _offset: u64) -> Result<Vec<User>, PortError> {
        Ok(Vec::new())
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        Ok(0)
    }

    async fn purge_expired_unverified(
        &self,
        _created_before: chrono::DateTime<Utc>,
        _max_purge: u32,
    ) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[tokio::test]
async fn test_vuln09_mfa_enablement_atomicity_with_injected_failures() -> TestResult {
    let user_repo = Arc::new(FaultInjectingUserRepository::default());
    let totp_service = Arc::new(MockTotpServiceValid);
    let secret_cipher = Arc::new(MockSecretCipherEcho);
    let token_store = Arc::new(MockTokenStore::default());
    let (event_bus, mut event_rx) = EventBus::new(10);

    let use_case = EnableTotpUseCase::new(
        user_repo.clone(),
        totp_service.clone(),
        secret_cipher.clone(),
        token_store.clone(),
        event_bus,
    );

    let user_id = UserId::new();
    let email = EmailAddress::parse("bob@example.com")?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let user = User::new(email, Some(Username::new("bob")?), dummy_hash);
    let mut user = user;
    user.id = user_id;
    user.mfa_enabled = false;
    user_repo.create(&user).await?;

    // Seed pending TOTP secret in token store
    let raw_secret = b"12345678901234567890";
    let base32_secret = encode_base32(raw_secret);
    token_store
        .set_token(
            &format!("pending_totp:{user_id}"),
            &base32_secret,
            Duration::from_secs(300),
        )
        .await?;

    // Test Failure Mode A: Injected failure during users.mfa_enabled = true
    user_repo
        .fail_during_user_update
        .store(true, Ordering::SeqCst);

    let cmd_fail = EnableTotpCommand {
        user_id,
        code: "123456".to_owned(),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };

    let result = use_case.execute(cmd_fail).await;
    assert!(
        result.is_err(),
        "Expected enable_totp to fail on injected DB error"
    );

    // CRITICAL ATOMICITY ASSERTION:
    // When the user update fails, NO partial state must exist:
    // 1. user.mfa_enabled must remain FALSE
    let stored_user = user_repo.find_by_id(&user_id).await?.unwrap();
    assert!(
        !stored_user.mfa_enabled,
        "Partial state violation: user.mfa_enabled must be false!"
    );

    // 2. user_mfa table must NOT contain records for this user
    let stored_mfa = user_repo.find_mfa(&user_id).await?;
    assert!(
        stored_mfa.is_none(),
        "Partial state violation: user_mfa secrets stored while mfa_enabled is false!"
    );

    // 3. No MFA_ENABLED audit log event should have been dispatched
    assert!(
        event_rx.try_recv().is_err(),
        "Audit event for MFA_ENABLED must NOT be dispatched on failure!"
    );

    // Test Recovery / Success Path: Re-seed secret, clear failure flag, and execute
    token_store
        .set_token(
            &format!("pending_totp:{user_id}"),
            &base32_secret,
            Duration::from_secs(300),
        )
        .await?;
    user_repo
        .fail_during_user_update
        .store(false, Ordering::SeqCst);

    let cmd_success = EnableTotpCommand {
        user_id,
        code: "123456".to_owned(),
        ip_address: None,
        user_agent: None,
        request_id: RequestId::new(),
    };

    let success_res = use_case.execute(cmd_success).await?;
    assert_eq!(success_res.backup_codes.len(), 10);

    let post_user = user_repo.find_by_id(&user_id).await?.unwrap();
    assert!(
        post_user.mfa_enabled,
        "user.mfa_enabled must be true after success"
    );

    let post_mfa = user_repo.find_mfa(&user_id).await?.unwrap();
    assert_eq!(post_mfa.user_id, user_id);
    assert_eq!(post_mfa.backup_code_hashes.len(), 10);

    Ok(())
}

// ===========================================================================
// SECTION 4: Real PostgreSQL Transaction Rollback Verification
// ===========================================================================

#[tokio::test]
async fn test_vuln09_real_postgres_enable_mfa_atomic_rollback() -> TestResult {
    use korgan::adapters::outbound::postgres::PostgresUserRepository;

    let db_url = "postgres://korgan:korgan_dev_password@localhost:5432/korgan";
    let pool = match PgPool::connect(db_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping live postgres test: {e}");
            return Ok(());
        }
    };

    let repo = PostgresUserRepository::new(pool.clone());
    let user_id = UserId::new();
    let email_str = format!("pg_mfa_{}@example.com", uuid::Uuid::now_v7());
    let email = EmailAddress::parse(&email_str)?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(email, None, dummy_hash);
    user.id = user_id;
    user.mfa_enabled = false;

    // Insert user into real PostgreSQL
    repo.create(&user).await?;

    let mfa = UserMfa::new(
        user_id,
        b"encrypted_totp_secret".to_vec(),
        vec![0u8; 12],
        vec!["hash1".to_string(), "hash2".to_string()],
    );

    // STEP A: Inject failure via missing user on non-existent user ID
    let ghost_id = UserId::new();
    let ghost_mfa = UserMfa::new(
        ghost_id,
        b"ghost_secret".to_vec(),
        vec![0u8; 12],
        vec!["hash1".to_string()],
    );

    let res_ghost = repo.enable_mfa(&ghost_mfa).await;
    assert!(res_ghost.is_err(), "enable_mfa on ghost user must fail");

    // Verify rollback: user_mfa has NO record for ghost_id
    let ghost_mfa_in_db = repo.find_mfa(&ghost_id).await?;
    assert!(
        ghost_mfa_in_db.is_none(),
        "Rollback failed: ghost user_mfa row was persisted!"
    );

    // STEP B: Normal enable_mfa on existing user succeeds atomically
    repo.enable_mfa(&mfa).await?;

    let loaded_user = repo.find_by_id(&user_id).await?.unwrap();
    assert!(
        loaded_user.mfa_enabled,
        "Postgres: users.mfa_enabled must be true"
    );

    let loaded_mfa = repo.find_mfa(&user_id).await?.unwrap();
    assert_eq!(loaded_mfa.user_id, user_id);

    // Clean up test rows
    let _ = sqlx::query("DELETE FROM user_mfa WHERE user_id = $1")
        .bind(user_id.to_uuid())
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.to_uuid())
        .execute(&pool)
        .await;

    Ok(())
}

#[tokio::test]
async fn test_vuln09_real_postgres_injected_trigger_failure_rollback() -> TestResult {
    use korgan::adapters::outbound::postgres::PostgresUserRepository;

    let db_url = "postgres://korgan:korgan_dev_password@localhost:5432/korgan";
    let pool = match PgPool::connect(db_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping live postgres test: {e}");
            return Ok(());
        }
    };

    let repo = PostgresUserRepository::new(pool.clone());
    let user_id = UserId::new();
    let email_str = format!("pg_trig_{}@example.com", uuid::Uuid::now_v7());
    let email = EmailAddress::parse(&email_str)?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let test_username = Username::new("FAIL_MFA_TEST_USER")?;
    let mut user = User::new(email, Some(test_username), dummy_hash);
    user.id = user_id;
    user.mfa_enabled = false;
    repo.create(&user).await?;

    let mfa = UserMfa::new(
        user_id,
        b"trigger_test_secret".to_vec(),
        vec![0u8; 12],
        vec!["hash1".to_string()],
    );

    // Install an adversarial failure trigger that aborts UPDATE users only for this specific test user username
    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION abort_mfa_update_specific()
        RETURNS TRIGGER AS $$
        BEGIN
            IF NEW.username = 'FAIL_MFA_TEST_USER' AND NEW.mfa_enabled = TRUE THEN
                RAISE EXCEPTION 'ADVERSARIAL_INJECTED_FAILURE_ON_USERS_UPDATE';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE OR REPLACE TRIGGER trg_abort_mfa_specific
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION abort_mfa_update_specific();
        "#,
    )
    .execute(&pool)
    .await?;

    // Attempt enable_mfa. Step 1 (INSERT INTO user_mfa) succeeds, Step 2 (UPDATE users) FAILS due to trigger
    let res = repo.enable_mfa(&mfa).await;
    assert!(
        res.is_err(),
        "Expected enable_mfa to fail due to adversarial trigger exception"
    );

    // Tear down adversarial trigger before making assertions
    let _ = sqlx::query("DROP TRIGGER IF EXISTS trg_abort_mfa_specific ON users; DROP FUNCTION IF EXISTS abort_mfa_update_specific();")
        .execute(&pool)
        .await;

    // CRITICAL POSTGRESQL ATOMICITY ASSERTION:
    // Verify that the transaction rolled back COMPLETELY:
    // 1. user_mfa must have NO row for user_id
    let mfa_in_db = repo.find_mfa(&user_id).await?;
    assert!(
        mfa_in_db.is_none(),
        "CRITICAL ATOMICITY FLAW: user_mfa was persisted despite UPDATE users transaction abort!"
    );

    // 2. users.mfa_enabled must be false
    let user_in_db = repo.find_by_id(&user_id).await?.unwrap();
    assert!(
        !user_in_db.mfa_enabled,
        "users.mfa_enabled must remain false"
    );

    // Clean up
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id.to_uuid())
        .execute(&pool)
        .await;

    Ok(())
}

#[tokio::test]
async fn test_vuln10_concurrency_and_permit_restoration_under_load() -> TestResult {
    let user_repo = Arc::new(MockUserRepo::default());
    // Create hasher with tight concurrency limit = 4
    let hasher = Arc::new(Argon2PasswordHasher::new_with_concurrency(1024, 1, 1, 4)?);
    let token_store = Arc::new(MockTokenStore::default());
    let hibp_client = Arc::new(MockHibp);
    let (event_bus, _rx) = EventBus::new(100);

    let use_case = Arc::new(RegisterUserUseCase::new(
        user_repo.clone(),
        hasher.clone(),
        token_store.clone(),
        hibp_client.clone(),
        event_bus,
        Duration::from_secs(86400),
    ));

    // Pre-populate an existing user for conflict tests
    let existing_pw = RawPassword::new("ExistingPassword123!")?;
    let existing_hash = hasher.hash_password(&existing_pw).await?;
    let existing_user = User::new(
        EmailAddress::parse("taken_concurrent@example.com")?,
        Some(Username::new("taken_concurrent")?),
        existing_hash,
    );
    user_repo.create(&existing_user).await?;

    let mut handles = Vec::new();

    // Spawn 16 concurrent requests:
    // 4 new users, 6 duplicate emails, 6 duplicate usernames
    for i in 0..16 {
        let uc = use_case.clone();
        let handle = tokio::spawn(async move {
            let cmd = if i < 4 {
                RegisterCommand {
                    email: format!("new_user_{i}@example.com"),
                    password: "StrongPassword123!".to_owned(),
                    username: Some(format!("new_user_{i}")),
                    ip_address: None,
                    user_agent: None,
                    request_id: RequestId::new(),
                }
            } else if i < 10 {
                RegisterCommand {
                    email: "taken_concurrent@example.com".to_owned(),
                    password: "StrongPassword123!".to_owned(),
                    username: Some(format!("other_user_{i}")),
                    ip_address: None,
                    user_agent: None,
                    request_id: RequestId::new(),
                }
            } else {
                RegisterCommand {
                    email: format!("unique_email_{i}@example.com"),
                    password: "StrongPassword123!".to_owned(),
                    username: Some("taken_concurrent".to_owned()),
                    ip_address: None,
                    user_agent: None,
                    request_id: RequestId::new(),
                }
            };
            uc.execute(cmd).await
        });
        handles.push(handle);
    }

    let mut conflict_count = 0;
    let mut success_count = 0;

    for handle in handles {
        let res = handle.await?;
        match res {
            Ok(_) => success_count += 1,
            Err(AppError::Conflict) => conflict_count += 1,
            Err(e) => return Err(format!("Unexpected error: {e:?}").into()),
        }
    }

    assert_eq!(success_count, 4, "All 4 new users should register");
    assert_eq!(
        conflict_count, 12,
        "All 12 duplicate requests should return Conflict"
    );

    // CRITICAL CONCURRENCY INVARIANT:
    // All permits must be safely returned to the semaphore, zero permit leaks
    assert_eq!(
        hasher.available_permits(),
        4,
        "Permit leak detected! Expected 4 available permits, found {}",
        hasher.available_permits()
    );

    Ok(())
}
