//! Adversarial Stress Verification Harness:
//! - Refresh Token Concurrency Grace Period & Anti-Replay Ledger
//! - Audit Log Cryptographic Chain Monotonicity & Fork Elimination

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use korgan::application::dto::{AuthTokensResult, RefreshTokenCommand};
use korgan::application::error::AppError;
use korgan::application::use_cases::admin::{AuditVerificationResult, VerifyAuditChainUseCase};
use korgan::application::use_cases::auth::RefreshSessionUseCase;
use korgan::application::use_cases::token_utils;
use korgan::application::workers::{AppEvent, EventBus};
use korgan::domain::entities::{AccountStatus, AuditEventStatus, AuditLog, Session, User};
use korgan::domain::value_objects::*;
use korgan::ports::cache::TokenStore;
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{AuditLogRepository, SessionRepository, UserRepository};
use korgan::ports::services::{AccessTokenClaims, TokenSigner};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Mock Implementations for Adversarial Concurrency Testing
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct StressSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
    by_token_hash: Mutex<HashMap<String, SessionId>>,
    cas_race_count: AtomicUsize,
}

#[async_trait]
impl SessionRepository for StressSessionRepo {
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

        if let Some(id) = by_hash.get(token_hash) {
            return Ok(sessions.get(id).cloned());
        }
        Ok(None)
    }

    async fn list_by_user_id(
        &self,
        user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(sessions
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
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

            self.cas_race_count.fetch_add(1, Ordering::SeqCst);
            return Ok(Some(old_session));
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
        let mut revoked = Vec::new();
        let now = Utc::now();
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
        except: Option<&SessionId>,
        reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let mut revoked = Vec::new();
        let now = Utc::now();
        for session in sessions.values_mut() {
            if session.user_id == *user_id && Some(&session.id) != except && !session.is_revoked() {
                session.revoke(reason, now);
                revoked.push(session.id);
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct StressTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for StressTokenStore {
    async fn set_token(&self, key: &str, value: &str, _ttl: Duration) -> Result<(), PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    async fn set_tokens_batch(&self, entries: &[(&str, &str, Duration)]) -> Result<(), PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        for (k, v, _) in entries {
            lock.insert((*k).to_owned(), (*v).to_owned());
        }
        Ok(())
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
            .map_err(|e| PortError::database(e.to_string()))?;
        if lock.contains_key(key) {
            Ok(false)
        } else {
            lock.insert(key.to_owned(), value.to_owned());
            Ok(true)
        }
    }

    async fn get_token(&self, key: &str) -> Result<Option<String>, PortError> {
        let lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(key).cloned())
    }

    async fn delete_token(&self, key: &str) -> Result<(), PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        lock.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, PortError> {
        let mut lock = self
            .tokens
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.remove(key))
    }

    async fn consume_token(&self, _key: &str, _expected: &str) -> Result<bool, PortError> {
        Ok(true)
    }
}

#[derive(Default, Debug)]
struct StressUserRepo {
    users: Mutex<HashMap<UserId, User>>,
}

#[async_trait]
impl UserRepository for StressUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.get(id).cloned())
    }

    async fn find_by_email(&self, _email: &EmailAddress) -> Result<Option<User>, PortError> {
        Ok(None)
    }

    async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, PortError> {
        Ok(None)
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
        _hash: &PasswordHash,
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

    async fn find_mfa(
        &self,
        _user_id: &UserId,
    ) -> Result<Option<korgan::domain::entities::UserMfa>, PortError> {
        Ok(None)
    }

    async fn save_mfa(&self, _mfa: &korgan::domain::entities::UserMfa) -> Result<(), PortError> {
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
        let lock = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(lock.len() as u64)
    }

    async fn record_failed_login_atomic(
        &self,
        _user_id: &UserId,
        _max_attempts: u16,
        _lockout_until: DateTime<Utc>,
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

    async fn purge_expired_unverified(
        &self,
        _created_before: DateTime<Utc>,
        _max_purge: u32,
    ) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct StressTokenSigner;

impl TokenSigner for StressTokenSigner {
    fn sign_access_token(&self, _claims: &AccessTokenClaims) -> Result<String, PortError> {
        Ok("stress.jwt.token".to_owned())
    }

    fn verify_access_token(&self, _token: &str) -> Result<AccessTokenClaims, PortError> {
        Ok(AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "http://localhost:8080".to_owned(),
            aud: "korgan_api".to_owned(),
            exp: Utc::now().timestamp() + 900,
            iat: Utc::now().timestamp(),
            jti: "stress-jti".to_owned(),
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_string()],
        })
    }

    fn public_key_jwks(&self) -> Result<serde_json::Value, PortError> {
        Ok(serde_json::json!({ "keys": [] }))
    }
}

// ---------------------------------------------------------------------------
// Mock Audit Log Repository with Monotonicity Simulator
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct StressAuditRepo {
    entries: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for StressAuditRepo {
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

// ---------------------------------------------------------------------------
// TEST 1: Refresh Token High Concurrency Stress Test (N = 30 concurrent racing requests)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v02_massive_concurrent_refresh_race() -> TestResult {
    let session_repo = Arc::new(StressSessionRepo::default());
    let user_repo = Arc::new(StressUserRepo::default());
    let token_signer = Arc::new(StressTokenSigner);
    let token_store = Arc::new(StressTokenStore::default());
    let (event_bus, mut event_rx) = EventBus::new(200);

    let email = EmailAddress::parse("stress_user@example.com")?;
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlrcrcnhbvBlqETBXNkPlnYZCGviEbI",
    )?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = AccountStatus::Active;
    user_repo.create(&user).await?;

    let use_case = Arc::new(RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "http://localhost:8080".to_owned(),
        "korgan_api".to_owned(),
    ));

    // Create session
    let token_raw = "adversarial_stress_token_777";
    let token_hash = token_utils::hash_token(token_raw);
    let session = Session::new(
        user.id,
        token_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Chrome 130".to_owned()),
        Some("Linux Workstation".to_owned()),
        chrono::Duration::days(7),
    );
    let session_id = session.id;
    let family_id = session.token_family_id;
    session_repo.create(&session).await?;

    // Fire 30 concurrent requests for the exact same refresh token
    const CONCURRENCY: usize = 30;
    let mut handles = Vec::with_capacity(CONCURRENCY);

    for i in 0..CONCURRENCY {
        let uc = use_case.clone();
        let cmd = RefreshTokenCommand {
            refresh_token: token_raw.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            user_agent: Some(format!("Tab-{i}")),
            request_id: RequestId::new(),
        };
        handles.push(tokio::spawn(async move { uc.execute(cmd).await }));
    }

    let mut successes: Vec<AuthTokensResult> = Vec::new();
    let mut conflicts = 0;
    let mut false_positive_revocations = 0;
    let mut other_errors = Vec::new();

    for handle in handles {
        match handle.await? {
            Ok(tokens) => successes.push(tokens),
            Err(AppError::ConcurrentRefresh { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 1, "retry_after_secs must be exactly 1");
                conflicts += 1;
            }
            Err(AppError::TokenReuseDetected) => false_positive_revocations += 1,
            Err(e) => other_errors.push(e),
        }
    }

    // Assert strict invariants
    assert_eq!(
        successes.len(),
        1,
        "CRITICAL: Exactly 1 concurrent request must win the CAS race! Found: {}",
        successes.len()
    );
    assert_eq!(
        conflicts,
        CONCURRENCY - 1,
        "CRITICAL: Exactly {} losers must receive ConcurrentRefresh conflict! Found: {}",
        CONCURRENCY - 1,
        conflicts
    );
    assert_eq!(
        false_positive_revocations, 0,
        "CONCURRENCY REGRESSION: False-positive token family revocation occurred under concurrency!"
    );
    assert!(
        other_errors.is_empty(),
        "Unexpected errors during concurrent refresh: {:?}",
        other_errors
    );

    // Verify winning session is completely valid and active in database
    let winning_token = &successes[0];
    let winning_session = session_repo
        .find_by_id(&winning_token.session_id)
        .await?
        .ok_or("winning session not found in repository")?;

    assert!(
        !winning_session.is_revoked(),
        "Winning session must NOT be revoked!"
    );
    assert!(
        winning_session.is_valid(Utc::now()),
        "Winning session must be currently valid!"
    );
    assert_eq!(
        winning_session.token_family_id, family_id,
        "Winning session must preserve token family ID"
    );

    // Verify parent session is marked replaced but NOT revoked
    let parent_session = session_repo
        .find_by_id(&session_id)
        .await?
        .ok_or("parent session not found")?;
    assert!(
        parent_session.is_replaced,
        "Parent session must be replaced"
    );
    assert!(
        !parent_session.is_revoked(),
        "Parent session must NOT be revoked during grace period"
    );

    // Verify Redis token store blacklist is 100% CLEAN
    let blacklist_parent = token_store
        .get_token(&format!("blacklist:session:{session_id}"))
        .await?;
    let blacklist_winner = token_store
        .get_token(&format!("blacklist:session:{}", winning_session.id))
        .await?;
    assert!(
        blacklist_parent.is_none(),
        "Parent session must not be blacklisted in Redis during grace period"
    );
    assert!(
        blacklist_winner.is_none(),
        "Winning session must not be blacklisted in Redis"
    );

    // Verify no TOKEN_REUSE_DETECTED audit event was emitted
    while let Ok(event) = event_rx.try_recv() {
        if let AppEvent::LogAudit(log) = event {
            assert_ne!(
                log.event_type, "token_reuse_detected",
                "False-positive token_reuse_detected audit log emitted!"
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TEST 2: Replay Outside Grace Window Triggers Immediate Revocation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v02_replay_outside_grace_window_triggers_family_revocation() -> TestResult
{
    let session_repo = Arc::new(StressSessionRepo::default());
    let user_repo = Arc::new(StressUserRepo::default());
    let token_signer = Arc::new(StressTokenSigner);
    let token_store = Arc::new(StressTokenStore::default());
    let (event_bus, mut event_rx) = EventBus::new(200);

    let email = EmailAddress::parse("replay_victim@example.com")?;
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlrcrcnhbvBlqETBXNkPlnYZCGviEbI",
    )?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = AccountStatus::Active;
    user_repo.create(&user).await?;

    let use_case = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "http://localhost:8080".to_owned(),
        "korgan_api".to_owned(),
    );

    // 1. Initial login / session creation
    let token_1_raw = "root_token_1";
    let token_1_hash = token_utils::hash_token(token_1_raw);
    let initial_session = Session::new(
        user.id,
        token_1_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Desktop".to_owned()),
        Some("PC".to_owned()),
        chrono::Duration::days(7),
    );
    let s1_id = initial_session.id;
    let family_id = initial_session.token_family_id;
    session_repo.create(&initial_session).await?;

    // 2. Legitimate rotation: token_1 -> token_2
    let rotate_cmd = RefreshTokenCommand {
        refresh_token: token_1_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Desktop".to_owned()),
        request_id: RequestId::new(),
    };
    let token_2 = use_case.execute(rotate_cmd).await?;
    let s2_id = token_2.session_id;

    // 3. Replay within grace window (e.g. t + 5s) -> must return ConcurrentRefresh (409)
    let concurrent_cmd = RefreshTokenCommand {
        refresh_token: token_1_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Desktop-Tab2".to_owned()),
        request_id: RequestId::new(),
    };
    let within_grace_res = use_case.execute(concurrent_cmd).await;
    match within_grace_res {
        Err(AppError::ConcurrentRefresh {
            retry_after_secs: 1,
        }) => {}
        other => return Err(format!("expected ConcurrentRefresh(1), got {other:?}").into()),
    }

    // 4. Advance time past grace window (> 10s, e.g. 15s)
    let mut s1 = session_repo.find_by_id(&s1_id).await?.ok_or("s1 missing")?;
    s1.last_active_at = Utc::now() - chrono::Duration::seconds(15);
    session_repo.update(&s1).await?;

    // 5. Malicious replay of token_1 outside grace window
    let replay_cmd = RefreshTokenCommand {
        refresh_token: token_1_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
        user_agent: Some("Attacker-Tor-Exit".to_owned()),
        request_id: RequestId::new(),
    };
    let replay_res = use_case.execute(replay_cmd).await;
    match replay_res {
        Err(AppError::TokenReuseDetected) => {}
        other => return Err(format!("expected TokenReuseDetected, got {other:?}").into()),
    }

    // 6. Verify ENTIRE family was revoked
    let s1_revoked = session_repo.find_by_id(&s1_id).await?.ok_or("s1 missing")?;
    let s2_revoked = session_repo.find_by_id(&s2_id).await?.ok_or("s2 missing")?;
    assert!(
        s1_revoked.is_revoked(),
        "Parent session must be revoked upon replay"
    );
    assert!(
        s2_revoked.is_revoked(),
        "Child session must be revoked upon replay"
    );
    assert_eq!(
        s1_revoked.revoke_reason.as_deref(),
        Some("token_reuse_detected")
    );
    assert_eq!(
        s2_revoked.revoke_reason.as_deref(),
        Some("token_reuse_detected")
    );

    // 7. Verify Redis token store has blacklisted ALL revoked sessions
    let bl_s1 = token_store
        .get_token(&format!("blacklist:session:{s1_id}"))
        .await?;
    let bl_s2 = token_store
        .get_token(&format!("blacklist:session:{s2_id}"))
        .await?;
    assert_eq!(
        bl_s1.as_deref(),
        Some("revoked"),
        "s1 must be blacklisted in Redis"
    );
    assert_eq!(
        bl_s2.as_deref(),
        Some("revoked"),
        "s2 must be blacklisted in Redis"
    );

    // 8. Verify audit log was emitted for replay attack
    let mut audit_found = false;
    while let Ok(event) = event_rx.try_recv() {
        if let AppEvent::LogAudit(log) = event
            && log.event_type == "token_reuse_detected"
        {
            assert_eq!(log.event_status, AuditEventStatus::Blocked);
            assert_eq!(log.metadata["token_family_id"], family_id.to_string());
            audit_found = true;
        }
    }
    assert!(
        audit_found,
        "token_reuse_detected audit log must be emitted"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// TEST 3: Audit Log Concurrency Burst with Monotonic Timestamp Ordering
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v01_massive_concurrency_burst_unbroken_chain() -> TestResult {
    let audit_repo = Arc::new(StressAuditRepo::default());
    let num_events = 100;
    let mut handles = Vec::with_capacity(num_events);

    // Spawn 100 concurrent tasks with intentionally inverted/stale in-memory timestamps
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
                serde_json::json!({ "burst_id": i }),
            );
            // Simulate severe in-memory skew: reverse-ordered dispatch
            entry.created_at = Utc::now() - chrono::Duration::seconds((num_events - i) as i64 * 5);
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
        "All 100 concurrent burst entries must be recorded"
    );

    // 1. Verify Genesis Entry
    assert_eq!(
        entries[0].prev_hash, None,
        "Genesis entry must have prev_hash == None"
    );
    assert!(
        entries[0].verify_integrity(None),
        "Genesis entry cryptographic verification failed"
    );

    // 2. Verify strict microsecond monotonicity and unbending hash chain across all 100 entries
    for idx in 1..entries.len() {
        let prev = &entries[idx - 1];
        let curr = &entries[idx];

        // Monotonicity assertion: created_at must be strictly greater (by at least 1 microsecond)
        assert!(
            curr.created_at > prev.created_at,
            "CRITICAL: Monotonicity violation at index {idx}: curr.created_at ({}) <= prev.created_at ({})",
            curr.created_at,
            prev.created_at
        );

        // Chain linkage assertion: curr.prev_hash must exactly match prev.entry_hash
        assert_eq!(
            curr.prev_hash, prev.entry_hash,
            "CRITICAL: Cryptographic chain forked at index {idx}! curr.prev_hash ({:?}) != prev.entry_hash ({:?})",
            curr.prev_hash, prev.entry_hash
        );

        // Individual entry integrity assertion
        assert!(
            curr.verify_integrity(prev.entry_hash.as_deref()),
            "CRITICAL: Cryptographic SHA-256 integrity verification failed at index {idx}!"
        );
    }

    // 3. Verify via VerifyAuditChainUseCase
    let verify_use_case = VerifyAuditChainUseCase::new(audit_repo.clone());
    let verify_result = verify_use_case.execute().await?;

    assert_eq!(
        verify_result,
        AuditVerificationResult::Valid {
            verified_count: num_events
        },
        "VerifyAuditChainUseCase must validate 100% of the chain without any errors"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// TEST 4: Audit Log Adversarial Tamper Detection & Monotonicity Verification
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v01_tamper_and_monotonicity_oracle_detection() -> TestResult {
    let req_id = RequestId::new();
    let base_time = Utc::now();

    // Construct valid 3-element chain
    let mut e1 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event_1",
        AuditEventStatus::Success,
        serde_json::json!({"step": 1}),
    );
    e1.chain_with_timestamp(None, base_time);

    let mut e2 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event_2",
        AuditEventStatus::Success,
        serde_json::json!({"step": 2}),
    );
    e2.chain_with_timestamp(
        e1.entry_hash.as_deref(),
        base_time + chrono::Duration::microseconds(10),
    );

    let mut e3 = AuditLog::new(
        None,
        None,
        None,
        req_id,
        "event_3",
        AuditEventStatus::Success,
        serde_json::json!({"step": 3}),
    );
    e3.chain_with_timestamp(
        e2.entry_hash.as_deref(),
        base_time + chrono::Duration::microseconds(20),
    );

    // Baseline: Chain is valid
    let repo = Arc::new(DirectAuditRepo {
        entries: vec![e1.clone(), e2.clone(), e3.clone()],
    });
    let verifier = VerifyAuditChainUseCase::new(repo);
    let baseline_res = verifier.execute().await?;
    assert_eq!(
        baseline_res,
        AuditVerificationResult::Valid { verified_count: 3 }
    );

    // Attack Scenario A: Monotonicity Violation (Entry 2 timestamp shifted earlier than Entry 1)
    let mut e2_corrupted_time = e2.clone();
    e2_corrupted_time.created_at = base_time - chrono::Duration::microseconds(1);
    // Even if hash is recomputed to match the fake time:
    e2_corrupted_time.entry_hash =
        Some(e2_corrupted_time.compute_entry_hash(e1.entry_hash.as_deref()));
    let repo_time_corrupted = Arc::new(DirectAuditRepo {
        entries: vec![e1.clone(), e2_corrupted_time, e3.clone()],
    });
    let res_time = VerifyAuditChainUseCase::new(repo_time_corrupted)
        .execute()
        .await?;
    match res_time {
        AuditVerificationResult::Corrupted(broken) => {
            assert_eq!(broken.record_index, 1);
            assert!(broken.reason.contains("Monotonic timestamp violation"));
        }
        AuditVerificationResult::Valid { .. } => {
            return Err("Oracle failed to detect monotonic timestamp violation!".into());
        }
    }

    // Attack Scenario B: Payload Tampering (Metadata modified in flight)
    let mut e2_tampered_payload = e2.clone();
    e2_tampered_payload.metadata = serde_json::json!({"step": 2, "injected_payload": "evil"});
    let repo_payload_tampered = Arc::new(DirectAuditRepo {
        entries: vec![e1.clone(), e2_tampered_payload, e3.clone()],
    });
    let res_payload = VerifyAuditChainUseCase::new(repo_payload_tampered)
        .execute()
        .await?;
    match res_payload {
        AuditVerificationResult::Corrupted(broken) => {
            assert_eq!(broken.record_index, 1);
            assert!(broken.reason.contains("Hash mismatch"));
        }
        AuditVerificationResult::Valid { .. } => {
            return Err("Oracle failed to detect payload tampering!".into());
        }
    }

    // Attack Scenario C: Chain Fork / Broken Link (prev_hash corrupted)
    let mut e3_broken_link = e3.clone();
    e3_broken_link.prev_hash =
        Some("0000000000000000000000000000000000000000000000000000000000000000".to_owned());
    let repo_broken_link = Arc::new(DirectAuditRepo {
        entries: vec![e1.clone(), e2.clone(), e3_broken_link],
    });
    let res_link = VerifyAuditChainUseCase::new(repo_broken_link)
        .execute()
        .await?;
    match res_link {
        AuditVerificationResult::Corrupted(broken) => {
            assert_eq!(broken.record_index, 2);
            assert!(broken.reason.contains("Hash mismatch"));
        }
        AuditVerificationResult::Valid { .. } => {
            return Err("Oracle failed to detect broken chain link!".into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TEST 5: Refresh Token Exact Grace Boundaries, Clock Skew, and Expired Priority
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v02_grace_window_exact_boundaries_and_clock_skew() -> TestResult {
    let session_repo = Arc::new(StressSessionRepo::default());
    let user_repo = Arc::new(StressUserRepo::default());
    let token_signer = Arc::new(StressTokenSigner);
    let token_store = Arc::new(StressTokenStore::default());
    let (event_bus, _event_rx) = EventBus::new(200);

    let email = EmailAddress::parse("boundary@example.com")?;
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlrcrcnhbvBlqETBXNkPlnYZCGviEbI",
    )?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = AccountStatus::Active;
    user_repo.create(&user).await?;

    let use_case = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "http://localhost:8080".to_owned(),
        "korgan_api".to_owned(),
    );

    // Initial session
    let token_raw = "boundary_token_123";
    let token_hash = token_utils::hash_token(token_raw);
    let session = Session::new(
        user.id,
        token_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Browser".to_owned()),
        Some("PC".to_owned()),
        chrono::Duration::days(7),
    );
    let s_id = session.id;
    session_repo.create(&session).await?;

    // Rotate once
    let cmd = RefreshTokenCommand {
        refresh_token: token_raw.to_owned(),
        ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        user_agent: Some("Browser".to_owned()),
        request_id: RequestId::new(),
    };
    let token_2 = use_case.execute(cmd).await?;

    // Test Boundary 1: 9.0s after rotation (within grace window)
    {
        let mut s = session_repo.find_by_id(&s_id).await?.ok_or("s missing")?;
        s.last_active_at = Utc::now() - chrono::Duration::seconds(9);
        session_repo.update(&s).await?;
    }
    let res_within_grace = use_case
        .execute(RefreshTokenCommand {
            refresh_token: token_raw.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: Some("Browser-Tab".to_owned()),
            request_id: RequestId::new(),
        })
        .await;
    match res_within_grace {
        Err(AppError::ConcurrentRefresh {
            retry_after_secs: 1,
        }) => {}
        other => {
            return Err(format!("expected ConcurrentRefresh(1) at t=9s, got {other:?}").into());
        }
    }

    // Verify child session still alive
    assert!(
        !session_repo
            .find_by_id(&token_2.session_id)
            .await?
            .ok_or("token_2 session missing")?
            .is_revoked()
    );

    // Test Boundary 2: 11 seconds (outside 10s grace window)
    {
        let mut s = session_repo.find_by_id(&s_id).await?.ok_or("s missing")?;
        s.last_active_at = Utc::now() - chrono::Duration::seconds(11);
        session_repo.update(&s).await?;
    }
    let res_past_grace = use_case
        .execute(RefreshTokenCommand {
            refresh_token: token_raw.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: Some("Browser-Tab".to_owned()),
            request_id: RequestId::new(),
        })
        .await;
    match res_past_grace {
        Err(AppError::TokenReuseDetected) => {}
        other => return Err(format!("expected TokenReuseDetected at t=11s, got {other:?}").into()),
    }

    // Verify child session is now revoked
    assert!(
        session_repo
            .find_by_id(&token_2.session_id)
            .await?
            .ok_or("token_2 session missing")?
            .is_revoked()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// TEST 6: Expired Token Replay Does NOT Trigger Family Revocation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_adversarial_v02_expired_token_does_not_revoke_family() -> TestResult {
    let session_repo = Arc::new(StressSessionRepo::default());
    let user_repo = Arc::new(StressUserRepo::default());
    let token_signer = Arc::new(StressTokenSigner);
    let token_store = Arc::new(StressTokenStore::default());
    let (event_bus, _event_rx) = EventBus::new(200);

    let email = EmailAddress::parse("expired_test@example.com")?;
    let dummy_hash = PasswordHash::new(
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlrcrcnhbvBlqETBXNkPlnYZCGviEbI",
    )?;
    let mut user = User::new(email, None, dummy_hash);
    user.status = AccountStatus::Active;
    user_repo.create(&user).await?;

    let use_case = RefreshSessionUseCase::new(
        session_repo.clone(),
        user_repo.clone(),
        token_signer.clone(),
        token_store.clone(),
        event_bus,
        Duration::from_secs(900),
        Duration::from_secs(86400),
        "http://localhost:8080".to_owned(),
        "korgan_api".to_owned(),
    );

    let token_raw = "expired_raw_token";
    let token_hash = token_utils::hash_token(token_raw);

    // Create an expired session that is also marked replaced
    let mut session = Session::new(
        user.id,
        token_hash,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Browser".to_owned()),
        Some("PC".to_owned()),
        chrono::Duration::seconds(1),
    );
    session.is_replaced = true;
    session.last_active_at = Utc::now() - chrono::Duration::seconds(60); // 60s ago
    session.expires_at = Utc::now() - chrono::Duration::seconds(30); // expired 30s ago
    let family_id = session.token_family_id;
    session_repo.create(&session).await?;

    let res = use_case
        .execute(RefreshTokenCommand {
            refresh_token: token_raw.to_owned(),
            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: Some("Browser".to_owned()),
            request_id: RequestId::new(),
        })
        .await;

    // Must return TokenExpired, NOT TokenReuseDetected!
    match res {
        Err(AppError::TokenExpired) => {}
        other => return Err(format!("expected TokenExpired, got {other:?}").into()),
    }

    // Family must NOT be revoked!
    let found = session_repo
        .find_by_id(&session.id)
        .await?
        .ok_or("session missing")?;
    assert_eq!(found.token_family_id, family_id);
    assert!(
        !found.is_revoked(),
        "Expired token presentation must NOT revoke family!"
    );

    Ok(())
}

struct DirectAuditRepo {
    entries: Vec<AuditLog>,
}

#[async_trait]
impl AuditLogRepository for DirectAuditRepo {
    async fn append(&self, _entry: &AuditLog) -> Result<(), PortError> {
        Ok(())
    }
    async fn list_by_user_id(
        &self,
        _uid: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }
    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }
    async fn list_all_chronological(&self) -> Result<Vec<AuditLog>, PortError> {
        Ok(self.entries.clone())
    }
}
