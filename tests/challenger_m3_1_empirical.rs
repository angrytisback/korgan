//! Empirical Verification Harness for Milestone M3 (challenger_m3_1).
//! Temporary verification file — deleted before handoff to preserve clean workspace.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::middleware::from_fn;
use axum::routing::get;
use chrono::{DateTime, Utc};
use http::header::{AUTHORIZATION, COOKIE, RETRY_AFTER};
use http::{Request, StatusCode};
use korgan::adapters::inbound::http::error::{ApiError, ErrorKind, FieldError};
use korgan::adapters::inbound::http::extractors::auth::AuthUser;
use korgan::adapters::inbound::http::extractors::metadata::{ClientMetadata, ClientType};
use korgan::adapters::inbound::http::middleware::request_id::{
    X_REQUEST_ID, request_id_middleware, scope_request_id,
};
use korgan::adapters::inbound::http::openapi::ApiDoc;
use korgan::adapters::inbound::http::state::{AppState, AppStateInner};
use korgan::application::workers::EventBus;
use korgan::config::Settings;
use korgan::domain::entities::{
    AccountStatus, AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa,
};
use korgan::domain::value_objects::{
    EmailAddress, PasskeyId, PasswordHash, RawPassword, RequestId, SessionId, UserId, Username,
};
use korgan::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::{
    AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
    UserRepository,
};
use korgan::ports::services::{
    AccessTokenClaims, DecryptedSecret, HibpClient, MailProvider, OAuthProfile, OAuthProviderPort,
    PasswordHasher, SecretCipher, TokenSigner, TotpService, WebAuthnService,
};
use smallvec::smallvec;
use tokio::sync::{Mutex, mpsc};
use tower::ServiceExt;
use utoipa::OpenApi;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
    Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct StubUserRepo(User);
#[async_trait]
impl UserRepository for StubUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        Ok((*id == self.0.id).then(|| self.0.clone()))
    }
    async fn find_by_email(&self, _email: &EmailAddress) -> Result<Option<User>, PortError> {
        Ok(None)
    }
    async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, PortError> {
        Ok(None)
    }
    async fn create(&self, _user: &User) -> Result<(), PortError> {
        Ok(())
    }
    async fn update(&self, _user: &User) -> Result<(), PortError> {
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
    async fn list_paginated(&self, _limit: u32, _offset: u64) -> Result<Vec<User>, PortError> {
        Ok(Vec::new())
    }
    async fn count_all(&self) -> Result<u64, PortError> {
        Ok(1)
    }
}

struct StubSessionRepo(Session);
#[async_trait]
impl SessionRepository for StubSessionRepo {
    async fn create(&self, _session: &Session) -> Result<(), PortError> {
        Ok(())
    }
    async fn find_by_id(&self, id: &SessionId) -> Result<Option<Session>, PortError> {
        Ok((*id == self.0.id).then(|| self.0.clone()))
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
        _old_token_hash: &str,
        _new_session: &Session,
    ) -> Result<Option<Session>, PortError> {
        Ok(None)
    }
    async fn update(&self, _session: &Session) -> Result<(), PortError> {
        Ok(())
    }
    async fn revoke_by_id(&self, _id: &SessionId, _reason: &str) -> Result<(), PortError> {
        Ok(())
    }
    async fn revoke_by_id_and_user_id(
        &self,
        _id: &SessionId,
        _user_id: &UserId,
        _reason: &str,
    ) -> Result<Option<SessionId>, PortError> {
        Ok(None)
    }
    async fn revoke_family(
        &self,
        _family_id: &korgan::domain::value_objects::TokenFamilyId,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }
    async fn revoke_all_user_sessions(
        &self,
        _user_id: &UserId,
        _except_session: Option<&SessionId>,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(Vec::new())
    }
    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

struct RecordingTokenSigner {
    claims: AccessTokenClaims,
    observed_ptr: AtomicUsize,
    observed_len: AtomicUsize,
    observed_token: Mutex<Option<String>>,
}

impl TokenSigner for RecordingTokenSigner {
    fn sign_access_token(&self, _claims: &AccessTokenClaims) -> Result<String, PortError> {
        Ok("signed".to_owned())
    }
    fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, PortError> {
        self.observed_ptr
            .store(token.as_ptr() as usize, Ordering::SeqCst);
        self.observed_len.store(token.len(), Ordering::SeqCst);
        if let Ok(mut guard) = self.observed_token.try_lock() {
            *guard = Some(token.to_owned());
        }
        Ok(self.claims.clone())
    }
    fn public_key_jwks(&self) -> Result<serde_json::Value, PortError> {
        Ok(serde_json::json!({ "keys": [] }))
    }
}

struct NoopAuditRepo;
#[async_trait]
impl AuditLogRepository for NoopAuditRepo {
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

struct NoopOAuthRepo;
#[async_trait]
impl OAuthAccountRepository for NoopOAuthRepo {
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

struct NoopPasskeyRepo;
#[async_trait]
impl PasskeyRepository for NoopPasskeyRepo {
    async fn save(&self, _passkey: &Passkey) -> Result<(), PortError> {
        Ok(())
    }
    async fn find_by_credential_id(
        &self,
        _credential_id: &[u8],
    ) -> Result<Option<Passkey>, PortError> {
        Ok(None)
    }
    async fn find_by_id(&self, _id: &PasskeyId) -> Result<Option<Passkey>, PortError> {
        Ok(None)
    }
    async fn list_by_user_id(&self, _user_id: &UserId) -> Result<Vec<Passkey>, PortError> {
        Ok(Vec::new())
    }
    async fn delete_by_id(&self, _id: &PasskeyId) -> Result<(), PortError> {
        Ok(())
    }
    async fn delete_by_id_and_user_id(
        &self,
        _id: &PasskeyId,
        _user_id: &UserId,
    ) -> Result<bool, PortError> {
        Ok(false)
    }
}

struct NoopTokenStore;
#[async_trait]
impl TokenStore for NoopTokenStore {
    async fn set_token(
        &self,
        _key: &str,
        _token_hash: &str,
        _ttl: Duration,
    ) -> Result<(), PortError> {
        Ok(())
    }
    async fn get_token(&self, _key: &str) -> Result<Option<String>, PortError> {
        Ok(None)
    }
    async fn delete_token(&self, _key: &str) -> Result<(), PortError> {
        Ok(())
    }
    async fn get_and_delete(&self, _key: &str) -> Result<Option<String>, PortError> {
        Ok(None)
    }
    async fn consume_token(&self, _key: &str, _expected: &str) -> Result<bool, PortError> {
        Ok(false)
    }
    async fn set_if_not_exists(
        &self,
        _key: &str,
        _value: &str,
        _ttl: Duration,
    ) -> Result<bool, PortError> {
        Ok(true)
    }
}

struct NoopRateLimiter;
#[async_trait]
impl RateLimiterPort for NoopRateLimiter {
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
            reset_epoch_secs: 0,
            retry_after_secs: None,
        })
    }
    async fn reset(&self, _key: &str) -> Result<(), PortError> {
        Ok(())
    }
}

struct NoopHasher;
#[async_trait]
impl PasswordHasher for NoopHasher {
    async fn hash_password(&self, _password: &RawPassword) -> Result<PasswordHash, PortError> {
        PasswordHash::new(
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
                .to_owned(),
        )
        .map_err(|e| PortError::crypto(e.to_string()))
    }
    async fn verify_password(
        &self,
        _p: &RawPassword,
        _h: &PasswordHash,
    ) -> Result<bool, PortError> {
        Ok(false)
    }
    async fn verify_against_dummy_hash(&self, _password: &RawPassword) -> Result<(), PortError> {
        Ok(())
    }
}

struct NoopCipher;
impl SecretCipher for NoopCipher {
    fn encrypt_with_aad(&self, _p: &[u8], _a: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PortError> {
        Ok((Vec::new(), vec![0u8; 12]))
    }
    fn decrypt_with_aad(
        &self,
        _c: &[u8],
        _n: &[u8],
        _a: &[u8],
    ) -> Result<DecryptedSecret, PortError> {
        Ok(DecryptedSecret::new(Vec::new()))
    }
}

struct NoopTotp;
impl TotpService for NoopTotp {
    fn generate_secret(&self) -> Result<Vec<u8>, PortError> {
        Ok(vec![0u8; 20])
    }
    fn generate_qr_code_svg(
        &self,
        _e: &EmailAddress,
        _s: &[u8],
        _i: &str,
    ) -> Result<String, PortError> {
        Ok(String::new())
    }
    fn verify_code(&self, _s: &[u8], _c: &str, _n: u64) -> Result<bool, PortError> {
        Ok(false)
    }
}

struct NoopHibp;
#[async_trait]
impl HibpClient for NoopHibp {
    async fn is_password_breached(&self, _password: &RawPassword) -> Result<bool, PortError> {
        Ok(false)
    }
}

struct NoopMail;
#[async_trait]
impl MailProvider for NoopMail {
    async fn send_email(
        &self,
        _t: &EmailAddress,
        _s: &str,
        _tb: &str,
        _hb: &str,
    ) -> Result<(), PortError> {
        Ok(())
    }
}

struct NoopOAuthProvider(OAuthProvider);
#[async_trait]
impl OAuthProviderPort for NoopOAuthProvider {
    fn provider(&self) -> OAuthProvider {
        self.0
    }
    fn build_authorization_url(&self, _state: &str) -> String {
        "https://example.com".to_owned()
    }
    async fn exchange_code(&self, _code: &str) -> Result<OAuthProfile, PortError> {
        Err(PortError::external_service("oauth", "noop", None))
    }
}

struct NoopWebAuthn;
impl WebAuthnService for NoopWebAuthn {
    fn start_registration(
        &self,
        _u: &UserId,
        _un: &str,
        _e: &[Passkey],
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError> {
        Err(PortError::external_service("webauthn", "noop", None))
    }
    fn finish_registration(
        &self,
        _r: &RegisterPublicKeyCredential,
        _s: &PasskeyRegistration,
    ) -> Result<WebauthnPasskey, PortError> {
        Err(PortError::external_service("webauthn", "noop", None))
    }
    fn start_discoverable_login(
        &self,
    ) -> Result<(RequestChallengeResponse, DiscoverableAuthentication), PortError> {
        Err(PortError::external_service("webauthn", "noop", None))
    }
    fn finish_discoverable_login(
        &self,
        _a: &PublicKeyCredential,
        _s: DiscoverableAuthentication,
        _c: &[Passkey],
    ) -> Result<(AuthenticationResult, WebauthnPasskey), PortError> {
        Err(PortError::external_service("webauthn", "noop", None))
    }
}

fn build_state() -> Result<(AppState, Arc<RecordingTokenSigner>), Box<dyn std::error::Error>> {
    let env = HashMap::from([
        ("DATABASE_URL".to_owned(), "postgres://u:p@localhost:5432/db".to_owned()),
        ("REDIS_URL".to_owned(), "redis://localhost:6379".to_owned()),
        (
            "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----".to_owned(),
        ),
        (
            "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
            "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=".to_owned(),
        ),
    ]);
    let settings = Arc::new(Settings::load_from_env(env)?);
    let now = Utc::now();
    let mut user = User::new(EmailAddress::parse("challenger@example.com")?, None, None);
    user.status = AccountStatus::Active;
    let user_id = user.id;

    let session = Session::new(
        user_id,
        "hash".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        None,
        chrono::Duration::hours(1),
    );
    let session_id = session.id;

    let claims = AccessTokenClaims {
        sub: user_id,
        sid: session_id,
        iss: Cow::Owned(settings.auth.issuer.clone()),
        aud: Cow::Owned(settings.auth.audience.clone()),
        exp: (now + chrono::Duration::minutes(15)).timestamp(),
        iat: now.timestamp(),
        jti: RequestId::new().to_string(),
        auth_time: now.timestamp(),
        amr: smallvec![Cow::Borrowed("pwd")],
    };

    let signer = Arc::new(RecordingTokenSigner {
        claims,
        observed_ptr: AtomicUsize::new(0),
        observed_len: AtomicUsize::new(0),
        observed_token: Mutex::new(None),
    });

    let (tx, _rx) = mpsc::channel(4);
    let event_bus = EventBus::from_sender(tx);
    let pg_pool = sqlx::PgPool::connect_lazy("postgres://u:p@localhost:5432/db")?;
    let redis_pool = deadpool_redis::Config::from_url("redis://localhost:6379")
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    let state = AppState::with_ports(
        settings,
        Arc::new(StubUserRepo(user)),
        Arc::new(StubSessionRepo(session)),
        Arc::new(NoopAuditRepo),
        Arc::new(NoopOAuthRepo),
        Arc::new(NoopPasskeyRepo),
        Arc::new(NoopTokenStore),
        Arc::new(NoopRateLimiter),
        Arc::new(NoopHasher),
        signer.clone(),
        Arc::new(NoopCipher),
        Arc::new(NoopTotp),
        Arc::new(NoopHibp),
        Arc::new(NoopMail),
        Arc::new(NoopOAuthProvider(OAuthProvider::Google)),
        Arc::new(NoopOAuthProvider(OAuthProvider::GitHub)),
        Arc::new(NoopWebAuthn),
        event_bus,
        pg_pool,
        redis_pool,
    );

    Ok((state, signer))
}

#[tokio::test]
async fn m3_1_app_state_layout_and_shallow_clone_oracle() -> TestResult {
    assert_eq!(
        std::mem::size_of::<AppState>(),
        std::mem::size_of::<usize>()
    );
    assert_eq!(
        std::mem::align_of::<AppState>(),
        std::mem::align_of::<usize>()
    );
    let inner_size = std::mem::size_of::<AppStateInner>();
    assert!(inner_size > 256);

    let (state, _) = build_state()?;
    let base_user_repo_count = Arc::strong_count(&state.user_repo);
    let base_session_repo_count = Arc::strong_count(&state.session_repo);
    let base_hasher_count = Arc::strong_count(&state.password_hasher);

    let clones: Vec<AppState> = (0..1000).map(|_| state.clone()).collect();

    // Inner field Arc refcounts MUST remain completely unchanged!
    assert_eq!(Arc::strong_count(&state.user_repo), base_user_repo_count);
    assert_eq!(
        Arc::strong_count(&state.session_repo),
        base_session_repo_count
    );
    assert_eq!(Arc::strong_count(&state.password_hasher), base_hasher_count);

    for c in &clones {
        assert!(std::ptr::eq(&*state, &**c));
        assert!(Arc::ptr_eq(&state.user_repo, &c.user_repo));
    }
    drop(clones);

    assert_eq!(Arc::strong_count(&state.user_repo), base_user_repo_count);
    assert_eq!(
        Arc::strong_count(&state.session_repo),
        base_session_repo_count
    );
    assert_eq!(Arc::strong_count(&state.password_hasher), base_hasher_count);
    Ok(())
}

#[tokio::test]
async fn m3_2_extract_token_zero_copy_end_to_end_via_auth_user() -> TestResult {
    let (state, signer) = build_state()?;

    // Case 1: Authorization Bearer header with surrounding spaces
    let req = Request::builder()
        .header(AUTHORIZATION, "Bearer   header.jwt.payload   ")
        .body(())?;
    let (mut parts, ()) = req.into_parts();
    let hdr = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or("missing auth")?
        .as_bytes();
    let hdr_start = hdr.as_ptr() as usize;
    let hdr_end = hdr_start + hdr.len();

    let _auth = AuthUser::from_request_parts(&mut parts, &state)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let tok_ptr = signer.observed_ptr.load(Ordering::SeqCst);
    let tok_len = signer.observed_len.load(Ordering::SeqCst);
    let tok_str = signer
        .observed_token
        .lock()
        .await
        .clone()
        .ok_or("no token")?;
    assert_eq!(tok_str, "header.jwt.payload");
    assert_eq!(tok_len, "header.jwt.payload".len());
    assert!(
        tok_ptr >= hdr_start && tok_ptr + tok_len <= hdr_end,
        "token pointer {tok_ptr:#x}..{:#x} outside Authorization header buffer {hdr_start:#x}..{hdr_end:#x}",
        tok_ptr + tok_len
    );

    // Case 2: Cookie access_token with surrounding cookies & spaces
    let req = Request::builder()
        .header(
            COOKIE,
            "my_access_token=decoy;  access_token=cookie.jwt.token  ; theme=dark",
        )
        .body(())?;
    let (mut parts, ()) = req.into_parts();
    let hdr = parts
        .headers
        .get(COOKIE)
        .ok_or("missing cookie")?
        .as_bytes();
    let hdr_start = hdr.as_ptr() as usize;
    let hdr_end = hdr_start + hdr.len();

    let _auth = AuthUser::from_request_parts(&mut parts, &state)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let tok_ptr = signer.observed_ptr.load(Ordering::SeqCst);
    let tok_len = signer.observed_len.load(Ordering::SeqCst);
    let tok_str = signer
        .observed_token
        .lock()
        .await
        .clone()
        .ok_or("no token")?;
    assert_eq!(tok_str, "cookie.jwt.token");
    assert!(
        tok_ptr >= hdr_start && tok_ptr + tok_len <= hdr_end,
        "token pointer outside Cookie header buffer"
    );

    // Case 3: Empty Bearer falls back to Cookie access_token
    let req = Request::builder()
        .header(AUTHORIZATION, "Bearer    ")
        .header(COOKIE, "access_token=fallback.tok")
        .body(())?;
    let (mut parts, ()) = req.into_parts();
    let hdr = parts
        .headers
        .get(COOKIE)
        .ok_or("missing cookie")?
        .as_bytes();
    let hdr_start = hdr.as_ptr() as usize;
    let hdr_end = hdr_start + hdr.len();

    let _auth = AuthUser::from_request_parts(&mut parts, &state)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let tok_ptr = signer.observed_ptr.load(Ordering::SeqCst);
    let tok_len = signer.observed_len.load(Ordering::SeqCst);
    let tok_str = signer
        .observed_token
        .lock()
        .await
        .clone()
        .ok_or("no token")?;
    assert_eq!(tok_str, "fallback.tok");
    assert!(tok_ptr >= hdr_start && tok_ptr + tok_len <= hdr_end);

    // Case 4: Invalid/missing tokens rejected with Unauthenticated
    for (name, val) in [
        (AUTHORIZATION, "bearer lowercase"),
        (AUTHORIZATION, "Basic dXNlcjpwYXNz"),
        (COOKIE, "my_access_token=nope; access_token=   "),
    ] {
        let req = Request::builder().header(name, val).body(())?;
        let (mut parts, ()) = req.into_parts();
        let res = AuthUser::from_request_parts(&mut parts, &state).await;
        let Err(err) = res else {
            return Err("expected Err from invalid token".into());
        };
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
    }

    Ok(())
}

#[tokio::test]
async fn m3_3_stack_request_id_and_retry_after_headers() -> TestResult {
    // 1. Direct stack [u8; 36] encoding across 100 UUIDs
    for _ in 0..100 {
        let id = RequestId::new();
        let mut buf = [0u8; 36];
        let buf_ptr = buf.as_ptr();
        let encoded = id.encode_hyphenated(&mut buf);
        assert_eq!(encoded.as_ptr(), buf_ptr);
        assert_eq!(encoded.len(), 36);
        assert_eq!(encoded, id.to_string());
    }

    // 2. Middleware propagation, uppercase normalization, nil/invalid replacement
    let app = Router::new()
        .route("/ok", get(|| async { "ok" }))
        .layer(from_fn(request_id_middleware));

    // Uppercase valid UUID -> normalized lowercase 36 bytes
    let upper = "0192A8F0-7C1B-7000-8000-1A2B3C4D5E6F";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ok")
                .header(&X_REQUEST_ID, upper)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        resp.headers()
            .get(&X_REQUEST_ID)
            .and_then(|v| v.to_str().ok()),
        Some("0192a8f0-7c1b-7000-8000-1a2b3c4d5e6f")
    );

    // Nil UUID -> replaced with valid UUIDv7
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ok")
                .header(&X_REQUEST_ID, "00000000-0000-0000-0000-000000000000")
                .body(Body::empty())?,
        )
        .await?;
    let echoed = resp
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Request-Id")?;
    assert_ne!(echoed, "00000000-0000-0000-0000-000000000000");
    assert_eq!(
        Uuid::parse_str(echoed)?.get_version(),
        Some(uuid::Version::SortRand)
    );

    // 3. ApiError::into_response X-Request-Id & Retry-After across edge values
    for secs in [0_u64, 1, 42, 86400, u64::MAX] {
        let req_id = RequestId::new();
        let err = ApiError::new(ErrorKind::RateLimited).with_retry_after(secs);
        let resp = scope_request_id(req_id, async {
            axum::response::IntoResponse::into_response(err)
        })
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(&X_REQUEST_ID)
                .and_then(|v| v.to_str().ok()),
            Some(req_id.to_string().as_str())
        );
        assert_eq!(
            resp.headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some(secs.to_string().as_str())
        );
    }

    Ok(())
}

#[test]
fn m3_4_problem_details_cow_all_variants_and_openapi_schema() -> TestResult {
    let all_kinds = [
        ErrorKind::BadRequest,
        ErrorKind::ValidationFailed,
        ErrorKind::InvalidCredentials,
        ErrorKind::Unauthenticated,
        ErrorKind::TokenInvalid,
        ErrorKind::TokenExpired,
        ErrorKind::TokenReuseDetected,
        ErrorKind::Forbidden,
        ErrorKind::NotFound,
        ErrorKind::MethodNotAllowed,
        ErrorKind::RequestTimeout,
        ErrorKind::Conflict,
        ErrorKind::PayloadTooLarge,
        ErrorKind::UnsupportedMediaType,
        ErrorKind::RateLimited,
        ErrorKind::Internal,
        ErrorKind::ServiceUnavailable,
    ];

    let req_id = RequestId::new();
    for kind in all_kinds {
        let problem = ApiError::new(kind).to_problem(req_id);
        assert!(
            matches!(problem.type_uri, Cow::Borrowed(_)),
            "{kind:?} type_uri not Borrowed"
        );
        assert!(
            matches!(problem.title, Cow::Borrowed(_)),
            "{kind:?} title not Borrowed"
        );
        assert!(
            matches!(problem.detail, Cow::Borrowed(_)),
            "{kind:?} detail not Borrowed"
        );
        assert!(
            matches!(problem.code, Cow::Borrowed(_)),
            "{kind:?} code not Borrowed"
        );
        assert!(problem.type_uri.starts_with("https://errors.korgan.dev/"));
        assert_eq!(problem.instance, format!("urn:uuid:{req_id}"));

        let json_val = serde_json::to_value(&problem)?;
        let obj = json_val.as_object().ok_or("expected JSON object")?;
        assert!(obj.contains_key("type"));
        assert!(!obj.contains_key("type_uri"));
        assert!(!obj.contains_key("errors"));
        let ts = obj
            .get("timestamp")
            .and_then(|v| v.as_str())
            .ok_or("missing timestamp")?;
        assert!(ts.ends_with('Z') && !ts.contains('.'));
    }

    // Static override -> Borrowed, Dynamic override -> Owned
    let static_p = ApiError::new(ErrorKind::Forbidden)
        .with_detail("static text")
        .to_problem(req_id);
    assert!(matches!(static_p.detail, Cow::Borrowed("static text")));

    let dynamic_p = ApiError::new(ErrorKind::Forbidden)
        .with_detail(format!("dynamic {}", 42))
        .with_errors(vec![FieldError {
            field: "email".to_owned(),
            reason: "invalid".to_owned(),
        }])
        .to_problem(req_id);
    assert!(matches!(dynamic_p.detail, Cow::Owned(ref s) if s == "dynamic 42"));
    let dyn_json = serde_json::to_value(&dynamic_p)?;
    assert!(dyn_json.get("errors").is_some());

    // OpenAPI schema check
    let openapi_json = serde_json::to_value(ApiDoc::openapi())?;
    let schema = openapi_json
        .pointer("/components/schemas/ProblemDetails")
        .ok_or("missing ProblemDetails schema")?;
    let props = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .ok_or("missing properties")?;
    for key in ["type", "title", "detail", "instance", "code"] {
        assert_eq!(
            props
                .get(key)
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str()),
            Some("string"),
            "OpenAPI property {key} type mismatch"
        );
    }
    assert_eq!(
        props
            .get("status")
            .and_then(|v| v.get("type"))
            .and_then(|v| v.as_str()),
        Some("integer")
    );
    assert!(props.contains_key("timestamp"));
    assert!(props.contains_key("errors"));

    Ok(())
}

#[tokio::test]
async fn m3_6_client_metadata_alignment_and_client_type_parse() -> TestResult {
    assert_eq!(std::mem::size_of::<ClientMetadata>(), 88);
    assert_eq!(std::mem::align_of::<ClientMetadata>(), 8);

    for web_input in ["web", "Web", "WEB", "wEb", "  web  ", "\tWEB\n"] {
        assert_eq!(
            ClientType::parse(web_input),
            ClientType::Web,
            "failed for {web_input:?}"
        );
    }
    for mobile_input in ["mobile", "Mobile", "MOBILE", " MOBILE ", "\nMoBiLe\t"] {
        assert_eq!(
            ClientType::parse(mobile_input),
            ClientType::Mobile,
            "failed for {mobile_input:?}"
        );
    }
    let long_unknown = "x".repeat(4096);
    for cli_or_unknown in [
        "cli",
        "CLI",
        " Cli ",
        "",
        "   ",
        "unknown",
        "web2",
        "mobile_app",
        "desktop",
        "non-ascii-é",
        long_unknown.as_str(),
    ] {
        assert_eq!(
            ClientType::parse(cli_or_unknown),
            ClientType::Cli,
            "failed for {cli_or_unknown:?}"
        );
    }

    // Exercise ClientMetadata::from_request_parts end-to-end
    let (state, _) = build_state()?;
    let req_id = RequestId::new();
    let mut req = Request::builder()
        .header(http::header::USER_AGENT, "korgan-test/1.0")
        .header("x-device-name", "ThinkPad")
        .header("x-client-type", " MOBILE ")
        .header("x-forwarded-for", "203.0.113.9, 10.0.0.1")
        .body(())?;
    req.extensions_mut().insert(req_id);
    let (mut parts, ()) = req.into_parts();
    let meta = ClientMetadata::from_request_parts(&mut parts, &state).await?;
    assert_eq!(meta.user_agent.as_deref(), Some("korgan-test/1.0"));
    assert_eq!(meta.device_name.as_deref(), Some("ThinkPad"));
    assert_eq!(meta.client_type, ClientType::Mobile);
    assert_eq!(meta.request_id, req_id);
    // trust_proxy_headers defaults to false -> should stay 127.0.0.1
    assert_eq!(meta.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));

    Ok(())
}
