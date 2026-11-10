//! Adversarial stress tests for RFC 9068 `typ` and strict `iss`/`aud` validation.
//!
//! Verifies:
//! 1. Full RFC 9068 `typ` matrix rejection & acceptance in `Ed25519JwtService`.
//! 2. Strict string equality on `iss` and `aud` in `AuthUser` extractor across HTTP Bearer and Cookie channels.
//! 3. Edge cases: empty strings, whitespace, casing, path variations, cross-protocol tokens.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::response::Response;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer;
use http::header::{AUTHORIZATION, COOKIE};
use http::{Method, Request, StatusCode};
use korgan::adapters::inbound::http::{AppState, build_router};
use korgan::adapters::outbound::crypto::{
    Aes256GcmCipher, Argon2PasswordHasher, Ed25519JwtService, Rfc6238TotpService, WebauthnRsAdapter,
};
use korgan::adapters::outbound::hibp::NoopHibpClient;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::adapters::outbound::oauth::NoopOAuthProvider;
use korgan::application::workers::EventBus;
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
use korgan::ports::services::{AccessTokenClaims, OAuthProviderPort, TokenSigner, WebAuthnService};
use secrecy::ExposeSecret;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\n-----END PRIVATE KEY-----";
const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

// ---------------------------------------------------------------------------
// In-Memory Test Fixtures
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct TestUserRepo {
    users: Mutex<HashMap<UserId, User>>,
}

#[async_trait]
impl UserRepository for TestUserRepo {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, PortError> {
        let users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, _email: &EmailAddress) -> Result<Option<User>, PortError> {
        Ok(None)
    }

    async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, PortError> {
        Ok(None)
    }

    async fn create(&self, user: &User) -> Result<(), PortError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
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
        Ok(vec![])
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
        Ok(vec![])
    }

    async fn count_all(&self) -> Result<u64, PortError> {
        Ok(0)
    }

    async fn record_failed_login_atomic(
        &self,
        _user_id: &UserId,
        _max_attempts: u16,
        _lockout_until: chrono::DateTime<chrono::Utc>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(u16, Option<chrono::DateTime<chrono::Utc>>), PortError> {
        Ok((0, None))
    }

    async fn reset_failed_logins(
        &self,
        _user_id: &UserId,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
struct TestSessionRepo {
    sessions: Mutex<HashMap<SessionId, Session>>,
}

#[async_trait]
impl SessionRepository for TestSessionRepo {
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

    async fn find_by_token_hash(&self, _token_hash: &str) -> Result<Option<Session>, PortError> {
        Ok(None)
    }

    async fn list_by_user_id(
        &self,
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<Session>, PortError> {
        Ok(vec![])
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
        _family_id: &TokenFamilyId,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(vec![])
    }

    async fn revoke_all_user_sessions(
        &self,
        _user_id: &UserId,
        _except_session: Option<&SessionId>,
        _reason: &str,
    ) -> Result<Vec<SessionId>, PortError> {
        Ok(vec![])
    }

    async fn purge_expired(&self, _max_purge: u32) -> Result<u64, PortError> {
        Ok(0)
    }
}

#[derive(Default, Debug)]
struct TestAuditRepo;

#[async_trait]
impl AuditLogRepository for TestAuditRepo {
    async fn append(&self, _entry: &AuditLog) -> Result<(), PortError> {
        Ok(())
    }

    async fn list_by_user_id(
        &self,
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        Ok(vec![])
    }

    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        Ok(vec![])
    }
}

#[derive(Default, Debug)]
struct TestTokenStore {
    tokens: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl TokenStore for TestTokenStore {
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

    async fn consume_token(
        &self,
        _key: &str,
        _expected_token_hash: &str,
    ) -> Result<bool, PortError> {
        Ok(true)
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
struct TestRateLimiter;

#[async_trait]
impl RateLimiterPort for TestRateLimiter {
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
struct TestOAuthAccountRepo;

#[async_trait]
impl OAuthAccountRepository for TestOAuthAccountRepo {
    async fn find_by_provider_and_id(
        &self,
        _provider: OAuthProvider,
        _provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, PortError> {
        Ok(None)
    }

    async fn list_by_user_id(&self, _user_id: &UserId) -> Result<Vec<OAuthAccount>, PortError> {
        Ok(vec![])
    }

    async fn create(&self, _account: &OAuthAccount) -> Result<(), PortError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
struct TestPasskeyRepo;

#[async_trait]
impl PasskeyRepository for TestPasskeyRepo {
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
        Ok(vec![])
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

struct TestContext {
    app: Router,
    user_repo: Arc<TestUserRepo>,
    session_repo: Arc<TestSessionRepo>,
    jwt_service: Arc<Ed25519JwtService>,
}

fn setup_test_context() -> Result<TestContext, Box<dyn std::error::Error>> {
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

    let user_repo = Arc::new(TestUserRepo::default());
    let session_repo = Arc::new(TestSessionRepo::default());
    let audit_repo = Arc::new(TestAuditRepo);
    let token_store = Arc::new(TestTokenStore::default());
    let rate_limiter = Arc::new(TestRateLimiter);
    let oauth_account_repo: Arc<dyn OAuthAccountRepository> = Arc::new(TestOAuthAccountRepo);
    let passkey_repo: Arc<dyn PasskeyRepository> = Arc::new(TestPasskeyRepo);
    let google_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::Google));
    let github_oauth: Arc<dyn OAuthProviderPort> =
        Arc::new(NoopOAuthProvider::new(OAuthProvider::GitHub));
    let webauthn_service: Arc<dyn WebAuthnService> = Arc::new(WebauthnRsAdapter::new(
        "localhost",
        "http://localhost:8080",
    )?);

    let password_hasher = Arc::new(Argon2PasswordHasher::new(1024, 1, 1)?);
    let jwt_service = Arc::new(Ed25519JwtService::from_pkcs8_pem(
        settings.crypto.normalized_ed25519_pem().expose_secret(),
        Some(settings.crypto.ed25519_key_id.clone()),
    )?);
    let secret_cipher = Arc::new(Aes256GcmCipher::from_base64(
        settings.crypto.aes_master_key.expose_secret(),
    )?);
    let totp_service = Arc::new(Rfc6238TotpService::new());
    let hibp_client = Arc::new(NoopHibpClient);
    let mail_provider = Arc::new(ConsoleMailProvider::new("no-reply@example.com"));

    let (event_bus, _event_rx) = EventBus::new(100);

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
        jwt_service.clone(),
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
        jwt_service,
    })
}

async fn send_request(
    app: &Router,
    req: Request<Body>,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app.clone().oneshot(req).await?)
}

// ===========================================================================
// SECTION 1: Adversarial RFC 9068 `typ` Parameter Verification
// ===========================================================================

#[test]
fn adversarial_typ_header_rejection_matrix() -> TestResult {
    let now = Utc::now();
    let claims = AccessTokenClaims {
        sub: UserId::new(),
        sid: SessionId::new(),
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: now.timestamp() + 3600,
        iat: now.timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_string()],
    };

    // Matrix of invalid, dangerous, or cross-protocol `typ` values
    let invalid_typ_values = [
        // 1. Missing typ parameter
        None,
        // 2. Empty string
        Some(""),
        // 3. Whitespace strings
        Some(" "),
        Some("   "),
        Some("\t"),
        Some("\n"),
        // 4. Standard JOSE / JWT types (must NOT be accepted as RFC 9068 access tokens)
        Some("JWT"),
        Some("jwt"),
        Some("JWS"),
        // 5. OpenID Connect ID Token type confusion
        Some("id+jwt"),
        Some("ID+JWT"),
        // 6. Refresh token type confusion
        Some("refresh+jwt"),
        // 7. Logout token type confusion (RFC 8693 / RFC 8414)
        Some("logout+jwt"),
        // 8. Null / none / attack strings
        Some("none"),
        Some("None"),
        Some("null"),
        // 9. Padding / Whitespace injection
        Some("at+jwt "),
        Some(" at+jwt"),
        Some(" at+jwt "),
        Some("application/at+jwt "),
        Some(" application/at+jwt"),
        // 10. MIME type variants not permitted by RFC 9068
        Some("application/jwt"),
        Some("application/json"),
        Some("application/jose"),
        Some("text/plain"),
        // 11. Generic OAuth token types
        Some("bearer"),
        Some("Bearer"),
        Some("access_token"),
    ];

    for typ_opt in invalid_typ_values {
        let mut header_map = serde_json::Map::new();
        header_map.insert("alg".to_string(), serde_json::json!("EdDSA"));
        header_map.insert("kid".to_string(), serde_json::json!("test-adversarial-kid"));
        if let Some(typ_val) = typ_opt {
            header_map.insert("typ".to_string(), serde_json::json!(typ_val));
        }

        let header = serde_json::Value::Object(header_map);
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");

        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing_key = SigningKey::from_pkcs8_pem(TEST_PEM)?;
        let test_service =
            Ed25519JwtService::from_pkcs8_pem(TEST_PEM, Some("test-adversarial-kid".to_string()))?;

        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let result = test_service.verify_access_token(&token);
        assert!(
            result.is_err(),
            "RFC 9068 VIOLATION: Expected rejection for typ={typ_opt:?}, but verification succeeded!"
        );

        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => unreachable!(),
        };

        if typ_opt.is_none() {
            assert!(
                err_msg.contains("missing or empty JWT typ header parameter"),
                "Wrong error message for missing typ: {err_msg}"
            );
        } else {
            assert!(
                err_msg.contains("invalid JWT typ") || err_msg.contains("missing or empty"),
                "Wrong error message for invalid typ {typ_opt:?}: {err_msg}"
            );
        }
    }

    Ok(())
}

#[test]
fn adversarial_typ_header_acceptance_rfc9068() -> TestResult {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_pem(TEST_PEM)?;
    let test_service =
        Ed25519JwtService::from_pkcs8_pem(TEST_PEM, Some("test-rfc-kid".to_string()))?;
    let now = Utc::now();
    let claims = AccessTokenClaims {
        sub: UserId::new(),
        sid: SessionId::new(),
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: now.timestamp() + 3600,
        iat: now.timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_string()],
    };

    // Both "at+jwt" and "application/at+jwt" MUST be accepted per RFC 9068 Section 2.1
    for valid_typ in ["at+jwt", "application/at+jwt"] {
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": valid_typ,
            "kid": "test-rfc-kid"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let verified = test_service.verify_access_token(&token);
        assert!(
            verified.is_ok(),
            "RFC 9068 COMPLIANCE FAILURE: Failed to accept valid typ '{valid_typ}': {:?}",
            verified.err()
        );
        let claims_out = verified?;
        assert_eq!(claims_out.sub, claims.sub);
        assert_eq!(claims_out.iss, claims.iss);
        assert_eq!(claims_out.aud, claims.aud);
    }

    Ok(())
}

// ===========================================================================
// SECTION 2: Adversarial iss and aud Claim Verification in Ed25519JwtService
// ===========================================================================

#[test]
fn adversarial_empty_and_whitespace_claims_rejected() -> TestResult {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_pem(TEST_PEM)?;
    let test_service =
        Ed25519JwtService::from_pkcs8_pem(TEST_PEM, Some("test-claims-kid".to_string()))?;
    let now = Utc::now();

    // 1. Empty and whitespace `iss`
    for invalid_iss in ["", " ", "   ", "\t", "\n"] {
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: invalid_iss.to_string(),
            aud: "korgan".to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "at+jwt",
            "kid": "test-claims-kid"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let res = test_service.verify_access_token(&token);
        assert!(
            res.is_err(),
            "Expected error for empty/whitespace iss={invalid_iss:?}"
        );
        let err_msg = match res {
            Err(e) => e.to_string(),
            Ok(_) => unreachable!(),
        };
        assert!(err_msg.contains("missing or empty JWT issuer ('iss')"));
    }

    // 2. Empty and whitespace `aud`
    for invalid_aud in ["", " ", "   ", "\t", "\n"] {
        let claims = AccessTokenClaims {
            sub: UserId::new(),
            sid: SessionId::new(),
            iss: "http://localhost:8080".to_string(),
            aud: invalid_aud.to_string(),
            exp: now.timestamp() + 3600,
            iat: now.timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "at+jwt",
            "kid": "test-claims-kid"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let res = test_service.verify_access_token(&token);
        assert!(
            res.is_err(),
            "Expected error for empty/whitespace aud={invalid_aud:?}"
        );
        let err_msg = match res {
            Err(e) => e.to_string(),
            Ok(_) => unreachable!(),
        };
        assert!(err_msg.contains("missing or empty JWT audience ('aud')"));
    }

    Ok(())
}

// ===========================================================================
// SECTION 3: Adversarial AuthUser Extractor Integration Verification
// ===========================================================================

#[tokio::test]
async fn adversarial_auth_user_strict_iss_matching() -> TestResult {
    let ctx = setup_test_context()?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(
        EmailAddress::parse("iss_adv@example.com")?,
        Some(Username::new("iss_adv")?),
        dummy_hash,
    );
    user.status = AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    let session = Session::new(
        user.id,
        "hash_iss_adv".to_string(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    ctx.session_repo.create(&session).await?;

    // Server is configured with issuer = "http://localhost:8080"
    let mismatched_issuers = [
        // Foreign domains
        "https://evil.attacker.com",
        "https://auth.korgan.local",
        "http://evil.com/http://localhost:8080",
        // Subdomain / Port mismatch
        "http://localhost:8081",
        "http://sub.localhost:8080",
        // Scheme mismatch
        "https://localhost:8080",
        // IP vs Hostname mismatch
        "http://127.0.0.1:8080",
        // Path / Trailing slash variations
        "http://localhost:8080/",
        "http://localhost:8080/v1",
        // Case variations
        "HTTP://LOCALHOST:8080",
        "http://LocalHost:8080",
        // Substring injection
        "http://localhost:8080.evil.com",
    ];

    for bad_iss in mismatched_issuers {
        let claims = AccessTokenClaims {
            sub: user.id,
            sid: session.id,
            iss: bad_iss.to_string(),
            aud: "korgan".to_string(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let token = ctx.jwt_service.sign_access_token(&claims)?;

        // 1. Test via Authorization: Bearer <token>
        let req_bearer = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/users/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())?;

        let res_bearer = send_request(&ctx.app, req_bearer).await?;
        assert_eq!(
            res_bearer.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 9068 VIOLATION: Mismatched issuer '{bad_iss}' was accepted via Bearer!"
        );

        // 2. Test via Cookie: access_token=<token>
        let req_cookie = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/users/me")
            .header(COOKIE, format!("access_token={token}"))
            .body(Body::empty())?;

        let res_cookie = send_request(&ctx.app, req_cookie).await?;
        assert_eq!(
            res_cookie.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 9068 VIOLATION: Mismatched issuer '{bad_iss}' was accepted via Cookie!"
        );
    }

    Ok(())
}

#[tokio::test]
async fn adversarial_auth_user_strict_aud_matching() -> TestResult {
    let ctx = setup_test_context()?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(
        EmailAddress::parse("aud_adv@example.com")?,
        Some(Username::new("aud_adv")?),
        dummy_hash,
    );
    user.status = AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    let session = Session::new(
        user.id,
        "hash_aud_adv".to_string(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    ctx.session_repo.create(&session).await?;

    // Server is configured with audience = "korgan"
    let mismatched_audiences = [
        // Different service / audience
        "other-service",
        "api-gateway",
        "korgan-admin",
        // Case variations (strict string equality must reject uppercase)
        "KORGAN",
        "Korgan",
        "kOrgan",
        // Whitespace padding
        "korgan ",
        " korgan",
        // Substring / prefix injection
        "korgan-frontend",
        "korgan.local",
        "https://korgan",
    ];

    for bad_aud in mismatched_audiences {
        let claims = AccessTokenClaims {
            sub: user.id,
            sid: session.id,
            iss: "http://localhost:8080".to_string(),
            aud: bad_aud.to_string(),
            exp: Utc::now().timestamp() + 300,
            iat: Utc::now().timestamp(),
            jti: uuid::Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: vec!["pwd".to_string()],
        };

        let token = ctx.jwt_service.sign_access_token(&claims)?;

        // 1. Test via Bearer
        let req_bearer = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/users/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())?;

        let res_bearer = send_request(&ctx.app, req_bearer).await?;
        assert_eq!(
            res_bearer.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 9068 VIOLATION: Mismatched audience '{bad_aud}' was accepted via Bearer!"
        );

        // 2. Test via Cookie
        let req_cookie = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/users/me")
            .header(COOKIE, format!("access_token={token}"))
            .body(Body::empty())?;

        let res_cookie = send_request(&ctx.app, req_cookie).await?;
        assert_eq!(
            res_cookie.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 9068 VIOLATION: Mismatched audience '{bad_aud}' was accepted via Cookie!"
        );
    }

    Ok(())
}

#[tokio::test]
async fn adversarial_auth_user_exact_valid_tokens_succeed() -> TestResult {
    let ctx = setup_test_context()?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(
        EmailAddress::parse("valid_adv@example.com")?,
        Some(Username::new("valid_adv")?),
        dummy_hash,
    );
    user.status = AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    let session = Session::new(
        user.id,
        "hash_valid_adv".to_string(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    ctx.session_repo.create(&session).await?;

    // 1. Token signed normally ("at+jwt", exact iss, exact aud)
    let claims = AccessTokenClaims {
        sub: user.id,
        sid: session.id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };
    let normal_token = ctx.jwt_service.sign_access_token(&claims)?;

    let req1 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {normal_token}"))
        .body(Body::empty())?;
    let res1 = send_request(&ctx.app, req1).await?;
    assert_eq!(res1.status(), StatusCode::OK);

    // 2. Token forged with typ = "application/at+jwt" (RFC 9068 alternative valid typ)
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let signing_key = SigningKey::from_pkcs8_pem(TEST_PEM)?;

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "application/at+jwt",
        "kid": "korgan-key-1"
    });
    let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let app_at_jwt_token = format!("{signing_input}.{sig_b64}");

    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(AUTHORIZATION, format!("Bearer {app_at_jwt_token}"))
        .body(Body::empty())?;
    let res2 = send_request(&ctx.app, req2).await?;
    assert_eq!(
        res2.status(),
        StatusCode::OK,
        "RFC 9068 'application/at+jwt' should be accepted by AuthUser extractor!"
    );

    // 3. Cookie delivery with "application/at+jwt"
    let req3 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/users/me")
        .header(COOKIE, format!("access_token={app_at_jwt_token}"))
        .body(Body::empty())?;
    let res3 = send_request(&ctx.app, req3).await?;
    assert_eq!(res3.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn adversarial_auth_user_rejects_cross_protocol_tokens() -> TestResult {
    let ctx = setup_test_context()?;
    let dummy_hash =
        PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlndPqnRMg")?;
    let mut user = User::new(
        EmailAddress::parse("cross_adv@example.com")?,
        Some(Username::new("cross_adv")?),
        dummy_hash,
    );
    user.status = AccountStatus::Active;
    ctx.user_repo.create(&user).await?;

    let session = Session::new(
        user.id,
        "hash_cross_adv".to_string(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some("Mozilla/5.0".to_string()),
        None,
        chrono::Duration::days(1),
    );
    ctx.session_repo.create(&session).await?;

    let claims = AccessTokenClaims {
        sub: user.id,
        sid: session.id,
        iss: "http://localhost:8080".to_string(),
        aud: "korgan".to_string(),
        exp: Utc::now().timestamp() + 300,
        iat: Utc::now().timestamp(),
        jti: uuid::Uuid::now_v7().to_string(),
        auth_time: session.created_at.timestamp(),
        amr: vec!["pwd".to_string()],
    };

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let signing_key = SigningKey::from_pkcs8_pem(TEST_PEM)?;

    // Attack: Attacker presents validly signed ID token (`typ: "id+jwt"` or `typ: "JWT"`)
    // or Refresh token (`typ: "refresh+jwt"`) to the access-token protected API endpoint.
    let cross_protocol_typs = ["JWT", "id+jwt", "refresh+jwt", "logout+jwt", "none", ""];

    for dangerous_typ in cross_protocol_typs {
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": dangerous_typ,
            "kid": "korgan-key-1"
        });
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/users/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())?;

        let res = send_request(&ctx.app, req).await?;
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "RFC 9068 VIOLATION: Cross-protocol token with typ='{dangerous_typ}' was accepted by AuthUser!"
        );
    }

    Ok(())
}
