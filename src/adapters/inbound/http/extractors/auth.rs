use std::ops::Deref;

use axum::extract::FromRequestParts;
use chrono::Utc;
use http::header::AUTHORIZATION;
use http::request::Parts;

use crate::adapters::inbound::http::error::{ApiError, ErrorKind};
use crate::adapters::inbound::http::state::AppState;
use crate::domain::entities::{AccountStatus, User, UserRole};
use crate::domain::value_objects::{SessionId, UserId};
use crate::ports::services::AccessTokenClaims;

/// Authenticated user context injected into protected handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthUser {
    /// Authenticated user identifier.
    pub user_id: UserId,
    /// Associated session identifier (embedded as `sid` in the access token).
    pub session_id: SessionId,
    /// Authorization role assigned to this user.
    pub role: UserRole,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token(parts)?;

        let claims = state.token_signer.verify_access_token(token).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("expired") {
                ApiError::new(ErrorKind::TokenExpired)
            } else {
                ApiError::new(ErrorKind::TokenInvalid)
            }
        })?;

        let now = Utc::now();
        if claims.is_expired(now) {
            return Err(ApiError::new(ErrorKind::TokenExpired));
        }

        // Validate issuer and audience claims match server configuration exactly
        if claims.iss.as_ref() != state.settings.auth.issuer {
            tracing::warn!(
                claim_iss = %claims.iss,
                expected_iss = %state.settings.auth.issuer,
                "rejecting access token with mismatched issuer claim"
            );
            return Err(ApiError::new(ErrorKind::TokenInvalid));
        }
        if claims.aud.as_ref() != state.settings.auth.audience {
            tracing::warn!(
                claim_aud = %claims.aud,
                expected_aud = %state.settings.auth.audience,
                "rejecting access token with mismatched audience claim"
            );
            return Err(ApiError::new(ErrorKind::TokenInvalid));
        }

        // Distributed revocation check: fail-closed if blacklisted in Redis or on cache failure
        let blacklist_key = format!("blacklist:session:{}", claims.sid);
        match state.token_store.get_token(&blacklist_key).await {
            Ok(Some(_)) => return Err(ApiError::new(ErrorKind::TokenInvalid)),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "failed to query session blacklist during auth extraction; failing closed");
                return Err(ApiError::new(ErrorKind::ServiceUnavailable));
            }
        }

        // Validate session state in database to ensure session has not been revoked or replaced
        let session = state
            .session_repo
            .find_by_id(&claims.sid)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query session during auth extraction");
                ApiError::new(ErrorKind::Internal)
            })?
            .ok_or_else(|| ApiError::new(ErrorKind::TokenInvalid))?;

        if !session.is_valid(now) {
            return Err(ApiError::new(ErrorKind::TokenInvalid));
        }

        // Query user to ensure account is active and retrieve assigned role
        let user = state
            .user_repo
            .find_by_id(&claims.sub)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query user during auth extraction");
                ApiError::new(ErrorKind::Internal)
            })?
            .ok_or_else(|| ApiError::new(ErrorKind::TokenInvalid))?;

        match user.status {
            AccountStatus::Active => {}
            AccountStatus::Unverified => {
                return Err(
                    ApiError::new(ErrorKind::Forbidden).with_detail("e-mail verification required")
                );
            }
            AccountStatus::Suspended
            | AccountStatus::Deactivated
            | AccountStatus::PendingDeletion => {
                return Err(ApiError::new(ErrorKind::Forbidden));
            }
        }

        let user_id = claims.sub;
        let session_id = claims.sid;
        let role = user.role;

        parts.extensions.insert(claims);
        parts.extensions.insert(user);

        Ok(Self {
            user_id,
            session_id,
            role,
        })
    }
}

/// Extractor enforcing that the authenticated user possesses administrative privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminUser(pub AuthUser);

impl Deref for AdminUser {
    type Target = AuthUser;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;
        if !auth_user.role.is_admin() {
            return Err(ApiError::new(ErrorKind::Forbidden));
        }
        Ok(Self(auth_user))
    }
}

/// Extractor enforcing Step-Up authentication for sensitive operations.
///
/// Mandates:
/// 1. `auth_time` must be within the last 15 minutes (900 seconds), with 30s forward NTP clock skew tolerance.
/// 2. If the user has MFA enabled (`user.mfa_enabled`) or has registered passkeys,
///    the access token's `amr` claim MUST include `"mfa"` or `"passkey"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUpUser(pub AuthUser);

impl Deref for StepUpUser {
    type Target = AuthUser;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequestParts<AppState> for StepUpUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Authenticate user, session, and active account status first.
        // If the token or session is invalid, expired, revoked, or account suspended,
        // it rejects immediately with standard 401/403 before step-up inspection.
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        let claims = parts
            .extensions
            .get::<AccessTokenClaims>()
            .ok_or_else(|| ApiError::new(ErrorKind::TokenInvalid))?;

        let user = parts
            .extensions
            .get::<User>()
            .ok_or_else(|| ApiError::new(ErrorKind::TokenInvalid))?;

        // 2. Check auth_time freshness (must be within last 15 minutes / 900 seconds, with 30s forward clock skew tolerance)
        let now_sec = Utc::now().timestamp();
        // Reject future auth_time beyond 30s NTP clock skew tolerance
        if claims.auth_time > now_sec.saturating_add(30) {
            return Err(ApiError::new(ErrorKind::Forbidden).with_detail(
                "recent re-authentication required: auth_time is in the future beyond clock skew tolerance",
            ));
        }
        // Reject stale auth_time older than 15 minutes (900 seconds). Negative diffs (within 30s future tolerance) safely evaluate <= 900.
        let elapsed = now_sec.saturating_sub(claims.auth_time);
        if elapsed > 900 {
            return Err(ApiError::new(ErrorKind::Forbidden).with_detail(
                "recent re-authentication required: auth_time older than 15 minutes",
            ));
        }

        // 3. Check if user has MFA active or has registered passkeys.
        // Short-circuit when `user.mfa_enabled` is true to avoid a redundant passkey query.
        let requires_mfa_or_passkey = if user.mfa_enabled {
            true
        } else {
            let passkeys = state
                .passkey_repo
                .list_by_user_id(&auth_user.user_id)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to query user passkeys for step-up auth check");
                    ApiError::new(ErrorKind::Internal)
                })?;
            !passkeys.is_empty()
        };

        if requires_mfa_or_passkey {
            let has_valid_amr = claims
                .amr
                .iter()
                .any(|m| m.as_ref() == "mfa" || m.as_ref() == "passkey");
            if !has_valid_amr {
                return Err(ApiError::new(ErrorKind::Forbidden).with_detail(
                    "step-up authentication required: token must have 'mfa' or 'passkey' amr claim",
                ));
            }
        } else {
            // For standard users without MFA or Passkeys enrolled yet (e.g. initial passkey registration or password change),
            // a fresh primary authentication method (such as "pwd" or "oauth") is required and accepted.
            let has_valid_primary = claims.amr.iter().any(|m| {
                m.as_ref() == "pwd"
                    || m.starts_with("oauth")
                    || m.as_ref() == "mfa"
                    || m.as_ref() == "passkey"
            });
            if !has_valid_primary {
                return Err(ApiError::new(ErrorKind::Forbidden).with_detail(
                    "step-up authentication required: token must have valid authentication method",
                ));
            }
        }

        Ok(Self(auth_user))
    }
}

/// Extracts access token from Authorization header (`Bearer <token>`) or Cookie (`access_token=<token>`).
#[inline]
fn extract_token(parts: &Parts) -> Result<&str, ApiError> {
    // 1. Authorization: Bearer <token>
    let bearer = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());

    // 2. Cookie: access_token=<token>
    let cookie_token = parts
        .headers
        .get(http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .filter_map(|c| c.trim().strip_prefix("access_token="))
                .map(str::trim)
                .find(|t| !t.is_empty())
        });

    match (bearer, cookie_token) {
        // Hybrid requests mixing both channels are rejected outright so a
        // caller-supplied header can never shadow (or be confused with) a
        // browser session cookie.
        (Some(_), Some(_)) => {
            tracing::warn!("rejecting hybrid request carrying both Bearer header and cookie");
            Err(ApiError::new(ErrorKind::Unauthenticated))
        }
        (Some(token), None) | (None, Some(token)) => Ok(token),
        (None, None) => Err(ApiError::new(ErrorKind::Unauthenticated)),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use http::Request;
    use http::header::COOKIE;
    use smallvec::smallvec;
    use tokio::sync::mpsc;
    use webauthn_rs::prelude::{
        AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication,
        Passkey as WebauthnPasskey, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential, RequestChallengeResponse,
    };

    use super::*;
    use crate::application::workers::EventBus;
    use crate::config::Settings;
    use crate::domain::entities::{
        AuditLog, OAuthAccount, OAuthProvider, Passkey, Session, User, UserMfa,
    };
    use crate::domain::value_objects::{
        EmailAddress, PasskeyId, PasswordHash, RawPassword, RequestId, Username,
    };
    use crate::ports::cache::{RateLimitStatus, RateLimiterPort, TokenStore};
    use crate::ports::errors::PortError;
    use crate::ports::repositories::{
        AuditLogRepository, OAuthAccountRepository, PasskeyRepository, SessionRepository,
        UserRepository,
    };
    use crate::ports::services::{
        DecryptedSecret, HibpClient, MailProvider, OAuthProfile, OAuthProviderPort, PasswordHasher,
        SecretCipher, TokenSigner, TotpService, WebAuthnService,
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
            _family_id: &crate::domain::value_objects::TokenFamilyId,
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

    struct CountingPasskeyRepo {
        calls: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl PasskeyRepository for CountingPasskeyRepo {
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(PortError::database("simulated passkey db outage"))
            } else {
                Ok(Vec::new())
            }
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

    struct StubTokenSigner(AccessTokenClaims);

    impl TokenSigner for StubTokenSigner {
        fn sign_access_token(&self, _claims: &AccessTokenClaims) -> Result<String, PortError> {
            Ok("stub-token".to_owned())
        }
        fn verify_access_token(&self, _token: &str) -> Result<AccessTokenClaims, PortError> {
            Ok(self.0.clone())
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

    struct NoopTokenStore {
        fail_get: bool,
    }
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
            if self.fail_get {
                return Err(PortError::cache("redis unreachable"));
            }
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
            _password: &RawPassword,
            _hash: &PasswordHash,
        ) -> Result<bool, PortError> {
            Ok(false)
        }
        async fn verify_against_dummy_hash(
            &self,
            _password: &RawPassword,
        ) -> Result<(), PortError> {
            Ok(())
        }
    }

    struct NoopCipher;
    impl SecretCipher for NoopCipher {
        fn encrypt_with_aad(
            &self,
            _plaintext: &[u8],
            _aad: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), PortError> {
            Ok((Vec::new(), vec![0u8; 12]))
        }
        fn decrypt_with_aad(
            &self,
            _ciphertext: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
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
            _email: &EmailAddress,
            _secret: &[u8],
            _issuer: &str,
        ) -> Result<String, PortError> {
            Ok(String::new())
        }
        fn verify_code(
            &self,
            _secret: &[u8],
            _code: &str,
            _now_epoch_secs: u64,
        ) -> Result<bool, PortError> {
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
            _to: &EmailAddress,
            _subject: &str,
            _text_body: &str,
            _html_body: &str,
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
            _user_id: &UserId,
            _username: &str,
            _existing_passkeys: &[Passkey],
        ) -> Result<(CreationChallengeResponse, PasskeyRegistration), PortError> {
            Err(PortError::external_service("webauthn", "noop", None))
        }
        fn finish_registration(
            &self,
            _reg_response: &RegisterPublicKeyCredential,
            _reg_state: &PasskeyRegistration,
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
            _auth_response: &PublicKeyCredential,
            _auth_state: DiscoverableAuthentication,
            _candidate_passkeys: &[Passkey],
        ) -> Result<(AuthenticationResult, WebauthnPasskey), PortError> {
            Err(PortError::external_service("webauthn", "noop", None))
        }
    }

    fn test_settings() -> Result<Arc<Settings>, Box<dyn std::error::Error>> {
        let env = HashMap::from([
            (
                "DATABASE_URL".to_owned(),
                "postgres://u:p@localhost:5432/db".to_owned(),
            ),
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
        Ok(Arc::new(Settings::load_from_env(env)?))
    }

    fn build_step_up_test_state(
        mfa_enabled: bool,
        fail_passkeys: bool,
    ) -> Result<(AppState, Arc<CountingPasskeyRepo>), Box<dyn std::error::Error>> {
        build_test_state(mfa_enabled, fail_passkeys, false)
    }

    fn build_test_state(
        mfa_enabled: bool,
        fail_passkeys: bool,
        fail_blacklist: bool,
    ) -> Result<(AppState, Arc<CountingPasskeyRepo>), Box<dyn std::error::Error>> {
        let settings = test_settings()?;
        let now = Utc::now();

        let mut user = User::new(EmailAddress::parse("stepup@example.com")?, None, None);
        user.status = AccountStatus::Active;
        user.mfa_enabled = mfa_enabled;
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
            amr: smallvec![Cow::Borrowed("pwd"), Cow::Borrowed("mfa")],
        };

        let passkey_repo = Arc::new(CountingPasskeyRepo {
            calls: AtomicUsize::new(0),
            fail: fail_passkeys,
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
            passkey_repo.clone(),
            Arc::new(NoopTokenStore {
                fail_get: fail_blacklist,
            }),
            Arc::new(NoopRateLimiter),
            Arc::new(NoopHasher),
            Arc::new(StubTokenSigner(claims)),
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

        Ok((state, passkey_repo))
    }

    #[test]
    fn extract_token_borrows_zero_copy_from_bearer_header() -> TestResult {
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer  abc.def.ghi  ")
            .body(())?;
        let (parts, ()) = req.into_parts();
        let hdr_bytes = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or("missing auth header")?
            .as_bytes();

        let token = extract_token(&parts).map_err(|_| "expected token")?;
        assert_eq!(token, "abc.def.ghi");
        let start = hdr_bytes.as_ptr() as usize;
        let end = start + hdr_bytes.len();
        let tok_ptr = token.as_ptr() as usize;
        assert!(tok_ptr >= start && tok_ptr + token.len() <= end);
        Ok(())
    }

    #[test]
    fn extract_token_borrows_zero_copy_from_cookie_and_rejects_empty() -> TestResult {
        let req = Request::builder()
            .header(COOKIE, "theme=dark; access_token=tok_123 ; other=1")
            .body(())?;
        let (parts, ()) = req.into_parts();
        let hdr_bytes = parts
            .headers
            .get(COOKIE)
            .ok_or("missing cookie header")?
            .as_bytes();

        let token = extract_token(&parts).map_err(|_| "expected token")?;
        assert_eq!(token, "tok_123");
        let start = hdr_bytes.as_ptr() as usize;
        let end = start + hdr_bytes.len();
        let tok_ptr = token.as_ptr() as usize;
        assert!(tok_ptr >= start && tok_ptr + token.len() <= end);

        let empty_req = Request::builder()
            .header(AUTHORIZATION, "Bearer    ")
            .body(())?;
        let (empty_parts, ()) = empty_req.into_parts();
        assert!(extract_token(&empty_parts).is_err());
        Ok(())
    }

    /// KRG-SEC-01: a request carrying both a Bearer header and an access-token
    /// cookie is a hybrid request and must be rejected, never silently resolved.
    #[test]
    fn krg_sec_01_extract_token_rejects_hybrid_bearer_and_cookie() -> TestResult {
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer attacker.chosen.token")
            .header(COOKIE, "access_token=victim.session.token")
            .body(())?;
        let (parts, ()) = req.into_parts();

        let err = extract_token(&parts)
            .err()
            .ok_or("hybrid Bearer+cookie request must be rejected")?;
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
        Ok(())
    }

    /// KRG-SEC-04: a Redis outage during the blacklist lookup must fail closed
    /// with 503 (project invariants), not a generic 500.
    #[tokio::test]
    async fn krg_sec_04_blacklist_cache_failure_returns_service_unavailable() -> TestResult {
        let (state, _) = build_test_state(true, false, true)?;
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer stub-token")
            .body(())?;
        let (mut parts, ()) = req.into_parts();

        let err = AuthUser::from_request_parts(&mut parts, &state)
            .await
            .err()
            .ok_or("blacklist failure must reject the request")?;
        assert_eq!(err.kind(), ErrorKind::ServiceUnavailable);
        Ok(())
    }

    #[tokio::test]
    async fn step_up_short_circuits_passkey_query_when_mfa_enabled() -> TestResult {
        let (state, passkey_repo) = build_step_up_test_state(true, true)?;
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer stub-token")
            .body(())?;
        let (mut parts, ()) = req.into_parts();

        let extracted = StepUpUser::from_request_parts(&mut parts, &state)
            .await
            .map_err(|_| "expected step-up auth to succeed")?;
        assert_eq!(
            passkey_repo.calls.load(Ordering::SeqCst),
            0,
            "passkey_repo.list_by_user_id must NOT be called when user.mfa_enabled == true"
        );
        assert_eq!(extracted.user_id, extracted.0.user_id);
        Ok(())
    }

    #[tokio::test]
    async fn step_up_queries_passkeys_and_preserves_db_error_when_mfa_disabled() -> TestResult {
        let (state, passkey_repo) = build_step_up_test_state(false, true)?;
        let req = Request::builder()
            .header(AUTHORIZATION, "Bearer stub-token")
            .body(())?;
        let (mut parts, ()) = req.into_parts();

        let res = StepUpUser::from_request_parts(&mut parts, &state).await;
        assert_eq!(passkey_repo.calls.load(Ordering::SeqCst), 1);
        let err = res.err().ok_or("expected DB error to propagate")?;
        assert_eq!(err.kind(), ErrorKind::Internal);
        Ok(())
    }

    #[tokio::test]
    async fn app_state_clone_shares_inner_allocation_via_deref() -> TestResult {
        let (state, _) = build_step_up_test_state(true, false)?;
        let cloned = state.clone();
        assert!(std::ptr::eq(&raw const *state, &raw const *cloned));
        assert!(Arc::ptr_eq(&state.user_repo, &cloned.user_repo));
        Ok(())
    }
}
