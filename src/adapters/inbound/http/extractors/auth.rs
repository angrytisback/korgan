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

        let claims = state
            .token_signer
            .verify_access_token(&token)
            .map_err(|e| {
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
        if claims.iss != state.settings.auth.issuer {
            tracing::warn!(
                claim_iss = %claims.iss,
                expected_iss = %state.settings.auth.issuer,
                "rejecting access token with mismatched issuer claim"
            );
            return Err(ApiError::new(ErrorKind::TokenInvalid));
        }
        if claims.aud != state.settings.auth.audience {
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
                return Err(ApiError::new(ErrorKind::Internal));
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
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorKind::TokenInvalid))?;

        let user = parts
            .extensions
            .get::<User>()
            .cloned()
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

        // 3. Check if user has MFA active or has registered passkeys
        let passkeys = state
            .passkey_repo
            .list_by_user_id(&auth_user.user_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to query user passkeys for step-up auth check");
                ApiError::new(ErrorKind::Internal)
            })?;

        let requires_mfa_or_passkey = user.mfa_enabled || !passkeys.is_empty();
        if requires_mfa_or_passkey {
            let has_valid_amr = claims.amr.iter().any(|m| m == "mfa" || m == "passkey");
            if !has_valid_amr {
                return Err(ApiError::new(ErrorKind::Forbidden).with_detail(
                    "step-up authentication required: token must have 'mfa' or 'passkey' amr claim",
                ));
            }
        } else {
            // For standard users without MFA or Passkeys enrolled yet (e.g. initial passkey registration or password change),
            // a fresh primary authentication method (such as "pwd" or "oauth") is required and accepted.
            let has_valid_primary = claims
                .amr
                .iter()
                .any(|m| m == "pwd" || m.starts_with("oauth") || m == "mfa" || m == "passkey");
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
fn extract_token(parts: &Parts) -> Result<String, ApiError> {
    // 1. Check Authorization: Bearer <token>
    if let Some(auth_header) = parts.headers.get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }

    // 2. Check Cookie: access_token=<token>
    if let Some(cookie_hdr) = parts.headers.get(http::header::COOKIE)
        && let Ok(cookie_str) = cookie_hdr.to_str()
    {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some(token) = cookie.strip_prefix("access_token=") {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_owned());
                }
            }
        }
    }

    Err(ApiError::new(ErrorKind::Unauthenticated))
}
