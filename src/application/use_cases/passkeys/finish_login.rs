//! Use case: complete discoverable WebAuthn passkey login ceremony.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use uuid::Uuid;
use webauthn_rs::prelude::DiscoverableAuthentication;

use crate::application::dto::auth::AuthTokensResult;
use crate::application::dto::passkeys::PasskeyLoginFinishCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::{AuditEventStatus, AuditLog, Session, audit_events};
use crate::domain::errors::DomainError;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{PasskeyRepository, SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, TokenSigner, WebAuthnService};

/// Orchestrates completing discoverable WebAuthn passkey authentication.
#[derive(Clone)]
pub struct FinishPasskeyLoginUseCase {
    user_repo: Arc<dyn UserRepository>,
    passkey_repo: Arc<dyn PasskeyRepository>,
    session_repo: Arc<dyn SessionRepository>,
    webauthn_service: Arc<dyn WebAuthnService>,
    token_store: Arc<dyn TokenStore>,
    token_signer: Arc<dyn TokenSigner>,
    event_bus: EventBus,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for FinishPasskeyLoginUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishPasskeyLoginUseCase")
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl FinishPasskeyLoginUseCase {
    /// Creates a new [`FinishPasskeyLoginUseCase`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        passkey_repo: Arc<dyn PasskeyRepository>,
        session_repo: Arc<dyn SessionRepository>,
        webauthn_service: Arc<dyn WebAuthnService>,
        token_store: Arc<dyn TokenStore>,
        token_signer: Arc<dyn TokenSigner>,
        event_bus: EventBus,
        access_token_ttl: Duration,
        refresh_token_ttl: Duration,
        issuer: String,
        audience: String,
    ) -> Self {
        Self {
            user_repo,
            passkey_repo,
            session_repo,
            webauthn_service,
            token_store,
            token_signer,
            event_bus,
            access_token_ttl,
            refresh_token_ttl,
            issuer,
            audience,
        }
    }

    /// Verifies discoverable authentication assertion and creates an authenticated session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if challenge expired, credential unknown, signature invalid, or user blocked.
    pub async fn execute(
        &self,
        cmd: PasskeyLoginFinishCommand,
    ) -> Result<AuthTokensResult, AppError> {
        let res = self.execute_internal(cmd).await;
        match &res {
            Ok(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "passkey", "status" => "success").increment(1);
            }
            Err(_) => {
                metrics::counter!("korgan_auth_attempts_total", "method" => "passkey", "status" => "failure").increment(1);
            }
        }
        res
    }

    async fn execute_internal(
        &self,
        cmd: PasskeyLoginFinishCommand,
    ) -> Result<AuthTokensResult, AppError> {
        let now = Utc::now();

        // 1. Atomically consume challenge state
        let cache_key = format!("passkey:login:{}", cmd.challenge_id);
        let state_json = self
            .token_store
            .get_and_delete(&cache_key)
            .await?
            .ok_or(DomainError::ChallengeExpired)?;

        let auth_state: DiscoverableAuthentication =
            serde_json::from_str(&state_json).map_err(|_| DomainError::ChallengeExpired)?;

        // 2. Identify candidate passkey by raw credential ID
        let maybe_passkey = self
            .passkey_repo
            .find_by_credential_id(cmd.credential.raw_id.as_slice())
            .await?;

        let candidate_passkeys = match maybe_passkey {
            Some(pk) => vec![pk],
            None => {
                let audit = AuditLog::new(
                    None,
                    Some(cmd.ip_address),
                    cmd.user_agent,
                    cmd.request_id,
                    audit_events::PASSKEY_LOGIN,
                    AuditEventStatus::Failure,
                    serde_json::json!({
                        "reason": "passkey credential not found",
                    }),
                );
                self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));
                return Err(AppError::InvalidCredentials);
            }
        };

        // 3. Complete authentication verification via WebAuthn service
        let (_auth_result, updated_passkey) = match self.webauthn_service.finish_discoverable_login(
            &cmd.credential,
            auth_state,
            &candidate_passkeys,
        ) {
            Ok(res) => res,
            Err(e) => {
                let audit = AuditLog::new(
                    Some(candidate_passkeys[0].user_id),
                    Some(cmd.ip_address),
                    cmd.user_agent,
                    cmd.request_id,
                    audit_events::PASSKEY_LOGIN,
                    AuditEventStatus::Failure,
                    serde_json::json!({
                        "passkey_id": candidate_passkeys[0].id,
                        "reason": e.to_string(),
                    }),
                );
                self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));
                return Err(AppError::InvalidCredentials);
            }
        };

        let mut passkey_entity = candidate_passkeys
            .into_iter()
            .next()
            .ok_or(AppError::InvalidCredentials)?;

        // 4. Load User and verify active status BEFORE mutating passkey state
        let user = self
            .user_repo
            .find_by_id(&passkey_entity.user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if let Err(domain_err) = user.can_login(now) {
            let audit = AuditLog::new(
                Some(user.id),
                Some(cmd.ip_address),
                cmd.user_agent,
                cmd.request_id,
                audit_events::PASSKEY_LOGIN,
                AuditEventStatus::Blocked,
                serde_json::json!({
                    "passkey_id": passkey_entity.id,
                    "reason": domain_err.to_string(),
                }),
            );
            self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));
            return Err(AppError::from(domain_err));
        }

        passkey_entity.record_usage(now);
        let updated_json = serde_json::to_value(&updated_passkey)
            .map_err(|e| AppError::internal("failed to serialize updated passkey credential", e))?;
        passkey_entity.update_passkey_json(updated_json.clone());
        self.passkey_repo
            .update_credential_state(&passkey_entity.id, &updated_json, now)
            .await?;

        // 5. Create Session & Tokens
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let chrono_refresh_ttl = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token ttl configuration", e))?;

        let session = Session::new(
            user.id,
            refresh_token_hash,
            cmd.ip_address,
            cmd.user_agent.clone(),
            cmd.device_name,
            chrono_refresh_ttl,
        )
        .with_amr(vec!["passkey".to_string()]);
        self.session_repo
            .create(&session)
            .await
            .map_err(|e| match e {
                crate::ports::PortError::Conflict { .. } => AppError::Forbidden,
                other => AppError::from(other),
            })?;

        let expires_in = self.access_token_ttl.as_secs() as i64;
        let claims = AccessTokenClaims {
            sub: user.id,
            sid: session.id,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: now.timestamp() + expires_in,
            iat: now.timestamp(),
            jti: Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        // 6. Audit Logging
        let audit = AuditLog::new(
            Some(user.id),
            Some(cmd.ip_address),
            cmd.user_agent,
            cmd.request_id,
            audit_events::PASSKEY_LOGIN,
            AuditEventStatus::Success,
            serde_json::json!({
                "passkey_id": passkey_entity.id,
                "session_id": session.id,
            }),
        );
        self.event_bus.dispatch(AppEvent::LogAudit(Box::new(audit)));

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in,
            session_id: session.id,
        })
    }
}
