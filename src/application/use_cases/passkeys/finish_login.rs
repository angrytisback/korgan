//! Use case: complete discoverable WebAuthn passkey login ceremony.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use smallvec::smallvec;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey as WebauthnPasskey, PublicKeyCredential,
};

use crate::application::dto::auth::AuthTokensResult;
use crate::application::dto::passkeys::PasskeyLoginFinishCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::EventBus;
use crate::domain::entities::{AuditEventStatus, AuditLog, Passkey, Session, audit_events};
use crate::domain::errors::DomainError;
use crate::domain::value_objects::{RequestId, UserId};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::{PasskeyRepository, SessionRepository, UserRepository};
use crate::ports::services::{AccessTokenClaims, TokenSigner, WebAuthnService};

#[derive(Debug)]
struct PasskeySessionContext {
    ip_address: IpAddr,
    user_agent: Option<String>,
    device_name: Option<String>,
    request_id: RequestId,
}

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
    issuer: Cow<'static, str>,
    audience: Cow<'static, str>,
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
        issuer: impl Into<Cow<'static, str>>,
        audience: impl Into<Cow<'static, str>>,
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
            issuer: issuer.into(),
            audience: audience.into(),
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

        let (mut passkey_entity, updated_passkey) = self
            .verify_passkey_assertion(
                cmd.challenge_id,
                cmd.credential,
                cmd.ip_address,
                cmd.user_agent.as_deref(),
                cmd.request_id,
            )
            .await?;

        // Load User and verify active status BEFORE mutating passkey state
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
            self.event_bus.record_audit(audit).await;
            return Err(AppError::from(domain_err));
        }

        passkey_entity.record_usage(now);
        let updated_json = serde_json::to_value(&updated_passkey)
            .map_err(|e| AppError::internal("failed to serialize updated passkey credential", e))?;
        passkey_entity.update_passkey_json(updated_json.clone());

        self.issue_passkey_session(
            user.id,
            &passkey_entity,
            &updated_json,
            PasskeySessionContext {
                ip_address: cmd.ip_address,
                user_agent: cmd.user_agent,
                device_name: cmd.device_name,
                request_id: cmd.request_id,
            },
            now,
        )
        .await
    }

    async fn verify_passkey_assertion(
        &self,
        challenge_id: Uuid,
        credential: PublicKeyCredential,
        ip_address: IpAddr,
        user_agent: Option<&str>,
        request_id: RequestId,
    ) -> Result<(Passkey, WebauthnPasskey), AppError> {
        // 1. Atomically consume challenge state
        let cache_key = format!("passkey:login:{challenge_id}");
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
            .find_by_credential_id(credential.raw_id.as_slice())
            .await?;

        let Some(pk) = maybe_passkey else {
            let audit = AuditLog::new(
                None,
                Some(ip_address),
                user_agent.map(str::to_owned),
                request_id,
                audit_events::PASSKEY_LOGIN,
                AuditEventStatus::Failure,
                serde_json::json!({
                    "reason": "passkey credential not found",
                }),
            );
            self.event_bus.record_audit(audit).await;
            return Err(AppError::InvalidCredentials);
        };
        let candidate_passkeys = vec![pk];

        // 3. Complete authentication verification via WebAuthn service offloaded to blocking thread
        let webauthn = self.webauthn_service.clone();
        let (verify_res, candidate_passkeys) = tokio::task::spawn_blocking(move || {
            let res =
                webauthn.finish_discoverable_login(&credential, auth_state, &candidate_passkeys);
            (res, candidate_passkeys)
        })
        .await
        .map_err(|e| AppError::internal("passkey authentication verification task failed", e))?;

        let (_auth_result, updated_passkey) = match verify_res {
            Ok(res) => res,
            Err(e) => {
                let candidate = candidate_passkeys.first();
                let audit = AuditLog::new(
                    candidate.map(|pk| pk.user_id),
                    Some(ip_address),
                    user_agent.map(str::to_owned),
                    request_id,
                    audit_events::PASSKEY_LOGIN,
                    AuditEventStatus::Failure,
                    serde_json::json!({
                        "passkey_id": candidate.map(|pk| pk.id),
                        "reason": e.to_string(),
                    }),
                );
                self.event_bus.record_audit(audit).await;
                return Err(AppError::InvalidCredentials);
            }
        };

        let passkey_entity = candidate_passkeys
            .into_iter()
            .next()
            .ok_or(AppError::InvalidCredentials)?;

        Ok((passkey_entity, updated_passkey))
    }

    async fn issue_passkey_session(
        &self,
        user_id: UserId,
        passkey_entity: &Passkey,
        updated_json: &serde_json::Value,
        ctx: PasskeySessionContext,
        now: DateTime<Utc>,
    ) -> Result<AuthTokensResult, AppError> {
        let (raw_refresh_token, refresh_token_hash) = generate_opaque_token();
        let chrono_refresh_ttl = chrono::Duration::from_std(self.refresh_token_ttl)
            .map_err(|e| AppError::internal("invalid refresh token ttl configuration", e))?;

        let session = Session::new(
            user_id,
            refresh_token_hash,
            ctx.ip_address,
            ctx.user_agent.clone(),
            ctx.device_name,
            chrono_refresh_ttl,
        )
        .with_amr(smallvec![Cow::Borrowed("passkey")]);

        let audit = AuditLog::new(
            Some(user_id),
            Some(ctx.ip_address),
            ctx.user_agent,
            ctx.request_id,
            audit_events::PASSKEY_LOGIN,
            AuditEventStatus::Success,
            serde_json::json!({
                "passkey_id": passkey_entity.id,
                "session_id": session.id,
            }),
        );

        // Credential counter update, session creation and the audit entry
        // commit together: no session without its audit record, and no
        // consumed credential state without a session.
        self.event_bus
            .audited(
                async {
                    self.passkey_repo
                        .update_credential_state(&passkey_entity.id, updated_json, now)
                        .await?;
                    self.session_repo
                        .create(&session)
                        .await
                        .map_err(|e| match e {
                            crate::ports::PortError::Conflict { .. } => AppError::Forbidden,
                            other => AppError::from(other),
                        })?;
                    Ok::<(), AppError>(())
                },
                audit,
            )
            .await?;

        let expires_in = i64::try_from(self.access_token_ttl.as_secs()).unwrap_or(i64::MAX);
        let iat = now.timestamp();
        let claims = AccessTokenClaims {
            sub: user_id,
            sid: session.id,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: iat + expires_in,
            iat,
            jti: Uuid::now_v7().to_string(),
            auth_time: session.created_at.timestamp(),
            amr: session.amr.clone(),
        };

        let access_token = self.token_signer.sign_access_token(&claims)?;

        Ok(AuthTokensResult {
            access_token,
            refresh_token: raw_refresh_token,
            token_type: "Bearer",
            expires_in,
            session_id: session.id,
        })
    }
}
