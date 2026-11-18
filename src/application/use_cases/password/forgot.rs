//! Forgot password use case implementation with anti-enumeration protection.

use std::sync::Arc;
use std::time::Duration;

use validator::Validate;

use crate::application::dto::ForgotPasswordCommand;
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog};
use crate::domain::value_objects::EmailAddress;
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;

/// Default validity lifetime for password reset tokens (1 hour).
pub const DEFAULT_PASSWORD_RESET_TTL: Duration = Duration::from_secs(3600);

/// Coordinates password reset requests, guaranteeing anti-enumeration.
#[derive(Clone)]
pub struct ForgotPasswordUseCase {
    user_repo: Arc<dyn UserRepository>,
    token_store: Arc<dyn TokenStore>,
    event_bus: EventBus,
    reset_token_ttl: Duration,
}

impl std::fmt::Debug for ForgotPasswordUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgotPasswordUseCase")
            .field("reset_token_ttl", &self.reset_token_ttl)
            .finish_non_exhaustive()
    }
}

impl ForgotPasswordUseCase {
    /// Creates a new [`ForgotPasswordUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        token_store: Arc<dyn TokenStore>,
        event_bus: EventBus,
        reset_token_ttl: Duration,
    ) -> Self {
        Self {
            user_repo,
            token_store,
            event_bus,
            reset_token_ttl,
        }
    }

    /// Requests a password reset link.
    ///
    /// ALWAYS returns `Ok(())` even if the e-mail is not registered, preventing
    /// attacker user enumeration.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Validation`] only if e-mail format is syntactically invalid.
    pub async fn execute(&self, cmd: ForgotPasswordCommand) -> Result<(), AppError> {
        cmd.validate()?;

        let maybe_email = EmailAddress::parse(&cmd.email).ok();

        let eligible_user = match maybe_email {
            Some(ref email) => match self.user_repo.find_by_email(email).await {
                Ok(Some(user)) if user.status == crate::domain::entities::AccountStatus::Active => {
                    Some(user)
                }
                _ => None,
            },
            None => None,
        };

        // Constant-work path: whether or not the account exists, perform the
        // same token generation, cache write and audit enqueue so response
        // latency cannot be used to enumerate accounts. Only the real path
        // stores a resolvable key and dispatches the e-mail.
        let (raw_token, token_hash) = generate_opaque_token();
        let (key, value) = match &eligible_user {
            Some(user) => (format!("reset_password:{token_hash}"), user.id.to_string()),
            None => (
                format!("reset_password_decoy:{token_hash}"),
                String::from("decoy"),
            ),
        };
        let _ = self
            .token_store
            .set_token(&key, &value, self.reset_token_ttl)
            .await;

        if let Some(user) = &eligible_user {
            self.event_bus.dispatch(AppEvent::SendPasswordResetEmail {
                to: user.email.clone(),
                token: raw_token,
            });
        }

        let (subject, status, metadata) = match &eligible_user {
            Some(user) => (
                Some(user.id),
                AuditEventStatus::Success,
                serde_json::json!({ "email": user.email.as_str() }),
            ),
            None => (
                None,
                AuditEventStatus::Blocked,
                serde_json::json!({ "reason": "no_eligible_account" }),
            ),
        };
        self.event_bus
            .record_audit(AuditLog::new(
                subject,
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::PASSWORD_RESET_REQUESTED,
                status,
                metadata,
            ))
            .await;

        Ok(())
    }
}
