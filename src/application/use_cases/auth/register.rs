//! Registration use case implementation.

use std::sync::Arc;
use std::time::Duration;

use validator::Validate;

use crate::application::dto::{RegisterCommand, RegisterResult};
use crate::application::error::AppError;
use crate::application::use_cases::token_utils::generate_opaque_token;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::entities::audit_events;
use crate::domain::entities::{AuditEventStatus, AuditLog, User};
use crate::domain::errors::FieldViolation;
use crate::domain::value_objects::{EmailAddress, RawPassword, Username};
use crate::ports::cache::TokenStore;
use crate::ports::repositories::UserRepository;
use crate::ports::services::{HibpClient, PasswordHasher};

/// Default lifetime for email verification tokens (24 hours).
pub const DEFAULT_EMAIL_VERIFICATION_TTL: Duration = Duration::from_secs(24 * 3600);

/// Coordinates user account registration.
#[derive(Clone)]
pub struct RegisterUserUseCase {
    user_repo: Arc<dyn UserRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    token_store: Arc<dyn TokenStore>,
    hibp_client: Arc<dyn HibpClient>,
    event_bus: EventBus,
    verification_ttl: Duration,
}

impl std::fmt::Debug for RegisterUserUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterUserUseCase")
            .field("verification_ttl", &self.verification_ttl)
            .finish()
    }
}

impl RegisterUserUseCase {
    /// Creates a new [`RegisterUserUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        token_store: Arc<dyn TokenStore>,
        hibp_client: Arc<dyn HibpClient>,
        event_bus: EventBus,
        verification_ttl: Duration,
    ) -> Self {
        Self {
            user_repo,
            password_hasher,
            token_store,
            hibp_client,
            event_bus,
            verification_ttl,
        }
    }

    /// Executes the registration workflow.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Validation`] on format violation or breached password,
    /// [`AppError::Conflict`] if email or username already exists, or [`AppError::Internal`].
    pub async fn execute(&self, cmd: RegisterCommand) -> Result<RegisterResult, AppError> {
        cmd.validate()?;

        let email = EmailAddress::parse(&cmd.email)?;
        let raw_password = RawPassword::new(&cmd.password)?;

        let username = match &cmd.username {
            Some(u) => Some(Username::new(u)?),
            None => None,
        };

        if self.hibp_client.is_password_breached(&raw_password).await? {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "password",
                "this password has appeared in a known data breach and cannot be used",
            )]));
        }

        if self.user_repo.find_by_email(&email).await?.is_some() {
            return Err(AppError::Conflict);
        }

        if let Some(ref u) = username
            && self.user_repo.find_by_username(u).await?.is_some()
        {
            return Err(AppError::Conflict);
        }

        let password_hash = self.password_hasher.hash_password(&raw_password).await?;
        let user = User::with_password(email, username, password_hash);

        self.user_repo.create(&user).await?;

        let (raw_token, token_hash) = generate_opaque_token();
        let token_key = format!("verify_email:{token_hash}");
        self.token_store
            .set_token(&token_key, &user.id.to_string(), self.verification_ttl)
            .await?;

        self.event_bus.dispatch(AppEvent::SendVerificationEmail {
            to: user.email.clone(),
            token: raw_token,
        });

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                cmd.ip_address,
                cmd.user_agent,
                cmd.request_id,
                audit_events::REGISTER,
                AuditEventStatus::Success,
                serde_json::json!({ "email": user.email.as_str() }),
            ))));

        Ok(RegisterResult {
            user_id: user.id,
            email: user.email.to_string(),
            status: user.status,
            verification_required: true,
        })
    }
}
