//! Superadmin bootstrap use case.

use std::sync::Arc;

use chrono::Utc;

use crate::application::error::AppError;
use crate::application::workers::{AppEvent, EventBus};
use crate::domain::FieldViolation;
use crate::domain::entities::{AccountStatus, AuditEventStatus, AuditLog, User, UserRole};
use crate::domain::value_objects::{EmailAddress, RawPassword, RequestId};
use crate::ports::repositories::UserRepository;
use crate::ports::services::PasswordHasher;

/// Use case to initialize the first superadmin user.
///
/// If an administrator already exists in the system, execution is rejected for security.
#[derive(Clone)]
pub struct BootstrapSuperadminUseCase {
    user_repo: Arc<dyn UserRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    event_bus: EventBus,
}

impl std::fmt::Debug for BootstrapSuperadminUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapSuperadminUseCase").finish()
    }
}

impl BootstrapSuperadminUseCase {
    /// Creates a new [`BootstrapSuperadminUseCase`].
    #[must_use]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            user_repo,
            password_hasher,
            event_bus,
        }
    }

    /// Bootstraps the first superadmin user.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Forbidden`] if an administrator already exists,
    /// [`AppError::Conflict`] if the email is already registered,
    /// or [`AppError::Validation`] if the email/password format is invalid.
    pub async fn execute(&self, email: &str, password: &str) -> Result<User, AppError> {
        let email_addr = EmailAddress::parse(email)?;

        if password.trim().is_empty() {
            return Err(AppError::Validation(vec![FieldViolation::new(
                "password",
                "password cannot be empty",
            )]));
        }

        // Security check: reject if any administrator already exists in the database
        if self.user_repo.has_admin_user().await? {
            return Err(AppError::Forbidden);
        }

        // Reject if email is already taken
        if self.user_repo.find_by_email(&email_addr).await?.is_some() {
            return Err(AppError::Conflict);
        }

        let raw_pw = RawPassword::new(password)?;
        let password_hash = self.password_hasher.hash_password(&raw_pw).await?;

        let now = Utc::now();
        let mut user = User::with_password(email_addr.clone(), None, password_hash);
        user.role = UserRole::Superadmin;
        user.status = AccountStatus::Active;
        user.email_verified_at = Some(now);
        user.created_at = now;
        user.updated_at = now;

        self.user_repo.create(&user).await?;

        self.event_bus
            .dispatch(AppEvent::LogAudit(Box::new(AuditLog::new(
                Some(user.id),
                None,
                Some("korgan-cli-bootstrap".to_string()),
                RequestId::new(),
                "bootstrap_superadmin",
                AuditEventStatus::Success,
                serde_json::json!({
                    "email": user.email.as_str(),
                    "role": user.role.as_str(),
                }),
            ))));

        Ok(user)
    }
}
