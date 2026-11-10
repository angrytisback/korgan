//! Password management HTTP handlers.
//!
//! * `POST /api/v1/password/forgot` - request password reset e-mail
//! * `POST /api/v1/password/reset` - reset password using single-use token
//! * `POST /api/v1/password/change` - change password for authenticated caller

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use utoipa::ToSchema;

use super::auth::MessageResponse;
use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::{ClientMetadata, StepUpUser};
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::{ChangePasswordCommand, ForgotPasswordCommand, ResetPasswordCommand};

/// Forgot password request payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ForgotPasswordRequest {
    /// Account e-mail address.
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Reset password request payload.
#[derive(Clone, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    /// Opaque reset token from email.
    #[schema(example = "reset_token_abc123...")]
    pub token: String,

    /// New plaintext candidate password.
    #[schema(example = "NewS3cureP@ssword!")]
    pub new_password: String,
}

impl std::fmt::Debug for ResetPasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetPasswordRequest")
            .field("token", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Change password request payload.
#[derive(Clone, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current plaintext password to confirm authority.
    #[schema(example = "CurrentP@ssword123!")]
    pub current_password: String,

    /// New plaintext candidate password.
    #[schema(example = "NewS3cureP@ssword!")]
    pub new_password: String,
}

impl std::fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswordRequest")
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

/// Triggers password reset email workflow with anti-enumeration protection.
#[utoipa::path(
    post,
    path = "/api/v1/password/forgot",
    tag = "Password",
    operation_id = "password_forgot",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Password reset request accepted", body = MessageResponse),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn forgot(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let cmd = ForgotPasswordCommand {
        email: body.email,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.forgot_password_use_case.execute(cmd).await?;

    Ok(Json(MessageResponse::new(
        "If an account with that email exists, a password reset link has been dispatched.",
    )))
}

/// Completes password reset using a single-use token.
#[utoipa::path(
    post,
    path = "/api/v1/password/reset",
    tag = "Password",
    operation_id = "password_reset",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successful", body = MessageResponse),
        (status = 401, description = "Invalid or expired reset token", body = ProblemDetails),
        (status = 422, description = "Validation failed or password in history / breached", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn reset(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let cmd = ResetPasswordCommand {
        token: body.token,
        new_password: body.new_password,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.reset_password_use_case.execute(cmd).await?;

    Ok(Json(MessageResponse::new(
        "Password has been reset successfully. All existing sessions have been revoked.",
    )))
}

/// Changes the authenticated caller's password.
#[utoipa::path(
    post,
    path = "/api/v1/password/change",
    tag = "Password",
    operation_id = "password_change",
    security(("BearerAuth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully", body = MessageResponse),
        (status = 401, description = "Invalid current credentials or unauthenticated", body = ProblemDetails),
        (status = 403, description = "Step-up authentication required", body = ProblemDetails),
        (status = 422, description = "Validation failed or password in history / breached", body = ProblemDetails),
        (status = 429, description = "Rate limit exceeded", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn change(
    State(state): State<AppState>,
    auth_user: StepUpUser,
    metadata: ClientMetadata,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let cmd = ChangePasswordCommand {
        user_id: auth_user.user_id,
        current_session_id: Some(auth_user.session_id),
        current_password: body.current_password,
        new_password: body.new_password,
        ip_address: Some(metadata.ip),
        user_agent: metadata.user_agent,
        request_id: metadata.request_id,
    };

    state.change_password_use_case.execute(cmd).await?;

    Ok(Json(MessageResponse::new(
        "Password has been changed successfully. Other active sessions have been revoked.",
    )))
}
