//! HTTP handlers for FIDO2 / WebAuthn passkey registration and authentication.

use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use super::auth::{AuthTokensResponse, attach_auth_cookies};
use crate::adapters::inbound::http::error::{ApiError, ProblemDetails};
use crate::adapters::inbound::http::extractors::{AuthUser, ClientMetadata, StepUpUser};
use crate::adapters::inbound::http::state::AppState;
use crate::application::dto::passkeys::{
    PasskeyLoginFinishCommand, PasskeyRegistrationFinishCommand,
};
use crate::domain::value_objects::PasskeyId;

/// Response returned when beginning WebAuthn registration.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyRegistrationStartResponse {
    /// Opaque challenge identifier to return in the finish step.
    pub challenge_id: Uuid,
    /// Credential creation options to pass to `navigator.credentials.create()`.
    #[schema(value_type = Object)]
    pub options: CreationChallengeResponse,
}

/// Request payload to complete WebAuthn passkey registration.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyRegistrationFinishRequest {
    /// Challenge identifier received from registration start.
    pub challenge_id: Uuid,
    /// Optional label for the passkey device (e.g. "MacBook TouchID", "YubiKey").
    pub name: Option<String>,
    /// WebAuthn registration credential from authenticator.
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
}

/// Response returned when passkey registration successfully finishes.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyRegistrationFinishResponse {
    /// Unique passkey identifier.
    pub id: Uuid,
    /// Device label.
    pub name: String,
    /// Registration timestamp.
    pub created_at: DateTime<Utc>,
}

/// Response returned when beginning discoverable passkey login.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyLoginStartResponse {
    /// Opaque challenge identifier to return in the finish step.
    pub challenge_id: Uuid,
    /// Credential request options to pass to `navigator.credentials.get()`.
    #[schema(value_type = Object)]
    pub options: RequestChallengeResponse,
}

/// Request payload to complete discoverable passkey login.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyLoginFinishRequest {
    /// Challenge identifier received from login start.
    pub challenge_id: Uuid,
    /// WebAuthn assertion credential from authenticator.
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

/// Item representation for a registered user passkey.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasskeyItemResponse {
    /// Unique passkey identifier.
    pub id: Uuid,
    /// Device label.
    pub name: String,
    /// Timestamp when this passkey was last used, if ever.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Registration timestamp.
    pub created_at: DateTime<Utc>,
}

/// Initiates WebAuthn passkey registration for the authenticated user.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/register/start",
    tag = "Passkeys",
    operation_id = "passkeys_register_start",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "Passkey registration challenge created", body = PasskeyRegistrationStartResponse),
        (status = 401, description = "Authentication required", body = ProblemDetails),
        (status = 403, description = "Step-up authentication required", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn register_start(
    State(state): State<AppState>,
    auth_user: StepUpUser,
) -> Result<Json<PasskeyRegistrationStartResponse>, ApiError> {
    let res = state
        .start_passkey_registration_use_case
        .execute(auth_user.user_id)
        .await?;

    Ok(Json(PasskeyRegistrationStartResponse {
        challenge_id: res.challenge_id,
        options: res.options,
    }))
}

/// Completes WebAuthn passkey registration and persists the new credential.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/register/finish",
    tag = "Passkeys",
    operation_id = "passkeys_register_finish",
    security(("BearerAuth" = [])),
    request_body = PasskeyRegistrationFinishRequest,
    responses(
        (status = 201, description = "Passkey credential registered successfully", body = PasskeyRegistrationFinishResponse),
        (status = 400, description = "Challenge expired or invalid", body = ProblemDetails),
        (status = 401, description = "Authentication required or verification failed", body = ProblemDetails),
        (status = 422, description = "Validation failed", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn register_finish(
    State(state): State<AppState>,
    auth_user: AuthUser,
    metadata: ClientMetadata,
    Json(req): Json<PasskeyRegistrationFinishRequest>,
) -> Result<(StatusCode, Json<PasskeyRegistrationFinishResponse>), ApiError> {
    let cmd = PasskeyRegistrationFinishCommand {
        challenge_id: req.challenge_id,
        name: req.name,
        credential: req.credential,
    };

    let res = state
        .finish_passkey_registration_use_case
        .execute(
            auth_user.user_id,
            cmd,
            metadata.request_id,
            Some(metadata.ip),
            metadata.user_agent,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(PasskeyRegistrationFinishResponse {
            id: res.id.to_uuid(),
            name: res.name,
            created_at: res.created_at,
        }),
    ))
}

/// Initiates discoverable passkey login (usernameless authentication).
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/login/start",
    tag = "Passkeys",
    operation_id = "passkeys_login_start",
    responses(
        (status = 200, description = "Discoverable authentication challenge created", body = PasskeyLoginStartResponse),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn login_start(
    State(state): State<AppState>,
) -> Result<Json<PasskeyLoginStartResponse>, ApiError> {
    let res = state.start_passkey_login_use_case.execute().await?;

    Ok(Json(PasskeyLoginStartResponse {
        challenge_id: res.challenge_id,
        options: res.options,
    }))
}

/// Completes discoverable passkey login, issuing access and refresh tokens.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkeys/login/finish",
    tag = "Passkeys",
    operation_id = "passkeys_login_finish",
    request_body = PasskeyLoginFinishRequest,
    responses(
        (status = 200, description = "Authentication successful; tokens issued", body = AuthTokensResponse),
        (status = 401, description = "Invalid credentials or verification failed", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn login_finish(
    State(state): State<AppState>,
    metadata: ClientMetadata,
    jar: CookieJar,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<(CookieJar, Json<AuthTokensResponse>), ApiError> {
    let cmd = PasskeyLoginFinishCommand {
        challenge_id: req.challenge_id,
        credential: req.credential,
        ip_address: metadata.ip,
        user_agent: metadata.user_agent,
        device_name: metadata.device_name,
        request_id: metadata.request_id,
    };

    let tokens = state.finish_passkey_login_use_case.execute(cmd).await?;

    let mut updated_jar = jar;
    if metadata.client_type.is_web() {
        updated_jar = attach_auth_cookies(updated_jar, &tokens, &state);
    }

    Ok((updated_jar, Json(tokens.into())))
}

/// Lists all passkey credentials registered for the authenticated user.
#[utoipa::path(
    get,
    path = "/api/v1/users/me/passkeys",
    tag = "Passkeys",
    operation_id = "passkeys_list_mine",
    security(("BearerAuth" = [])),
    responses(
        (status = 200, description = "List of registered passkeys", body = Vec<PasskeyItemResponse>),
        (status = 401, description = "Authentication required", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<PasskeyItemResponse>>, ApiError> {
    let items = state
        .list_passkeys_use_case
        .execute(auth_user.user_id)
        .await?;

    let response = items
        .into_iter()
        .map(|p| PasskeyItemResponse {
            id: p.id.to_uuid(),
            name: p.name,
            last_used_at: p.last_used_at,
            created_at: p.created_at,
        })
        .collect();

    Ok(Json(response))
}

/// Deletes a passkey credential owned by the authenticated user.
#[utoipa::path(
    delete,
    path = "/api/v1/users/me/passkeys/{id}",
    tag = "Passkeys",
    operation_id = "passkeys_delete",
    security(("BearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Passkey unique identifier")
    ),
    responses(
        (status = 204, description = "Passkey deleted successfully"),
        (status = 401, description = "Authentication required", body = ProblemDetails),
        (status = 403, description = "Forbidden (passkey belongs to another user)", body = ProblemDetails),
        (status = 404, description = "Passkey not found", body = ProblemDetails),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    auth_user: AuthUser,
    metadata: ClientMetadata,
    Path(id): Path<PasskeyId>,
) -> Result<StatusCode, ApiError> {
    state
        .delete_passkey_use_case
        .execute(
            auth_user.user_id,
            id,
            metadata.request_id,
            Some(metadata.ip),
            metadata.user_agent,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
