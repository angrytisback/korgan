//! OpenAPI 3.1 document and embedded Scalar UI.
//!
//! * `GET /openapi.json` & `GET /api-docs/openapi.json` - machine-readable specification
//! * `GET /docs` - interactive Scalar documentation

use axum::routing::get;
use axum::{Json, Router};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable};

use super::error::{FieldError, ProblemDetails};
use super::handlers::admin::{
    self, AdminUserItemResponse, BanUserRequest, BanUserResponse, PaginatedUsersResponse,
    UnbanUserResponse,
};
use super::handlers::auth::{
    self, AuthTokensResponse, LoginRequest, LoginResponse, MessageResponse, MfaChallengeResponse,
    RefreshTokenRequest, RegisterRequest, RegisterResponse, VerifyEmailRequest, VerifyMfaRequest,
    VerifyWsTicketRequest, VerifyWsTicketResponse, WsTicketResponse,
};
use super::handlers::health::{self, HealthResponse, HealthStatus};
use super::handlers::jwks;
use super::handlers::mfa::{
    self, DisableTotpRequest, EnableTotpRequest, TotpEnabledResponse, TotpSetupResponse,
};
use super::handlers::oauth::{self, OAuthCallbackQuery, OAuthUrlResponse};
use super::handlers::passkeys::{
    self, PasskeyItemResponse, PasskeyLoginFinishRequest, PasskeyLoginStartResponse,
    PasskeyRegistrationFinishRequest, PasskeyRegistrationFinishResponse,
    PasskeyRegistrationStartResponse,
};
use super::handlers::password::{
    self, ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordRequest,
};
use super::handlers::sessions::{self, ListSessionsParams, SessionResponse};
use super::handlers::users::{self, UpdateProfileRequest, UserProfileResponse};
use super::state::AppState;

/// Injects Bearer authentication security definition into the OpenAPI document.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "BearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("RFC 9068 EdDSA Access Token JWT"))
                        .build(),
                ),
            );
        }
    }
}

/// Aggregated OpenAPI 3.1 definition.
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        title = "Korgan Identity & Access Management API",
        version = "0.1.0",
        description = "Enterprise-grade Identity and Access Management & User Management API in Rust.\n\nAll non-2xx errors conform to RFC 9457 `application/problem+json`.",
        contact(name = "Eigen", email = "eigen@teapot-dev.com"),
        license(name = "AGPL-3.0")
    ),
    paths(
        health::live,
        health::ready,
        jwks::jwks,
        auth::register,
        auth::login,
        auth::verify_mfa,
        auth::refresh,
        auth::verify_email,
        auth::logout,
        auth::issue_ws_ticket,
        auth::verify_ws_ticket,
        oauth::generate_url,
        oauth::callback,
        password::forgot,
        password::reset,
        password::change,
        mfa::setup,
        mfa::enable,
        mfa::disable,
        sessions::list,
        sessions::revoke,
        sessions::revoke_all,
        users::me,
        users::update,
        admin::list_users,
        admin::ban_user,
        admin::unban_user,
        passkeys::register_start,
        passkeys::register_finish,
        passkeys::login_start,
        passkeys::login_finish,
        passkeys::list,
        passkeys::delete
    ),
    components(schemas(
        ProblemDetails,
        FieldError,
        HealthResponse,
        HealthStatus,
        RegisterRequest,
        RegisterResponse,
        LoginRequest,
        LoginResponse,
        AuthTokensResponse,
        MfaChallengeResponse,
        VerifyMfaRequest,
        RefreshTokenRequest,
        VerifyEmailRequest,
        WsTicketResponse,
        VerifyWsTicketRequest,
        VerifyWsTicketResponse,
        OAuthUrlResponse,
        OAuthCallbackQuery,
        MessageResponse,
        ForgotPasswordRequest,
        ResetPasswordRequest,
        ChangePasswordRequest,
        TotpSetupResponse,
        EnableTotpRequest,
        TotpEnabledResponse,
        DisableTotpRequest,
        ListSessionsParams,
        SessionResponse,
        UserProfileResponse,
        UpdateProfileRequest,
        AdminUserItemResponse,
        PaginatedUsersResponse,
        BanUserRequest,
        BanUserResponse,
        UnbanUserResponse,
        PasskeyRegistrationStartResponse,
        PasskeyRegistrationFinishRequest,
        PasskeyRegistrationFinishResponse,
        PasskeyLoginStartResponse,
        PasskeyLoginFinishRequest,
        PasskeyItemResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Liveness and readiness probes"),
        (name = "Discovery", description = "Public keys and cryptographic discovery"),
        (name = "Auth", description = "Registration, login, MFA challenge verification, refresh, and logout"),
        (name = "Password", description = "Password reset and authenticated password changes"),
        (name = "MFA", description = "TOTP multi-factor authentication setup and management"),
        (name = "Sessions", description = "Session listing and revocation"),
        (name = "Users", description = "User profile retrieval and management"),
        (name = "Admin", description = "Backoffice administration and user lifecycle controls"),
        (name = "Passkeys", description = "FIDO2 / WebAuthn passkey registration and authentication")
    )
)]
pub struct ApiDoc;

/// Routes serving the OpenAPI 3.1 specification and the interactive Scalar UI.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .route(
            "/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .merge(Scalar::with_url("/docs", ApiDoc::openapi()))
}
