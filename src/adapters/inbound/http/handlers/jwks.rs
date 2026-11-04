//! JSON Web Key Set (JWKS) discovery handler.
//!
//! * `GET /.well-known/jwks.json` - exports Ed25519 public key

use axum::Json;
use axum::extract::State;
use serde_json::Value;

use crate::adapters::inbound::http::error::{ApiError, ErrorKind, ProblemDetails};
use crate::adapters::inbound::http::state::AppState;

/// Serves the public Ed25519 JSON Web Key Set (JWKS) document.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "Discovery",
    operation_id = "discovery_jwks",
    responses(
        (status = 200, description = "RFC 7517 / RFC 8037 JWKS document", body = Object),
        (status = 500, description = "Unexpected server error", body = ProblemDetails)
    )
)]
pub async fn jwks(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let jwks = state.token_signer.public_key_jwks().map_err(|e| {
        tracing::error!(error = %e, "failed to export public key JWKS");
        ApiError::new(ErrorKind::Internal)
    })?;

    Ok(Json(jwks))
}
