//! Issue ephemeral WebSocket/WebRTC ticket use case.

use std::sync::Arc;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use rand::TryRng;
use rand::rngs::SysRng as OsRng;

use crate::application::error::AppError;
use crate::domain::value_objects::{SessionId, UserId};
use crate::ports::cache::{TokenStore, WsTicketPayload};

/// Ephemeral ticket issued for WebSocket connection authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsTicketResult {
    /// High-entropy Base64URL opaque ticket.
    pub ticket: String,
    /// Lifetime of ticket in seconds.
    pub expires_in: u64,
}

/// Use case to issue a one-time WebSocket/WebRTC ephemeral ticket with 15s TTL.
#[derive(Clone)]
pub struct IssueWsTicketUseCase {
    token_store: Arc<dyn TokenStore>,
}

impl std::fmt::Debug for IssueWsTicketUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssueWsTicketUseCase").finish()
    }
}

impl IssueWsTicketUseCase {
    /// Creates a new [`IssueWsTicketUseCase`].
    #[must_use]
    pub fn new(token_store: Arc<dyn TokenStore>) -> Self {
        Self { token_store }
    }

    /// Issues a 32-byte CSPRNG Base64URL token via `OsRng` and writes the payload to Redis for 15s.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Unauthenticated`] if the session has been revoked/blacklisted,
    /// or [`AppError`] if storing the ticket in the token store fails.
    pub async fn execute(
        &self,
        user_id: UserId,
        session_id: SessionId,
        role: String,
    ) -> Result<WsTicketResult, AppError> {
        // Defense-in-depth: reject immediately if session is revoked/blacklisted
        let blacklist_key = format!("blacklist:session:{session_id}");
        if self.token_store.get_token(&blacklist_key).await?.is_some() {
            return Err(AppError::Unauthenticated);
        }

        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| AppError::internal("failed to generate random bytes from OsRng", e))?;
        let ticket = BASE64_URL_SAFE_NO_PAD.encode(bytes);

        let payload = WsTicketPayload {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            role,
        };

        // Write to Redis with key ws:ticket:{token} and 15s TTL
        self.token_store
            .save_ws_ticket(&ticket, &payload, 15)
            .await?;

        Ok(WsTicketResult {
            ticket,
            expires_in: 15,
        })
    }
}
