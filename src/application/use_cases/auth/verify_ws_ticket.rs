//! Verify and atomically consume ephemeral WebSocket/WebRTC ticket use case.

use std::sync::Arc;

use crate::application::error::AppError;
use crate::ports::cache::{TokenStore, WsTicketPayload};

/// Use case to verify and atomically consume a WebSocket ticket.
#[derive(Clone)]
pub struct VerifyWsTicketUseCase {
    token_store: Arc<dyn TokenStore>,
}

impl std::fmt::Debug for VerifyWsTicketUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyWsTicketUseCase").finish()
    }
}

impl VerifyWsTicketUseCase {
    /// Creates a new [`VerifyWsTicketUseCase`].
    #[must_use]
    pub fn new(token_store: Arc<dyn TokenStore>) -> Self {
        Self { token_store }
    }

    /// Atomically consumes a ticket via GETDEL and verifies its session is not blacklisted.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenInvalid`] if the ticket is non-existent, expired, already consumed,
    /// or if its session is blacklisted.
    pub async fn execute(&self, ticket: &str) -> Result<WsTicketPayload, AppError> {
        let trimmed = ticket.trim();
        if trimmed.is_empty() {
            return Err(AppError::TokenInvalid);
        }

        // Atomically consume ticket (GETDEL)
        let payload = match self.token_store.consume_ws_ticket(trimmed).await? {
            Some(p) => p,
            None => return Err(AppError::TokenInvalid),
        };

        // Check if session has been revoked/blacklisted in Redis: blacklist:session:{sid}
        let blacklist_key = format!("blacklist:session:{}", payload.sid);
        match self.token_store.get_token(&blacklist_key).await? {
            Some(_) => Err(AppError::TokenInvalid),
            None => Ok(payload),
        }
    }
}
