//! In-memory asynchronous application event bus.
//!
//! Decouples use case business transactions from background side-effects:
//! e-mail delivery, immutable audit log persistence, and metrics collection.

use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

use crate::domain::entities::AuditLog;
use crate::domain::value_objects::EmailAddress;

/// Security and lifecycle events emitted during use case execution.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Dispatches an account confirmation e-mail with a single-use token.
    SendVerificationEmail {
        /// Recipient email address.
        to: EmailAddress,
        /// Raw Base64URL opaque verification token.
        token: String,
    },

    /// Dispatches a password reset e-mail with a single-use token.
    SendPasswordResetEmail {
        /// Recipient email address.
        to: EmailAddress,
        /// Raw Base64URL opaque password reset token.
        token: String,
    },

    /// Persists an immutable security audit trail entry.
    LogAudit(Box<AuditLog>),
}

/// Asynchronous event bus handle backed by a bounded MPSC channel.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: Sender<AppEvent>,
}

impl EventBus {
    /// Creates a new [`EventBus`] with a bounded channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<AppEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Creates an [`EventBus`] wrapping an existing [`Sender`].
    #[must_use]
    pub fn from_sender(sender: Sender<AppEvent>) -> Self {
        Self { sender }
    }

    /// Dispatches an event without blocking the caller.
    ///
    /// If the channel is saturated or closed, a warning is logged and the event
    /// is dropped rather than stalling the request/response cycle.
    pub fn dispatch(&self, event: AppEvent) {
        if let Err(e) = self.sender.try_send(event) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("event bus channel saturated; background event dropped");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    warn!("event bus receiver closed; background event dropped");
                }
            }
        }
    }

    /// Asynchronously sends an event, waiting if the channel is full.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::error::SendError`] if the receiver has shut down.
    pub async fn send(&self, event: AppEvent) -> Result<(), mpsc::error::SendError<AppEvent>> {
        self.sender.send(event).await
    }
}
