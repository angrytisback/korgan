//! In-memory asynchronous application event bus.
//!
//! Decouples use case business transactions from background side-effects:
//! e-mail delivery, immutable audit log persistence, and metrics collection.

use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

use crate::domain::entities::AuditLog;
use crate::domain::value_objects::EmailAddress;

/// Security and lifecycle events emitted during use case execution.
///
/// `Debug` is implemented by hand so single-use tokens never reach logs.
#[derive(Clone)]
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

impl AppEvent {
    /// Stable, low-cardinality label for metrics and logs.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SendVerificationEmail { .. } => "verification_email",
            Self::SendPasswordResetEmail { .. } => "password_reset_email",
            Self::LogAudit(_) => "audit",
        }
    }
}

impl std::fmt::Debug for AppEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendVerificationEmail { to, .. } => f
                .debug_struct("SendVerificationEmail")
                .field("to", to)
                .field("token", &"<redacted>")
                .finish(),
            Self::SendPasswordResetEmail { to, .. } => f
                .debug_struct("SendPasswordResetEmail")
                .field("to", to)
                .field("token", &"<redacted>")
                .finish(),
            Self::LogAudit(entry) => f.debug_tuple("LogAudit").field(entry).finish(),
        }
    }
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
        let kind = event.kind();
        if let Err(e) = self.sender.try_send(event) {
            let reason = match e {
                mpsc::error::TrySendError::Full(_) => "queue_full",
                mpsc::error::TrySendError::Closed(_) => "receiver_closed",
            };
            metrics::counter!("korgan_events_dropped_total", "kind" => kind, "reason" => reason)
                .increment(1);
            warn!(
                kind,
                reason, "event bus could not accept event; background event dropped"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-token-value";

    fn recipient() -> Result<EmailAddress, Box<dyn std::error::Error>> {
        Ok(EmailAddress::parse("user@example.com")?)
    }

    #[test]
    fn debug_output_never_contains_single_use_tokens() -> Result<(), Box<dyn std::error::Error>> {
        let events = [
            AppEvent::SendVerificationEmail {
                to: recipient()?,
                token: SECRET.to_owned(),
            },
            AppEvent::SendPasswordResetEmail {
                to: recipient()?,
                token: SECRET.to_owned(),
            },
        ];
        for event in &events {
            let rendered = format!("{event:?}");
            assert!(!rendered.contains(SECRET), "token leaked: {rendered}");
        }
        Ok(())
    }
}
