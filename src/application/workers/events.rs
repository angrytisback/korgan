//! In-memory asynchronous application event bus.
//!
//! Decouples use case business transactions from background side-effects:
//! e-mail delivery, immutable audit log persistence, and metrics collection.

use std::sync::Arc;

use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, warn};

use crate::application::error::AppError;
use crate::application::unit_of_work::UnitOfWork;
use crate::application::use_cases::shielded;
use crate::ports::repositories::AuditOutbox;

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
        /// Raw `Base64URL` opaque verification token.
        token: String,
    },

    /// Dispatches a password reset e-mail with a single-use token.
    SendPasswordResetEmail {
        /// Recipient email address.
        to: EmailAddress,
        /// Raw `Base64URL` opaque password reset token.
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
///
/// E-mail events always travel through the in-memory channel. Audit events go
/// to the durable [`AuditOutbox`] when one is configured (production) and fall
/// back to the channel otherwise, or when the outbox itself fails.
#[derive(Clone)]
pub struct EventBus {
    sender: Sender<AppEvent>,
    audit_outbox: Option<Arc<dyn AuditOutbox>>,
    unit_of_work: Option<Arc<dyn UnitOfWork>>,
    outbox_wake: Arc<Notify>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("durable_audit", &self.audit_outbox.is_some())
            .finish_non_exhaustive()
    }
}

impl EventBus {
    /// Creates a new [`EventBus`] with a bounded channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Receiver<AppEvent>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (Self::from_sender(sender), receiver)
    }

    /// Creates an [`EventBus`] wrapping an existing [`Sender`].
    #[must_use]
    pub fn from_sender(sender: Sender<AppEvent>) -> Self {
        Self {
            sender,
            audit_outbox: None,
            unit_of_work: None,
            outbox_wake: Arc::new(Notify::new()),
        }
    }

    /// Routes audit events through a durable outbox instead of the in-memory queue.
    #[must_use]
    pub fn with_audit_outbox(mut self, outbox: Arc<dyn AuditOutbox>) -> Self {
        self.audit_outbox = Some(outbox);
        self
    }

    /// Enables [`audited`](Self::audited) to commit a state change and its
    /// audit entry in one database transaction.
    #[must_use]
    pub fn with_unit_of_work(mut self, unit_of_work: Arc<dyn UnitOfWork>) -> Self {
        self.unit_of_work = Some(unit_of_work);
        self
    }

    /// Signal raised after every successful outbox enqueue; the worker waits on it.
    #[must_use]
    pub fn audit_outbox_wake(&self) -> Arc<Notify> {
        self.outbox_wake.clone()
    }

    /// Runs `work` and records `audit` for it, atomically when possible.
    ///
    /// With a unit of work and an outbox (production), `work` and the audit
    /// INSERT share one database transaction: either the state change and its
    /// audit entry both commit, or neither does. If the audit entry cannot be
    /// written, the state change is rolled back (fail-closed).
    ///
    /// Without them (in-memory fakes) this runs `work` and then falls back to
    /// [`record_audit`](Self::record_audit).
    ///
    /// `work` must only perform database repository calls directly (it must not
    /// spawn tasks or touch Redis): spawned tasks do not join the transaction.
    ///
    /// # Errors
    ///
    /// Returns the error of `work`, or an error if the transaction fails.
    pub async fn audited<T, W>(&self, work: W, audit: AuditLog) -> Result<T, AppError>
    where
        T: Send,
        W: std::future::Future<Output = Result<T, AppError>> + Send,
    {
        self.audited_with(work, move |_| audit).await
    }

    /// Like [`audited`](Self::audited), but builds the audit entry from the
    /// result of `work` (for entries whose metadata depends on it).
    ///
    /// # Errors
    ///
    /// Returns the error of `work`, or an error if the transaction fails.
    pub async fn audited_with<T, W, F>(&self, work: W, build_audit: F) -> Result<T, AppError>
    where
        T: Send,
        W: std::future::Future<Output = Result<T, AppError>> + Send,
        F: FnOnce(&T) -> AuditLog + Send,
    {
        let (Some(unit_of_work), Some(outbox)) = (&self.unit_of_work, &self.audit_outbox) else {
            let value = work.await?;
            self.record_audit(build_audit(&value)).await;
            return Ok(value);
        };

        let outbox = outbox.clone();
        let mut slot: Option<T> = None;
        let target = &mut slot;
        unit_of_work
            .run(Box::pin(async move {
                let value = work.await?;
                let audit = build_audit(&value);
                outbox.enqueue(&audit).await.map_err(AppError::from)?;
                *target = Some(value);
                Ok(())
            }))
            .await?;
        self.outbox_wake.notify_one();

        slot.ok_or_else(|| {
            AppError::internal(
                "unit of work finished without a result",
                std::io::Error::other("missing result"),
            )
        })
    }

    /// Records an audit entry.
    ///
    /// With an outbox the entry is durably queued before this returns (shielded
    /// from request cancellation, retried on transient errors), so a full
    /// in-memory queue or a crash cannot lose it. Without an outbox, or if the
    /// outbox fails, it falls back to best-effort [`dispatch`](Self::dispatch).
    pub async fn record_audit(&self, entry: AuditLog) {
        let Some(outbox) = self.audit_outbox.clone() else {
            self.dispatch(AppEvent::LogAudit(Box::new(entry)));
            return;
        };

        let shared = Arc::new(entry);
        let queued = {
            let shared = shared.clone();
            shielded(move || {
                let outbox = outbox.clone();
                let shared = shared.clone();
                async move { outbox.enqueue(&shared).await.map_err(AppError::from) }
            })
            .await
        };

        match queued {
            Ok(()) => self.outbox_wake.notify_one(),
            Err(e) => {
                metrics::counter!("korgan_audit_outbox_enqueue_failures_total").increment(1);
                error!(error = %e, "audit outbox enqueue failed; falling back to the in-memory queue");
                self.dispatch(AppEvent::LogAudit(Box::new(
                    Arc::try_unwrap(shared).unwrap_or_else(|arc| (*arc).clone()),
                )));
            }
        }
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
