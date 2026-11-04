//! Background event consumer and periodic maintenance workers.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::sync::watch;
use tracing::{error, info};

use crate::application::workers::events::AppEvent;
use crate::ports::repositories::{AuditLogRepository, SessionRepository, UserRepository};
use crate::ports::services::MailProvider;
use chrono::Utc;

/// Background consumer that processes events from the application event bus.
pub struct EventWorker {
    receiver: Receiver<AppEvent>,
    mail_provider: Arc<dyn MailProvider>,
    audit_repo: Arc<dyn AuditLogRepository>,
    base_url: String,
}

impl std::fmt::Debug for EventWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventWorker")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl EventWorker {
    /// Creates a new [`EventWorker`].
    #[must_use]
    pub fn new(
        receiver: Receiver<AppEvent>,
        mail_provider: Arc<dyn MailProvider>,
        audit_repo: Arc<dyn AuditLogRepository>,
        base_url: String,
    ) -> Self {
        Self {
            receiver,
            mail_provider,
            audit_repo,
            base_url,
        }
    }

    /// Runs the worker event loop until shutdown signal or channel closure.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!("event worker background task started");

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("event worker received shutdown signal; stopping");
                        break;
                    }
                }
                maybe_event = self.receiver.recv() => {
                    match maybe_event {
                        Some(event) => self.handle_event(event).await,
                        None => {
                            info!("event worker channel closed; stopping");
                            break;
                        }
                    }
                }
            }
        }

        // Drain any remaining buffered events before completing shutdown
        self.drain().await;
        info!("event worker drained all pending events and stopped");
    }

    /// Drains and processes all currently buffered events in the channel.
    pub async fn drain(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            self.handle_event(event).await;
        }
    }

    /// Dispatches a single background event.
    pub async fn handle_event(&self, event: AppEvent) {
        match event {
            AppEvent::SendVerificationEmail { to, token } => {
                let link = format!(
                    "{}/verify-email?token={}",
                    self.base_url.trim_end_matches('/'),
                    token
                );
                let subject = "Verify your email address";
                let text = format!(
                    "Please verify your email address by visiting:\n{link}\n\nThis link will expire in 24 hours."
                );
                let html = format!(
                    "<p>Please verify your email address by clicking <a href=\"{link}\">here</a>.</p><p>This link will expire in 24 hours.</p>"
                );

                if let Err(e) = self
                    .mail_provider
                    .send_email(&to, subject, &text, &html)
                    .await
                {
                    error!(error = %e, recipient = %to, "failed to dispatch verification email");
                }
            }
            AppEvent::SendPasswordResetEmail { to, token } => {
                let link = format!(
                    "{}/reset-password?token={}",
                    self.base_url.trim_end_matches('/'),
                    token
                );
                let subject = "Reset your password";
                let text = format!(
                    "You requested a password reset. Visit the link below to set a new password:\n{link}\n\nThis link will expire in 1 hour.\nIf you did not request this, you can ignore this email."
                );
                let html = format!(
                    "<p>You requested a password reset. Click <a href=\"{link}\">here</a> to set a new password.</p><p>This link will expire in 1 hour.</p><p>If you did not request this, you can ignore this email.</p>"
                );

                if let Err(e) = self
                    .mail_provider
                    .send_email(&to, subject, &text, &html)
                    .await
                {
                    error!(error = %e, recipient = %to, "failed to dispatch password reset email");
                }
            }
            AppEvent::LogAudit(mut entry) => {
                if let Err(e) = self.audit_repo.append_and_chain(&mut entry).await {
                    error!(
                        error = %e,
                        event_type = %entry.event_type,
                        request_id = %entry.request_id,
                        "failed to append audit log"
                    );
                }
            }
        }
    }
}

/// Periodic maintenance worker that purges expired sessions.
pub struct SessionPurgeWorker {
    session_repo: Arc<dyn SessionRepository>,
    interval: Duration,
    batch_size: u32,
}

impl std::fmt::Debug for SessionPurgeWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPurgeWorker")
            .field("interval", &self.interval)
            .field("batch_size", &self.batch_size)
            .finish()
    }
}

impl SessionPurgeWorker {
    /// Creates a new [`SessionPurgeWorker`].
    #[must_use]
    pub fn new(
        session_repo: Arc<dyn SessionRepository>,
        interval: Duration,
        batch_size: u32,
    ) -> Self {
        Self {
            session_repo,
            interval,
            batch_size,
        }
    }

    /// Runs periodic purging until shutdown is requested.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
            batch_size = self.batch_size,
            "session purge worker started"
        );

        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("session purge worker received shutdown signal; stopping");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match self.session_repo.purge_expired(self.batch_size).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(purged_sessions = count, "purged expired sessions from database");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to purge expired sessions");
                        }
                    }
                }
            }
        }
    }
}

/// Periodic garbage collection worker that purges expired sessions and stale unverified user accounts.
pub struct RetentionGcWorker {
    session_repo: Arc<dyn SessionRepository>,
    user_repo: Arc<dyn UserRepository>,
    interval: Duration,
    batch_size: u32,
    unverified_retention: Duration,
}

impl std::fmt::Debug for RetentionGcWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetentionGcWorker")
            .field("interval", &self.interval)
            .field("batch_size", &self.batch_size)
            .field("unverified_retention", &self.unverified_retention)
            .finish()
    }
}

impl RetentionGcWorker {
    /// Creates a new [`RetentionGcWorker`].
    #[must_use]
    pub fn new(
        session_repo: Arc<dyn SessionRepository>,
        user_repo: Arc<dyn UserRepository>,
        interval: Duration,
        batch_size: u32,
        unverified_retention: Duration,
    ) -> Self {
        Self {
            session_repo,
            user_repo,
            interval,
            batch_size,
            unverified_retention,
        }
    }

    /// Runs periodic purging until shutdown is requested.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
            batch_size = self.batch_size,
            "retention GC worker started"
        );

        let mut ticker = tokio::time::interval(self.interval);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("retention GC worker received shutdown signal; stopping");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    // 1. Purge expired sessions
                    match self.session_repo.purge_expired(self.batch_size).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(purged_sessions = count, "retention GC purged expired sessions");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "retention GC failed to purge expired sessions");
                        }
                    }

                    // 2. Purge stale unverified user accounts
                    let cutoff_chrono = match chrono::Duration::from_std(self.unverified_retention) {
                        Ok(d) => d,
                        Err(_) => chrono::Duration::days(7),
                    };
                    let cutoff = Utc::now() - cutoff_chrono;

                    match self.user_repo.purge_expired_unverified(cutoff, self.batch_size).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(purged_unverified_users = count, "retention GC purged unverified users");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "retention GC failed to purge expired unverified users");
                        }
                    }
                }
            }
        }
    }
}
