//! Background event consumer and periodic maintenance workers.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::application::workers::events::AppEvent;
use crate::domain::value_objects::EmailAddress;
use crate::ports::repositories::{
    AuditLogRepository, AuditOutbox, SessionRepository, UserRepository,
};
use crate::ports::services::MailProvider;
use chrono::Utc;

/// Background consumer that processes events from the application event bus.
pub struct EventWorker {
    receiver: Receiver<AppEvent>,
    mail_provider: Arc<dyn MailProvider>,
    audit_repo: Arc<dyn AuditLogRepository>,
    base_url: String,
    outbox: Option<OutboxDrain>,
}

/// Durable audit outbox plus how the worker drains it.
struct OutboxDrain {
    outbox: Arc<dyn AuditOutbox>,
    wake: Arc<Notify>,
    batch_size: u32,
    poll_interval: Duration,
}

impl std::fmt::Debug for EventWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventWorker")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Maximum number of e-mails delivered concurrently by [`EventWorker::run`].
const MAIL_CONCURRENCY: usize = 8;

/// Maximum number of e-mail deliveries queued or in flight; further e-mail
/// events are dropped (and counted) instead of growing memory without bound.
const MAIL_MAX_PENDING: usize = 256;

/// Upper bound for a single e-mail delivery attempt.
const MAIL_SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// A rendered outbound e-mail.
struct OutboundMail {
    to: EmailAddress,
    subject: &'static str,
    text: String,
    html: String,
    kind: &'static str,
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
            outbox: None,
        }
    }

    /// Drains the durable audit outbox: immediately when `wake` is notified and
    /// at least every `poll_interval` (which also picks up entries enqueued by
    /// other replicas or left over from a crash).
    #[must_use]
    pub fn with_audit_outbox(
        mut self,
        outbox: Arc<dyn AuditOutbox>,
        wake: Arc<Notify>,
        batch_size: u32,
        poll_interval: Duration,
    ) -> Self {
        self.outbox = Some(OutboxDrain {
            outbox,
            wake,
            batch_size: batch_size.max(1),
            poll_interval,
        });
        self
    }

    /// Runs the worker event loop until shutdown signal or channel closure.
    ///
    /// Audit events are persisted in order on this task. E-mails are delivered
    /// on separate tasks with bounded concurrency and a per-send timeout, so a
    /// slow mail server can never delay audit persistence.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!("event worker background task started");

        let mail_slots = Arc::new(Semaphore::new(MAIL_CONCURRENCY));
        let mut mail_tasks: JoinSet<()> = JoinSet::new();

        // When every stop sender is gone (embedded use via `build_app`) the stop
        // branch is disabled instead of polled: a closed `watch` channel resolves
        // immediately and would otherwise turn this loop into a busy spin. The
        // worker then runs until the event bus is closed.
        let mut stop_channel_open = true;

        let wake = self.outbox.as_ref().map(|o| o.wake.clone());
        let mut outbox_ticker = self.outbox.as_ref().map(|o| {
            let mut ticker = tokio::time::interval(o.poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker
        });

        loop {
            tokio::select! {
                () = async {
                    match &wake {
                        Some(wake) => wake.notified().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.drain_outbox().await;
                }
                () = async {
                    match outbox_ticker.as_mut() {
                        Some(ticker) => { ticker.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    self.drain_outbox().await;
                    self.report_outbox_backlog().await;
                }
                changed = shutdown.changed(), if stop_channel_open => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => {
                            info!("event worker received shutdown signal; stopping");
                            break;
                        }
                        Ok(()) => {}
                        Err(_) => {
                            stop_channel_open = false;
                            debug!("event worker stop channel closed; running until the event bus closes");
                        }
                    }
                }
                Some(joined) = mail_tasks.join_next(), if !mail_tasks.is_empty() => {
                    if let Err(e) = joined {
                        error!(error = %e, "mail delivery task failed");
                    }
                }
                maybe_event = self.receiver.recv() => {
                    let Some(event) = maybe_event else {
                        info!("event worker channel closed; stopping");
                        break;
                    };
                    self.route_event(event, &mut mail_tasks, &mail_slots).await;
                }
            }
        }

        // Drain any remaining buffered events before completing shutdown
        self.drain().await;
        while let Some(joined) = mail_tasks.join_next().await {
            if let Err(e) = joined {
                error!(error = %e, "mail delivery task failed");
            }
        }
        info!("event worker drained all pending events and stopped");
    }

    /// Persists audit events inline and hands e-mails to the bounded mail pool.
    async fn route_event(
        &self,
        event: AppEvent,
        mail_tasks: &mut JoinSet<()>,
        mail_slots: &Arc<Semaphore>,
    ) {
        let Some(mail) = self.render_mail(&event) else {
            self.handle_event(event).await;
            return;
        };

        if mail_tasks.len() >= MAIL_MAX_PENDING {
            metrics::counter!("korgan_events_dropped_total", "kind" => mail.kind, "reason" => "mail_backlog")
                .increment(1);
            warn!(kind = mail.kind, "mail backlog full; e-mail dropped");
            return;
        }

        let provider = self.mail_provider.clone();
        let slots = mail_slots.clone();
        mail_tasks.spawn(async move {
            let Ok(_permit) = slots.acquire_owned().await else {
                return;
            };
            deliver_mail(provider.as_ref(), &mail).await;
        });
    }

    /// Drains and processes all currently buffered events in the channel.
    ///
    /// Also empties the durable audit outbox, so short-lived processes (CLI
    /// commands) leave nothing behind.
    pub async fn drain(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            self.handle_event(event).await;
        }
        self.drain_outbox().await;
    }

    /// Moves queued audit entries into the chain, batch by batch, until the
    /// outbox is empty or a batch fails (the next wake-up or tick retries).
    async fn drain_outbox(&self) {
        let Some(drain) = &self.outbox else {
            return;
        };
        loop {
            match drain.outbox.drain(drain.batch_size).await {
                Ok(moved) if moved >= drain.batch_size => {}
                Ok(_) => break,
                Err(e) => {
                    error!(error = %e, "failed to drain the audit outbox; will retry");
                    break;
                }
            }
        }
    }

    /// Publishes the outbox backlog as a gauge.
    async fn report_outbox_backlog(&self) {
        let Some(drain) = &self.outbox else {
            return;
        };
        if let Ok(pending) = drain.outbox.pending().await {
            // Prometheus gauges require f64; outbox backlog is well below 2^53 records.
            #[allow(clippy::cast_precision_loss)]
            metrics::gauge!("korgan_audit_outbox_pending").set(pending as f64);
        }
    }

    /// Processes a single background event to completion.
    pub async fn handle_event(&self, event: AppEvent) {
        if let Some(mail) = self.render_mail(&event) {
            deliver_mail(self.mail_provider.as_ref(), &mail).await;
            return;
        }
        if let AppEvent::LogAudit(mut entry) = event
            && let Err(e) = self.audit_repo.append_and_chain(&mut entry).await
        {
            error!(
                error = %e,
                event_type = %entry.event_type,
                request_id = %entry.request_id,
                "failed to append audit log"
            );
        }
    }

    /// Renders e-mail events; returns `None` for non-mail events.
    fn render_mail(&self, event: &AppEvent) -> Option<OutboundMail> {
        let base = self.base_url.trim_end_matches('/');
        match event {
            AppEvent::SendVerificationEmail { to, token } => {
                let link = format!("{base}/verify-email?token={token}");
                Some(OutboundMail {
                    to: to.clone(),
                    subject: "Verify your email address",
                    text: format!(
                        "Please verify your email address by visiting:\n{link}\n\nThis link will expire in 24 hours."
                    ),
                    html: format!(
                        "<p>Please verify your email address by clicking <a href=\"{link}\">here</a>.</p><p>This link will expire in 24 hours.</p>"
                    ),
                    kind: "verification_email",
                })
            }
            AppEvent::SendPasswordResetEmail { to, token } => {
                let link = format!("{base}/reset-password?token={token}");
                Some(OutboundMail {
                    to: to.clone(),
                    subject: "Reset your password",
                    text: format!(
                        "You requested a password reset. Visit the link below to set a new password:\n{link}\n\nThis link will expire in 1 hour.\nIf you did not request this, you can ignore this email."
                    ),
                    html: format!(
                        "<p>You requested a password reset. Click <a href=\"{link}\">here</a> to set a new password.</p><p>This link will expire in 1 hour.</p><p>If you did not request this, you can ignore this email.</p>"
                    ),
                    kind: "password_reset_email",
                })
            }
            AppEvent::LogAudit(_) => None,
        }
    }
}

/// Delivers one e-mail, bounded by [`MAIL_SEND_TIMEOUT`]; failures are logged.
async fn deliver_mail(provider: &dyn MailProvider, mail: &OutboundMail) {
    let send = provider.send_email(&mail.to, mail.subject, &mail.text, &mail.html);
    match tokio::time::timeout(MAIL_SEND_TIMEOUT, send).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!(error = %e, recipient = %mail.to, kind = mail.kind, "failed to dispatch e-mail");
        }
        Err(_) => {
            error!(
                timeout_secs = MAIL_SEND_TIMEOUT.as_secs(),
                recipient = %mail.to,
                kind = mail.kind,
                "e-mail delivery timed out"
            );
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
            .finish_non_exhaustive()
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
    ///
    /// A purge step that is still waiting (for example on a database
    /// connection) is cancelled when shutdown is requested.
    pub async fn run(self, shutdown: watch::Receiver<bool>) {
        info!(
            interval_secs = self.interval.as_secs(),
            batch_size = self.batch_size,
            "retention GC worker started"
        );
        let this = &self;
        run_periodic("retention GC worker", self.interval, shutdown, || {
            this.purge_once()
        })
        .await;
    }

    /// Purges expired sessions and stale unverified accounts once.
    async fn purge_once(&self) {
        // 1. Purge expired sessions
        match self.session_repo.purge_expired(self.batch_size).await {
            Ok(count) => {
                if count > 0 {
                    info!(
                        purged_sessions = count,
                        "retention GC purged expired sessions"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "retention GC failed to purge expired sessions");
            }
        }

        // 2. Purge stale unverified user accounts
        let cutoff_chrono = chrono::Duration::from_std(self.unverified_retention)
            .unwrap_or_else(|_| chrono::Duration::days(7));
        let cutoff = Utc::now() - cutoff_chrono;

        match self
            .user_repo
            .purge_expired_unverified(cutoff, self.batch_size)
            .await
        {
            Ok(count) => {
                if count > 0 {
                    info!(
                        purged_unverified_users = count,
                        "retention GC purged unverified users"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "retention GC failed to purge expired unverified users");
            }
        }
    }
}

/// Runs `tick` every `interval` until `shutdown` fires (or its sender is gone).
///
/// The in-flight tick is dropped on shutdown, so a hanging dependency can
/// never hold up process termination; the next start simply repeats the work.
async fn run_periodic<F, Fut>(
    name: &'static str,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut tick: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!(worker = name, "received shutdown signal; stopping");
                break;
            }
            _ = ticker.tick() => {
                tokio::select! {
                    () = tick() => {}
                    _ = shutdown.changed() => {
                        info!(worker = name, "shutdown requested during a tick; cancelling it");
                        break;
                    }
                }
            }
        }
    }
}

/// Awaits a background worker task and reports whether it ended cleanly.
///
/// A panicked or cancelled worker is logged instead of silently discarded.
pub async fn join_worker(name: &'static str, handle: tokio::task::JoinHandle<()>) -> bool {
    match handle.await {
        Ok(()) => true,
        Err(e) => {
            error!(worker = name, error = %e, "background worker terminated abnormally");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{join_worker, run_periodic};
    use std::time::Duration;
    use tokio::sync::watch;

    /// A tick that hangs (e.g. DB acquire wait) must not delay shutdown.
    #[tokio::test]
    async fn periodic_worker_stops_promptly_while_a_tick_is_hanging() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = tokio::spawn(run_periodic(
            "test",
            Duration::from_millis(10),
            stop_rx,
            || async { std::future::pending::<()>().await },
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(stop_tx.send(true).is_ok());
        let stopped = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(stopped.is_ok(), "worker kept waiting on the hanging tick");
    }

    #[tokio::test]
    async fn join_worker_reports_clean_exit() {
        assert!(join_worker("ok", tokio::spawn(async {})).await);
    }

    #[tokio::test]
    async fn join_worker_reports_panicked_worker() {
        #[allow(clippy::panic)]
        let handle = tokio::spawn(async { panic!("worker crashed") });
        assert!(!join_worker("panicky", handle).await);
    }
}
