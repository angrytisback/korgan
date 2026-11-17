//! Lifecycle guarantees of the background [`EventWorker`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use async_trait::async_trait;
use korgan::adapters::outbound::mail::ConsoleMailProvider;
use korgan::application::workers::{AppEvent, EventBus, EventWorker};
use korgan::domain::entities::{AuditEventStatus, AuditLog};
use korgan::domain::value_objects::{RequestId, UserId};
use korgan::ports::errors::PortError;
use korgan::ports::repositories::AuditLogRepository;
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Default)]
struct RecordingAuditRepo {
    entries: Mutex<Vec<AuditLog>>,
}

#[async_trait]
impl AuditLogRepository for RecordingAuditRepo {
    async fn append(&self, entry: &AuditLog) -> Result<(), PortError> {
        self.entries
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?
            .push(entry.clone());
        Ok(())
    }

    async fn list_by_user_id(
        &self,
        _user_id: &UserId,
        _limit: u32,
        _offset: u64,
    ) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }

    async fn list_recent(&self, _limit: u32, _offset: u64) -> Result<Vec<AuditLog>, PortError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn audit_event() -> AppEvent {
    AppEvent::LogAudit(Box::new(AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "test.event",
        AuditEventStatus::Success,
        serde_json::Value::Null,
    )))
}

fn build_worker(repo: Arc<RecordingAuditRepo>) -> (EventBus, EventWorker) {
    let (bus, rx) = EventBus::new(8);
    let worker = EventWorker::new(
        rx,
        Arc::new(ConsoleMailProvider::new("noreply@example.test")),
        repo,
        "https://example.test".to_owned(),
    );
    (bus, worker)
}

/// A dropped stop sender must not turn the idle worker into a busy loop.
///
/// The first poll runs on a helper thread: a worker that spins never returns
/// `Pending`, so the poll itself would hang the test.
#[test]
fn idle_worker_does_not_spin_when_stop_sender_is_dropped() -> TestResult {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (_bus, worker) = build_worker(Arc::new(RecordingAuditRepo::default()));
        let (stop_tx, stop_rx) = watch::channel(false);
        drop(stop_tx);

        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(worker.run(stop_rx));
        let first = fut.as_mut().poll(&mut cx);
        let _ = done_tx.send((
            matches!(first, Poll::Pending),
            wakes.0.load(Ordering::SeqCst),
        ));
    });

    let (pending, wakes) = done_rx
        .recv_timeout(Duration::from_secs(3))
        .map_err(|_| "worker never yielded: busy loop on closed stop channel")?;
    assert!(pending, "worker must stay alive");
    assert_eq!(wakes, 0, "idle worker re-woke itself");
    Ok(())
}

/// With the stop sender gone the worker keeps serving events until the bus closes.
#[tokio::test]
async fn worker_keeps_processing_events_after_stop_sender_is_dropped() -> TestResult {
    let repo = Arc::new(RecordingAuditRepo::default());
    let (bus, worker) = build_worker(repo.clone());
    let (stop_tx, stop_rx) = watch::channel(false);
    drop(stop_tx);

    let handle = tokio::spawn(worker.run(stop_rx));
    bus.dispatch(audit_event());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(repo.entries.lock().map_err(|e| e.to_string())?.len(), 1);

    drop(bus);
    tokio::time::timeout(Duration::from_secs(2), handle).await??;
    Ok(())
}

/// Mail provider that never completes within the test horizon.
#[derive(Debug, Default)]
struct StalledMailProvider {
    started: AtomicUsize,
}

#[async_trait]
impl korgan::ports::services::MailProvider for StalledMailProvider {
    async fn send_email(
        &self,
        _to: &korgan::domain::value_objects::EmailAddress,
        _subject: &str,
        _text_body: &str,
        _html_body: &str,
    ) -> Result<(), PortError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        Ok(())
    }
}

/// A stalled mail server must not delay audit persistence (head-of-line blocking).
#[tokio::test]
async fn stalled_mail_provider_does_not_block_audit_persistence() -> TestResult {
    let repo = Arc::new(RecordingAuditRepo::default());
    let mail = Arc::new(StalledMailProvider::default());
    let (bus, rx) = EventBus::new(16);
    let worker = EventWorker::new(
        rx,
        mail.clone(),
        repo.clone(),
        "https://example.test".to_owned(),
    );
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(stop_rx));

    bus.dispatch(AppEvent::SendVerificationEmail {
        to: korgan::domain::value_objects::EmailAddress::parse("user@example.com")?,
        token: "tok".to_owned(),
    });
    bus.dispatch(audit_event());

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if repo.entries.lock().map(|e| e.len()).unwrap_or(0) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "audit event was blocked behind a stalled mail send")?;
    assert_eq!(mail.started.load(Ordering::SeqCst), 1);

    stop_tx.send(true)?;
    handle.abort();
    Ok(())
}

/// A full queue drops (rather than blocks) and never panics.
#[tokio::test]
async fn dispatch_on_full_queue_drops_without_blocking() {
    let (bus, mut rx) = EventBus::new(1);
    bus.dispatch(audit_event());
    bus.dispatch(audit_event());
    assert!(rx.try_recv().is_ok());
    assert!(
        rx.try_recv().is_err(),
        "second event must have been dropped"
    );
}

// ---------------------------------------------------------------------------
// Durable audit outbox
// ---------------------------------------------------------------------------

use korgan::ports::repositories::AuditOutbox;

#[derive(Default)]
struct FakeOutbox {
    queued: Mutex<Vec<AuditLog>>,
    chained: Mutex<Vec<AuditLog>>,
    fail_enqueue: bool,
}

#[async_trait]
impl AuditOutbox for FakeOutbox {
    async fn enqueue(&self, entry: &AuditLog) -> Result<(), PortError> {
        if self.fail_enqueue {
            return Err(PortError::database("outbox unavailable"));
        }
        self.queued
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?
            .push(entry.clone());
        Ok(())
    }

    async fn drain(&self, limit: u32) -> Result<u32, PortError> {
        let mut queued = self
            .queued
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?;
        let take = queued.len().min(limit as usize);
        let moved: Vec<AuditLog> = queued.drain(..take).collect();
        let count = moved.len();
        self.chained
            .lock()
            .map_err(|e| PortError::database(e.to_string()))?
            .extend(moved);
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn pending(&self) -> Result<u64, PortError> {
        Ok(self.queued.lock().map(|q| q.len() as u64).unwrap_or(0))
    }
}

fn audit_log(n: u32) -> AuditLog {
    AuditLog::new(
        None,
        None,
        None,
        RequestId::new(),
        "outbox.fake",
        AuditEventStatus::Success,
        serde_json::json!({ "n": n }),
    )
}

/// The guarantee behind A-02: a saturated in-memory queue no longer loses audit events.
#[tokio::test]
async fn audit_events_are_not_dropped_when_the_memory_queue_is_full() {
    let (bus, mut rx) = EventBus::new(1);
    let outbox = Arc::new(FakeOutbox::default());
    let bus = bus.with_audit_outbox(outbox.clone());

    for n in 0..20 {
        bus.record_audit(audit_log(n)).await;
    }

    assert_eq!(
        outbox.pending().await.unwrap_or(0),
        20,
        "all 20 must be durable"
    );
    assert!(
        rx.try_recv().is_err(),
        "the memory queue is not used when the outbox works"
    );
}

#[tokio::test]
async fn audit_falls_back_to_the_memory_queue_when_the_outbox_fails() {
    let (bus, mut rx) = EventBus::new(8);
    let outbox = Arc::new(FakeOutbox {
        fail_enqueue: true,
        ..Default::default()
    });
    let bus = bus.with_audit_outbox(outbox);

    bus.record_audit(audit_log(1)).await;

    assert!(
        matches!(rx.try_recv(), Ok(AppEvent::LogAudit(_))),
        "entry must reach the in-memory fallback"
    );
}

#[tokio::test]
async fn without_an_outbox_audit_still_uses_the_memory_queue() {
    let (bus, mut rx) = EventBus::new(8);
    bus.record_audit(audit_log(1)).await;
    assert!(matches!(rx.try_recv(), Ok(AppEvent::LogAudit(_))));
}

#[tokio::test]
async fn worker_drains_the_outbox_when_woken_and_on_shutdown_drain() -> TestResult {
    let outbox = Arc::new(FakeOutbox::default());
    let (bus, rx) = EventBus::new(8);
    let bus = bus.with_audit_outbox(outbox.clone());
    let worker = EventWorker::new(
        rx,
        Arc::new(ConsoleMailProvider::new("noreply@example.test")),
        Arc::new(RecordingAuditRepo::default()),
        "https://example.test".to_owned(),
    )
    .with_audit_outbox(
        outbox.clone(),
        bus.audit_outbox_wake(),
        10,
        Duration::from_secs(3_600), // only the wake-up can trigger this drain
    );
    let (stop_tx, stop_rx) = watch::channel(false);
    let handle = tokio::spawn(worker.run(stop_rx));

    bus.record_audit(audit_log(1)).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while outbox.chained.lock().map(|c| c.len()).unwrap_or(0) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "worker did not drain the outbox after being woken")?;

    // Entries left behind are flushed on shutdown.
    bus.record_audit(audit_log(2)).await;
    stop_tx.send(true)?;
    tokio::time::timeout(Duration::from_secs(2), handle).await??;
    assert_eq!(outbox.chained.lock().map_err(|e| e.to_string())?.len(), 2);
    assert_eq!(outbox.pending().await?, 0);
    Ok(())
}
