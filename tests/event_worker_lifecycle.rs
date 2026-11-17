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
