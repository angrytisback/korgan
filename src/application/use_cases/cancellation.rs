//! Future cancellation safety utilities for asynchronous side-effects.

use std::future::Future;
use std::time::Duration;

use crate::application::error::AppError;

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

static ACTIVE_SHIELDED_TASKS: AtomicUsize = AtomicUsize::new(0);
static SHIELDED_DRAIN_NOTIFY: Notify = Notify::const_new();

/// Guard that tracks active shielded tasks and notifies waiters upon completion.
struct ShieldedGuard;

impl ShieldedGuard {
    fn new() -> Self {
        ACTIVE_SHIELDED_TASKS.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for ShieldedGuard {
    fn drop(&mut self) {
        let prev = ACTIVE_SHIELDED_TASKS.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            SHIELDED_DRAIN_NOTIFY.notify_waiters();
        }
    }
}

/// Returns the current number of in-flight shielded tasks.
#[must_use]
pub fn active_shielded_tasks() -> usize {
    ACTIVE_SHIELDED_TASKS.load(Ordering::SeqCst)
}

/// Waits for all currently in-flight shielded background tasks to drain, up to `timeout`.
/// Returns `true` if all tasks drained cleanly, or `false` if the timeout elapsed.
pub async fn wait_for_shielded_tasks(timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let notified = SHIELDED_DRAIN_NOTIFY.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if ACTIVE_SHIELDED_TASKS.load(Ordering::SeqCst) == 0 {
            return true;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        let _ = tokio::time::timeout(remaining, notified).await;
    }
}

/// Shields an asynchronous side-effect (such as Redis blacklist dual-write) from future cancellation,
/// with a 3-attempt exponential backoff retry for transient network dropouts.
///
/// Spawns the operation onto the Tokio runtime and awaits its completion.
/// If the calling future is dropped before completion (e.g. client disconnect / Request Drop in Axum),
/// the spawned task is detached and continues executing to completion in the background.
///
/// Executes `op()` up to 3 times on transient failures:
/// - Attempt 1: immediate execution.
/// - Attempt 2: retried after 25ms delay.
/// - Attempt 3: retried after 50ms delay.
///
/// Returns the `Result<T, AppError>` produced by `op()`, or `AppError::Internal` if the
/// background task panicked or was aborted (`tokio::task::JoinError`).
pub async fn shielded<F, Fut, T>(mut op: F) -> Result<T, AppError>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, AppError>> + Send + 'static,
    T: Send + 'static,
{
    let guard = ShieldedGuard::new();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        let mut attempts = 0u32;
        let mut backoff = Duration::from_millis(25);
        loop {
            attempts += 1;
            match op().await {
                Ok(val) => return Ok(val),
                Err(err) if attempts < 3 => {
                    tracing::warn!(
                        attempt = attempts,
                        error = %err,
                        "transient error in shielded block; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                Err(err) => return Err(err),
            }
        }
    });

    match handle.await {
        Ok(res) => res,
        Err(join_err) => Err(AppError::internal(
            "shielded background task failed",
            join_err,
        )),
    }
}
