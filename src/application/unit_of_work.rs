//! Atomic unit of work: runs a block of repository calls in ONE database
//! transaction.
//!
//! Adapters implement [`UnitOfWork`]; use cases normally reach it through
//! [`EventBus::audited`](crate::application::workers::EventBus::audited), which
//! pairs a state change with its audit entry so both commit or neither does.

use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

use crate::application::error::AppError;

/// A boxed, sendable future borrowing for `'a`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs a unit of work atomically.
#[async_trait]
pub trait UnitOfWork: Send + Sync + 'static {
    /// Executes `work` inside a single transaction.
    ///
    /// Every repository call made *directly* by `work` (same task) joins the
    /// transaction. It commits when `work` returns `Ok` and rolls back when it
    /// returns `Err` or the future is dropped. Work spawned onto other tasks
    /// does **not** join the transaction, so `work` must not spawn.
    ///
    /// Nested calls join the outer transaction.
    ///
    /// # Errors
    ///
    /// Returns the error of `work`, or an internal error if the transaction
    /// cannot be started or committed.
    async fn run(&self, work: BoxFuture<'_, Result<(), AppError>>) -> Result<(), AppError>;
}
