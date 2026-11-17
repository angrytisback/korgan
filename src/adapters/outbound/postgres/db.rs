//! Connection access shared by the PostgreSQL repositories, with support for
//! an *ambient* transaction.
//!
//! [`PostgresUnitOfWork::run`] opens a transaction and publishes it in a
//! task-local. Every repository call made by the same task then runs on that
//! transaction instead of on a pooled connection, which is what lets a state
//! change and its audit-outbox row commit atomically.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::pool::PoolConnection;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::application::error::AppError;
use crate::application::unit_of_work::{BoxFuture, UnitOfWork};

type SharedTx = Arc<Mutex<Transaction<'static, Postgres>>>;

tokio::task_local! {
    static AMBIENT_TX: SharedTx;
}

/// A connection for one repository call: the ambient transaction when the
/// task runs inside a unit of work, otherwise a connection from the pool.
pub enum DbConn {
    /// Plain pooled connection (autocommit per statement).
    Pooled(PoolConnection<Postgres>),
    /// The task's ambient transaction.
    Ambient(OwnedMutexGuard<Transaction<'static, Postgres>>),
}

impl DbConn {
    /// Acquires the ambient transaction if there is one, else a pooled connection.
    ///
    /// # Errors
    ///
    /// Returns the sqlx error if no pooled connection can be acquired.
    pub async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        match AMBIENT_TX.try_with(Arc::clone) {
            Ok(shared) => Ok(Self::Ambient(shared.lock_owned().await)),
            Err(_) => Ok(Self::Pooled(pool.acquire().await?)),
        }
    }
}

impl std::fmt::Debug for DbConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pooled(_) => "DbConn::Pooled",
            Self::Ambient(_) => "DbConn::Ambient",
        })
    }
}

impl Deref for DbConn {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        match self {
            Self::Pooled(conn) => conn,
            Self::Ambient(tx) => tx,
        }
    }
}

impl DerefMut for DbConn {
    fn deref_mut(&mut self) -> &mut PgConnection {
        match self {
            Self::Pooled(conn) => conn,
            Self::Ambient(tx) => tx,
        }
    }
}

/// [`UnitOfWork`] backed by a PostgreSQL transaction.
#[derive(Debug, Clone)]
pub struct PostgresUnitOfWork {
    pool: PgPool,
}

impl PostgresUnitOfWork {
    /// Creates a unit-of-work runner on `pool`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UnitOfWork for PostgresUnitOfWork {
    async fn run(&self, work: BoxFuture<'_, Result<(), AppError>>) -> Result<(), AppError> {
        // Nested units of work join the outer transaction.
        if AMBIENT_TX.try_with(|_| ()).is_ok() {
            return work.await;
        }

        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::internal("begin transaction failed", e))?;
        let shared: SharedTx = Arc::new(Mutex::new(tx));

        let outcome = AMBIENT_TX.scope(shared.clone(), work).await;

        let tx = Arc::try_unwrap(shared)
            .map_err(|_| {
                AppError::internal(
                    "transaction still borrowed after unit of work",
                    std::io::Error::other("ambient transaction leaked"),
                )
            })?
            .into_inner();

        match outcome {
            Ok(()) => tx
                .commit()
                .await
                .map_err(|e| AppError::internal("commit failed", e)),
            Err(error) => {
                // Roll back explicitly; the original error is what matters.
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(error = %rollback_error, "rollback failed after unit of work error");
                }
                Err(error)
            }
        }
    }
}
