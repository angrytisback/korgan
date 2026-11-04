//! IAM service library: application assembly and integration-test surface.
//!
//! Layering (dependencies point inward only):
//! `adapters -> application -> ports -> domain`.

pub mod adapters;
pub mod application;
pub mod config;
pub mod domain;
pub mod ports;
pub mod security;
pub mod telemetry;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;

pub use crate::adapters::inbound::cli;
use crate::adapters::inbound::http::{AppState, RouterError, build_router};
use crate::config::Settings;

/// Errors raised while running the HTTP server.
#[derive(Debug, Error)]
pub enum ServeError {
    /// The server terminated with an I/O error.
    #[error("http server error: {0}")]
    Io(#[from] std::io::Error),
}

/// Assembles the application router from validated settings.
///
/// # Errors
///
/// Returns [`RouterError`] when the router cannot be configured.
pub fn build_app(settings: Arc<Settings>) -> Result<Router, RouterError> {
    let (state, worker) =
        AppState::from_settings(settings).map_err(RouterError::StateInitialization)?;

    let (_stop_tx, stop_rx) = watch::channel(false);
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(worker.run(stop_rx));
    }

    build_router(state)
}

/// Serves `app` on `listener` until `shutdown` resolves, then drains in-flight
/// requests for at most `grace` before returning.
///
/// # Errors
///
/// Returns [`ServeError::Io`] when the server fails.
pub async fn serve<F>(
    listener: TcpListener,
    app: Router,
    shutdown: F,
    grace: Duration,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (stop_tx, mut stop_graceful) = watch::channel(false);
    let mut stop_deadline = stop_tx.subscribe();

    tokio::spawn(async move {
        shutdown.await;
        // Receivers only disappear when the server is already gone.
        let _ = stop_tx.send(true);
    });

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = stop_graceful.wait_for(|stop| *stop).await;
    });

    let deadline = async move {
        let _ = stop_deadline.wait_for(|stop| *stop).await;
        tokio::time::sleep(grace).await;
    };

    tokio::select! {
        result = server => result.map_err(ServeError::Io),
        () = deadline => {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "graceful shutdown period elapsed; terminating remaining connections"
            );
            Ok(())
        }
    }
}

/// Resolves when the process receives `SIGINT` (Ctrl-C) or `SIGTERM`.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
