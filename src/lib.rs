//! IAM service library: application assembly and integration-test surface.
//!
//! Layering (dependencies point inward only):
//! `adapters -> application -> ports -> domain`.

pub mod adapters;
pub mod application;
pub mod bootstrap;
pub mod config;
pub mod domain;
pub mod ports;
pub mod security;
pub mod telemetry;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::{Extension, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::ServiceExt as _;

pub use crate::adapters::inbound::cli;
use crate::adapters::inbound::http::{RouterError, build_router};
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
        bootstrap::build_state(settings).map_err(RouterError::StateInitialization)?;

    let (_stop_tx, stop_rx) = watch::channel(false);
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(worker.run(stop_rx));
    }

    build_router(state)
}

/// Builds the router for the dedicated metrics listener
/// (`server.metrics_addr`): `GET /metrics` only, no application state.
pub fn build_metrics_router() -> Router {
    Router::new().route(
        "/metrics",
        axum::routing::get(adapters::inbound::http::handlers::metrics::metrics),
    )
}

/// Maximum time a client may take to deliver a complete request head
/// (request line + headers) before the connection is dropped. Defends against
/// slow-loris style resource exhaustion; `TimeoutLayer` only starts counting
/// once the head has been parsed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

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
    serve_with_header_timeout(listener, app, shutdown, grace, HEADER_READ_TIMEOUT).await
}

/// Like [`serve`], with an explicit request-head read timeout.
///
/// # Errors
///
/// Returns [`ServeError::Io`] when the server fails.
pub async fn serve_with_header_timeout<F>(
    listener: TcpListener,
    app: Router,
    shutdown: F,
    grace: Duration,
    header_read_timeout: Duration,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));

    let graceful = GracefulShutdown::new();
    let mut shutdown = Box::pin(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(error) => {
                    // Typically EMFILE/ENFILE: back off instead of spinning.
                    tracing::warn!(%error, "failed to accept connection");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // Best effort: latency tuning only.
        let _ = stream.set_nodelay(true);

        let service = TowerToHyperService::new(
            app.clone()
                .layer(Extension(ConnectInfo(peer)))
                .map_request(|request: Request<Incoming>| request.map(Body::new)),
        );
        let connection = graceful.watch(
            builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .into_owned(),
        );
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%peer, %error, "connection terminated with an error");
            }
        });
    }

    // Stop accepting, then drain in-flight requests for at most `grace`.
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(grace) => {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "graceful shutdown period elapsed; terminating remaining connections"
            );
        }
    }
    Ok(())
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
