//! Binary entrypoint: loads configuration, initialises telemetry and serves
//! the HTTP API with graceful shutdown and background worker execution.

// Before telemetry is initialised, stderr is the only channel for fatal
// start-up errors.
#![allow(clippy::print_stderr)]

use std::error::Error;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use korgan::adapters::inbound::cli::{
    AuditCommands, Cli, Commands, UserCommands, handle_audit_verify, handle_bootstrap,
    handle_user_unlock,
};
use korgan::adapters::inbound::http::{AppState, build_router};
use korgan::application::use_cases::cancellation::wait_for_shielded_tasks;
use korgan::application::workers::{RetentionGcWorker, join_worker};
use korgan::config::Settings;
use korgan::{build_metrics_router, security, serve, shutdown_signal, telemetry};
use tokio::net::TcpListener;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    // 1. Process memory hardening against core dumps
    security::harden_process_memory();

    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(error) if error.not_found() => {}
        Err(error) => return Err(Box::new(error)),
    }

    let cli = Cli::parse();

    let settings = Arc::new(Settings::load()?);
    telemetry::init(&settings.telemetry)?;

    let (state, mut worker) =
        AppState::from_settings(settings.clone()).map_err(|e| e as Box<dyn Error>)?;

    // Handle CLI subcommands if supplied
    match cli.command {
        Some(Commands::Bootstrap { email, password }) => {
            let res = handle_bootstrap(&state, &email, &password).await;
            worker.drain().await;
            res?;
            return Ok(());
        }
        Some(Commands::Audit { command }) => match command {
            AuditCommands::Verify => {
                handle_audit_verify(&state).await?;
                return Ok(());
            }
        },
        Some(Commands::User { command }) => match command {
            UserCommands::Unlock { email } => {
                let res = handle_user_unlock(&state, &email).await;
                worker.drain().await;
                res?;
                return Ok(());
            }
        },
        Some(Commands::Serve) | None => {}
    }

    let address = settings.socket_addr()?;
    let grace = settings.server.shutdown_grace();
    let environment = settings.server.environment;

    let (worker_stop_tx, worker_stop_rx) = watch::channel(false);
    let worker_handle = tokio::spawn(worker.run(worker_stop_rx));

    let (gc_stop_tx, gc_stop_rx) = watch::channel(false);
    let gc_worker = RetentionGcWorker::new(
        state.session_repo.clone(),
        state.user_repo.clone(),
        settings.workers.gc_interval(),
        settings.workers.gc_batch_size,
        settings.workers.unverified_retention(),
    );
    let gc_handle = tokio::spawn(gc_worker.run(gc_stop_rx));

    let gauge_state = state.clone();
    let app = build_router(state)?;
    let listener = TcpListener::bind(address).await?;

    // Seed the DB-backed gauges only after the socket is bound: with an
    // unreachable database this call waits for the pool acquire timeout and
    // must not delay readiness/liveness endpoints.
    tokio::spawn(async move { gauge_state.sync_telemetry_gauges().await });

    tracing::info!(
        %address,
        ?environment,
        version = env!("CARGO_PKG_VERSION"),
        "korgan listening"
    );

    // One OS signal stops every listener.
    let (signal_tx, signal_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        // Receivers only disappear when the servers are already gone.
        let _ = signal_tx.send(true);
    });

    let metrics_handle = match settings.metrics_socket_addr() {
        Some(metrics_addr) => {
            let metrics_listener = TcpListener::bind(metrics_addr).await?;
            tracing::info!(address = %metrics_addr, "metrics listener started");
            Some(tokio::spawn(serve(
                metrics_listener,
                build_metrics_router(),
                wait_for_signal(signal_rx.clone()),
                grace,
            )))
        }
        None => None,
    };

    // Keep the result: workers must be drained even when the server failed,
    // otherwise buffered audit events would be lost on an unclean exit.
    let served = serve(listener, app, wait_for_signal(signal_rx), grace).await;
    if let Some(handle) = metrics_handle {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "metrics listener terminated with an error"),
            Err(error) => tracing::error!(%error, "metrics listener task failed"),
        }
    }
    if let Err(error) = &served {
        tracing::error!(%error, "http server terminated with an error; draining workers");
    }

    // 2. Drain active shielded background tasks before terminating
    let drain_timeout = settings.workers.shutdown_drain();
    tracing::info!(
        timeout_secs = drain_timeout.as_secs(),
        "draining active shielded tasks"
    );
    if !wait_for_shielded_tasks(drain_timeout).await {
        tracing::warn!(
            timeout_secs = drain_timeout.as_secs(),
            "shielded task draining timed out"
        );
    } else {
        tracing::info!("all shielded tasks drained successfully");
    }

    // 3. Signal workers to drain remaining jobs and shut down
    // INVARIANT: a send error only means the worker already exited; its exit
    // status is reported by `join_worker` below.
    let _ = worker_stop_tx.send(true);
    let _ = gc_stop_tx.send(true);
    let events_clean = join_worker("event-worker", worker_handle).await;
    let gc_clean = join_worker("retention-gc", gc_handle).await;

    served?;
    if !(events_clean && gc_clean) {
        return Err("a background worker terminated abnormally".into());
    }

    tracing::info!("korgan stopped");
    Ok(())
}

/// Resolves once the shared shutdown signal has fired.
async fn wait_for_signal(mut signal: watch::Receiver<bool>) {
    // A closed channel means the signal task is gone: treat it as shutdown.
    let _ = signal.wait_for(|fired| *fired).await;
}
