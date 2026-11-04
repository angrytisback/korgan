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
use korgan::application::workers::RetentionGcWorker;
use korgan::config::Settings;
use korgan::{security, serve, shutdown_signal, telemetry};
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

    state.sync_telemetry_gauges().await;

    let address = settings.socket_addr()?;
    let grace = settings.server.shutdown_grace();
    let environment = settings.server.environment;

    let (worker_stop_tx, worker_stop_rx) = watch::channel(false);
    let worker_handle = tokio::spawn(worker.run(worker_stop_rx));

    let (gc_stop_tx, gc_stop_rx) = watch::channel(false);
    let gc_worker = RetentionGcWorker::new(
        state.session_repo.clone(),
        state.user_repo.clone(),
        std::time::Duration::from_secs(3600),
        500,
        std::time::Duration::from_secs(86400 * 7),
    );
    let gc_handle = tokio::spawn(gc_worker.run(gc_stop_rx));

    let app = build_router(state)?;
    let listener = TcpListener::bind(address).await?;

    tracing::info!(
        %address,
        ?environment,
        version = env!("CARGO_PKG_VERSION"),
        "korgan listening"
    );

    serve(listener, app, shutdown_signal(), grace).await?;

    // 2. Drain active shielded background tasks before terminating
    let drain_timeout = std::time::Duration::from_secs(10);
    tracing::info!("draining active shielded tasks (timeout: 10s)...");
    if !wait_for_shielded_tasks(drain_timeout).await {
        tracing::warn!("shielded task draining timed out after 10s");
    } else {
        tracing::info!("all shielded tasks drained successfully");
    }

    // 3. Signal workers to drain remaining jobs and shut down
    let _ = worker_stop_tx.send(true);
    let _ = gc_stop_tx.send(true);
    let _ = worker_handle.await;
    let _ = gc_handle.await;

    tracing::info!("korgan stopped");
    Ok(())
}
