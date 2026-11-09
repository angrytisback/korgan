//! Structured logging / tracing initialisation.
//!
//! * `pretty` - human-friendly console output for local development.
//! * `json`   - one JSON object per line, including the current span chain, so
//!   the `request_id` recorded by the request-id middleware appears on every
//!   log line emitted while handling a request.
//!
//! `RUST_LOG` takes precedence over `telemetry.log_filter`.

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::{LogFormat, TelemetrySettings};

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Errors raised while initialising telemetry.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The configured filter directive could not be parsed.
    #[error("invalid log filter directive: {0}")]
    InvalidFilter(#[from] tracing_subscriber::filter::ParseError),

    /// A global subscriber has already been installed.
    #[error("tracing subscriber could not be installed: {0}")]
    Init(#[from] tracing_subscriber::util::TryInitError),

    /// Metrics exporter installation failure.
    #[error("metrics installation error: {0}")]
    Metrics(String),
}

/// Installs the global Prometheus metrics recorder. If already installed, returns the existing handle.
///
/// # Errors
///
/// Returns [`TelemetryError::Metrics`] if installing the Prometheus recorder fails.
pub fn init_prometheus() -> Result<PrometheusHandle, TelemetryError> {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        return Ok(handle.clone());
    }

    let handle = match PrometheusBuilder::new().install_recorder() {
        Ok(h) => h,
        Err(e) => {
            if let Some(existing) = PROMETHEUS_HANDLE.get() {
                return Ok(existing.clone());
            }
            return Err(TelemetryError::Metrics(e.to_string()));
        }
    };

    metrics::describe_counter!(
        "korgan_auth_attempts_total",
        "Total authentication attempts partitioned by method and status"
    );
    metrics::describe_counter!(
        "korgan_token_reuse_events_total",
        "Critical security alert counter for replayed refresh tokens"
    );
    metrics::describe_gauge!(
        "korgan_argon2_semaphore_waiting",
        "Instantaneous count of tasks waiting for an Argon2 semaphore permit"
    );
    metrics::describe_gauge!(
        "korgan_audit_chain_length",
        "Current length of the cryptographic audit log hash chain"
    );
    metrics::describe_gauge!(
        "korgan_active_sessions_gauge",
        "Current number of active user sessions"
    );

    metrics::gauge!("korgan_argon2_semaphore_waiting").set(0.0);
    metrics::gauge!("korgan_audit_chain_length").set(0.0);
    metrics::gauge!("korgan_active_sessions_gauge").set(0.0);
    metrics::counter!("korgan_token_reuse_events_total").increment(0);
    for method in ["pwd", "mfa", "passkey", "oauth"] {
        for status in ["success", "failure"] {
            metrics::counter!("korgan_auth_attempts_total", "method" => method, "status" => status)
                .increment(0);
        }
    }

    let _ = PROMETHEUS_HANDLE.set(handle.clone());
    Ok(handle)
}

/// Renders all registered Prometheus metrics in standard exposition format.
#[must_use]
pub fn render_metrics() -> String {
    if let Some(handle) = PROMETHEUS_HANDLE.get() {
        handle.render()
    } else if let Ok(handle) = init_prometheus() {
        handle.render()
    } else {
        String::new()
    }
}

/// Installs the global `tracing` subscriber and Prometheus metrics recorder.
///
/// # Errors
///
/// Returns [`TelemetryError`] when the filter directive is invalid or a global
/// subscriber is already installed.
pub fn init(settings: &TelemetrySettings) -> Result<(), TelemetryError> {
    let _ = init_prometheus();

    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::try_new(&settings.log_filter)?,
    };

    let registry = tracing_subscriber::registry().with(filter);

    match settings.log_format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_target(true),
            )
            .try_init()?,
        LogFormat::Pretty => registry.with(fmt::layer().pretty()).try_init()?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_filter_directive_is_reported() {
        let settings = TelemetrySettings {
            log_format: LogFormat::Json,
            log_filter: "info,=== not valid ===".to_owned(),
        };
        // RUST_LOG may be set in the developer's shell; only assert when unset.
        if std::env::var_os("RUST_LOG").is_none() {
            assert!(matches!(
                init(&settings),
                Err(TelemetryError::InvalidFilter(_))
            ));
        }
    }
}
