//! Handlers for CLI commands.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use thiserror::Error;

use crate::adapters::inbound::http::AppState;
use crate::application::error::AppError;
use crate::application::use_cases::admin::AuditVerificationResult;

/// Errors arising during CLI command execution.
#[derive(Debug, Error)]
pub enum CliError {
    /// Business logic or port failure.
    #[error("application error: {0}")]
    App(#[from] AppError),
    /// Cryptographic chain corruption detected.
    #[error("audit chain corrupted at record {0}")]
    AuditCorrupted(String),
}

/// Executes the bootstrap command to create the initial superadmin.
///
/// # Errors
///
/// Returns [`CliError`] if bootstrap fails (e.g. admin already exists or validation fails).
pub async fn handle_bootstrap(
    state: &AppState,
    email: &str,
    password: &str,
) -> Result<(), CliError> {
    match state.bootstrap_use_case.execute(email, password).await {
        Ok(user) => {
            println!(
                "Superadmin user '{}' ({}) successfully created with status 'active'.",
                user.email, user.id
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("Bootstrap failed: {e}");
            Err(CliError::App(e))
        }
    }
}

/// Executes cryptographic verification of the audit log chain.
///
/// # Errors
///
/// Returns [`CliError::AuditCorrupted`] if the chain is broken, or [`CliError::App`] if querying logs fails.
pub async fn handle_audit_verify(state: &AppState) -> Result<(), CliError> {
    match state.verify_audit_chain_use_case.execute().await {
        Ok(AuditVerificationResult::Valid { verified_count }) => {
            println!(
                "Audit log cryptographic chain is valid. Total verified records: {verified_count}."
            );
            Ok(())
        }
        Ok(AuditVerificationResult::Corrupted(broken)) => {
            eprintln!(
                "Audit log cryptographic chain is CORRUPTED! Tampered entry ID: {}, reason: {}",
                broken.log_id, broken.reason
            );
            Err(CliError::AuditCorrupted(broken.log_id.to_string()))
        }
        Err(e) => {
            eprintln!("Audit verification failed to read logs: {e}");
            Err(CliError::App(e))
        }
    }
}

/// Executes user account unlock.
///
/// # Errors
///
/// Returns [`CliError`] if the user does not exist or unlock fails.
pub async fn handle_user_unlock(state: &AppState, email: &str) -> Result<(), CliError> {
    match state.unlock_user_use_case.execute(email).await {
        Ok(()) => {
            println!("User account '{email}' successfully unlocked.");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to unlock user '{email}': {e}");
            Err(CliError::App(e))
        }
    }
}
