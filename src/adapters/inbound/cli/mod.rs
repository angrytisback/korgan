//! Command-line interface inbound adapter.

pub mod args;
pub mod commands;

pub use args::{AuditCommands, Cli, Commands, UserCommands};
pub use commands::{CliError, handle_audit_verify, handle_bootstrap, handle_user_unlock};
