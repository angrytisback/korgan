//! Command-line argument parser definitions using `clap`.

use clap::{Parser, Subcommand};

/// Command-line interface for Korgan IAM management.
#[derive(Parser, Debug)]
#[command(
    name = "korgan",
    about = "Enterprise-grade Identity and Access Management (IAM) service & management CLI",
    version
)]
pub struct Cli {
    /// Subcommand to execute. Defaults to running the HTTP service when omitted.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Runs the HTTP API server (default when no subcommand is specified).
    Serve,
    /// Bootstrap the first superadmin user.
    Bootstrap {
        /// Superadmin email address.
        #[arg(long)]
        email: String,
        /// Superadmin password.
        #[arg(long)]
        password: String,
    },
    /// Audit log chain operations.
    Audit {
        /// Audit subcommand to execute.
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// User administration operations.
    User {
        /// User subcommand to execute.
        #[command(subcommand)]
        command: UserCommands,
    },
}

/// Audit log subcommands.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AuditCommands {
    /// Sequentially traverses and cryptographically verifies the audit log chain.
    Verify,
}

/// User administration subcommands.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum UserCommands {
    /// Unlocks a locked user account and clears failed login attempts.
    Unlock {
        /// Target user email address.
        #[arg(long)]
        email: String,
    },
}
