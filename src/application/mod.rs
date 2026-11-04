//! Application layer: use cases and orchestration.
//!
//! Depends only on `domain` and `ports`. MUST NOT import `axum`, `http`, `sqlx`
//! or any Redis client.

pub mod dto;
pub mod error;
pub mod use_cases;
pub mod workers;

pub use error::{AppError, BoxError};
