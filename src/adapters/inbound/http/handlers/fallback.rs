//! Fallback for unmatched routes.

use crate::adapters::inbound::http::error::{ApiError, ErrorKind};

/// Responds to any unmatched route with an RFC 9457 `404`.
pub async fn not_found() -> ApiError {
    ApiError::new(ErrorKind::NotFound)
}
