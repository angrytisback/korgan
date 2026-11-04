//! Session management DTO queries, commands and results.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::domain::value_objects::{RequestId, SessionId, UserId};

/// Query to list active sessions for a user.
#[derive(Debug, Clone, Validate)]
pub struct ListSessionsQuery {
    /// Owner user identifier.
    pub user_id: UserId,

    /// Identifier of the caller's current session (for highlighting).
    pub current_session_id: Option<SessionId>,

    /// Maximum number of sessions to return.
    #[validate(range(min = 1, max = 100, message = "limit must be between 1 and 100"))]
    pub limit: u32,

    /// Offset for pagination.
    pub offset: u64,
}

/// Summary description of an active or recent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session identifier.
    pub id: SessionId,

    /// Device or browser description.
    pub device_name: Option<String>,

    /// Client User-Agent string.
    pub user_agent: Option<String>,

    /// Client IP address.
    pub ip_address: IpAddr,

    /// Whether this session corresponds to the caller's current connection.
    pub is_current: bool,

    /// Timestamp of most recent activity.
    pub last_active_at: DateTime<Utc>,

    /// Timestamp when session was originally created.
    pub created_at: DateTime<Utc>,
}

/// Command to revoke a specific session.
#[derive(Debug, Clone, Validate)]
pub struct RevokeSessionCommand {
    /// Authenticated caller identifier.
    pub user_id: UserId,

    /// Session identifier to revoke.
    pub session_id: SessionId,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}

/// Command to revoke all active sessions for a user.
#[derive(Debug, Clone, Validate)]
pub struct RevokeAllSessionsCommand {
    /// Authenticated caller identifier.
    pub user_id: UserId,

    /// Optional current session ID to exempt from revocation.
    pub except_session_id: Option<SessionId>,

    /// Client IP address.
    pub ip_address: Option<IpAddr>,

    /// Client User-Agent header.
    pub user_agent: Option<String>,

    /// Correlation request identifier.
    pub request_id: RequestId,
}
