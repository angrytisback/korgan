//! Cache and ephemeral storage port interfaces.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::ports::errors::PortError;

/// Ephemeral WebSocket / WebRTC ticket payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsTicketPayload {
    /// Authenticated user identifier.
    pub sub: String,
    /// Authenticated session identifier.
    pub sid: String,
    /// User authorization role.
    pub role: String,
}

impl WsTicketPayload {
    /// Creates a new WebSocket ticket payload.
    #[must_use]
    pub fn new(sub: impl Into<String>, sid: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            sid: sid.into(),
            role: role.into(),
        }
    }
}

/// Outcome of a rate limit check against an action/identifier key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitStatus {
    /// Whether the request is permitted within the current budget.
    pub allowed: bool,
    /// Maximum permitted requests within the window.
    pub limit: u32,
    /// Remaining request budget in the current window.
    pub remaining: u32,
    /// Unix timestamp (seconds) when the window resets.
    pub reset_epoch_secs: u64,
    /// Seconds to wait before retrying, present when `allowed` is false.
    pub retry_after_secs: Option<u64>,
}

/// Ephemeral token storage for short-lived security secrets:
/// - E-mail verification tokens (SHA-256 hashed)
/// - Password reset tokens (SHA-256 hashed)
/// - MFA challenges
#[async_trait]
pub trait TokenStore: Send + Sync + 'static {
    /// Stores an opaque token hash with a time-to-live.
    async fn set_token(&self, key: &str, token_hash: &str, ttl: Duration) -> Result<(), PortError>;

    /// Retrieves an unconsumed token hash, if present and not expired.
    async fn get_token(&self, key: &str) -> Result<Option<String>, PortError>;

    /// Deletes a token explicitly.
    async fn delete_token(&self, key: &str) -> Result<(), PortError>;

    /// Atomically retrieves the value of a key and deletes it in a single step (GETDEL).
    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, PortError>;

    /// Atomically verifies and consumes a single-use token.
    ///
    /// If the stored token hash matches `expected_token_hash` in constant time,
    /// it is deleted and `Ok(true)` is returned. Otherwise `Ok(false)` is returned.
    async fn consume_token(&self, key: &str, expected_token_hash: &str) -> Result<bool, PortError>;

    /// Atomically sets the key with expiration only if it does not already exist (SET NX).
    ///
    /// Returns `Ok(true)` if the key was set, or `Ok(false)` if the key already existed.
    async fn set_if_not_exists(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> Result<bool, PortError>;

    /// Stores multiple tokens with their respective time-to-live values in batch.
    ///
    /// The default implementation loops sequentially over `set_token`,
    /// ensuring backwards compatibility for in-memory mocks. Concrete
    /// stores (such as Redis) may override this with a pipelined implementation.
    async fn set_tokens_batch(&self, items: &[(&str, &str, Duration)]) -> Result<(), PortError> {
        for &(key, val, ttl) in items {
            self.set_token(key, val, ttl).await?;
        }
        Ok(())
    }

    /// Saves a one-time WebSocket/WebRTC ephemeral ticket with its payload and TTL (in seconds).
    async fn save_ws_ticket(
        &self,
        ticket: &str,
        payload: &WsTicketPayload,
        ttl_sec: u64,
    ) -> Result<(), PortError> {
        let key = if ticket.starts_with("ws:ticket:") {
            ticket.to_string()
        } else {
            format!("ws:ticket:{ticket}")
        };
        let json = serde_json::to_string(payload)
            .map_err(|e| PortError::cache(format!("failed to serialize ws ticket payload: {e}")))?;
        self.set_token(&key, &json, Duration::from_secs(ttl_sec.max(1)))
            .await
    }

    /// Atomically retrieves and deletes a one-time WebSocket/WebRTC ephemeral ticket (GETDEL).
    async fn consume_ws_ticket(&self, ticket: &str) -> Result<Option<WsTicketPayload>, PortError> {
        let key = if ticket.starts_with("ws:ticket:") {
            ticket.to_string()
        } else {
            format!("ws:ticket:{ticket}")
        };
        match self.get_and_delete(&key).await? {
            Some(json) => {
                let payload = serde_json::from_str(&json).map_err(|e| {
                    PortError::cache(format!("failed to deserialize ws ticket payload: {e}"))
                })?;
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }
}

/// Sliding-window rate limiter port.
#[async_trait]
pub trait RateLimiterPort: Send + Sync + 'static {
    /// Checks and increments the counter for a given rate-limit key.
    async fn check_and_increment(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitStatus, PortError>;

    /// Resets the rate limit counter for a specific key (e.g. after successful login).
    async fn reset(&self, key: &str) -> Result<(), PortError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct MockStore {
        tokens: Mutex<HashMap<String, (String, Duration)>>,
        fail: Mutex<bool>,
    }

    #[async_trait]
    impl TokenStore for MockStore {
        async fn set_token(
            &self,
            key: &str,
            token_hash: &str,
            ttl: Duration,
        ) -> Result<(), PortError> {
            if *self
                .fail
                .lock()
                .map_err(|e| PortError::cache(e.to_string()))?
            {
                return Err(PortError::cache("mock write failure"));
            }
            self.tokens
                .lock()
                .map_err(|e| PortError::cache(e.to_string()))?
                .insert(key.to_string(), (token_hash.to_string(), ttl));
            Ok(())
        }
        async fn get_token(&self, key: &str) -> Result<Option<String>, PortError> {
            Ok(self
                .tokens
                .lock()
                .map_err(|e| PortError::cache(e.to_string()))?
                .get(key)
                .map(|(v, _)| v.clone()))
        }
        async fn delete_token(&self, _key: &str) -> Result<(), PortError> {
            Ok(())
        }
        async fn get_and_delete(&self, _key: &str) -> Result<Option<String>, PortError> {
            Ok(None)
        }
        async fn consume_token(&self, _key: &str, _expected: &str) -> Result<bool, PortError> {
            Ok(true)
        }
        async fn set_if_not_exists(
            &self,
            _key: &str,
            _val: &str,
            _ttl: Duration,
        ) -> Result<bool, PortError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_set_tokens_batch_default_implementation() -> TestResult {
        let store = MockStore::default();
        let items = [
            ("key1", "val1", Duration::from_secs(60)),
            ("key2", "val2", Duration::from_secs(120)),
        ];

        store.set_tokens_batch(&items).await?;

        let val1 = store.get_token("key1").await?;
        assert_eq!(val1, Some("val1".to_string()));

        let val2 = store.get_token("key2").await?;
        assert_eq!(val2, Some("val2".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn test_set_tokens_batch_empty() -> TestResult {
        let store = MockStore::default();
        store.set_tokens_batch(&[]).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_set_tokens_batch_propagates_error() -> TestResult {
        let store = MockStore::default();
        *store
            .fail
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))? = true;
        let items = [("key1", "val1", Duration::from_secs(60))];
        let res = store.set_tokens_batch(&items).await;
        assert!(res.is_err());
        assert!(matches!(res, Err(PortError::Cache(_))));
        Ok(())
    }
}
