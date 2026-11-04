//! Redis token store adapter for ephemeral tokens (email verification, password reset, challenges).

use std::time::Duration;

use async_trait::async_trait;
use deadpool_redis::Pool;
use deadpool_redis::redis::{AsyncCommands, cmd, pipe};

use crate::ports::cache::{TokenStore, WsTicketPayload};
use crate::ports::errors::PortError;

/// Atomic token consumption Lua script:
/// Retrieves token, compares against expected hash, and if matching, deletes it atomically.
const CONSUME_TOKEN_LUA: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
    return 0
end
if current == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
else
    return 0
end
"#;

/// Atomic GETDEL Lua script:
/// Retrieves the current value of the key and deletes it atomically in a single step.
const GET_AND_DELETE_LUA: &str = r#"
local current = redis.call('GET', KEYS[1])
if current then
    redis.call('DEL', KEYS[1])
end
return current
"#;

/// Atomic SET NX EX Lua script:
/// Sets the key with expiration only if it does not already exist.
/// Returns 1 if set, 0 if already existed.
const SET_IF_NOT_EXISTS_LUA: &str = r#"
local res = redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')
if res then
    return 1
else
    return 0
end
"#;

/// Redis-backed implementation of [`TokenStore`].
#[derive(Clone)]
pub struct RedisTokenStore {
    pool: Pool,
    prefix: String,
}

impl std::fmt::Debug for RedisTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisTokenStore")
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl RedisTokenStore {
    /// Creates a new [`RedisTokenStore`].
    #[must_use]
    pub fn new(pool: Pool, prefix: impl Into<String>) -> Self {
        Self {
            pool,
            prefix: prefix.into(),
        }
    }

    /// Prefixes a raw key with the configured namespace.
    fn namespaced_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", self.prefix.trim_end_matches(':'), key)
        }
    }

    /// Acquires a connection from the pool.
    async fn get_conn(&self) -> Result<deadpool_redis::Connection, PortError> {
        self.pool.get().await.map_err(|e| {
            PortError::cache(format!("failed to acquire Redis connection from pool: {e}"))
        })
    }
}

#[async_trait]
impl TokenStore for RedisTokenStore {
    async fn set_token(&self, key: &str, token_hash: &str, ttl: Duration) -> Result<(), PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);
        let ttl_secs = ttl.as_secs().max(1);

        conn.set_ex::<_, _, ()>(namespaced, token_hash, ttl_secs)
            .await
            .map_err(|e| PortError::cache(format!("failed to set token in Redis: {e}")))?;

        Ok(())
    }

    async fn get_token(&self, key: &str) -> Result<Option<String>, PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        let value: Option<String> = conn
            .get(namespaced)
            .await
            .map_err(|e| PortError::cache(format!("failed to get token from Redis: {e}")))?;

        Ok(value)
    }

    async fn delete_token(&self, key: &str) -> Result<(), PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        conn.del::<_, ()>(namespaced)
            .await
            .map_err(|e| PortError::cache(format!("failed to delete token from Redis: {e}")))?;

        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        let result: Option<String> = cmd("EVAL")
            .arg(GET_AND_DELETE_LUA)
            .arg(1)
            .arg(namespaced)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                PortError::cache(format!(
                    "failed to execute atomic get-and-delete script: {e}"
                ))
            })?;

        Ok(result)
    }

    async fn consume_token(&self, key: &str, expected_token_hash: &str) -> Result<bool, PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        let result: i32 = cmd("EVAL")
            .arg(CONSUME_TOKEN_LUA)
            .arg(1)
            .arg(namespaced)
            .arg(expected_token_hash)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                PortError::cache(format!(
                    "failed to execute atomic token consumption script: {e}"
                ))
            })?;

        Ok(result == 1)
    }

    async fn set_if_not_exists(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> Result<bool, PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);
        let ttl_secs = ttl.as_secs().max(1);

        let result: i32 = cmd("EVAL")
            .arg(SET_IF_NOT_EXISTS_LUA)
            .arg(1)
            .arg(namespaced)
            .arg(value)
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                PortError::cache(format!(
                    "failed to execute atomic set-if-not-exists script: {e}"
                ))
            })?;

        Ok(result == 1)
    }

    async fn set_tokens_batch(&self, items: &[(&str, &str, Duration)]) -> Result<(), PortError> {
        if items.is_empty() {
            return Ok(());
        }

        let mut conn = self.get_conn().await?;
        let mut p = pipe();

        for &(key, val, ttl) in items {
            let namespaced = self.namespaced_key(key);
            let ttl_secs = ttl.as_secs().max(1);
            p.cmd("SET")
                .arg(namespaced)
                .arg(val)
                .arg("EX")
                .arg(ttl_secs)
                .ignore();
        }

        p.query_async::<()>(&mut conn).await.map_err(|e| {
            PortError::cache(format!("failed to execute Redis batch pipeline: {e}"))
        })?;

        Ok(())
    }

    async fn save_ws_ticket(
        &self,
        ticket: &str,
        payload: &WsTicketPayload,
        ttl_sec: u64,
    ) -> Result<(), PortError> {
        let mut conn = self.get_conn().await?;
        let key = if ticket.starts_with("ws:ticket:") {
            ticket.to_string()
        } else {
            format!("ws:ticket:{ticket}")
        };
        let namespaced = self.namespaced_key(&key);
        let json = serde_json::to_string(payload)
            .map_err(|e| PortError::cache(format!("failed to serialize ws ticket payload: {e}")))?;

        conn.set_ex::<_, _, ()>(namespaced, json, ttl_sec.max(1))
            .await
            .map_err(|e| PortError::cache(format!("failed to save ws ticket in Redis: {e}")))?;

        Ok(())
    }

    async fn consume_ws_ticket(&self, ticket: &str) -> Result<Option<WsTicketPayload>, PortError> {
        let mut conn = self.get_conn().await?;
        let key = if ticket.starts_with("ws:ticket:") {
            ticket.to_string()
        } else {
            format!("ws:ticket:{ticket}")
        };
        let namespaced = self.namespaced_key(&key);

        let result: Option<String> = cmd("GETDEL")
            .arg(namespaced)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                PortError::cache(format!("failed to execute GETDEL for ws ticket: {e}"))
            })?;

        match result {
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

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_namespaced_key_with_prefix() {
        let pool = deadpool_redis::Config::default()
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|e| format!("{e}"));
        if let Ok(pool) = pool {
            let store = RedisTokenStore::new(pool, "iam:");
            assert_eq!(store.namespaced_key("test_key"), "iam:test_key");
        }
    }

    #[test]
    fn test_namespaced_key_empty_prefix() {
        let pool = deadpool_redis::Config::default()
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|e| format!("{e}"));
        if let Ok(pool) = pool {
            let store = RedisTokenStore::new(pool, "");
            assert_eq!(store.namespaced_key("test_key"), "test_key");
        }
    }

    #[tokio::test]
    async fn test_set_tokens_batch_empty_slice_succeeds_without_conn() -> TestResult {
        let pool =
            deadpool_redis::Config::default().create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
        let store = RedisTokenStore::new(pool, "test");
        let res = store.set_tokens_batch(&[]).await;
        assert!(res.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_set_tokens_batch_fails_when_unconnected() -> TestResult {
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
        let store = RedisTokenStore::new(pool, "test");
        let items = [("k1", "v1", Duration::from_secs(60))];
        let res = store.set_tokens_batch(&items).await;
        assert!(res.is_err());
        assert!(matches!(res, Err(PortError::Cache(_))));
        Ok(())
    }
}
