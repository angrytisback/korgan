//! Redis sliding-window rate limiter using Redis sorted sets (ZSET) and atomic Lua script.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use deadpool_redis::Pool;
use deadpool_redis::redis::{AsyncCommands, cmd};

use crate::ports::cache::{RateLimitStatus, RateLimiterPort};
use crate::ports::errors::PortError;

/// Sliding-window rate limiter Lua script using Redis sorted sets.
///
/// KEYS[1]: rate limit key
/// ARGV[1]: current timestamp in milliseconds (now)
/// ARGV[2]: window duration in milliseconds
/// ARGV[3]: maximum allowed requests in window (limit)
/// ARGV[4]: unique member identifier (now:uuid)
///
/// Returns an array: { allowed (1 or 0), remaining, reset_epoch_secs }
const SLIDING_WINDOW_LUA: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

local clear_before = now - window
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('PEXPIRE', key, window)
    local remaining = limit - current_count - 1
    local reset_epoch = math.ceil((now + window) / 1000)
    return { 1, remaining, reset_epoch }
else
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_epoch
    if #oldest >= 2 then
        reset_epoch = math.ceil((tonumber(oldest[2]) + window) / 1000)
    else
        reset_epoch = math.ceil((now + window) / 1000)
    end
    return { 0, 0, reset_epoch }
end
"#;

/// Production Redis sliding-window rate limiter implementing [`RateLimiterPort`].
#[derive(Clone)]
pub struct RedisRateLimiter {
    pool: Pool,
    prefix: String,
}

impl std::fmt::Debug for RedisRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimiter")
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl RedisRateLimiter {
    /// Creates a new [`RedisRateLimiter`].
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
            format!("ratelimit:{key}")
        } else {
            format!("{}:ratelimit:{key}", self.prefix.trim_end_matches(':'))
        }
    }

    /// Acquires a connection from the pool.
    async fn get_conn(&self) -> Result<deadpool_redis::Connection, PortError> {
        self.pool.get().await.map_err(|e| {
            PortError::cache(format!(
                "failed to acquire Redis connection for rate limiter: {e}"
            ))
        })
    }
}

#[async_trait]
impl RateLimiterPort for RedisRateLimiter {
    async fn check_and_increment(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitStatus, PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        let now_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let now_ms = now_since_epoch.as_millis() as u64;
        let now_secs = now_since_epoch.as_secs();
        let window_ms = window.as_millis().max(1) as u64;
        let member = format!("{now_ms}:{}", uuid::Uuid::now_v7());

        let result: (i32, i32, i64) = cmd("EVAL")
            .arg(SLIDING_WINDOW_LUA)
            .arg(1)
            .arg(namespaced)
            .arg(now_ms)
            .arg(window_ms)
            .arg(limit)
            .arg(member)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                PortError::rate_limit(format!("failed to evaluate sliding window script: {e}"))
            })?;

        let allowed = result.0 == 1;
        let remaining = result.1.max(0) as u32;
        let reset_epoch_secs = result.2.max(0) as u64;

        let retry_after_secs = if allowed {
            None
        } else {
            Some(reset_epoch_secs.saturating_sub(now_secs).max(1))
        };

        Ok(RateLimitStatus {
            allowed,
            limit,
            remaining,
            reset_epoch_secs,
            retry_after_secs,
        })
    }

    async fn reset(&self, key: &str) -> Result<(), PortError> {
        let mut conn = self.get_conn().await?;
        let namespaced = self.namespaced_key(key);

        conn.del::<_, ()>(namespaced).await.map_err(|e| {
            PortError::cache(format!("failed to reset rate limit key in Redis: {e}"))
        })?;

        Ok(())
    }
}
