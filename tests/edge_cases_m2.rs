//! Edge-case and adversarial stress tests for Milestone 2 (R3 & R7).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use korgan::ports::cache::TokenStore;
use korgan::ports::errors::PortError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// Controllable Mock Token Store for Testing Default Trait Implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ControllableStore {
    tokens: Mutex<HashMap<String, (String, Duration)>>,
    fail_on_index: Mutex<Option<usize>>,
    writes_called: AtomicU32,
}

#[async_trait]
impl TokenStore for ControllableStore {
    async fn set_token(&self, key: &str, token_hash: &str, ttl: Duration) -> Result<(), PortError> {
        let idx = self.writes_called.fetch_add(1, Ordering::SeqCst) as usize;
        let fail = self
            .fail_on_index
            .lock()
            .map_err(|e| PortError::cache(e.to_string()))?;
        if *fail == Some(idx) {
            return Err(PortError::cache(format!(
                "simulated failure at index {idx}"
            )));
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
        _value: &str,
        _ttl: Duration,
    ) -> Result<bool, PortError> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Edge Case 1: Empty slice batch write
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_batch_empty_slice_succeeds_with_zero_calls() -> TestResult {
    let store = ControllableStore::default();
    store.set_tokens_batch(&[]).await?;
    assert_eq!(store.writes_called.load(Ordering::SeqCst), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Edge Case 2: Single item batch write
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_batch_single_item() -> TestResult {
    let store = ControllableStore::default();
    let items = [("session_key_1", "valid_hash", Duration::from_secs(3600))];

    store.set_tokens_batch(&items).await?;
    assert_eq!(store.writes_called.load(Ordering::SeqCst), 1);

    let val = store.get_token("session_key_1").await?;
    assert_eq!(val, Some("valid_hash".to_string()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Edge Case 3: Multiple items (50 items) and overwrite semantics
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_batch_multiple_items_and_duplicate_overwrite() -> TestResult {
    let store = ControllableStore::default();
    let mut items = Vec::new();
    for i in 0..50 {
        items.push((
            format!("key_{i}"),
            format!("val_{i}"),
            Duration::from_secs(60),
        ));
    }
    // Duplicate key with new value
    items.push((
        "key_0".to_string(),
        "val_overwritten".to_string(),
        Duration::from_secs(120),
    ));

    let borrowed: Vec<(&str, &str, Duration)> = items
        .iter()
        .map(|(k, v, ttl)| (k.as_str(), v.as_str(), *ttl))
        .collect();

    store.set_tokens_batch(&borrowed).await?;
    assert_eq!(store.writes_called.load(Ordering::SeqCst), 51);

    for i in 1..50 {
        let val = store.get_token(&format!("key_{i}")).await?;
        assert_eq!(val, Some(format!("val_{i}")));
    }
    // Key 0 must reflect the last write (overwrite)
    assert_eq!(
        store.get_token("key_0").await?,
        Some("val_overwritten".to_string())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Edge Case 4: Error propagation stops subsequent writes immediately
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_batch_error_propagation_stops_execution() -> TestResult {
    let store = ControllableStore::default();
    // Inject failure at index 2 (the 3rd item out of 5)
    *store.fail_on_index.lock().map_err(|e| e.to_string())? = Some(2);

    let items = [
        ("k0", "v0", Duration::from_secs(60)),
        ("k1", "v1", Duration::from_secs(60)),
        ("k2", "v2", Duration::from_secs(60)), // FAILS HERE
        ("k3", "v3", Duration::from_secs(60)), // MUST NOT BE ATTEMPTED
        ("k4", "v4", Duration::from_secs(60)), // MUST NOT BE ATTEMPTED
    ];

    let result = store.set_tokens_batch(&items).await;
    assert!(result.is_err(), "Must return error on item failure");

    // Total writes attempted should be exactly 3 (indices 0, 1, 2)
    assert_eq!(
        store.writes_called.load(Ordering::SeqCst),
        3,
        "Subsequent writes after failure must be aborted immediately"
    );

    let Err(err) = result else {
        return Err("expected error from set_tokens_batch".into());
    };
    let err_str = err.to_string();
    assert!(
        err_str.contains("simulated failure at index 2"),
        "Error message must reflect the failing item"
    );

    // Verify item 0 and 1 were written, but items 3 and 4 were not
    assert_eq!(store.get_token("k0").await?, Some("v0".to_string()));
    assert_eq!(store.get_token("k1").await?, Some("v1".to_string()));
    assert_eq!(store.get_token("k3").await?, None);
    assert_eq!(store.get_token("k4").await?, None);

    Ok(())
}

// ---------------------------------------------------------------------------
// Edge Case 5: Sub-second TTL duration handling
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_batch_sub_second_ttl_durations() -> TestResult {
    let store = ControllableStore::default();
    let items = [
        ("micro", "v_micro", Duration::from_micros(500)),
        ("zero", "v_zero", Duration::ZERO),
    ];

    store.set_tokens_batch(&items).await?;
    assert_eq!(store.writes_called.load(Ordering::SeqCst), 2);
    assert_eq!(store.get_token("micro").await?, Some("v_micro".to_string()));
    assert_eq!(store.get_token("zero").await?, Some("v_zero".to_string()));
    Ok(())
}
