//! Retry policy of `shielded` side-effects.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use korgan::application::error::AppError;
use korgan::application::use_cases::shielded;

async fn attempts_for(error: fn() -> AppError) -> u32 {
    let attempts = Arc::new(AtomicU32::new(0));
    let counter = attempts.clone();
    let _ = shielded(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<(), AppError>(error())
        }
    })
    .await;
    attempts.load(Ordering::SeqCst)
}

#[tokio::test]
async fn permanent_errors_are_not_retried() {
    assert_eq!(attempts_for(|| AppError::Conflict).await, 1);
    assert_eq!(attempts_for(|| AppError::NotFound).await, 1);
    assert_eq!(attempts_for(|| AppError::Forbidden).await, 1);
    assert_eq!(attempts_for(|| AppError::TokenInvalid).await, 1);
}

#[tokio::test]
async fn transient_errors_are_retried_up_to_the_limit() {
    assert_eq!(attempts_for(|| AppError::ServiceUnavailable).await, 3);
    assert_eq!(
        attempts_for(|| AppError::internal("redis", std::io::Error::other("reset"))).await,
        3
    );
}
