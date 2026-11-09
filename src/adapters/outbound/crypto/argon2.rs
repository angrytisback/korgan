use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use password_hash::phc::PasswordHash as PhcHash;
use password_hash::{Error as HashError, PasswordHasher as _, PasswordVerifier as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::domain::value_objects::{PasswordHash, RawPassword};
use crate::ports::errors::PortError;
use crate::ports::services::PasswordHasher;

/// Default maximum number of concurrent Argon2id operations to protect
/// against CPU starvation and out-of-memory (OOM) conditions.
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;

/// Production Argon2id password hasher.
///
/// Limits concurrent operations via a [`tokio::sync::Semaphore`] and executes
/// CPU-intensive hashing and verification inside [`tokio::task::spawn_blocking`]
/// to prevent starving async Tokio runtime worker threads or exhausting memory.
#[derive(Debug, Clone)]
pub struct Argon2PasswordHasher {
    params: Params,
    dummy_hash: PasswordHash,
    semaphore: Arc<Semaphore>,
    max_concurrency: usize,
    waiting_tasks: Arc<AtomicUsize>,
}

impl Argon2PasswordHasher {
    /// Creates a new [`Argon2PasswordHasher`] with default concurrency limit ([`DEFAULT_MAX_CONCURRENCY`])
    /// and precomputes the dummy hash used for constant-time login mitigation on non-existent accounts.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if the provided Argon2 parameters are invalid
    /// or dummy hash generation fails.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, PortError> {
        Self::new_with_concurrency(memory_kib, iterations, parallelism, DEFAULT_MAX_CONCURRENCY)
    }

    /// Creates a new [`Argon2PasswordHasher`] with explicit maximum concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if `max_concurrency` is 0, the provided Argon2 parameters
    /// are invalid, or dummy hash generation fails.
    pub fn new_with_concurrency(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        max_concurrency: usize,
    ) -> Result<Self, PortError> {
        if max_concurrency == 0 {
            return Err(PortError::crypto(
                "Argon2 max concurrency must be at least 1",
            ));
        }

        let params = Params::new(memory_kib, iterations, parallelism, Some(32))
            .map_err(|e| PortError::crypto(format!("invalid Argon2 parameters: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
        let dummy_secret = b"iam-timing-attack-mitigation-dummy-password";
        let phc = argon2
            .hash_password(dummy_secret)
            .map_err(|e| PortError::crypto(format!("failed to compute dummy Argon2 hash: {e}")))?
            .to_string();

        let dummy_hash = PasswordHash::new(phc)
            .map_err(|e| PortError::crypto(format!("failed to validate dummy Argon2 hash: {e}")))?;

        Ok(Self {
            params,
            dummy_hash,
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            max_concurrency,
            waiting_tasks: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Acquires an execution permit bounded by a maximum queue depth and a 3-second timeout.
    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, PortError> {
        const MAX_QUEUE_DEPTH: usize = 32;
        let prev = self.waiting_tasks.fetch_add(1, Ordering::SeqCst);
        let waiting = prev.saturating_add(1);
        metrics::gauge!("korgan_argon2_semaphore_waiting").set(waiting as f64);
        if prev >= MAX_QUEUE_DEPTH {
            self.waiting_tasks.fetch_sub(1, Ordering::SeqCst);
            metrics::gauge!("korgan_argon2_semaphore_waiting").set(prev as f64);
            return Err(PortError::service_unavailable(
                "argon2 hasher overloaded: queue capacity exceeded",
            ));
        }

        struct QueueGuard(Arc<AtomicUsize>);
        impl Drop for QueueGuard {
            fn drop(&mut self) {
                let prev = self.0.fetch_sub(1, Ordering::SeqCst);
                let waiting = prev.saturating_sub(1);
                metrics::gauge!("korgan_argon2_semaphore_waiting").set(waiting as f64);
            }
        }
        let _guard = QueueGuard(self.waiting_tasks.clone());

        match tokio::time::timeout(
            Duration::from_secs(3),
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(e)) => Err(PortError::crypto(format!("hasher semaphore closed: {e}"))),
            Err(_) => Err(PortError::service_unavailable(
                "argon2 hasher timed out waiting for permit",
            )),
        }
    }

    /// Returns a reference to the pre-computed dummy hash.
    #[must_use]
    pub fn dummy_hash(&self) -> &PasswordHash {
        &self.dummy_hash
    }

    /// Returns the maximum allowed concurrency for Argon2id hashing/verification.
    #[must_use]
    pub fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }

    /// Returns the number of currently available concurrency permits.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Returns the internal semaphore for concurrency and timeout testing.
    #[must_use]
    pub fn semaphore_for_test(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash_password(&self, password: &RawPassword) -> Result<PasswordHash, PortError> {
        let permit = self.acquire_permit().await?;

        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
        let params = self.params.clone();

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let hash_res = argon2.hash_password(&password_bytes);

            let phc = hash_res
                .map_err(|e| {
                    PortError::crypto(format!("failed to hash password with Argon2id: {e}"))
                })?
                .to_string();

            PasswordHash::new(phc)
                .map_err(|e| PortError::crypto(format!("generated hash failed validation: {e}")))
        })
        .await
        .map_err(|e| {
            PortError::crypto(format!("blocking hash task panicked or was cancelled: {e}"))
        })?
    }

    async fn verify_password(
        &self,
        password: &RawPassword,
        hash: &PasswordHash,
    ) -> Result<bool, PortError> {
        let permit = self.acquire_permit().await?;

        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
        let hash_str = hash.as_str().to_string();

        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed_hash = PhcHash::new(&hash_str)
                .map_err(|e| PortError::crypto(format!("failed to parse PHC hash: {e}")))?;

            let argon2 = Argon2::default();
            let verify_res = argon2.verify_password(&password_bytes, &parsed_hash);

            match verify_res {
                Ok(()) => Ok(true),
                Err(HashError::PasswordInvalid) => Ok(false),
                Err(e) => Err(PortError::crypto(format!("Argon2 verification error: {e}"))),
            }
        })
        .await
        .map_err(|e| {
            PortError::crypto(format!(
                "blocking verify task panicked or was cancelled: {e}"
            ))
        })?
    }

    async fn verify_against_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError> {
        let _ = self.verify_password(password, &self.dummy_hash).await?;
        Ok(())
    }

    async fn compute_dummy_hash(&self, password: &RawPassword) -> Result<(), PortError> {
        let _ = self.hash_password(password).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn hashes_and_verifies_password() -> TestResult {
        // Fast parameters for unit tests
        let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
        let raw = RawPassword::new("CorrectHorseBatteryStaple!123")?;
        let wrong = RawPassword::new("WrongPassword123!")?;

        let hash = hasher.hash_password(&raw).await?;
        assert!(hash.as_str().starts_with("$argon2id$"));

        let is_valid = hasher.verify_password(&raw, &hash).await?;
        assert!(is_valid);

        let is_invalid = hasher.verify_password(&wrong, &hash).await?;
        assert!(!is_invalid);
        Ok(())
    }

    #[tokio::test]
    async fn dummy_hash_verification_always_completes_safely() -> TestResult {
        let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
        let raw = RawPassword::new("NonExistentUserPassword123!")?;

        hasher.verify_against_dummy_hash(&raw).await?;
        Ok(())
    }

    #[tokio::test]
    async fn dummy_hash_computation_always_completes_safely() -> TestResult {
        let hasher = Argon2PasswordHasher::new(1024, 1, 1)?;
        let raw = RawPassword::new("DuplicateUserPassword123!")?;

        hasher.compute_dummy_hash(&raw).await?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_zero_concurrency() {
        let res = Argon2PasswordHasher::new_with_concurrency(1024, 1, 1, 0);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn concurrency_limit_enforced_and_permits_restored() -> TestResult {
        let hasher = Arc::new(Argon2PasswordHasher::new_with_concurrency(1024, 1, 1, 2)?);
        assert_eq!(hasher.max_concurrency(), 2);
        assert_eq!(hasher.available_permits(), 2);

        let mut handles = Vec::new();
        for i in 0..6 {
            let hasher_clone = hasher.clone();
            let handle = tokio::spawn(async move {
                let raw = RawPassword::new(format!("Password_{i}!123"))?;
                let hash = hasher_clone.hash_password(&raw).await?;
                let ok = hasher_clone.verify_password(&raw, &hash).await?;
                assert!(ok);
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            let res = handle.await.map_err(|e| e.to_string())?;
            res.map_err(|e| e.to_string())?;
        }

        // All permits must be safely released after concurrent execution
        assert_eq!(hasher.available_permits(), 2);
        Ok(())
    }
}
