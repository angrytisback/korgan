//! Cryptographic audit log chain integrity verification use case.

use std::sync::Arc;

use crate::application::error::AppError;
use crate::ports::repositories::AuditLogRepository;

/// Details of a broken cryptographic audit link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenAuditLink {
    /// Zero-based position in chronological chain.
    pub record_index: usize,
    /// Unique identifier of the corrupted audit log entry.
    pub log_id: String,
    /// Reason why verification failed.
    pub reason: String,
}

/// Outcome of the cryptographic audit chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerificationResult {
    /// Entire chain is mathematically verified.
    Valid {
        /// Number of verified records in the chain.
        verified_count: usize,
    },
    /// A broken link or tampered entry was detected.
    Corrupted(BrokenAuditLink),
}

/// Use case that sequentially traverses `audit_logs` and verifies hashes.
#[derive(Clone)]
pub struct VerifyAuditChainUseCase {
    audit_repo: Arc<dyn AuditLogRepository>,
}

impl std::fmt::Debug for VerifyAuditChainUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyAuditChainUseCase").finish()
    }
}

impl VerifyAuditChainUseCase {
    /// Creates a new [`VerifyAuditChainUseCase`].
    #[must_use]
    pub fn new(audit_repo: Arc<dyn AuditLogRepository>) -> Self {
        Self { audit_repo }
    }

    /// Verifies the cryptographic chain across all audit entries from genesis.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if retrieving the audit log entries fails.
    pub async fn execute(&self) -> Result<AuditVerificationResult, AppError> {
        let entries = self.audit_repo.list_all_chronological().await?;

        let mut expected_prev: Option<&str> = None;
        for (idx, entry) in entries.iter().enumerate() {
            if !entry.verify_integrity(expected_prev) {
                return Ok(AuditVerificationResult::Corrupted(BrokenAuditLink {
                    record_index: idx,
                    log_id: entry.id.to_string(),
                    reason: format!(
                        "Hash mismatch or broken link at record index {idx}: expected prev_hash {:?}, recorded prev_hash {:?}",
                        expected_prev, entry.prev_hash
                    ),
                }));
            }
            expected_prev = entry.entry_hash.as_deref();
        }

        let verified_count = entries.len();
        metrics::gauge!("korgan_audit_chain_length").set(verified_count as f64);

        Ok(AuditVerificationResult::Valid { verified_count })
    }
}
