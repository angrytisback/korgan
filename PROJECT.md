# Project: Korgan (`korgan`) Hardening & Modernization

## Architecture
Korgan is an identity and access management service designed following Hexagonal Architecture (Ports and Adapters):
- `src/domain/`: Pure domain logic (entities, value objects, domain errors). Zero dependencies on frameworks or external I/O. Zero panics (`0 unwrap/expect`).
- `src/ports/`: Primary (driving) and secondary (driven) port interfaces, shared contract types, and `PortError`.
- `src/application/`: Application use cases, commands, and orchestration. Implements driving ports and coordinates driven ports. Forbidden imports: `axum`, `sqlx`, `redis`, `http::`. Zero panics (`0 unwrap/expect`).
- `src/adapters/inbound/`: Inbound HTTP handlers (Axum), extractors, middleware, and API error mappings.
- `src/adapters/outbound/`: Outbound adapter implementations:
  - `crypto/`: Argon2 password hasher, Ed25519 JWT token signer/verifier, AES-256-GCM symmetric cipher, TOTP service.
  - `postgres/`: SQLx repositories (User, Session, Passkey, etc.).
  - `redis/`: Redis token store, rate limiter, blacklist cache.
  - `oauth/`: Google and GitHub OAuth2 adapters.

## Feature Inventory
Every requirement from ORIGINAL_REQUEST.md is inventoried and mapped to a milestone below.

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | R1.1 Google Verified Email | Check `email_verified: bool`; reject unverified profiles with security error | M3 | ORIGINAL_REQUEST Section R1 |
| 2 | R1.2 GitHub Primary Email | Ignore unverified bio email; accept strictly verified primary email from `/user/emails` | M3 | ORIGINAL_REQUEST Section R1 |
| 3 | R1.3 Unverified Account Takeover Protection | Reset `password_hash` to `None`, clear lock counters, verify email, revoke active sessions | M3 | ORIGINAL_REQUEST Section R1 |
| 4 | R1.4 E2E OAuth Test Update | Update `e2e_oauth` test to assert password deletion and verify login rejection with old password | M3 | ORIGINAL_REQUEST Section R1 |
| 5 | R2.1 Symmetric Decryption Zeroize | Wrap `SecretCipher::decrypt_with_aad` output in zeroize wrapper (`DecryptedSecret`), zeroize TOTP plaintext on drop | M1 | ORIGINAL_REQUEST Section R2 |
| 6 | R2.2 JWT Multi-Verifying-Keys & Rotation | Support `verifying_keys: HashMap<String, VerifyingKey>`, decode/match `kid`, list all keys in JWKS | M1 | ORIGINAL_REQUEST Section R2 |
| 7 | R2.3 `user_mfa` Key Versioning | Support `key_id TEXT NOT NULL DEFAULT 'v1'` in `user_mfa` schema and entity | M1 | ORIGINAL_REQUEST Section R2 |
| 8 | R3.1 Dual-Token Ambiguity Check | Reject `/auth/refresh` and `/auth/logout` with 422 (`ValidationFailed`) if token present in both cookie and JSON | M2 | ORIGINAL_REQUEST Section R3 |
| 9 | R3.2 Strict Channel Separation | Web: cookie-only (reject JSON body with 422); Mobile/CLI: JSON body only (reject cookie with 403 Forbidden) | M2 | ORIGINAL_REQUEST Section R3 |
| 10 | R4.1 Passkey Optimistic Lock SQL | `update_credential_state` requires `new_counter > old_counter` for hardware tokens, allows 0 -> 0 for cloud passkeys | M4 | ORIGINAL_REQUEST Section R4 |
| 11 | R4.2 Passkey Cloning Conflict Error | When `rows_affected == 0`, return counter regression / cloning conflict error (`PortError::Conflict` / 409) | M4 | ORIGINAL_REQUEST Section R4 |
| 12 | R5.1 Argon2 Semaphore Timeout | Add 3-second timeout to Argon2 permit acquisition (`acquire_owned`) | M5 | ORIGINAL_REQUEST Section R5 |
| 13 | R5.2 Argon2 Queue Bounding | Add queue depth limit (max 32 waiting tasks) to prevent CPU/memory starvation | M5 | ORIGINAL_REQUEST Section R5 |
| 14 | R5.3 Argon2 503 Mapping | Map semaphore timeout and queue capacity exhaustion to HTTP 503 `ServiceUnavailable` | M5 | ORIGINAL_REQUEST Section R5 |
| 15 | R6.1 Client IP Extraction | Parse rightmost valid IP from `X-Forwarded-For` in `metadata.rs` and `rate_limit.rs` using `rsplit(',')` | M5 | ORIGINAL_REQUEST Section R6 |
| 16 | R6.2 Fail-Closed Rate Limiter | Return HTTP 503 (`ServiceUnavailable`) on Redis rate limiter errors instead of failing open | M5 | ORIGINAL_REQUEST Section R6 |
| 17 | R7.1 Redis Pipeline Batch Revocation | Add `set_tokens_batch` to `TokenStore` using Redis pipeline (`deadpool_redis::redis::pipe()`) | M2 | ORIGINAL_REQUEST Section R7 |
| 18 | R7.2 Shielded Exponential Backoff Retry | Implement 3-attempt exponential backoff retry in `shielded` for transient network failures | M2 | ORIGINAL_REQUEST Section R7 |
| 19 | R8.1 Password O(1) Pre-Normalization Bound | In `RawPassword::new`, check `raw.as_ref().len() > MAX_PASSWORD_LENGTH * 4` before Unicode NFC normalization | M1 | ORIGINAL_REQUEST Section R8 |
| 20 | T1 Regression Test 1 | `test_oauth_pre_account_takeover_prevention` in `tests/e2e_oauth.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 21 | T2 Regression Test 2 | `test_oauth_google_rejects_unverified_email` in `tests/e2e_oauth.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 22 | T3 Regression Test 3 | `test_oauth_github_ignores_public_bio_email` in `tests/e2e_oauth.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 23 | T4 Regression Test 4 | `test_passkey_concurrent_counter_update_optimistic_lock` in `tests/e2e_passkeys.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 24 | T5 Regression Test 5 | `test_refresh_ambiguous_token_injection_rejected` in `tests/http_api.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 25 | T6 Regression Test 6 | `test_rate_limit_ip_spoofing_via_x_forwarded_for` in `tests/http_api.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 26 | T7 Regression Test 7 | `test_argon2_semaphore_queue_timeout` in `tests/use_cases.rs` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 27 | AC1 Cargo Test Suite | `SQLX_OFFLINE=true cargo test` (all 147+ tests passing) | M6 | ORIGINAL_REQUEST Section Acceptance |
| 28 | AC2 Cargo Clippy Clean | `SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 29 | AC3 Cargo Fmt Clean | `cargo fmt --all -- --check` | M6 | ORIGINAL_REQUEST Section Acceptance |
| 30 | AC4 Architectural & Zero Panic | `python3 scripts/check_boundaries.py` (0 violations) | M6 | ORIGINAL_REQUEST Section Acceptance |

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Domain & Crypto Foundation | R8 (Password O(1) bound), R2 (Zeroize wrapper, multi-key JWT & JWKS, user_mfa key_id) | None | DONE |
| M2 | Channel Separation & Redis Batch | R3 (Dual-mode channel separation & 422 ambiguous token), R7 (Redis batch pipeline & retry) | M1 | DONE |
| M3 | OAuth2 Takeover & Verification | R1 (Google/GitHub email verification, takeover mitigation, test updates) | M1, M2 | DONE |
| M4 | Passkey Optimistic Lock | R4 (Passkey sign_count atomic optimistic lock SQL & conflict error) | M1 | DONE |
| M5 | Infrastructure Protection | R5 (Argon2 semaphore timeout/queue limit 503), R6 (IP extraction & fail-closed rate limit) | M1 | DONE |
| M6 | Regression Suite & Gate | 7 Regression Tests (T1-T7), full cargo test (147+), clippy, fmt, check_boundaries | M1, M2, M3, M4, M5 | DONE |

## Interface Contracts

### M1 <-> Downstream (Crypto & Domain Types)
- `RawPassword::new(raw: impl AsRef<str>) -> Result<Self, DomainError>`:
  Rejects inputs with `raw.as_ref().len() > 512` with `DomainError::PasswordTooLong` before NFC normalization.
- `SecretCipher`:
  `fn decrypt_with_aad(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<DecryptedSecret, PortError>;`
  where `DecryptedSecret` derives/implements `Zeroize` and `ZeroizeOnDrop`.
- `TokenSigner`:
  `Ed25519JwtService` contains `verifying_keys: HashMap<String, VerifyingKey>`.
  Decodes JOSE header, matches `kid`, verifies signature with matching key.
  `public_key_jwks()` returns all keys formatted with their respective `kid`s.
- `UserMfa`:
  Has field `pub key_id: String`. `UserMfa::new` defaults to `"v1"`, while `UserMfa::new_with_key_id` allows explicit key id.

### M2 <-> Downstream (Token & Cache Contracts)
- `TokenStore`:
  `async fn set_tokens_batch(&self, items: &[(&str, &str, Duration)]) -> Result<(), PortError>;`
  Default trait implementation loops over `set_token`. `RedisTokenStore` executes pipeline commands via `deadpool_redis::redis::pipe()`.
- HTTP Auth Endpoints:
  `/auth/refresh` and `/auth/logout` reject requests with `422 Unprocessable Entity` if tokens exist in both cookie and JSON body.
  Reject Web clients sending JSON body tokens with `422`.
  Reject Mobile/CLI clients sending cookies with `403 Forbidden`.

### M4 <-> Downstream (Passkey Repository Contract)
- `PasskeyRepository::update_credential_state`:
  `async fn update_credential_state(&self, id: &PasskeyId, passkey_json: &serde_json::Value, last_used_at: DateTime<Utc>) -> Result<(), PortError>;`
  Requires `new_counter > old_counter` for hardware tokens; permits `0 -> 0` for cloud credentials.
  Returns `PortError::conflict(...)` when `rows_affected == 0` for an existing passkey.

### M5 <-> Downstream (Error & IP Contracts)
- `PortError::ServiceUnavailable` / `PortError::service_unavailable(msg)`:
  Maps to `AppError::ServiceUnavailable` and HTTP 503 (`ErrorKind::ServiceUnavailable`).
- IP Extraction:
  Inspects `X-Forwarded-For` using `.rsplit(',')` to extract the rightmost valid IP address.

## Code Layout
- `src/domain/value_objects/password.rs`: RawPassword validation and normalization.
- `src/domain/entities/mfa.rs`: UserMfa entity and constructors.
- `src/ports/services.rs`: `SecretCipher`, `TokenSigner`, `DecryptedSecret`.
- `src/ports/cache.rs`: `TokenStore` trait and `set_tokens_batch`.
- `src/ports/repositories.rs`: `PasskeyRepository` trait and default methods.
- `src/ports/errors.rs`: `PortError` definitions and helpers.
- `src/application/use_cases/cancellation.rs`: `shielded` execution with retry.
- `src/application/use_cases/oauth/callback.rs`: OAuth callback logic and account linking.
- `src/application/use_cases/mfa/verify_login.rs`: TOTP verification with zeroized secret.
- `src/adapters/inbound/http/handlers/auth.rs`: `/auth/refresh` and `/auth/logout`.
- `src/adapters/inbound/http/extractors/metadata.rs`: Client metadata extraction and IP parsing.
- `src/adapters/inbound/http/middleware/rate_limit.rs`: Rate limiting middleware and IP parsing.
- `src/adapters/outbound/crypto/aes.rs`: AES-256-GCM cipher returning DecryptedSecret.
- `src/adapters/outbound/crypto/jwt.rs`: Ed25519 JWT service with multi-verifying-keys.
- `src/adapters/outbound/crypto/argon2.rs`: Argon2 password hasher with timeout and queue limits.
- `src/adapters/outbound/postgres/passkey_repository.rs`: Optimistic locking SQL query.
- `src/adapters/outbound/postgres/user_repository.rs`: `user_mfa` queries with `key_id`.
- `src/adapters/outbound/redis/token_store.rs`: Pipelined batch token blacklisting.
- `src/adapters/outbound/oauth/google.rs`: Google OAuth adapter with `email_verified`.
- `src/adapters/outbound/oauth/github.rs`: GitHub OAuth adapter querying `/user/emails`.
- `migrations/0003_sessions_and_mfa.sql`: `user_mfa` schema definition.
- `tests/e2e_oauth.rs`: OAuth E2E tests and regressions (T1, T2, T3).
- `tests/e2e_passkeys.rs`: Passkey E2E tests and regression (T4).
- `tests/http_api.rs`: HTTP API tests and regressions (T5, T6).
- `tests/use_cases.rs`: Use case tests and regression (T7).
