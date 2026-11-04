# Original User Request

## 2026-10-31T18:54:57Z

Remediation of 8 critical P0, P1, and P2 security vulnerabilities detected in the Korgan (`korgan`) identity and authorization engine, preserving strict architectural boundaries and zero-panic guarantees, alongside adding 7 new regression tests.

Working directory: `/home/eigen/Projects/Korgan`
Integrity mode: development

## Requirements

### R1. OAuth2 Pre-Account Takeover Defense & Email Verification Enforcement
- Inspect the `email_verified` field in the user profile returned by Google; reject unverified accounts with a security error.
- In GitHub provider, ignore unverified public profile emails; only accept verified primary email addresses returned from `/user/emails`.
- When an existing `Unverified` account links via OAuth, prevent attacker lock and password traps by clearing its password (`password_hash = None`), resetting lock counters, verifying the email, and revoking active sessions.
- Update `e2e_oauth` test assertions to verify password erasure (`password_hash.is_none()`) and verify that login with the old password is denied.

### R2. Cryptographic Memory Safety (`Zeroizing`) & Multi-Key Rotation
- Wrap symmetric decryption output (`SecretCipher::decrypt_with_aad`) in `zeroize::Zeroizing` (or `DecryptedSecret`) to prevent unprotected heap copies; guarantee decrypted TOTP secrets are zeroized in memory upon completion.
- Extend `Ed25519JwtService` to support multiple public verification keys (`verifying_keys: HashMap<String, VerifyingKey>`) alongside the active signing key; expose all valid keys with their `kid` in the JWKS endpoint and enforce `kid` resolution on verification.
- Support `key_id` versioning in the `user_mfa` table.

### R3. Dual-Mode Strict Channel Separation & Ambiguous Token Injection Protection
- Reject refresh requests at `/auth/refresh` and logout at `/auth/logout` with `422 Unprocessable Entity` (`ValidationFailed`) if tokens are submitted via both Cookie and JSON body simultaneously.
- For Web clients (`metadata.client_type.is_web()`), accept tokens strictly from Cookie; reject tokens sent in JSON body. For Mobile/CLI clients, accept tokens strictly from JSON body; reject tokens sent in Cookie with `403 Forbidden`.

### R4. Passkey `sign_count` Atomic Optimistic Lock
- In `update_credential_state` SQL query, require the new sign counter to be strictly greater (`>`) than the old counter for hardware security keys, exempting cloud passkeys (counter 0 -> 0).
- If zero rows are updated (`rows_affected == 0`), return a counter rollback / clone collision error instead of silently succeeding.

### R5. Argon2id Semaphore Timeout & DoS Protection
- Enforce a 3-second timeout and queue bounding on password verification and hashing semaphore acquisition (`acquire_owned`).
- In case of timeout or capacity exhaustion, map the failure to HTTP `503 Service Unavailable`.

### R6. `X-Forwarded-For` Spoofing Protection & Fail-Closed Rate Limiter
- In `extract_ip`, parse the rightmost valid IP address appended by the trusted reverse proxy instead of the client-controlled first IP.
- Return Fail-Closed (`503 Service Unavailable`) on Redis rate limiter connection errors instead of Fail-Open.

### R7. Redis Batch Token Blacklisting & Retry Mechanism
- In session revocation (`revoke_family`, `revoke_all_user_sessions`), execute batch blacklisting via Redis pipeline (`set_tokens_batch`) instead of individual round-trips.
- Apply a 3-attempt exponential backoff retry mechanism to Redis operations within `shielded` execution blocks to handle transient network hiccups.

### R8. Pre-Normalization $O(1)$ Password Size Guard
- In `RawPassword::new`, validate byte length in $O(1)$ time (`MAX_PASSWORD_LENGTH * 4` byte limit) before executing Unicode NFC normalization; reject immediately without full string re-scanning.

## Acceptance Criteria

### Automated Quality & Regression Suite
- [ ] 7 new regression tests written and passing:
  1. `test_oauth_pre_account_takeover_prevention`
  2. `test_oauth_google_rejects_unverified_email`
  3. `test_oauth_github_ignores_public_bio_email`
  4. `test_passkey_concurrent_counter_update_optimistic_lock`
  5. `test_refresh_ambiguous_token_injection_rejected`
  6. `test_rate_limit_ip_spoofing_via_x_forwarded_for`
  7. `test_argon2_semaphore_queue_timeout`
- [ ] `SQLX_OFFLINE=true cargo test` passes with zero errors across all unit, integration, and E2E tests (147+ tests).
- [ ] `SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings` passes with zero warnings.
- [ ] `cargo fmt --all -- --check` passes with zero diffs.
- [ ] `python3 scripts/check_boundaries.py` confirms 0 forbidden imports and 0 unwrap/expect violations.


## 2026-10-31T21:21:31Z

Apply exact security patches for audit findings (P0, P1, P2) in the Korgan authentication service including 6 critical edge-case fixes, implement comprehensive regression tests, and satisfy all architecture and verification gates.

Working directory: /home/eigen/Projects/Korgan
Integrity mode: development

## Requirements

### R1. [P0] OAuth2 Pre-Account Takeover Defense & Email Verification Enforcement
- In `src/adapters/outbound/oauth/google.rs`: add `#[serde(default)] email_verified: Option<bool>` to `GoogleUserInfo`; if `!email_verified.unwrap_or(false)`, return `Err(PortError::security("google account email is not verified"))`.
- In `src/adapters/outbound/oauth/github.rs`: never trust unverified public profile email (`gh_user.email`). Always query `/user/emails` endpoint and require `e.verified && e.primary` (or verified email). If no verified email exists, return `PortError::security`.
- In `src/application/use_cases/oauth/callback.rs`: when matching an existing user with `AccountStatus::Unverified`, before `can_login` check:
  1. Clear `password_hash = None` (prevent pre-account takeover).
  2. Reset `failed_login_attempts = 0` and `locked_until = None`.
  3. Verify email via `verify_email(now)`, execute `can_login(now)?`, and persist with `user_repo.update(&existing_user).await?` (ensuring `password_hash = None` writes `NULL` in SQL).
  4. Revoke all existing sessions via `session_repo.revoke_all_user_sessions(&existing_user.id, None, "oauth_pre_account_takeover_defense")`.
- In `tests/e2e_oauth.rs`: update line 1189 assertion to verify `updated_user.password_hash.is_none()` and assert that login with previous password via `/api/v1/auth/login` is rejected.

### R2. [P1] Cryptographic Memory Safety (Zeroizing) & Key Rotation / MFA Versioning
- In `src/ports/services.rs` and `src/adapters/outbound/crypto/aes.rs`: change `SecretCipher::decrypt_with_aad` return type to `Result<zeroize::Zeroizing<Vec<u8>>, PortError>` (or `DecryptedSecret`), preventing unprotected heap copies via `.to_vec()`.
- Ensure TOTP decrypted secrets in `src/application/use_cases/mfa/verify_login.rs` and callers remain protected by `Zeroizing` through UTF-8 / Base32 transformations and are cleared on drop.
- In `src/adapters/outbound/crypto/jwt.rs`: extend `Ed25519JwtService` to support multiple verifying keys (`verifying_keys: HashMap<String, VerifyingKey>`) alongside the active signing key (`signing_key`, `active_kid`).
- Expose all active/transition keys in `jwks_json()`.
- In `verify_access_token`: enforce header `alg == "EdDSA"` and resolve verification key strictly by `kid`.
- Add `key_id` support (default `'v1'`) to `user_mfa` and maintain backward compatibility for encryption/decryption.

### R3. [P2] Dual-Mode (X-Client-Type) Channel Separation & Ambiguous Token Rejection
- In `src/adapters/inbound/http/handlers/auth.rs` for both `refresh` and `logout` handlers:
  - If both `token_from_body` and `token_from_cookie` are present `(Some(_), Some(_))`, reject immediately with `422 Unprocessable Entity` (`ValidationFailed`).
  - If `metadata.client_type.is_web()`: accept **only** `token_from_cookie`. If received via JSON body `(Some(_), None)`, reject with `422 ValidationFailed` or `403 Forbidden` to prevent session fixation.
  - If `!metadata.client_type.is_web()` (`mobile` / `cli`): accept **only** `token_from_body`. If received via cookie `(None, Some(_))`, reject with `403 Forbidden`.

### R4. [P2] Passkey sign_count Atomic Optimistic Lock
- In `src/adapters/outbound/postgres/passkey_repository.rs`, update `update_credential_state`:
  - For cloud passkeys (current counter is 0 and new counter is 0), allow update.
  - For hardware keys (current counter > 0), enforce strictly that new counter is strictly greater (`>`) than existing counter:
    ```sql
    UPDATE passkeys
    SET passkey_json = $2, last_used_at = $3
    WHERE id = $1
      AND (
        (COALESCE((passkey_json->'cred'->>'counter')::bigint, 0) = 0 AND COALESCE(($2->'cred'->>'counter')::bigint, 0) = 0)
        OR COALESCE(($2->'cred'->>'counter')::bigint, 0) > COALESCE((passkey_json->'cred'->>'counter')::bigint, 0)
      )
    ```
  - If `result.rows_affected() == 0`, return `Err(PortError::security("passkey counter state conflict or replay detected"))`.

### R5. [P2] Argon2id Semaphore Queue Timeout & Overload Protection
- In `src/adapters/outbound/crypto/argon2.rs`: wrap `acquire_owned()` with a 3-second timeout (`tokio::time::timeout(Duration::from_secs(3), ...)`).
- Implement waiting permit bounding (e.g. `AtomicUsize` tracking pending requests up to 256) or fast queue failure, returning `PortError::external_service("argon2", "hasher overloaded", None)` on timeout or queue capacity exceeded.
- Map this error to HTTP `503 Service Unavailable` in `src/application/error.rs` and HTTP error handling.

### R6. [P2] X-Forwarded-For Rightmost Parsing & Fail-Closed Rate Limiter
- In `src/adapters/inbound/http/extractors/metadata.rs`: when `trust_proxy` is enabled, parse the rightmost valid IP address from `x-forwarded-for` (`s.split(',').rev().find_map(|part| part.trim().parse::<IpAddr>().ok())`).
- In `src/adapters/inbound/http/middleware/rate_limit.rs`: eliminate fail-open on Redis rate limiter errors (`Err(e)`); fail-closed with `503 Service Unavailable`.

### R7. [P2] Redis Batch Token Blacklisting & Retry in Shielded Blocks
- In `src/ports/repositories.rs` and Redis adapter: add `set_tokens_batch` using Redis pipelines for multi-session revocations (`revoke_family`, `revoke_all_user_sessions`).
- In `shielded` execution blocks in `refresh.rs`, `ban.rs`, and token store: add 3-attempt exponential backoff retry (e.g. 20ms, 50ms, 100ms) for transient Redis errors.

### R8. [P2] RawPassword::new O(1) Pre-Normalization Length Check
- In `src/domain/value_objects/password.rs`: check byte length before unicode NFC normalization (`raw.as_ref().nfc().collect()`).
- On length failure, avoid calling `raw_str.chars().count()`. Return `Err(DomainError::PasswordTooLong { max: MAX_PASSWORD_LENGTH, actual: raw_str.len() })` immediately if `raw_str.len() > MAX_PASSWORD_LENGTH * 4`.

## Acceptance Criteria

### Security & Regression Test Suite
- [ ] `test_oauth_pre_account_takeover_prevention` implemented and passing.
- [ ] `test_oauth_google_rejects_unverified_email` implemented and passing.
- [ ] `test_oauth_github_ignores_public_bio_email` implemented and passing.
- [ ] `test_passkey_concurrent_counter_update_optimistic_lock` implemented and passing.
- [ ] `test_refresh_ambiguous_token_injection_rejected` implemented and passing.
- [ ] `test_rate_limit_ip_spoofing_via_x_forwarded_for` implemented and passing.
- [ ] `test_argon2_semaphore_queue_timeout` implemented and passing.

### Tooling & Quality Gates
- [ ] `cargo test` passes without errors.
- [ ] `cargo clippy --all-targets -- -D warnings` completes cleanly with 0 warnings.
- [ ] `cargo fmt --check` succeeds.
- [ ] `python3 scripts/check_boundaries.py` succeeds without domain boundary violations.

