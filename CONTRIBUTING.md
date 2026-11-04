# Contributing to korgan

Thank you for your interest in contributing to `korgan`! We are building an enterprise-grade, zero-trust, open-source Identity and Access Management (IAM) engine in Rust.

To maintain our strict security guarantees, extreme performance, and architectural purity, all contributions must adhere to the engineering standards detailed below.

---

## 1. Architectural Philosophy: Strict Hexagonal Architecture

`korgan` follows the Ports and Adapters (Hexagonal Architecture) pattern with four concentric layers. Dependencies point strictly inward: `adapters` → `application` → `ports` / `domain`.

> **Strict rule:** the `domain` and `application` layers must not contain any external I/O and must not import `axum`, `sqlx` (or `redis`, `http`). All I/O goes through traits in `ports`, implemented in `adapters`. `scripts/check_boundaries.py` enforces this and fails CI on violations.

1. **`src/domain/` (Pure Rust, Zero I/O)**:
   - Contains core domain entities (`User`, `Passkey`, `OAuthAccount`, `Session`, `AuditLog`), Value Objects (`UserId`, `PasskeyId`, `EmailAddress`, `RawPassword`, `PasswordHash`, `Username`), and Domain Errors.
   - **MUST NEVER** import or depend on transport, database, or cache libraries (`axum`, `http`, `sqlx`, `redis`).
   - Uses the Newtype Pattern with smart constructors (e.g. `EmailAddress::parse`) to make invalid domain states unrepresentable in memory.

2. **`src/ports/` (Abstract Traits & Interfaces)**:
   - Defines abstract repository traits (`UserRepository`, `PasskeyRepository`, `SessionRepository`, `AuditLogRepository`, `OAuthAccountRepository`), cache/rate limiting interfaces (`TokenStore`, `RateLimiterPort`), and external services (`PasswordHasher`, `TokenSigner`, `WebAuthnService`, `OAuthProviderPort`, `MailProvider`, `HibpClient`).
   - All outbound traits must be `Send + Sync + 'static` to support `Arc<dyn Trait>` dependency injection.

3. **`src/application/` (Use Cases & Orchestration)**:
   - Implements business workflows and command/query orchestrations.
   - Dispatches non-blocking background tasks via `EventBus` (e.g., audit logging, welcome/verification emails).
   - **MUST NEVER** import transport, database, or cache crates (`axum`, `http`, `sqlx`, `redis`).

4. **`src/adapters/` (Infrastructure & Delivery)**:
   - **Inbound (`src/adapters/inbound/`)**: Axum HTTP handlers, routing, extractors (`AuthUser`, `ClientMetadata`), middlewares (`RequestIdMiddleware`, `RateLimitMiddleware`, `SecurityHeadersMiddleware`), OpenAPI 3.1 & Scalar specs.
   - **Outbound (`src/adapters/outbound/`)**: Concrete implementations for PostgreSQL (`sqlx`), Redis (`deadpool-redis`), cryptographic services (Argon2id, Ed25519, AES-256-GCM, WebAuthn FIDO2), OAuth2 providers (Google, GitHub), and email delivery.

---

## 2. Hard Engineering Rules & Anti-Patterns

- **Zero `.unwrap()` or `.expect()` in Production Code**:
  - The compiler enforces `#![deny(clippy::unwrap_used)]` and `#![deny(clippy::expect_used)]`.
  - Never call `.unwrap()` or `.expect()` in `src/`. Always propagate typed errors using `?` or map them cleanly to `DomainError`, `AppError`, or `PortError`.
- **Zero `unsafe` Blocks**:
  - The codebase enforces `#![forbid(unsafe_code)]`.
- **Memory Zeroization & Secret Hygiene**:
  - Plaintext passwords, raw TOTP secrets, and private keys must derive `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
  - Sensitive strings must be wrapped in `secrecy::SecretString` to guarantee redaction in logs and debug traces.
- **Constant-Time Comparison**:
  - Cryptographic token, password hash, and TOTP comparisons in memory must use `subtle::ConstantTimeEq` to prevent timing attacks.
- **UUIDv7 Everywhere**:
  - All database primary keys, session IDs, and request correlation IDs must use time-ordered `UUIDv7` (RFC 9562).
- **RFC 9457 Error Standard**:
  - Every non-2xx HTTP response must return `application/problem+json` matching the RFC 9457 specification.

---

## 3. Database Migrations & SQLx Offline Compilation

We enforce compile-time SQL verification via SQLx macros (`sqlx::query!`, `sqlx::query_as!`). All CI jobs and Docker builds run with `SQLX_OFFLINE=true` without requiring a live database.

When modifying or adding database queries:
1. Create a new numbered migration file in `migrations/` (e.g., `migrations/0008_feature.sql`).
2. Run migrations against a local PostgreSQL 17 test instance:
   ```bash
   sqlx migrate run --database-url "postgres://postgres:postgres@localhost:5432/iam_dev"
   ```
3. Update the offline query metadata cache:
   ```bash
   cargo sqlx prepare --database-url "postgres://postgres:postgres@localhost:5432/iam_dev"
   ```
4. Commit the generated JSON files in `.sqlx/` alongside your code changes.

---

## 4. Local Development & Verification Workflow

Before submitting a Pull Request, run the full verification gate locally:

```bash
# 1. Check code formatting
cargo fmt --check

# 2. Run static analysis with strict warnings denied
SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings

# 3. Run all unit, integration, and E2E tests
SQLX_OFFLINE=true cargo test

# 4. Verify dependency security advisories
cargo audit

# 5. Verify Hexagonal Architecture boundaries and the zero-panic rule
python3 scripts/check_boundaries.py
```

---

## 5. Pull Request & Branch Policy

- **Target Branch**: All PRs should branch from and target `main`.
- **Commit Messages**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: add passkey conditional UI support`
  - `fix: resolve token family rotation race condition`
  - `docs: update OAuth2 callback configuration reference`
  - `test: add cross-tenant deletion integration test`
- **CI Gates**: All automated GitHub Actions checks (`lint`, `test`, `audit`) must pass before a PR can be merged.
