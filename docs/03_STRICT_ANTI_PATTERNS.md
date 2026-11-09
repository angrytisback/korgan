# 03. STRICT ANTI-PATTERNS & FORBIDDEN PRACTICES (DO NOT DO)

Violating any rule in this document is considered a critical security or architectural failure. AI Agents must treat these as hard constraints.

## 1. Rust Code & Runtime Anti-Patterns

- **NO `.unwrap()` or `.expect()` in Production Code:** Never use `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or `unimplemented!()` inside `domain`, `application`, or `adapters` (except during initial startup config parsing in `main.rs` before the server binds). Always propagate errors with `?` and typed `thiserror` enums.
- **NO Blocking Calls on Async Threads:** Never run `argon2::hash_password`, synchronous file I/O, or heavy cryptographic key generation directly inside an `async fn` without wrapping it in `tokio::task::spawn_blocking`.
- **NO `unsafe` Blocks:** Do not write `unsafe` Rust code anywhere in the codebase. Rely strictly on audited crates for low-level primitives.
- **NO Direct Infrastructure Imports in Business Logic:** `src/domain/*` and `src/application/*` must NEVER import `axum::*`, `http::*`, `sqlx::*`, or `redis::*`.

## 2. Authentication & Security Anti-Patterns

- **NO Stateless-Only Refresh Tokens:** Never use stateless JWTs as Refresh Tokens. Refresh tokens must be opaque, random byte strings backed by stateful storage (`sessions` table) to allow instant revocation and reuse detection.
- **NO Symmetric JWT Signing (`HS256`):** Do not use shared secrets (`HS256`) for Access Tokens. Exclusively use asymmetric **`EdDSA` (`Ed25519`)** so downstream microservices can verify tokens using only the Public Key / JWKS endpoint (`/.well-known/jwks.json`).
- **NO Plaintext Secrets or Tokens in Storage:** Never store plaintext passwords, plaintext TOTP secrets, plaintext backup codes, or plaintext reset/refresh tokens in PostgreSQL or Redis.
- **NO User Enumeration:**
  - `POST /api/v1/password/forgot` MUST return `200 OK` with the exact same generic message regardless of whether the email exists.
  - `POST /api/v1/auth/login` MUST return a generic `401 Unauthorized` ("Invalid credentials") for both non-existent emails and wrong passwords.
- **NO Unbounded Queries or Unpaginated Lists:** Never execute `SELECT *` without explicit column names and a `LIMIT` clause. Session and audit log endpoints must enforce cursor or offset pagination with a hard maximum limit.
- **NO Synchronous External I/O in Auth Critical Paths:** Never send SMTP/HTTP emails synchronously inside the HTTP request-response cycle of `/register` or `/password/forgot`. Always enqueue a job into the internal async worker queue so response times remain fast and deterministic.

## 3. Database & Data Modeling Anti-Patterns

- **NO `UUIDv4` or `SERIAL / BIGSERIAL` Primary Keys:** Never use sequential integers (which leak user counts and enable ID enumeration attacks) or random `UUIDv4` (which causes B-Tree index fragmentation in PostgreSQL). Exclusively use **`UUIDv7`**.
- **NO `TIMESTAMP WITHOUT TIME ZONE`:** Every timestamp column in PostgreSQL must be `TIMESTAMPTZ` (`TIMESTAMP WITH TIME ZONE`) mapped to `chrono::DateTime<chrono::Utc>` or `time::OffsetDateTime` in Rust.
- **NO Hard Deletes on Active Foreign Keys without Cascade/Audit Policy:** Account deletion must first transition through a configurable grace period (`pending_deletion`) or scrub PII while preserving anonymized security audit logs where legally required.

## 4. API Design Anti-Patterns

- **NO Custom/Ad-Hoc Error JSON Formats:** Never return `{ "error": "something went wrong" }` or `{ "success": false, "msg": "..." }`. Every error must strictly conform to **RFC 9457 (`application/problem+json`)**.
- **NO Leaking Internal Database/Library Errors:** Never expose raw `sqlx::Error`, stack traces, SQL table names, or Redis connection errors in HTTP responses. Log the detailed internal error via `tracing::error!` with the `request_id`, and return a sanitized RFC 9457 `500 Internal Server Error` to the client.
