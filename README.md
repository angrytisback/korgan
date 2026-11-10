<div align="center">

![Korgan Logo](docs/assets/logo.png)

# Korgan

**Stateful Control with Stateless Speed. The ultra-lightweight IAM written in Rust.**

[![CI](https://img.shields.io/github/actions/workflow/status/angrytisback/korgan/ci.yml?branch=main&label=CI%2FCD&logo=github)](https://github.com/angrytisback/korgan/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/angrytisback/korgan?logo=docker&logoColor=white)](https://github.com/angrytisback/korgan/pkgs/container/korgan)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust)](https://www.rust-lang.org)

</div>

---

Korgan is a high-performance, self-hosted Identity and Access Management (IAM) engine. It ships as a single static binary (< 15 MB) in a `distroless` OCI image, with zero garbage collection and predictable sub-millisecond latency.

## Why Korgan?

| | **Korgan** | **Keycloak** | **Authentik** |
|---|---|---|---|
| **Memory Footprint** | **< 20 MB** | 1 GB+ | 500 MB+ |
| **Language** | **Rust** | Java | Python (Django) |
| **Cold Start** | **Instant** | Slow (JVM warm-up, 10s+) | Moderate |
| **Latency Profile** | **Predictable, sub-millisecond (no GC)** | GC pauses | Interpreter overhead |
| **Deployment Artifact** | **Single static binary (< 15 MB), distroless** | Large JVM image | Multi-container (server + worker) |
| **Default Security Posture** | **Hardened by default (EdDSA, replay detection, Argon2id guard, memory hardening)** | Configurable, requires tuning | Configurable, requires tuning |
| **Dependencies** | PostgreSQL, Redis | PostgreSQL | PostgreSQL, Redis |

> Figures are indicative of typical idle deployments and may vary with configuration and workload.

## Core Features

- **Ed25519 (EdDSA) JWTs:** Asymmetric, compact, and fast-to-verify access tokens.
- **Token Rotation & Replay Detection:** Opaque refresh tokens with Token Family tracking. Reuse of a rotated token revokes the entire family.
- **Passkeys (WebAuthn):** Phishing-resistant, passwordless authentication.
- **Anti-Enumeration:** Uniform responses and constant-time dummy hashing prevent account discovery.
- **Immutable Audit Logs:** Append-only, hash-chained records of security-relevant events.
- **Argon2id with Semaphore Protection:** Password hashing is concurrency-bounded to prevent CPU exhaustion attacks.
- **Encrypted TOTP Secrets:** Stored with AES-256-GCM.
- **OS-Level Memory Hardening:** Core dump prevention to keep secrets out of crash artifacts.
- **Strict Verification Gating:** Unverified and non-active accounts are strictly denied authentication tokens and gated from all protected resources.
- **Browser-Bound OAuth Anti-CSRF:** OAuth state is cryptographically bound to an isolated, ephemeral `__Host-` cookie (`SameSite=Lax`, `Path=/`, `HttpOnly`, `Secure`), mitigating Login CSRF attacks per RFC 6749 §10.12 and RFC 6265bis.
- **Strict Step-Up Credential Protection:** Passkey registration ceremonies (`/register/start` and `/register/finish`) strictly mandate fresh Step-Up authentication, with challenges securely scoped per user.

## Quick Start

Korgan requires an Ed25519 signing key and an AES-256 master key. Generate them:

```bash
# PEM is stored on one line with literal \n separators
export KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM="$(openssl genpkey -algorithm ed25519 | awk 'NF {printf "%s\\n", $0}')"
export KORGAN__CRYPTO__AES_MASTER_KEY="$(openssl rand -base64 32)"
```

Create a `docker-compose.yml`:

```yaml
services:
  korgan:
    image: ghcr.io/angrytisback/korgan:latest
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://korgan:change-me@postgres:5432/korgan
      REDIS_URL: redis://redis:6379
      KORGAN__SERVER__HOST: 0.0.0.0
      KORGAN__SERVER__PORT: 8080
      KORGAN__SERVER__ENVIRONMENT: development
      KORGAN__SERVER__PUBLIC_BASE_URL: http://localhost:8080
      KORGAN__AUTH__ISSUER: http://localhost:8080
      KORGAN__AUTH__AUDIENCE: korgan
      KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM: ${KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM}
      KORGAN__CRYPTO__AES_MASTER_KEY: ${KORGAN__CRYPTO__AES_MASTER_KEY}
      MAIL_PROVIDER: console
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started

  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: korgan
      POSTGRES_PASSWORD: change-me
      POSTGRES_DB: korgan
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U korgan -d korgan"]
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:8-alpine

volumes:
  pgdata:
```

```bash
docker compose up -d
```

Korgan is now listening on `http://localhost:8080`.

> **Note:** This configuration is for local evaluation. Before production use, replace `change-me`, set `KORGAN__SERVER__ENVIRONMENT=production`, and configure a real mail provider (`console` is rejected in production). See [`.env.example`](.env.example) for the full list of settings.

---

## Architecture & Deep Dive

# Korgan (korgan)

Open-Source IAM and Session Engine in Rust (2024 Edition).

Target Repository: https://github.com/angrytisback/korgan
License: GNU Affero General Public License v3.0 (AGPL-3.0)

--------------------------------------------------------------------------------

Table of Contents
- 1. Executive Overview
- 2. Competitive Differentiators and Architectural Moat
- 3. Specification and RFC Compliance Matrix
- 4. Architecture and Layer Invariants (Hexagonal / Ports & Adapters)
- 5. Threat Model and Distributed Concurrency Invariants
- 6. Complete Endpoint Specification
- 7. CLI Administration Guide
- 8. Test Suite and Verification Gates
- 9. Quickstart and Deployment
- 10. Security Policy and License

--------------------------------------------------------------------------------

## 1. Executive Overview

Korgan is an open-source IAM and session engine written in Rust, focusing on zero SMS costs, strict client isolation, and cryptographic auditability. It unifies passwordless authentication (FIDO2 WebAuthn Passkeys), multi-factor authentication (RFC 6238 TOTP), federated identity (OAuth2 Google/GitHub), high-frequency real-time edge gateways (ephemeral WebSocket/WebRTC tickets), and auditable administration into a single-binary daemon.

### Zero-Marginal-Cost Identity Architecture
Traditional enterprise identity stacks depend heavily on SMS aggregators, paid telephony APIs, or recurring per-MAU vendor licensing. These channels introduce recurring variable operational expenses, carrier latency, and severe vulnerability to SIM swapping and SS7 interception. Korgan eliminates recurring credential delivery costs:
- Primary and secondary factors rely exclusively on local, hardware-backed authenticators (FIDO2 WebAuthn / Passkeys via Apple FaceID, TouchID, Windows Hello, Android Biometrics, physical YubiKeys) and open-standard RFC 6238 TOTP algorithms.
- Peripheral API gateways and distributed edge proxies perform sub-millisecond local token validation using background-cached asymmetric Ed25519 JWKS keys (RFC 8037), eliminating expensive database read amplification during real-time connection establishment.

### Core Architectural Guarantees
1. Strict Hexagonal Isolation: Complete architectural decoupling. Domain and application logic are forbidden from importing HTTP frameworks, database drivers, or cache clients.
2. Zero-Panic Production Codebase: Enforces #![forbid(unsafe_code)] and strict compiler denial flags (clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented). Every fallible branch propagates typed domain errors mapped to RFC 9457 Problem Details.
3. Cryptographic and Process Memory Hardening: Sensitive credential containers implement zeroize::Zeroize and zeroize::ZeroizeOnDrop. Memory buffers holding candidate secrets or decrypted master keys are wiped upon leaving scope. Process memory is hardened at startup via Linux kernel-level limits (RLIMIT_CORE = 0 and prctl PR_SET_DUMPABLE = 0) to prevent memory dumps and unauthorized debugger attachment.

--------------------------------------------------------------------------------

## 2. Competitive Differentiators and Architectural Moat

Existing identity solutions (Keycloak, Ory Kratos, Zitadel, Auth0, Supabase Auth) frequently suffer from distributed race conditions, runtime memory overhead, leaky abstractions between transport and persistence, or external vendor lock-in. Korgan establishes an architectural moat across six foundational dimensions:

| Architectural Capability | Korgan | Keycloak / Ory Kratos / Zitadel / Auth0 / Supabase | Technical Vulnerability in Alternative Approaches |
| :--- | :--- | :--- | :--- |
| 1. Atomic CTE State Machine vs Distributed TOCTOU | Single-roundtrip atomic CTE CAS for token rotation. A single atomic PostgreSQL statement flips is_replaced from false to true and conditionally inserts the successor session row. | Multi-step read-modify-write patterns, ORM transaction locks, or distributed network locks across separate services. | Network jitter or concurrent rotation requests cause Time-of-Check to Time-of-Use (TOCTOU) races, resulting in stale reads, double-rotation bypasses, or false-positive family revocation storms. |
| 2. Hardware-Enforced Cryptographic Hash-Chained Audit Trails | PostgreSQL trigger-level tamper protection preventing log alteration even by database superusers, combined with SHA-256 chain verification. Writes are serialized via pg_advisory_xact_lock. | Application-level logging tables or external forwarders without cryptographic linking or database-level immutability triggers. | An attacker gaining database superuser access or SQL injection can alter, truncate, or rewrite historical access logs without detection. |
| 3. True Dual-Mode Client Isolation | Hard boundary separating __Host- strict cookie semantics from mobile/CLI bearer tokens with ambiguous delivery rejection (RFC 9457 HTTP 422). | Mixed cookie and header parsing, generic token extractors, or fallback heuristical handling. | Ambiguous token injection vectors allow CSRF exploitation, token confusion attacks, or leaking browser tokens into mobile header contexts. |
| 4. Sub-Millisecond In-Memory Ed25519 Local Verification | Eliminating introspect network roundtrips with background-cached JWKS and strict fail-closed Redis session blacklist gating. | Centralized OAuth2 /introspect RPC endpoints or shared central database lookups on every request. | High-frequency API calls degrade rapidly due to database connection saturation and introspect latency under high concurrency. |
| 5. Zero-Allocation Ephemeral WebSocket/WebRTC Handshake Tickets | Preventing token leakage in URL query parameters with single-use Redis GETDEL semantics (15-second TTL). | Passing raw JWT access tokens in WebSocket connection URL query strings (?token=...). | URL tokens are persistently recorded in reverse proxy access logs (Nginx/Cloudflare), browser histories, and edge proxy telemetry. |
| 6. NIST SP 800-63B Constant-Time Dummy Hashes | Mitigating account enumeration and timing side-channels even on locked or non-existent accounts using simulated Argon2id workloads. | Immediate return on unknown user lookup (e.g. User Not Found in 2ms vs 180ms Argon2 verification). | Attackers systematically harvest valid corporate email addresses through statistical timing analysis of login endpoint latencies. |

--------------------------------------------------------------------------------

## 3. Specification and RFC Compliance Matrix

Korgan is engineered to comply with modern IETF standards and federal security guidelines:

| Standard / RFC | Category | System Component | Implementation Details |
| :--- | :--- | :--- | :--- |
| RFC 9562 | Identifiers | domain::value_objects::ids | UUIDv7 Everywhere: 128-bit time-ordered, monotonic primary keys featuring millisecond-level UNIX epoch timestamps and cryptographically secure entropy. Prevents PostgreSQL B-Tree index fragmentation and guarantees optimal sequential insert locality. |
| RFC 8037 / RFC 7517 | Cryptography and Discovery | adapters::outbound::crypto::jwt, handlers::jwks | Ed25519 (EdDSA) and JWKS: Asymmetric JWT access token signing with public verification keys exposed at GET /.well-known/jwks.json. Implements RFC 7638 SHA-256 key thumbprint matching for zero-downtime key rotation. |
| RFC 8176 | Token Authentication | ports::services::AccessTokenClaims | Authentication Method References (AMR): Access tokens explicitly declare the exact authentication vectors utilized during session creation (e.g. ["pwd"], ["pwd", "mfa"], ["passkey"]). Downstream services enforce granular authorization based on authentication strength. |
| RFC 7519 / OIDC Core | Token Claims | ports::services::AccessTokenClaims | Immutable auth_time Enforcement: The initial authentication timestamp is preserved across subsequent refresh token rotations within the token family, enabling downstream microservices to demand step-up re-authentication for privileged operations. |
| RFC 6238 | Multi-Factor Auth | adapters::outbound::crypto::totp, use_cases::mfa | Time-Based One-Time Passwords (TOTP): HMAC-SHA1 algorithm, 30-second time step, +/-1 step clock-drift tolerance with atomic Redis replay locks (SET ... EX 120 NX). TOTP secrets are encrypted at rest with AES-256-GCM using UserId as Associated Authenticated Data (AAD). |
| RFC 6265bis | Cookie Security | adapters::inbound::http::handlers::auth | Strict Host-Prefixed Cookies: Web clients receive refresh tokens bound to __Host-refresh_token (Secure, HttpOnly, SameSite=Strict, Path=/, omitted Domain attribute) to thwart subdomain hijacking and CSRF vectors. |
| RFC 9457 | Error Semantics | adapters::inbound::http::error | Problem Details for HTTP APIs: Uniform machine-readable error responses with Content-Type: application/problem+json providing URI error classification, contextual error codes, instance UUIDs, and field-specific validation failures. |
| FIDO2 WebAuthn L3 | Passwordless Auth | adapters::outbound::crypto::passkey, use_cases::passkeys | FIDO2 / WebAuthn Level 3: Resident and discoverable credentials supporting usernameless biometric login and physical YubiKey signature counter (sign_count) clone detection with CTAP2 rollback checks. |
| NIST SP 800-63B | Credential Management | domain::value_objects::password, adapters::outbound::hibp | Digital Identity Guidelines: Enforces 8 to 128 character passphrases, Unicode NFC normalization, zero arbitrary composition rules, HIBP k-Anonymity checks, and password history depth checks. |

--------------------------------------------------------------------------------

## 4. Architecture and Layer Invariants (Hexagonal / Ports & Adapters)

Korgan strictly isolates business logic from transport and storage layers:

| Layer | Responsibility | Components & Technologies |
| :--- | :--- | :--- |
| **Inbound Adapters (Transport)** | HTTP parsing, routing, CLI commands, telemetry, rate limiting | Axum 0.8, Tower middleware, Scalar OpenAPI (`/docs`), CLI commands |
| **Application Services (Use Cases)** | Orchestration, MFA workflows, token lifecycles, background jobs | Authentication orchestrator, AMR evaluation, non-blocking audit dispatcher |
| **Domain Core (Entities & Invariants)** | Pure business logic, identity rules, zero-panic types | `User`, `Session`, `Passkey`, Unicode NFC normalization, constant-time checks |
| **Outbound Ports (Contracts)** | Abstract interfaces implemented by adapters | `UserRepository`, `SessionRepository`, `TokenSigner`, `MailProvider` |
| **Outbound Adapters (Infrastructure)** | Persistence, caching, cryptographic implementations | PostgreSQL 17 (SQLx, UUIDv7), Valkey/Redis 8, Argon2id, Ed25519-dalek |

##### Architectural Rules:
- **Zero Inward Leakage:** Domain layer has no dependencies on Axum, SQLx, Redis, or external crates.
- **Fail-Closed Strategy:** Session invalidation defaults to blocking access if cache/database state becomes unreachable.
- **Panic Isolation:** Production paths strictly forbid `unwrap()` and `expect()`, bubbling typed errors via RFC 9457 problem details.

--------------------------------------------------------------------------------

## 5. Threat Model and Distributed Concurrency Invariants

| Attack Vector & Threat Scenario | Severity | Vulnerability Mechanism | Enforced Mitigation & Architectural Guarantee |
| :--- | :--- | :--- | :--- |
| Refresh Token TOCTOU | Critical | Parallel rotation requests using the same refresh token yield multiple active token pairs. | PostgreSQL Single-Query Atomic CTE (rotate_atomic): Flipping is_replaced = true and inserting the new session happens in one atomic SQL command. Concurrent requests find 0 updated rows and fail immediately. |
| Token Family Replay | High | Intercepted or previously consumed refresh token is replayed. | Cascading Family Revocation: Presenting a token where is_replaced == true triggers atomic revocation of all sessions sharing that token_family_id, distributes a Redis blacklist entry, and writes an audit event. |
| Orphan Session (Ban Race) | High | Admin ban executes concurrently with token rotation, committing an active session for a banned account. | Conditional Session Insertion: Token rotation and session creation queries enforce INSERT ... SELECT ... FROM users WHERE status = 'active'. If banned mid-flight, zero rows are inserted. |
| Failed Login Lost Update | High | Parallel automated password attempts trigger concurrent updates to failed_login_attempts, bypassing lockout thresholds. | Atomic Database Increment (record_failed_login_atomic): Counter updates execute via atomic SQL row increments with row-level locks, guaranteeing exact serialization of failed attempt counts. |
| Unban Race / Stale Overwrite | Medium | User logs in while admin bans account; full entity write-back overwrites the ban. | Segregated Counter Reset: Successful login triggers a targeted counter reset (reset_failed_logins) updating only counter columns, leaving administrative status intact. |
| TOTP Concurrent Replay | Medium | Same 6-digit TOTP code submitted across parallel connections within its 30-second validity window. | Atomic Redis Lock (set_if_not_exists): After cryptographic verification, an atomic SET totp_used:{user_id}:{code} 1 EX 120 NX is acquired. Concurrent submissions are rejected immediately. |
| Hardware Key Cloning | Critical | Cloned security key or software authenticator attempts login. | CTAP2 Signature Counter Regression Check: Asserts presented sign_count is strictly greater than stored counter. Counter rollback immediately aborts ceremony with HTTP 401. |
| Timing Side-Channel | Low | Latency variations between existing and non-existent users allow account enumeration. | Constant-Time Dummy Hashes: Evaluates a full-cost Argon2id dummy hash for non-existent users, ensuring indistinguishable response latencies. |
| Future Cancellation Dropping | Medium | Abrupt client disconnection terminates async futures before Redis blacklist or audit log writes complete. | Shielded Task Execution: Critical state operations run inside shielded background tasks that complete even if the client disconnects, while propagating failures to preserve fail-closed semantics. |
| Process Core Dump Extraction | Critical | Operating system core dumps capture master encryption keys and plaintext credentials from RAM. | Kernel-Level Hardening: Startup routines invoke security::harden_process_memory() to set RLIMIT_CORE = 0 and disable ptrace attach via prctl PR_SET_DUMPABLE = 0. |

--------------------------------------------------------------------------------

## 6. Complete Endpoint Specification

All endpoints are mounted under /api/v1 (except root health, discovery, and documentation endpoints):

| Method & Route | Auth Level Required | Accepted Transport | Success Status | Operational Description & Security Contract |
| :--- | :--- | :--- | :--- | :--- |
| GET /health | Anonymous | HTTP Any | 200 OK | Liveness probe: confirms HTTP listener is active. Does not probe databases. |
| GET /health/live | Anonymous | HTTP Any | 200 OK | Alias for liveness probe. |
| GET /health/ready | Anonymous | HTTP Any | 200 OK | Readiness probe: checks PostgreSQL and Redis connections. Returns 503 on partition. |
| GET /metrics | Anonymous | HTTP Any | 200 OK | Prometheus metrics exposition endpoint for latency, requests, and active sessions. |
| GET /.well-known/jwks.json | Anonymous | HTTP Any | 200 OK | Public JWKS Discovery: serves RFC 7517 / RFC 8037 Ed25519 verifying keys. |
| GET /openapi.json | Anonymous | HTTP Any | 200 OK | Raw machine-readable OpenAPI 3.1 schema. |
| GET /api-docs/openapi.json | Anonymous | HTTP Any | 200 OK | Alias for OpenAPI specification. |
| GET /docs | Anonymous | HTTP Any | 200 OK | Embedded interactive Scalar documentation UI. |
| POST /api/v1/auth/register | Anonymous | JSON Body | 201 Created | Registers user account and dispatches email verification token. |
| POST /api/v1/auth/login | Anonymous | JSON Body (Dual-Mode) | 200 OK | Credential verification. Returns tokens or ephemeral mfa_ticket. |
| POST /api/v1/auth/mfa/verify | MFA Ticket Required | JSON Body (Dual-Mode) | 200 OK | Exchanges mfa_ticket and TOTP/backup code for access and refresh tokens. |
| POST /api/v1/auth/refresh | Anonymous | Dual-Mode (Cookie/Body) | 200 OK | Consumes refresh token, verifies family integrity, and rotates token pair. |
| POST /api/v1/auth/verify-email | Anonymous | JSON Body | 200 OK | Consumes verification token and transitions user status to active. |
| POST /api/v1/auth/logout | AuthUser | Dual-Mode (Cookie/Body) | 204 No Content | Revokes active session, writes Redis blacklist entry, and clears client cookies. |
| POST /api/v1/auth/ws-ticket | AuthUser | Dual-Mode (Cookie/Body) | 200 OK | Issues single-use 15-second ephemeral ticket for secure WebSocket/WebRTC handshake. |
| POST /api/v1/auth/ws-ticket/verify | Anonymous | JSON Body | 200 OK | Gateway verification endpoint: atomically verifies and consumes ticket via GETDEL. |
| GET /api/v1/auth/oauth/{provider}/url | Anonymous | HTTP GET | 200 OK | Generates signed anti-CSRF state and authorization URL for Google or GitHub. |
| GET /api/v1/auth/oauth/{provider}/callback | Anonymous | HTTP Query (Dual-Mode) | 200 OK | Validates state, exchanges provider code, links account, and issues tokens. |
| POST /api/v1/auth/passkeys/register/start | StepUpUser | Dual-Mode (Cookie/Body) | 200 OK | Initiates WebAuthn registration ceremony. Requires step-up authentication. |
| POST /api/v1/auth/passkeys/register/finish | AuthUser | Dual-Mode + JSON Body | 201 Created | Verifies authenticator attestation, stores credential ID, and records sign_count. |
| POST /api/v1/auth/passkeys/login/start | Anonymous | HTTP POST | 200 OK | Initiates discoverable (usernameless) WebAuthn authentication ceremony. |
| POST /api/v1/auth/passkeys/login/finish | Anonymous | JSON Body (Dual-Mode) | 200 OK | Verifies assertion signature, validates sign_count progression, and issues tokens. |
| POST /api/v1/password/forgot | Anonymous | JSON Body | 200 OK | Dispatches password reset token via email with constant-time response latency. |
| POST /api/v1/password/reset | Anonymous | JSON Body | 200 OK | Consumes reset token, enforces password history rules, and revokes all sessions. |
| POST /api/v1/password/change | StepUpUser | Dual-Mode + JSON Body | 200 OK | Changes password, enforces history depth, and updates auth_time. Requires step-up. |
| POST /api/v1/mfa/setup | AuthUser | Dual-Mode (Cookie/Body) | 200 OK | Generates 160-bit TOTP secret, encrypts with AES-256-GCM, and returns SVG QR code. |
| POST /api/v1/mfa/enable | AuthUser | Dual-Mode + JSON Body | 200 OK | Verifies first TOTP code and returns 10 single-use emergency backup codes. |
| POST /api/v1/mfa/disable | StepUpUser | Dual-Mode + JSON Body | 200 OK | Disables MFA and purges backup codes after validating password. Requires step-up. |
| GET /api/v1/sessions | AuthUser | Dual-Mode (Cookie/Body) | 200 OK | Lists active sessions belonging to the caller with client metadata. |
| DELETE /api/v1/sessions | StepUpUser | Dual-Mode (Cookie/Body) | 204 No Content | Revokes all sessions belonging to caller and blacklists them in Redis. Requires step-up. |
| DELETE /api/v1/sessions/{id} | AuthUser | Dual-Mode (Cookie/Body) | 204 No Content | Revokes specific session identifier owned by caller. |
| GET /api/v1/users/me | AuthUser | Dual-Mode (Cookie/Body) | 200 OK | Returns authenticated caller's profile. |
| PATCH /api/v1/users/me | AuthUser | Dual-Mode + JSON Body | 200 OK | Updates user profile attributes (e.g. username) subject to validation. |
| GET /api/v1/users/me/passkeys | AuthUser | Dual-Mode (Cookie/Body) | 200 OK | Lists registered WebAuthn credentials for caller with metadata. |
| DELETE /api/v1/users/me/passkeys/{id} | AuthUser | Dual-Mode (Cookie/Body) | 204 No Content | Deletes specific registered passkey credential by UUID. |
| GET /api/v1/admin/users | AdminUser | Dual-Mode (Cookie/Body) | 200 OK | Paginated user management table with query filtering by status, email, username. |
| POST /api/v1/admin/users/{id}/ban | AdminUser | Dual-Mode + JSON Body | 200 OK | Suspends user, revokes all sessions, and publishes Redis revocation event. |
| POST /api/v1/admin/users/{id}/unban | AdminUser | Dual-Mode (Cookie/Body) | 200 OK | Restores suspended user account to active status. |

--------------------------------------------------------------------------------

## 7. CLI Administration Guide

The Korgan binary includes built-in administrative commands for disaster recovery, bootstrapping, and tamper audit verification:

### 1. Superadmin Bootstrap
Initializes the first superadmin account in a fresh deployment. This command fails closed if an administrator account already exists.
```bash
cargo run --release -- bootstrap --email superadmin@korgan.local --password "SuperAdminSecret123!"
```

### 2. Cryptographic Audit Chain Verification
Traverses the full audit log table in PostgreSQL, recomputes SHA-256 hashes across previous hashes and entry payloads, and asserts that no entries have been modified, deleted, or inserted out of order.
```bash
cargo run --release -- audit verify
```
Example Output:
```
Verifying audit log chain integrity...
Verified 1,420 entries. Chain integrity 100% valid.
```

### 3. Administrative User Unlock
Unlocks an account locked due to repeated failed login attempts, clearing failed attempt counters and removing lock expiration timestamps.
```bash
cargo run --release -- user unlock --email engineer@example.com
```

### 4. Default Server Execution
Runs the Axum HTTP server with graceful shutdown and worker listeners:
```bash
cargo run --release -- serve
# or simply:
cargo run --release
```

--------------------------------------------------------------------------------

## 8. Test Suite and Verification Gates

All CI/CD checks pass locally with zero warnings and zero errors under strict denial flags:

| Verification Stage | Command Line Invocation | Verification Target | Result |
| :--- | :--- | :--- | :--- |
| Boundary and Zero-Panic Linter | python3 scripts/check_boundaries.py | Asserts 0 forbidden imports across layers and 0 unwrap/expect in production code | Clean (0 violations) |
| Code Formatting | cargo fmt --all -- --check | Asserts compliance with standard Rust formatting | Clean (0 diff) |
| Static Analysis & Lints | SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings | Denies all warnings, clippy panics, and unwrap/expect calls | Clean (0 warnings, 0 errors) |
| Dependency Vulnerability Audit | cargo audit --deny warnings | Scans Cargo.lock against the RustSec Advisory Database | Clean (0 vulnerabilities across 455 crates) |
| Comprehensive Test Suite | SQLX_OFFLINE=true cargo test | Executes all unit, integration, concurrency, and E2E test suites | 211 / 211 Passed (100% success rate) |

--------------------------------------------------------------------------------

## 9. Quickstart and Deployment

### 1. Environment Setup
```bash
# Clone repository
git clone https://github.com/angrytisback/korgan.git
cd korgan

# Generate Ed25519 PKCS#8 PEM and AES-256-GCM Master Key
ED_KEY=$(openssl genpkey -algorithm ed25519 | awk '{printf "%s\\n", $0}')
AES_KEY=$(openssl rand -base64 32)

cp .env.example .env
sed -i "s|KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM=.*|KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM=$ED_KEY|" .env
sed -i "s|KORGAN__CRYPTO__AES_MASTER_KEY=.*|KORGAN__CRYPTO__AES_MASTER_KEY=$AES_KEY|" .env
```

### 2. Infrastructure Boot
```bash
# Start PostgreSQL 17, Valkey/Redis 8, and Mailpit
docker compose up -d

# Run database migrations
cargo sqlx migrate run

# Bootstrap initial superadmin
cargo run -- bootstrap --email superadmin@korgan.local --password "SuperAdminSecret123!"

# Run production server
cargo run --release
```

Interactive documentation is available immediately at http://localhost:8080/docs.

--------------------------------------------------------------------------------

## 10. Security Policy and License

### Vulnerability Disclosure
For security disclosures, please consult SECURITY.md. Direct all sensitive vulnerability reports to eigen@teapot-dev.com.

### License
Korgan is licensed under the GNU Affero General Public License v3.0 (GNU AGPLv3). See the LICENSE file for full legal terms.
