# 01. VISION, MISSION & INDUSTRY STANDARDS

## 1. Project Identity & Vision

This project is an enterprise-grade, open-source, self-hosted **Identity and Access Management (IAM) & User Management API** written in **Rust**.
Our vision is to provide developers with a zero-compromise, drop-in authentication and user management engine that matches the security, session visibility, and reliability of platforms like Discord, Instagram, and GitHub, while distributing as a single static binary (<15 MB) or a minimal `scratch`/`distroless` container.

## 2. Core Mission

1. **Security by Default:** Implement defense-in-depth cryptography and battle-tested authentication flows without requiring developers to be security experts.
2. **Extreme Performance & Low Footprint:** Leverage Rust's zero-cost abstractions and async runtime (`Tokio` + `Axum`) to handle tens of thousands of requests per second with minimal memory overhead and zero Garbage Collection pauses.
3. **Developer Experience (DX) First:** Provide out-of-the-box OpenAPI 3.1 specifications, embedded interactive Scalar documentation (`/docs`), deterministic error structures, and pluggable providers configurable purely via environment variables or `config.toml`.
4. **Stateful Control with Stateless Speed:** Combine short-lived asymmetric JWT Access Tokens (`EdDSA / Ed25519`) with stateful, rotating Opaque Refresh Tokens to grant instant session revocation and device management.

## 3. Mandatory Industry Standards Compliance

Every architectural decision and line of code in this repository MUST strictly adhere to the following international standards:

### A. NIST SP 800-63B (Digital Identity Guidelines)

- Passwords must be at least 8 characters and up to 128 characters long.
- Do NOT enforce arbitrary composition rules (e.g., requiring symbols/uppercase) that reduce entropy; instead, check against breached password corpuses (HaveIBeenPwned k-Anonymity API) and enforce minimum length/entropy.
- Normalize all passwords using **Unicode NFC (Normalization Form Canonical Composition)** before hashing.
- Allow all printing ASCII and Unicode characters (including spaces and emojis) in passwords.

### B. OWASP ASVS v4.0.3 (Level 2/3)

- **Password Hashing:** Exclusively use **Argon2id** (minimum 19 MiB memory, 2 iterations, 1 degree of parallelism, configurable via ENV).
- **Anti-Enumeration:** Authentication, registration, and password reset endpoints must never leak whether an email/account exists via HTTP status codes, response payloads, or response timing disparities.
- **Session Binding:** Bind every refresh session to device metadata (`User-Agent`, `IP Address`, `Created At`, `Last Active At`) and group rotated tokens under a common `token_family_id`.

### C. IETF RFCs

- **RFC 9562 (UUIDv7):** All primary keys, session IDs, token family IDs, and correlation/request IDs MUST use time-ordered UUIDv7.
- **RFC 9457 (Problem Details for HTTP APIs):** Every non-2xx HTTP response MUST return `application/problem+json` with standardized fields (`type`, `title`, `status`, `detail`, `instance`, and optional `errors` array for validation failures).
- **RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens):** Access tokens must include `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, and `sid` (Session ID), signed asymmetrically using `Ed25519` (`EdDSA`).
- **RFC 6238 (TOTP):** Multi-Factor Authentication must follow standard 6-digit, 30-second window SHA-1/SHA-256 TOTP compatible with Google/Microsoft/Authy authenticators, allowing a +/-1 step clock-drift tolerance.
- **Draft IETF HTTPAPI RateLimit Headers:** All rate-limited endpoints must emit `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` headers.

## 4. Target Distribution Models

1. **Single Static Binary:** Compiled with `musl` target (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`), embedding SQL migrations (`sqlx::migrate!`), static email templates, and OpenAPI docs directly into the binary.
2. **Docker / OCI Image:** Multi-stage build resulting in a `gcr.io/distroless/static-debian12:nonroot` image running as an unprivileged UID.
