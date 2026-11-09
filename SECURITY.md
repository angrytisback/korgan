# Security Policy

## Supported Versions

Only the versions below receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

---

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Send a private report to **security@yigitturan.com**. GitHub's Private Vulnerability Reporting feature may also be used.

Encrypt sensitive reports with our PGP key:

- **Key ID / Fingerprint:** `[PGP-FINGERPRINT-PLACEHOLDER]`
- **Public key:** `[LINK-TO-PUBLIC-KEY-PLACEHOLDER]`

### What to Include in Your Report

1. A detailed description of the vulnerability, attack vector, and potential impact.
2. Step-by-step reproduction steps or a minimal proof of concept (PoC).
3. Relevant logs, network traces, or environment details.
4. Affected version(s) or commit hash, and a proposed patch or mitigation if available.

---

## Disclosure Policy

- **Acknowledgement:** within **48 hours** of receipt.
- **Assessment:** we will confirm validity and severity and keep you updated on progress.
- **Fix:** we will develop and release a patch, prioritized by severity, and coordinate a security advisory (and CVE where applicable).
- **Coordinated disclosure:** details are made public after a fix is released, or **90 days** after the initial report, whichever comes first. We may agree to an extension if a fix needs more time.
- **Credit:** reporters are credited in the advisory unless they prefer to remain anonymous.

We ask that you act in good faith: avoid privacy violations, data destruction, and service disruption, and give us reasonable time to respond before any public disclosure.

---

## Core Security & Architecture Guarantees

`korgan` is engineered as a zero-trust, banking-grade universal identity engine adhering to strict Hexagonal Architecture and Zero-Panic standards:

### 1. Cryptographic Rigor
- **Password Hashing:** Argon2id (`m=19456`, `t=2`, `p=1`) compliant with OWASP & NIST SP 800-63B recommendations.
- **Timing Parity:** Constant-time dummy hash verification on non-existent, locked, or OAuth2-only accounts to eliminate timing side-channels.
- **CPU & OOM Protection:** Bounded concurrency via `tokio::sync::Semaphore` with blocking CPU offload (`tokio::task::spawn_blocking`).
- **Secrets at Rest:** AES-256-GCM authenticated encryption using user-specific `UserId` as Associated Authenticated Data (AAD).
- **Token Signing:** Asymmetric Ed25519 (`EdDSA`) JWTs with strict header validation (`alg: EdDSA`), RFC 8037 JWKS, and immutable RFC 8176 (`amr`, `auth_time`) claims.
- **Memory Zeroization:** Plaintext passwords (`RawPassword`) and decrypted secrets (`DecryptedSecret`) strictly implement `Zeroize` and `ZeroizeOnDrop`. Sensitive credentials redact automatically as `[REDACTED]` in `Debug` and `Display` traits.

### 2. Distributed State & Concurrency Invariants
- **Refresh Token TOCTOU Protection:** Single-query atomic PostgreSQL CTE (`rotate_atomic`) combining replacement and rotation with active status verification.
- **Lost Update Elimination:** Atomic database-level increments (`record_failed_login_atomic`) preventing race conditions under concurrent brute-force attempts.
- **Distributed Revocation:** Immediate Redis session blacklisting (`blacklist:session:{sid}`) synchronized across logout, revocation, password reset, and administrative bans.
- **Fail-Closed Auth Extractor:** Auth extractors fail closed upon cache or database failure, rejecting unverified access.
- **Cancellation Safety:** Critical distributed revocations are shielded (`shielded`) against future cancellation or client disconnection, while propagating Redis errors for fail-closed safety.

### 3. FIDO2 / WebAuthn & Multi-Factor Security
- **Hardware Token Clone Detection:** Strict signature counter (`sign_count`) verification rejecting rollbacks with immediate account compromise audits.
- **TOTP Replay Protection:** Atomic `SET ... NX EX` Redis locks preventing duplicate code submissions within time drift windows.
- **Constant-Time Backup Codes:** Pad-to-10 traversal using `subtle::ConstantTimeEq` to prevent timing leaks during backup code consumption.
