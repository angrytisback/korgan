# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Closed 18 findings from the internal security audit (KRG-SEC-01..18): MFA factor
  replacement now requires step-up and refuses to overwrite an existing factor,
  constant-work password reset, per-endpoint password budgets, pending TOTP secrets
  sealed with AES-256-GCM in the cache, slow-loris header read timeout, and more.

### Changed
- **Breaking:** web access tokens are carried in the `__Host-access_token` cookie;
  the `auth.cookie_domain` setting was removed.
- **Breaking:** state-changing web requests are subject to an `Origin` check.
- **Breaking:** MFA backup codes are stored as HMAC digests.

## [0.1.0]

Initial development version.
