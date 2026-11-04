//! Outbound adapters: implementations of the `ports` traits against real
//! infrastructure.
//!
//! * [`postgres`] - `sqlx` repositories and the transaction manager
//! * [`redis`] - ephemeral tokens, sliding-window rate limiter, session blacklist
//! * [`crypto`] - Argon2id, Ed25519 JWT + JWKS, AES-256-GCM, TOTP (RFC 6238)
//! * [`mail`] - console, SMTP and Resend senders
//! * [`hibp`] - k-anonymity Have I Been Pwned client

pub mod crypto;
pub mod hibp;
pub mod http_client;
pub mod mail;
pub mod oauth;
pub mod postgres;
pub mod redis;
