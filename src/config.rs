//! Strongly-typed, hierarchical application configuration.
//!
//! Layers, from lowest to highest precedence:
//!
//! 1. `config/default.toml` (embedded into the binary at compile time)
//! 2. an optional file named by `KORGAN_CONFIG_FILE`
//! 3. process environment (after `.env` has been loaded by the caller):
//!    `KORGAN__<SECTION>__<KEY>` plus the aliases `DATABASE_URL`, `REDIS_URL`,
//!    `MAIL_PROVIDER`, `HIBP_ENABLED` and `TOKEN_DELIVERY_MODE`.
//!
//! All secrets are held as [`SecretString`] so that `Debug` output and
//! accidental logging never reveal them. [`Settings::validate`] runs after
//! deserialization and reports **every** problem at once.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use config::{Config, Environment, File, FileFormat};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// Embedded base configuration.
const DEFAULT_CONFIG_TOML: &str = include_str!("../config/default.toml");

/// Prefix of generic environment overrides (`KORGAN__SERVER__PORT`, ...).
const ENV_PREFIX: &str = "KORGAN";
/// Separator between prefix / section / key in environment variable names.
const ENV_SEPARATOR: &str = "__";
/// Environment variable naming an additional configuration file.
const CONFIG_FILE_ENV: &str = "KORGAN_CONFIG_FILE";

/// Short, well-known environment variable aliases and the canonical variable
/// each one maps to. An explicit canonical variable always wins.
const ENV_ALIASES: &[(&str, &str)] = &[
    ("DATABASE_URL", "KORGAN__DATABASE__URL"),
    ("REDIS_URL", "KORGAN__REDIS__URL"),
    ("MAIL_PROVIDER", "KORGAN__MAIL__PROVIDER"),
    ("HIBP_ENABLED", "KORGAN__HIBP__ENABLED"),
    ("TOKEN_DELIVERY_MODE", "KORGAN__AUTH__TOKEN_DELIVERY_MODE"),
    (
        "KORGAN__OAUTH__GOOGLE_CLIENT_ID",
        "KORGAN__OAUTH__GOOGLE__CLIENT_ID",
    ),
    (
        "KORGAN__OAUTH__GOOGLE_CLIENT_SECRET",
        "KORGAN__OAUTH__GOOGLE__CLIENT_SECRET",
    ),
    (
        "KORGAN__OAUTH__GITHUB_CLIENT_ID",
        "KORGAN__OAUTH__GITHUB__CLIENT_ID",
    ),
    (
        "KORGAN__OAUTH__GITHUB_CLIENT_SECRET",
        "KORGAN__OAUTH__GITHUB__CLIENT_SECRET",
    ),
    ("KORGAN__WEBAUTHN_RP_ID", "KORGAN__WEBAUTHN__RP_ID"),
    ("KORGAN__WEBAUTHN_RP_ORIGIN", "KORGAN__WEBAUTHN__RP_ORIGIN"),
];

/// OWASP ASVS / project minimums for Argon2id.
const ARGON2_MIN_MEMORY_KIB: u32 = 19_456;
const ARGON2_MIN_ITERATIONS: u32 = 2;
/// Upper bound on the access token lifetime (RFC 9068 tokens are short-lived).
const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 3_600;
/// Required AES-256 key length in bytes.
const AES_256_KEY_LEN: usize = 32;

/// Errors produced while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The layered sources could not be read or deserialized.
    #[error("failed to load configuration: {0}")]
    Load(#[from] config::ConfigError),

    /// The configuration was well-formed but violates one or more rules.
    #[error("invalid configuration: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

/// Deployment environment. `production` enables stricter validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppEnvironment {
    /// Local development.
    Development,
    /// Production deployment.
    Production,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-friendly multi-line console output.
    Pretty,
    /// One JSON object per line for log shippers.
    Json,
}

/// How access / refresh tokens are delivered to and read from clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenDeliveryMode {
    /// Cookies for web clients, JSON payload + `Authorization` header otherwise.
    Dual,
    /// JSON payload + `Authorization: Bearer` only.
    HeaderOnly,
    /// `HttpOnly` cookies only.
    CookieOnly,
}

/// Outbound e-mail provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailProvider {
    /// Writes e-mails to the log (development only).
    Console,
    /// Generic SMTP relay.
    Smtp,
    /// Resend HTTP API.
    Resend,
    /// Amazon SES.
    Ses,
}

/// SMTP transport security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Plaintext (local Mailpit only).
    None,
    /// Opportunistic upgrade via `STARTTLS`.
    Starttls,
    /// Implicit TLS.
    Tls,
}

/// Root configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// HTTP server settings.
    pub server: ServerSettings,
    /// Logging / tracing settings.
    pub telemetry: TelemetrySettings,
    /// PostgreSQL settings.
    pub database: DatabaseSettings,
    /// Redis / Valkey settings.
    pub redis: RedisSettings,
    /// Cryptographic parameters and key material.
    pub crypto: CryptoSettings,
    /// Authentication policy.
    pub auth: AuthSettings,
    /// Outbound mail settings.
    pub mail: MailSettings,
    /// Have I Been Pwned settings.
    pub hibp: HibpSettings,
    /// Rate limiting settings.
    pub rate_limit: RateLimitSettings,
    /// External OAuth2 identity provider settings.
    pub oauth: OAuthSettings,
    /// WebAuthn / Passkeys settings.
    pub webauthn: WebauthnSettings,
}

/// HTTP server settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    /// Interface to bind.
    pub host: String,
    /// TCP port to bind.
    pub port: u16,
    /// Deployment environment.
    pub environment: AppEnvironment,
    /// Externally reachable base URL (used in e-mail links).
    pub public_base_url: String,
    /// Exact CORS origins (TOML array, or a comma-separated string from the
    /// environment).
    #[serde(deserialize_with = "deserialize_string_list")]
    pub cors_allowed_origins: Vec<String>,
    /// Maximum accepted request body size.
    pub request_body_limit_bytes: usize,
    /// Per-request timeout.
    pub request_timeout_secs: u64,
    /// Time allowed for in-flight requests during graceful shutdown.
    pub shutdown_grace_secs: u64,
}

/// Logging / tracing settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySettings {
    /// Output format.
    pub log_format: LogFormat,
    /// `EnvFilter` directive used when `RUST_LOG` is unset.
    pub log_filter: String,
}

/// PostgreSQL settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSettings {
    /// Connection URL (contains credentials).
    pub url: SecretString,
    /// Maximum pool size.
    pub max_connections: u32,
    /// Minimum idle connections.
    pub min_connections: u32,
    /// Pool acquire timeout.
    pub acquire_timeout_secs: u64,
    /// Idle connection timeout.
    pub idle_timeout_secs: u64,
    /// Whether embedded migrations run at startup.
    pub run_migrations: bool,
}

/// Redis / Valkey settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSettings {
    /// Connection URL (may contain credentials).
    pub url: SecretString,
    /// Connection pool size.
    pub pool_size: usize,
    /// Connect timeout.
    pub connect_timeout_secs: u64,
    /// Prefix applied to every key.
    pub key_prefix: String,
}

/// Cryptographic parameters and key material.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoSettings {
    /// Argon2id memory cost in KiB.
    pub argon2_memory_kib: u32,
    /// Argon2id iteration count.
    pub argon2_iterations: u32,
    /// Argon2id degree of parallelism.
    pub argon2_parallelism: u32,
    /// Maximum concurrent Argon2id hashing/verification operations to prevent CPU starvation and OOM.
    #[serde(default = "default_argon2_max_concurrency")]
    pub argon2_max_concurrency: usize,
    /// `kid` published in the JWKS document.
    pub ed25519_key_id: String,
    /// PKCS#8 PEM encoded Ed25519 private key (`\n` escapes accepted).
    pub ed25519_private_key_pem: SecretString,
    /// Base64 encoded 32-byte AES-256-GCM master key.
    pub aes_master_key: SecretString,
}

const fn default_argon2_max_concurrency() -> usize {
    16
}

impl CryptoSettings {
    /// Returns the Ed25519 PEM with literal `\n` escape sequences expanded.
    #[must_use]
    pub fn normalized_ed25519_pem(&self) -> SecretString {
        SecretString::from(
            self.ed25519_private_key_pem
                .expose_secret()
                .replace("\\n", "\n"),
        )
    }

    /// Decodes the AES-256-GCM master key; the result is zeroized on drop.
    ///
    /// # Errors
    ///
    /// Returns an error message when the value is not valid Base64 or does not
    /// decode to exactly 32 bytes.
    pub fn decode_aes_master_key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let decoded = Zeroizing::new(
            BASE64_STANDARD
                .decode(self.aes_master_key.expose_secret().trim())
                .map_err(|_| "crypto.aes_master_key must be valid standard Base64".to_owned())?,
        );
        if decoded.len() == AES_256_KEY_LEN {
            Ok(decoded)
        } else {
            Err(format!(
                "crypto.aes_master_key must decode to exactly {AES_256_KEY_LEN} bytes"
            ))
        }
    }
}

/// Authentication policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSettings {
    /// JWT `iss` claim.
    pub issuer: String,
    /// JWT `aud` claim.
    pub audience: String,
    /// Token delivery mode.
    pub token_delivery_mode: TokenDeliveryMode,
    /// Access token lifetime.
    pub access_token_ttl_secs: u64,
    /// Refresh token / session lifetime.
    pub refresh_token_ttl_secs: u64,
    /// E-mail verification token lifetime.
    pub email_verification_ttl_secs: u64,
    /// Password reset token lifetime.
    pub password_reset_ttl_secs: u64,
    /// MFA challenge lifetime.
    pub mfa_challenge_ttl_secs: u64,
    /// Failed logins before temporary lockout.
    pub max_failed_login_attempts: u16,
    /// Lockout duration.
    pub lockout_duration_secs: u64,
    /// Number of previous password hashes retained.
    pub password_history_depth: u16,
    /// Grace period before a `pending_deletion` account is purged.
    pub account_deletion_grace_days: u32,
    /// Optional `Domain` attribute for auth cookies.
    #[serde(default)]
    pub cookie_domain: Option<String>,
}

/// Outbound mail settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailSettings {
    /// Selected provider.
    pub provider: MailProvider,
    /// `From` address.
    pub from_address: String,
    /// `From` display name.
    pub from_name: String,
    /// SMTP provider settings.
    pub smtp: SmtpSettings,
    /// Resend provider settings.
    pub resend: ResendSettings,
    /// SES provider settings.
    pub ses: SesSettings,
}

/// SMTP provider settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpSettings {
    /// Relay host.
    pub host: String,
    /// Relay port.
    pub port: u16,
    /// Transport security.
    pub tls: SmtpTls,
    /// Optional username.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password.
    #[serde(default)]
    pub password: Option<SecretString>,
}

/// Resend provider settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResendSettings {
    /// API base URL.
    pub api_url: String,
    /// API key.
    #[serde(default)]
    pub api_key: Option<SecretString>,
}

/// SES provider settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SesSettings {
    /// AWS region.
    #[serde(default)]
    pub region: Option<String>,
    /// AWS access key id.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// AWS secret access key.
    #[serde(default)]
    pub secret_access_key: Option<SecretString>,
}

/// Have I Been Pwned settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HibpSettings {
    /// Whether breached-password screening is enabled.
    pub enabled: bool,
    /// Range API base URL.
    pub api_url: String,
    /// Request timeout.
    pub timeout_secs: u64,
    /// Accept passwords when HIBP is unreachable.
    pub fail_open: bool,
}

/// Rate limiting settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSettings {
    /// Master switch.
    pub enabled: bool,
    /// Sliding window length.
    pub window_secs: u64,
    /// Global per-client budget per window.
    pub global_max_requests: u32,
    /// Login budget per window.
    pub login_max_requests: u32,
    /// Registration budget per window.
    pub register_max_requests: u32,
    /// Forgot-password budget per window.
    pub forgot_password_max_requests: u32,
    /// MFA verification budget per window.
    pub mfa_max_requests: u32,
    /// Trust `X-Forwarded-For` (only behind a trusted proxy).
    pub trust_proxy_headers: bool,
}

/// External OAuth2 identity provider settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthSettings {
    /// Google OAuth settings.
    pub google: OAuthClientSettings,
    /// GitHub OAuth settings.
    pub github: OAuthClientSettings,
}

/// Settings for an individual OAuth2 identity provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientSettings {
    /// Whether this provider is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// OAuth2 client identifier.
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth2 client secret.
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// Configured OAuth2 callback redirect URI.
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

/// WebAuthn / Passkeys Relying Party settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnSettings {
    /// Relying Party identifier (e.g. "localhost" or domain name).
    pub rp_id: String,
    /// Relying Party origin (e.g. "http://localhost:8080" or "https://auth.example.com").
    pub rp_origin: String,
}

impl Settings {
    /// Loads and validates configuration from the real process environment.
    ///
    /// The caller is expected to have loaded `.env` beforehand.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a source cannot be read, a required value
    /// (such as a secret) is missing, or validation fails.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_env(std::env::vars().collect())
    }

    /// Loads and validates configuration from an explicit environment map.
    ///
    /// # Errors
    ///
    /// See [`Settings::load`].
    pub fn load_from_env(env: HashMap<String, String>) -> Result<Self, ConfigError> {
        let env = apply_aliases(env);

        let mut builder =
            Config::builder().add_source(File::from_str(DEFAULT_CONFIG_TOML, FileFormat::Toml));

        if let Some(path) = env.get(CONFIG_FILE_ENV).filter(|p| !p.trim().is_empty()) {
            builder = builder.add_source(File::new(path, FileFormat::Toml).required(true));
        }

        builder = builder.add_source(
            Environment::with_prefix(ENV_PREFIX)
                .prefix_separator(ENV_SEPARATOR)
                .separator(ENV_SEPARATOR)
                .source(Some(env)),
        );

        let settings: Self = builder.build()?.try_deserialize()?;
        settings.validate()?;
        Ok(settings)
    }

    /// Validates cross-field and security constraints, reporting all problems.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] listing every violated rule.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();
        self.validate_server(&mut problems);
        self.validate_storage(&mut problems);
        self.validate_crypto(&mut problems);
        self.validate_auth(&mut problems);
        self.validate_mail(&mut problems);
        self.validate_integrations(&mut problems);
        self.validate_oauth(&mut problems);
        self.validate_webauthn(&mut problems);

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems))
        }
    }

    /// Whether the service runs in the production environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.server.environment == AppEnvironment::Production
    }

    fn validate_server(&self, problems: &mut Vec<String>) {
        let server = &self.server;
        if IpAddr::from_str(&server.host).is_err() {
            problems.push("server.host must be a valid IP address".to_owned());
        }
        if server.port == 0 {
            problems.push("server.port must be non-zero".to_owned());
        }
        if server.request_body_limit_bytes == 0 {
            problems.push("server.request_body_limit_bytes must be greater than zero".to_owned());
        }
        if server.request_timeout_secs == 0 {
            problems.push("server.request_timeout_secs must be greater than zero".to_owned());
        }
        if self.telemetry.log_filter.trim().is_empty() {
            problems.push("telemetry.log_filter must not be empty".to_owned());
        }

        check_origin(
            "server.public_base_url",
            &server.public_base_url,
            self.is_production(),
            problems,
        );
        for origin in &server.cors_allowed_origins {
            if origin == "*" {
                problems.push(
                    "server.cors_allowed_origins must not contain `*` (credentials are enabled)"
                        .to_owned(),
                );
            } else {
                check_origin(
                    "server.cors_allowed_origins",
                    origin,
                    self.is_production(),
                    problems,
                );
            }
        }
    }

    fn validate_storage(&self, problems: &mut Vec<String>) {
        let db_url = self.database.url.expose_secret();
        if !(db_url.starts_with("postgres://") || db_url.starts_with("postgresql://")) {
            problems.push("database.url must start with postgres:// or postgresql://".to_owned());
        }
        if self.database.max_connections == 0 {
            problems.push("database.max_connections must be at least 1".to_owned());
        }
        if self.database.min_connections > self.database.max_connections {
            problems.push(
                "database.min_connections must not exceed database.max_connections".to_owned(),
            );
        }
        if self.database.acquire_timeout_secs == 0 {
            problems.push("database.acquire_timeout_secs must be greater than zero".to_owned());
        }

        let redis_url = self.redis.url.expose_secret();
        if !(redis_url.starts_with("redis://") || redis_url.starts_with("rediss://")) {
            problems.push("redis.url must start with redis:// or rediss://".to_owned());
        }
        if self.redis.pool_size == 0 {
            problems.push("redis.pool_size must be at least 1".to_owned());
        }
        if self.redis.key_prefix.trim().is_empty() {
            problems.push("redis.key_prefix must not be empty".to_owned());
        }
    }

    fn validate_crypto(&self, problems: &mut Vec<String>) {
        let crypto = &self.crypto;
        if crypto.argon2_memory_kib < ARGON2_MIN_MEMORY_KIB {
            problems.push(format!(
                "crypto.argon2_memory_kib must be at least {ARGON2_MIN_MEMORY_KIB} (19 MiB)"
            ));
        }
        if crypto.argon2_iterations < ARGON2_MIN_ITERATIONS {
            problems.push(format!(
                "crypto.argon2_iterations must be at least {ARGON2_MIN_ITERATIONS}"
            ));
        }
        if crypto.argon2_parallelism == 0 {
            problems.push("crypto.argon2_parallelism must be at least 1".to_owned());
        }
        if crypto.argon2_max_concurrency == 0 {
            problems.push("crypto.argon2_max_concurrency must be at least 1".to_owned());
        }
        if argon2::Params::new(
            crypto.argon2_memory_kib,
            crypto.argon2_iterations,
            crypto.argon2_parallelism,
            None,
        )
        .is_err()
        {
            problems
                .push("crypto.argon2_* parameters are not a valid Argon2 configuration".to_owned());
        }
        if crypto.ed25519_key_id.trim().is_empty() {
            problems.push("crypto.ed25519_key_id must not be empty".to_owned());
        }
        if SigningKey::from_pkcs8_pem(crypto.normalized_ed25519_pem().expose_secret()).is_err() {
            problems.push(
                "crypto.ed25519_private_key_pem must be a valid PKCS#8 PEM Ed25519 private key"
                    .to_owned(),
            );
        }
        if let Err(problem) = crypto.decode_aes_master_key() {
            problems.push(problem);
        }
    }

    fn validate_auth(&self, problems: &mut Vec<String>) {
        let auth = &self.auth;
        check_origin("auth.issuer", &auth.issuer, self.is_production(), problems);
        if auth.audience.trim().is_empty() {
            problems.push("auth.audience must not be empty".to_owned());
        }
        if auth.access_token_ttl_secs == 0 || auth.access_token_ttl_secs > MAX_ACCESS_TOKEN_TTL_SECS
        {
            problems.push(format!(
                "auth.access_token_ttl_secs must be between 1 and {MAX_ACCESS_TOKEN_TTL_SECS}"
            ));
        }
        if auth.refresh_token_ttl_secs <= auth.access_token_ttl_secs {
            problems.push(
                "auth.refresh_token_ttl_secs must exceed auth.access_token_ttl_secs".to_owned(),
            );
        }
        for (name, value) in [
            (
                "auth.email_verification_ttl_secs",
                auth.email_verification_ttl_secs,
            ),
            ("auth.password_reset_ttl_secs", auth.password_reset_ttl_secs),
            ("auth.mfa_challenge_ttl_secs", auth.mfa_challenge_ttl_secs),
            ("auth.lockout_duration_secs", auth.lockout_duration_secs),
        ] {
            if value == 0 {
                problems.push(format!("{name} must be greater than zero"));
            }
        }
        if auth.max_failed_login_attempts == 0 {
            problems.push("auth.max_failed_login_attempts must be at least 1".to_owned());
        }
        if auth.account_deletion_grace_days == 0 {
            problems.push("auth.account_deletion_grace_days must be at least 1".to_owned());
        }
    }

    fn validate_mail(&self, problems: &mut Vec<String>) {
        let mail = &self.mail;
        if !mail.from_address.contains('@') {
            problems.push("mail.from_address must be an e-mail address".to_owned());
        }
        match mail.provider {
            MailProvider::Console => {
                if self.is_production() {
                    problems.push(
                        "mail.provider = console is forbidden in production (it logs tokens)"
                            .to_owned(),
                    );
                }
            }
            MailProvider::Smtp => {
                if mail.smtp.host.trim().is_empty() || mail.smtp.port == 0 {
                    problems.push("mail.smtp.host and mail.smtp.port are required".to_owned());
                }
                if mail.smtp.username.is_some() != mail.smtp.password.is_some() {
                    problems.push(
                        "mail.smtp.username and mail.smtp.password must be set together".to_owned(),
                    );
                }
            }
            MailProvider::Resend => {
                if mail.resend.api_key.is_none() {
                    problems
                        .push("mail.resend.api_key is required when provider = resend".to_owned());
                }
                check_http_url("mail.resend.api_url", &mail.resend.api_url, problems);
            }
            MailProvider::Ses => {
                if mail
                    .ses
                    .region
                    .as_deref()
                    .is_none_or(|r| r.trim().is_empty())
                    || mail.ses.access_key_id.is_none()
                    || mail.ses.secret_access_key.is_none()
                {
                    problems.push(
                        "mail.ses.region, access_key_id and secret_access_key are required when provider = ses"
                            .to_owned(),
                    );
                }
            }
        }
    }

    fn validate_integrations(&self, problems: &mut Vec<String>) {
        if self.hibp.enabled {
            check_http_url("hibp.api_url", &self.hibp.api_url, problems);
            if self.hibp.timeout_secs == 0 {
                problems.push("hibp.timeout_secs must be greater than zero".to_owned());
            }
        } else if self.is_production() {
            problems.push(
                "hibp.enabled must be true in production (NIST SP 800-63B breached-password screening)"
                    .to_owned(),
            );
        }

        let rl = &self.rate_limit;
        if rl.enabled {
            if rl.window_secs == 0 {
                problems.push("rate_limit.window_secs must be greater than zero".to_owned());
            }
            for (name, value) in [
                ("rate_limit.global_max_requests", rl.global_max_requests),
                ("rate_limit.login_max_requests", rl.login_max_requests),
                ("rate_limit.register_max_requests", rl.register_max_requests),
                (
                    "rate_limit.forgot_password_max_requests",
                    rl.forgot_password_max_requests,
                ),
                ("rate_limit.mfa_max_requests", rl.mfa_max_requests),
            ] {
                if value == 0 {
                    problems.push(format!("{name} must be greater than zero"));
                }
            }
        } else if self.is_production() {
            problems.push("rate_limit.enabled must be true in production".to_owned());
        }
    }

    fn validate_oauth(&self, problems: &mut Vec<String>) {
        if self.oauth.google.enabled {
            if self
                .oauth
                .google
                .client_id
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                problems.push(
                    "oauth.google.client_id must not be empty when google oauth is enabled"
                        .to_owned(),
                );
            }
            if self
                .oauth
                .google
                .client_secret
                .as_ref()
                .is_none_or(|s| s.expose_secret().trim().is_empty())
            {
                problems.push(
                    "oauth.google.client_secret must not be empty when google oauth is enabled"
                        .to_owned(),
                );
            }
        }
        if self.oauth.github.enabled {
            if self
                .oauth
                .github
                .client_id
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                problems.push(
                    "oauth.github.client_id must not be empty when github oauth is enabled"
                        .to_owned(),
                );
            }
            if self
                .oauth
                .github
                .client_secret
                .as_ref()
                .is_none_or(|s| s.expose_secret().trim().is_empty())
            {
                problems.push(
                    "oauth.github.client_secret must not be empty when github oauth is enabled"
                        .to_owned(),
                );
            }
        }
    }

    fn validate_webauthn(&self, problems: &mut Vec<String>) {
        if self.webauthn.rp_id.trim().is_empty() {
            problems.push("webauthn.rp_id must not be empty".to_owned());
        }
        check_origin(
            "webauthn.rp_origin",
            &self.webauthn.rp_origin,
            self.is_production(),
            problems,
        );
    }

    /// Socket address the HTTP server binds to.
    ///
    /// # Errors
    ///
    /// Returns an error message when `server.host` is not a valid IP address.
    pub fn socket_addr(&self) -> Result<SocketAddr, String> {
        IpAddr::from_str(&self.server.host)
            .map(|ip| SocketAddr::new(ip, self.server.port))
            .map_err(|_| "server.host must be a valid IP address".to_owned())
    }
}

impl ServerSettings {
    /// Per-request timeout as a [`Duration`].
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    /// Graceful shutdown grace period as a [`Duration`].
    #[must_use]
    pub const fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_secs)
    }
}

/// Deserializes either a sequence of strings or one comma-separated string.
///
/// Environment variables are always strings, while TOML files use arrays. This
/// keeps list parsing explicit instead of relying on the `config` crate's
/// `try_parsing`, which would also coerce numeric-looking secrets.
fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ListVisitor;

    impl<'de> serde::de::Visitor<'de> for ListVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a list of strings or a comma-separated string")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_any(ListVisitor)
}

/// Copies each alias onto its canonical variable unless that is already set.
fn apply_aliases(mut env: HashMap<String, String>) -> HashMap<String, String> {
    for (alias, canonical) in ENV_ALIASES {
        if !env.contains_key(*canonical)
            && let Some(value) = env.get(*alias).cloned()
        {
            env.insert((*canonical).to_owned(), value);
        }
    }
    env
}

/// Validates that `value` is an `http(s)://host[:port]` origin without a path.
fn check_origin(name: &str, value: &str, require_https: bool, problems: &mut Vec<String>) {
    let Ok(uri) = value.parse::<http::Uri>() else {
        problems.push(format!("{name} must be a valid URL"));
        return;
    };
    let scheme = uri.scheme_str();
    if !matches!(scheme, Some("http" | "https")) || uri.authority().is_none() {
        problems.push(format!("{name} must be an http(s) URL with a host"));
        return;
    }
    if require_https && scheme != Some("https") {
        problems.push(format!("{name} must use https in production"));
    }
}

/// Validates that `value` is an absolute `http(s)` URL.
fn check_http_url(name: &str, value: &str, problems: &mut Vec<String>) {
    match value.parse::<http::Uri>() {
        Ok(uri)
            if matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some() => {}
        _ => problems.push(format!("{name} must be an absolute http(s) URL")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // Throwaway key pair generated solely for tests; never used anywhere else.
    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\\nMC4CAQAwBQYDK2VwBCIEIFSBy32VLsvjiPTGXm9ph2VZP5r6FjDhPLO303Qtn3P7\\n-----END PRIVATE KEY-----";
    const TEST_AES: &str = "EoX9enVeNrsuJbH6JMOBqg7qEq9/41ceeI0Q6S4lyAA=";

    fn base_env() -> HashMap<String, String> {
        HashMap::from([
            (
                "DATABASE_URL".to_owned(),
                "postgres://u:p@localhost:5432/db".to_owned(),
            ),
            ("REDIS_URL".to_owned(), "redis://localhost:6379".to_owned()),
            (
                "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
                TEST_PEM.to_owned(),
            ),
            (
                "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
                TEST_AES.to_owned(),
            ),
        ])
    }

    fn production_env() -> HashMap<String, String> {
        let mut env = base_env();
        env.extend([
            (
                "KORGAN__SERVER__ENVIRONMENT".to_owned(),
                "production".to_owned(),
            ),
            (
                "KORGAN__SERVER__PUBLIC_BASE_URL".to_owned(),
                "https://iam.example.com".to_owned(),
            ),
            (
                "KORGAN__SERVER__CORS_ALLOWED_ORIGINS".to_owned(),
                "https://app.example.com".to_owned(),
            ),
            (
                "KORGAN__AUTH__ISSUER".to_owned(),
                "https://iam.example.com".to_owned(),
            ),
            (
                "KORGAN__WEBAUTHN__RP_ID".to_owned(),
                "iam.example.com".to_owned(),
            ),
            (
                "KORGAN__WEBAUTHN__RP_ORIGIN".to_owned(),
                "https://iam.example.com".to_owned(),
            ),
            ("MAIL_PROVIDER".to_owned(), "smtp".to_owned()),
        ]);
        env
    }

    fn problems_of(result: Result<Settings, ConfigError>) -> Vec<String> {
        match result {
            Err(ConfigError::Invalid(p)) => p,
            _ => Vec::new(),
        }
    }

    #[test]
    fn loads_defaults_with_required_secrets() -> TestResult {
        let settings = Settings::load_from_env(base_env())?;
        assert_eq!(settings.server.port, 8080);
        assert_eq!(settings.auth.token_delivery_mode, TokenDeliveryMode::Dual);
        assert_eq!(settings.mail.provider, MailProvider::Console);
        assert_eq!(settings.crypto.argon2_memory_kib, 19_456);
        assert!(!settings.is_production());
        Ok(())
    }

    #[test]
    fn missing_secrets_are_rejected() {
        assert!(matches!(
            Settings::load_from_env(HashMap::new()),
            Err(ConfigError::Load(_))
        ));
    }

    #[test]
    fn spec_aliases_and_generic_overrides_apply() -> TestResult {
        let mut env = base_env();
        env.extend([
            ("TOKEN_DELIVERY_MODE".to_owned(), "cookie_only".to_owned()),
            ("HIBP_ENABLED".to_owned(), "false".to_owned()),
            ("KORGAN__SERVER__PORT".to_owned(), "9090".to_owned()),
        ]);
        let settings = Settings::load_from_env(env)?;
        assert_eq!(
            settings.auth.token_delivery_mode,
            TokenDeliveryMode::CookieOnly
        );
        assert!(!settings.hibp.enabled);
        assert_eq!(settings.server.port, 9090);
        Ok(())
    }

    #[test]
    fn canonical_variable_wins_over_alias() -> TestResult {
        let mut env = base_env();
        env.extend([
            ("TOKEN_DELIVERY_MODE".to_owned(), "cookie_only".to_owned()),
            (
                "KORGAN__AUTH__TOKEN_DELIVERY_MODE".to_owned(),
                "header_only".to_owned(),
            ),
        ]);
        let settings = Settings::load_from_env(env)?;
        assert_eq!(
            settings.auth.token_delivery_mode,
            TokenDeliveryMode::HeaderOnly
        );
        Ok(())
    }

    #[test]
    fn cors_origins_parse_as_comma_separated_list() -> TestResult {
        let mut env = base_env();
        env.insert(
            "KORGAN__SERVER__CORS_ALLOWED_ORIGINS".to_owned(),
            "http://localhost:3000,https://app.example.com".to_owned(),
        );
        let settings = Settings::load_from_env(env)?;
        assert_eq!(settings.server.cors_allowed_origins.len(), 2);
        Ok(())
    }

    #[test]
    fn numeric_looking_secrets_are_not_mangled() -> TestResult {
        let mut env = base_env();
        env.extend([
            ("MAIL_PROVIDER".to_owned(), "smtp".to_owned()),
            (
                "KORGAN__MAIL__SMTP__USERNAME".to_owned(),
                "mailer".to_owned(),
            ),
            ("KORGAN__MAIL__SMTP__PASSWORD".to_owned(), "007".to_owned()),
        ]);
        let settings = Settings::load_from_env(env)?;
        let password = settings
            .mail
            .smtp
            .password
            .as_ref()
            .map(|p| p.expose_secret().to_owned());
        assert_eq!(password.as_deref(), Some("007"));
        Ok(())
    }

    #[test]
    fn weak_argon2_parameters_are_rejected() {
        let mut env = base_env();
        env.extend([
            (
                "KORGAN__CRYPTO__ARGON2_MEMORY_KIB".to_owned(),
                "4096".to_owned(),
            ),
            (
                "KORGAN__CRYPTO__ARGON2_ITERATIONS".to_owned(),
                "1".to_owned(),
            ),
        ]);
        let problems = problems_of(Settings::load_from_env(env));
        assert!(problems.iter().any(|p| p.contains("argon2_memory_kib")));
        assert!(problems.iter().any(|p| p.contains("argon2_iterations")));
    }

    #[test]
    fn invalid_key_material_is_rejected() {
        let mut env = base_env();
        env.extend([
            (
                "KORGAN__CRYPTO__ED25519_PRIVATE_KEY_PEM".to_owned(),
                "not a pem".to_owned(),
            ),
            (
                "KORGAN__CRYPTO__AES_MASTER_KEY".to_owned(),
                "c2hvcnQ=".to_owned(),
            ),
        ]);
        let problems = problems_of(Settings::load_from_env(env));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("ed25519_private_key_pem"))
        );
        assert!(problems.iter().any(|p| p.contains("aes_master_key")));
    }

    #[test]
    fn production_rejects_console_mail_and_disabled_hibp() {
        let mut env = production_env();
        env.extend([
            ("MAIL_PROVIDER".to_owned(), "console".to_owned()),
            ("HIBP_ENABLED".to_owned(), "false".to_owned()),
        ]);
        let problems = problems_of(Settings::load_from_env(env));
        assert!(problems.iter().any(|p| p.contains("mail.provider")));
        assert!(problems.iter().any(|p| p.contains("hibp.enabled")));
    }

    #[test]
    fn production_requires_https() {
        let mut env = production_env();
        env.insert(
            "KORGAN__SERVER__PUBLIC_BASE_URL".to_owned(),
            "http://iam.example.com".to_owned(),
        );
        let problems = problems_of(Settings::load_from_env(env));
        assert!(problems.iter().any(|p| p.contains("public_base_url")));
    }

    #[test]
    fn valid_production_configuration_is_accepted() -> TestResult {
        let settings = Settings::load_from_env(production_env())?;
        assert!(settings.is_production());
        Ok(())
    }

    #[test]
    fn wildcard_cors_is_rejected() {
        let mut env = base_env();
        env.insert(
            "KORGAN__SERVER__CORS_ALLOWED_ORIGINS".to_owned(),
            "*".to_owned(),
        );
        let problems = problems_of(Settings::load_from_env(env));
        assert!(problems.iter().any(|p| p.contains("cors_allowed_origins")));
    }

    #[test]
    fn smtp_requires_complete_credentials() {
        let mut env = base_env();
        env.extend([
            ("MAIL_PROVIDER".to_owned(), "smtp".to_owned()),
            (
                "KORGAN__MAIL__SMTP__USERNAME".to_owned(),
                "only-user".to_owned(),
            ),
        ]);
        let problems = problems_of(Settings::load_from_env(env));
        assert!(problems.iter().any(|p| p.contains("mail.smtp.username")));
    }

    #[test]
    fn debug_output_never_contains_secrets() -> TestResult {
        let settings = Settings::load_from_env(base_env())?;
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("u:p@localhost"));
        assert!(!rendered.contains(TEST_AES));
        assert!(!rendered.contains("MC4CAQAwBQYDK2VwBCIE"));
        Ok(())
    }

    #[test]
    fn socket_addr_is_derived_from_host_and_port() -> TestResult {
        let settings = Settings::load_from_env(base_env())?;
        assert_eq!(settings.socket_addr()?, "0.0.0.0:8080".parse()?);
        Ok(())
    }
}
