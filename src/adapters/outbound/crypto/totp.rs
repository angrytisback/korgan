//! RFC 6238 TOTP generator, QR code builder, and validator adapter.

use qrcode::QrCode;
use qrcode::render::svg;
use rand::Rng;
use totp_rs::{Algorithm, Totp};

use crate::domain::value_objects::EmailAddress;
use crate::ports::errors::PortError;
use crate::ports::services::TotpService;

/// Default TOTP secret size in bytes (160 bits = 20 bytes per RFC 4226/6238 recommendation).
pub const DEFAULT_TOTP_SECRET_BYTES: usize = 20;

/// Production RFC 6238 TOTP service.
#[derive(Debug, Clone, Default)]
pub struct Rfc6238TotpService;

impl Rfc6238TotpService {
    /// Creates a new [`Rfc6238TotpService`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TotpService for Rfc6238TotpService {
    fn generate_secret(&self) -> Result<Vec<u8>, PortError> {
        let mut bytes = vec![0u8; DEFAULT_TOTP_SECRET_BYTES];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    fn generate_qr_code_svg(
        &self,
        email: &EmailAddress,
        secret: &[u8],
        issuer: &str,
    ) -> Result<String, PortError> {
        #[allow(deprecated)]
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_vec(),
            Some(issuer.to_string()),
            email.as_str().to_string(),
        )
        .map_err(|e| PortError::crypto(format!("failed to create TOTP instance: {e}")))?;

        let url = totp
            .to_url()
            .map_err(|e| PortError::crypto(format!("failed to encode TOTP URL: {e}")))?;

        let qr = QrCode::new(url.as_bytes())
            .map_err(|e| PortError::crypto(format!("failed to generate QR code: {e}")))?;

        let svg = qr.render::<svg::Color>().build();
        Ok(svg)
    }

    fn verify_code(
        &self,
        secret: &[u8],
        code: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, PortError> {
        #[allow(deprecated)]
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_vec(),
            None,
            String::new(),
        )
        .map_err(|e| PortError::crypto(format!("failed to construct TOTP verifier: {e}")))?;

        Ok(totp.check(code, now_epoch_secs).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn generates_valid_secret() -> TestResult {
        let service = Rfc6238TotpService::new();
        let secret = service.generate_secret()?;
        assert_eq!(secret.len(), DEFAULT_TOTP_SECRET_BYTES);
        Ok(())
    }

    #[test]
    fn generates_qr_code_svg() -> TestResult {
        let service = Rfc6238TotpService::new();
        let email = EmailAddress::parse("alice@example.com")?;
        let secret = service.generate_secret()?;

        let svg = service.generate_qr_code_svg(&email, &secret, "korgan")?;
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        Ok(())
    }

    #[test]
    fn generates_and_verifies_code_within_drift_window() -> TestResult {
        let service = Rfc6238TotpService::new();
        let secret = b"12345678901234567890"; // 20-byte test secret
        let now = 1_700_000_000u64;

        #[allow(deprecated)]
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_vec(),
            None,
            String::new(),
        )
        .map_err(|e| format!("totp failed: {e}"))?;

        let code_str = totp.generate(now).to_string();

        // Exact match
        assert!(service.verify_code(secret, &code_str, now)?);
        // Step - 1 (within 30s drift)
        assert!(service.verify_code(secret, &code_str, now + 25)?);
        // Step + 1 (within 30s drift)
        assert!(service.verify_code(secret, &code_str, now - 25)?);
        // Step far away (drift exceeded)
        assert!(!service.verify_code(secret, &code_str, now + 120)?);
        // Invalid code string
        assert!(!service.verify_code(
            secret,
            "000000",
            if code_str == "000000" { now + 300 } else { now }
        )?);
        Ok(())
    }
}
