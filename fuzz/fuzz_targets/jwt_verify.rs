//! `verify_access_token` must never panic and must never accept an arbitrary string.
#![no_main]

use korgan::adapters::outbound::crypto::Ed25519JwtService;
use korgan::ports::services::TokenSigner;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn service() -> &'static Ed25519JwtService {
    static SVC: OnceLock<Ed25519JwtService> = OnceLock::new();
    SVC.get_or_init(|| match Ed25519JwtService::generate(Some("fuzz".to_owned())) {
        Ok(s) => s,
        Err(_) => std::process::abort(),
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        // Random input is never a validly signed token.
        assert!(service().verify_access_token(token).is_err());
    }
});
