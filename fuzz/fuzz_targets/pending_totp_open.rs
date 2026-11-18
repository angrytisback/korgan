//! Opening a sealed pending TOTP secret must reject garbage without panicking,
//! and a genuine seal must round-trip.
#![no_main]

use korgan::adapters::outbound::crypto::Aes256GcmCipher;
use korgan::application::use_cases::token_utils::{open_pending_totp_secret, seal_pending_totp_secret};
use korgan::domain::value_objects::UserId;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn cipher() -> &'static Aes256GcmCipher {
    static C: OnceLock<Aes256GcmCipher> = OnceLock::new();
    C.get_or_init(|| match Aes256GcmCipher::new(&[7u8; 32]) {
        Ok(c) => c,
        Err(_) => std::process::abort(),
    })
}

fuzz_target!(|data: &[u8]| {
    let user = UserId::new();
    if let Ok(s) = std::str::from_utf8(data) {
        assert!(open_pending_totp_secret(cipher(), &user, s).is_err());
    }
    if let Ok(sealed) = seal_pending_totp_secret(cipher(), &user, data) {
        let opened = open_pending_totp_secret(cipher(), &user, &sealed);
        assert_eq!(opened.as_deref().map(Vec::as_slice).ok(), Some(data));
        // Bound to the owner: another user cannot open it.
        assert!(open_pending_totp_secret(cipher(), &UserId::new(), &sealed).is_err());
    }
});
