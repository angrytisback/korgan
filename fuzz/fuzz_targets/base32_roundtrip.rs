//! Base32 decode never panics; encode/decode round-trips arbitrary bytes.
#![no_main]

use korgan::application::use_cases::token_utils::{decode_base32, encode_base32};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_base32(s);
    }
    let encoded = encode_base32(data);
    assert_eq!(decode_base32(&encoded).as_deref(), Some(data));
});
