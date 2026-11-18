//! Domain parsers must never panic on arbitrary input.
#![no_main]

use korgan::domain::value_objects::{EmailAddress, RawPassword, Username};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = EmailAddress::parse(s);
        let _ = Username::new(s);
        let _ = RawPassword::new(s);
    }
});
