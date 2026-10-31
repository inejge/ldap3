#![no_main]
//! Coverage-guided fuzz of the SASL-framing LDAP decoder (length-prefix handling,
//! multi-message buffers, split reads). Must never panic on any input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ldap3::fuzz::fuzz_decode(data);
});
