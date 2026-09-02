#![no_main]
//! Macaroon parse/serialize round trip must never panic.
use libfuzzer_sys::fuzz_target;
use storj_access::Macaroon;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Macaroon::parse(data) {
        let again = m.serialize();
        let _ = Macaroon::parse(&again);
        let _ = m.validate(&[0x42; 32]);
    }
});
