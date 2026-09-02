#![no_main]
//! Access grant parse/serialize must never panic.
use libfuzzer_sys::fuzz_target;
use storj_access::Grant;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(g) = Grant::parse(s) {
            let _ = g.serialize();
        }
    }
});
