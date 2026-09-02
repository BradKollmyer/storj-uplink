#![no_main]
//! Path component iteration and encrypted-component decoding must never panic.
use libfuzzer_sys::fuzz_target;
use storj_encryption::{CipherSuite, Key, PathIter, decrypt_iterator, encrypt_iterator};

fuzz_target!(|data: &[u8]| {
    let key = Key::from_bytes([7u8; 32]);
    for c in PathIter::new(data) {
        let _ = c;
    }
    let _ = decrypt_iterator(PathIter::new(data), CipherSuite::AES_GCM, &key);
    let _ = decrypt_iterator(PathIter::new(data), CipherSuite::SECRET_BOX, &key);
    let _ = encrypt_iterator(PathIter::new(data), CipherSuite::AES_GCM, &key);
});
