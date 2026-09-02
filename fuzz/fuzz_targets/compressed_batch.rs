#![no_main]
//! CompressedBatch decompression is bounded and must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = storj_proto::compressed::decompress(data);
});
