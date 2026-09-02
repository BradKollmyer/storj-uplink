#![no_main]
//! Frame parsing and packet reassembly must never panic on arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use storj_rpc::{PacketAssembler, parse_frame};

fuzz_target!(|data: &[u8]| {
    let mut asm = PacketAssembler::default();
    let mut buf = data;
    while let Ok(Some((frame, consumed))) = parse_frame(buf) {
        let _ = asm.push(frame);
        buf = &buf[consumed.min(buf.len())..];
        if consumed == 0 {
            break;
        }
    }
});
