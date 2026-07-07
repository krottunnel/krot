#![no_main]
//! libfuzzer target — feed arbitrary bytes to `MuxHeader::decode`.
//! Panics, hangs, or over-allocations here become libfuzzer crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krot_proto::MuxHeader::decode(data);
});
