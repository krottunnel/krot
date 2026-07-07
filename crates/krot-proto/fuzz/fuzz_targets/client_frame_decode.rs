#![no_main]
//! libfuzzer target — feed arbitrary bytes to
//! `decode_frame::<ClientFrame>`. Any panic here is a bug in the
//! frame parser.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krot_proto::decode_frame::<krot_proto::ClientFrame>(data);
});
