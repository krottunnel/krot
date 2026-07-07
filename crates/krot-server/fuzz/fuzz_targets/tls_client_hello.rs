#![no_main]
//! libfuzzer target — feed arbitrary bytes as a TLS ClientHello
//! record body to the SNI/ALPN parser. Panics are bugs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krot_server::domain::sni::parse_client_hello_for_fuzz(data);
});
