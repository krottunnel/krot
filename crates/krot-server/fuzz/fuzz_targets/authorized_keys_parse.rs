#![no_main]
//! libfuzzer target — feed arbitrary bytes as an `authorized_keys`
//! file, then open a registry. Panics are bugs in the parser.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("authorized_keys");
    if std::fs::write(&path, data).is_ok() {
        let _ = krot_server::keys::KeyRegistry::open(path);
    }
});
