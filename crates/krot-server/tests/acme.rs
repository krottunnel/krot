//! §12.1 ACME HTTP-01 integration test against a local Pebble server.
//!
//! Pebble ([`letsencrypt/pebble`](https://github.com/letsencrypt/pebble))
//! is a lightweight test ACME server. This test is `#[ignore]`-gated
//! because it needs external setup:
//!
//! 1. Start Pebble on localhost. The simplest recipe with docker:
//!
//!    ```sh
//!    docker run --rm --network host \
//!        -e PEBBLE_VA_NOSLEEP=1 \
//!        -e PEBBLE_VA_ALWAYS_VALID=1 \
//!        letsencrypt/pebble:latest \
//!        pebble -dnsserver 127.0.0.1:53 -config /test/config/pebble-config.json
//!    ```
//!
//!    Pebble's directory URL will be `https://localhost:14000/dir` and it
//!    signs certs with a self-signed root that lives on `:15000/roots/0`.
//!
//! 2. Because Pebble uses a self-signed cert on its own directory URL,
//!    `instant-acme` (which uses `reqwest`) needs to trust it. Set:
//!
//!    ```sh
//!    export KROT_PEBBLE_DIR_URL=https://localhost:14000/dir
//!    export SSL_CERT_FILE=/path/to/pebble/test/certs/pebble.minica.pem
//!    ```
//!
//! 3. Run the test:
//!
//!    ```sh
//!    cargo test -p krot-server --test acme -- --ignored --nocapture
//!    ```
//!
//! If `KROT_PEBBLE_DIR_URL` is unset the test prints a skip note and
//! passes — this lets `cargo test --ignored` succeed on machines without
//! a running Pebble instance while still exercising the assertion logic
//! when the env is present.

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::net::TcpListener;

use krot_server::domain::acme::acquire_cert;
use krot_server::domain::new_challenge_store;

#[tokio::test]
#[ignore = "requires a running Pebble ACME server; see file docstring"]
async fn acme_http01_end_to_end_against_pebble() {
    let Ok(dir_url) = std::env::var("KROT_PEBBLE_DIR_URL") else {
        eprintln!(
            "SKIP: KROT_PEBBLE_DIR_URL unset. Point it at a running Pebble \
             directory URL (e.g. https://localhost:14000/dir) and re-run."
        );
        return;
    };
    // Pebble in `PEBBLE_VA_ALWAYS_VALID=1` mode doesn't check the
    // HTTP-01 responder at all, but we still stand it up because
    // `acquire_cert` expects to be able to serve challenges.
    let http_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let http_listener = TcpListener::bind(http_bind).await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    eprintln!("ACME HTTP-01 responder on {http_addr}");
    let challenges = new_challenge_store();
    // Note: without PEBBLE_VA_ALWAYS_VALID=1, Pebble will try
    // http://<apex>:80/.well-known/... and won't reach an ephemeral
    // port — so this test only works with the "always valid" flag.
    let apex = "krot.test".to_string();
    let data_dir = TempDir::new().unwrap();

    // Run the ACME router alongside so /.well-known/acme-challenge/
    // requests are served.
    let router_task = tokio::spawn(krot_server::domain::run_http_router(
        http_listener,
        apex.clone(),
        Arc::new(krot_server::registry::TunnelRegistry::new(20_000..=20_010)),
        Arc::clone(&challenges),
    ));

    // acquire_cert honours the `directory: Option<&str>` override so
    // instant-acme talks to Pebble instead of Let's Encrypt.
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        acquire_cert(
            "acme@krot.test",
            &apex,
            Some(dir_url.as_str()),
            data_dir.path(),
            Arc::clone(&challenges),
        ),
    )
    .await;

    router_task.abort();

    let (chain, _key) = result
        .expect("acquire_cert timed out (60 s)")
        .expect("acquire_cert failed");
    assert!(
        !chain.is_empty(),
        "expected at least one certificate in the chain"
    );
}
