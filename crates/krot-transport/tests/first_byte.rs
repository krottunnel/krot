//! Unit test for `run_bidirectional_with_first_byte_deadline`: two idle
//! `DuplexStream`s should die within the configured deadline; two
//! streams that write immediately should complete a full echo.

use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use krot_transport::run_bidirectional_with_first_byte_deadline;

#[tokio::test]
async fn stalled_streams_hit_deadline() {
    // `duplex` returns two connected in-memory streams. Neither will
    // produce a byte, so the deadline must fire.
    let (mut a, _dead_end_a) = duplex(64);
    let (mut b, _dead_end_b) = duplex(64);

    let res =
        run_bidirectional_with_first_byte_deadline(&mut a, &mut b, Duration::from_millis(100))
            .await;

    let err = res.expect_err("expected TimedOut");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "got {err:?}");
}

#[tokio::test]
async fn first_byte_defers_to_unbounded_copy() {
    // Wire two duplex pairs so that A ↔ external_a and B ↔ external_b.
    // Bytes written on external_a should reach external_b via the relay.
    let (mut a, mut external_a) = duplex(4096);
    let (mut b, mut external_b) = duplex(4096);

    // Drive a byte through as soon as the relay is polled.
    external_a.write_all(b"hi").await.unwrap();
    external_a.shutdown().await.unwrap();

    let relay =
        run_bidirectional_with_first_byte_deadline(&mut a, &mut b, Duration::from_millis(500));

    let read_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        external_b.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let _ = relay.await.unwrap();
    let got = read_task.await.unwrap();
    assert_eq!(got, b"hi");
}
