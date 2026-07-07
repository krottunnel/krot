//! Smoke test for `Server::run_multicore`: 4 worker threads binding a
//! `SO_REUSEPORT` UDP endpoint on the same fixed port, one client from the
//! outside enrolls + authenticates, then we trigger graceful shutdown and
//! join the workers.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::watch;

use krot_client::{enroll, AuthenticatedSession, EnrollOptions};
use krot_server::{Mode, Server, ServerConfig};

const PORT_POOL_LO: u16 = 21_000;
const PORT_POOL_HI: u16 = 21_050;

/// Pick an ephemeral UDP port by binding+dropping a probe socket. Small race
/// window before workers rebind SO_REUSEPORT, but harmless for a test.
fn pick_free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multicore_boots_and_shuts_down_gracefully() {
    let dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();
    let port = pick_free_udp_port();

    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: PORT_POOL_LO..=PORT_POOL_HI,
        });

    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let fingerprint = format!("sha256:{}", server.fingerprint_hex().unwrap());
    let shared = Arc::clone(server.shared());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mc_handle = std::thread::spawn(move || {
        server.run_multicore(4, &shutdown_rx).unwrap();
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: quic_addr.port(),
            sni: Some("krot.test".into()),
            admin_token: token,
            label_hint: None,
            pinned_fingerprint: Some(fingerprint),
        },
        client_dir.path(),
    )
    .await
    .unwrap();

    let session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();
    session.shutdown().await;

    assert!(shared.registry.is_empty(), "no tunnels expected after Bye");

    // Trigger graceful shutdown; workers must exit within a reasonable window.
    shutdown_tx.send(true).unwrap();
    let joined = tokio::task::spawn_blocking(move || mc_handle.join());
    tokio::time::timeout(Duration::from_secs(10), joined)
        .await
        .expect("multicore did not shut down within 10s")
        .unwrap()
        .unwrap();
}
