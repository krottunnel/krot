//! End-to-end IpMode test that drives the real client library against the
//! real server library — no raw quinn/rustls on the client side.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use krot_client::{enroll, publish_tcp, AuthenticatedSession, ClientConfig, EnrollOptions};
use krot_server::{Mode, Server, ServerConfig};

const PORT_POOL_LO: u16 = 19_100;
const PORT_POOL_HI: u16 = 19_150;

async fn boot_server(dir: &TempDir) -> Server {
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: PORT_POOL_LO..=PORT_POOL_HI,
        });
    Server::start(config).await.unwrap()
}

/// Bind a local TCP echo target on a random ephemeral port. Returns the
/// bound address and a task handle running the echo loop.
async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn client_end_to_end() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    let server = boot_server(&server_dir).await;
    let server_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let fingerprint = format!("sha256:{}", server.fingerprint_hex().unwrap());

    let server = Arc::new(server);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.run().await })
    };

    // Local target the tunnel should proxy to.
    let (echo_addr, _echo_handle) = spawn_echo().await;

    // ==== enroll ====
    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: server_addr.port(),
            sni: Some("krot.test".into()),
            admin_token: token,
            label_hint: Some("client-test".into()),
            pinned_fingerprint: Some(fingerprint.clone()),
        },
        client_dir.path(),
    )
    .await
    .unwrap();
    assert_eq!(
        cfg.server.fingerprint.as_deref(),
        Some(fingerprint.as_str())
    );

    // Config should be reloadable from disk.
    let reloaded = ClientConfig::load_from(client_dir.path()).unwrap();
    assert_eq!(reloaded.identity.public_key, cfg.identity.public_key);

    // ==== authenticate + publish ====
    let session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();
    let (published, tunnel_task, shutdown) = publish_tcp(session, "echo", echo_addr).await.unwrap();
    assert!(published.public_port.is_some());
    let public_port = published.public_port.unwrap();
    assert!((PORT_POOL_LO..=PORT_POOL_HI).contains(&public_port));

    // ==== external client hits the public port ====
    let mut external = TcpStream::connect((Ipv4Addr::LOCALHOST, public_port))
        .await
        .unwrap();
    external.write_all(b"through krot").await.unwrap();
    external.shutdown().await.unwrap();

    let mut got = Vec::new();
    external.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"through krot");

    // Tear the client tunnel down; verify the task exits cleanly within a
    // short window.
    drop(shutdown);
    tokio::time::timeout(Duration::from_secs(3), tunnel_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    server_task.abort();
}
