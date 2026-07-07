//! DomainMode end-to-end: server with pemfile apex cert, HTTP-tunnel
//! registered under a label, external HTTP request routed to the tunnel
//! via `Host: <label>.<apex>`.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use krot_client::{enroll, publish_tcp, AuthenticatedSession, EnrollOptions};
use krot_server::{DomainTls, Mode, Server, ServerConfig};

const APEX: &str = "krot.test";

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Generate a self-signed cert for the apex, write PEM to `dir`, return
/// paths + hex-SHA256 of the SPKI (so we can pin from the client side).
fn gen_apex_pem(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![APEX.into(), format!("*.{APEX}")]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    let cert_path = dir.join("apex-cert.pem");
    let key_path = dir.join("apex-key.pem");
    fs::write(&cert_path, cert_pem).unwrap();
    fs::write(&key_path, key_pem).unwrap();

    // Compute SPKI SHA-256 for the client pin.
    let cert_der = cert.der().to_vec();
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(parsed.tbs_certificate.subject_pki.raw);
    let fp = hex::encode(hasher.finalize());
    (cert_path, key_path, fp)
}

async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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
async fn domain_http_tunnel_end_to_end() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    let (cert_path, key_path, fp_hex) = gen_apex_pem(server_dir.path());

    let config = ServerConfig::local_in(server_dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Domain {
            apex: APEX.into(),
            tls: DomainTls::PemFile {
                cert: cert_path,
                key: key_path,
            },
            http_bind: loopback(),
            https_bind: loopback(),
            tcp_port_pool: 20_000..=20_050,
        });

    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let http_addr = server.http_addr().expect("http listener bound");
    let _https_addr = server.https_addr().expect("https listener bound");
    let token = server.issue_admin_token().unwrap();

    let server = Arc::new(server);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.run().await })
    };

    // Local echo target the tunnel will proxy to.
    let (echo_addr, _echo_handle) = spawn_echo().await;

    // Enroll — pinning the apex cert SPKI so the QUIC handshake succeeds.
    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: quic_addr.port(),
            sni: Some(APEX.into()),
            admin_token: token,
            label_hint: Some("client-test".into()),
            pinned_fingerprint: Some(format!("sha256:{fp_hex}")),
        },
        client_dir.path(),
    )
    .await
    .unwrap();

    let session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();
    let (published, tunnel_task, shutdown) =
        publish_tcp_http(session, "alice", echo_addr).await.unwrap();

    assert!(published.public_url.starts_with("https://alice.krot.test"));
    assert!(published.public_port.is_none());

    // Simulate an external HTTP client hitting the router.
    let mut external = TcpStream::connect(http_addr).await.unwrap();
    let request = "GET / HTTP/1.1\r\nHost: alice.krot.test\r\nConnection: close\r\n\r\n";
    external.write_all(request.as_bytes()).await.unwrap();
    external.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    external.read_to_end(&mut echoed).await.unwrap();
    // The echo target mirrors every byte back verbatim, so we should see our
    // exact request bytes returning through the tunnel.
    assert_eq!(echoed.as_slice(), request.as_bytes());

    drop(shutdown);
    tokio::time::timeout(Duration::from_secs(3), tunnel_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    server_task.abort();
}

/// Local helper: publish a tunnel with `TunnelKind::Http` (the public
/// `publish_tcp` helper only registers `Tcp`). Reuses the client's proxy
/// machinery — the code path server-side is what we're actually exercising.
async fn publish_tcp_http(
    mut session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
) -> Result<
    (
        krot_client::tunnel::PublishedTunnel,
        tokio::task::JoinHandle<Result<(), krot_client::ClientError>>,
        tokio::sync::mpsc::Sender<()>,
    ),
    krot_client::ClientError,
> {
    use krot_proto::{ClientFrame, ServerFrame, TunnelKind};
    use krot_transport::{read_frame, write_frame};

    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: label.to_string(),
            kind: TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await?;

    let published = match read_frame::<ServerFrame>(&mut session.recv).await? {
        ServerFrame::TunnelRegistered {
            tunnel_id,
            public_url,
            public_port,
        } => krot_client::tunnel::PublishedTunnel {
            tunnel_id,
            public_url,
            public_port,
        },
        ServerFrame::TunnelRejected { code, detail } => {
            return Err(krot_client::ClientError::TunnelRejected(code, detail));
        }
        _ => {
            return Err(krot_client::ClientError::Protocol(
                "expected TunnelRegistered",
            ))
        }
    };

    let _ = publish_tcp; // silence unused import lint
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let tunnel_id = published.tunnel_id;
    let connection = session.connection.clone();

    let handle = tokio::spawn(async move {
        let keep_control = session;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    keep_control.shutdown().await;
                    return Ok(());
                }
                accept = connection.accept_bi() => {
                    match accept {
                        Ok((send, recv)) => {
                            tokio::spawn(async move {
                                let _ = krot_client::proxy::handle_bi(send, recv, tunnel_id, local_target).await;
                            });
                        }
                        Err(_) => return Ok(()),
                    }
                }
            }
        }
    });
    Ok((published, handle, shutdown_tx))
}
