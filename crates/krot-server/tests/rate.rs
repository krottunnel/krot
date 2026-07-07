//! §9 rate-limiting tests.
//!
//! Verifies that once a client's period quota is exhausted the server
//! emits a `RateLimit` frame on the Control stream and closes any
//! in-flight data streams.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use krot_proto::{
    sign_challenge, ClientFrame, PubKey, ServerFrame, StreamKind, TunnelKind, DATA_HEADER_SIZE,
};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

const SERVER_HOST: &str = "krot.test";
const PORT_POOL_LO: u16 = 19_200;
const PORT_POOL_HI: u16 = 19_250;

#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

fn client_tls() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

async fn boot_server(dir: &TempDir) -> Server {
    install_crypto_provider();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: PORT_POOL_LO..=PORT_POOL_HI,
        });
    Server::start(config).await.unwrap()
}

/// Directly write an authorized_keys entry with a `quota=` option so we
/// bypass the `subdomain=*` default from the enrollment flow.
fn seed_authorized_keys(dir: &TempDir, pubkey: PubKey, options: &str) {
    use base64::Engine as _;
    let line = format!(
        "ed25519 {} {}\n",
        base64::engine::general_purpose::STANDARD.encode(pubkey.0),
        options,
    );
    let path = dir.path().join("authorized_keys");
    std::fs::write(&path, line).unwrap();
}

#[tokio::test]
async fn quota_exhaustion_emits_rate_limit_frame() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,warn")
        .try_init();

    let dir = TempDir::new().unwrap();
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());

    // Seed authorized_keys BEFORE booting so the first handshake reads
    // the quota=1KB/day cap.
    std::fs::create_dir_all(dir.path()).unwrap();
    seed_authorized_keys(&dir, pubkey, "subdomain=*,quota=1KB/day");

    let server = boot_server(&dir).await;
    let server_addr = server.local_addr().unwrap();

    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();

    // Auth.
    let conn = client_ep
        .connect(server_addr, SERVER_HOST)
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(&mut send, &ClientFrame::AuthRequest { pubkey })
        .await
        .unwrap();
    let ServerFrame::AuthChallenge { nonce } = read_frame(&mut recv).await.unwrap() else {
        panic!("expected AuthChallenge");
    };
    let signature = sign_challenge(&signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let ServerFrame::AuthOk { .. } = read_frame(&mut recv).await.unwrap() else {
        panic!("expected AuthOk");
    };

    // Register TCP tunnel.
    write_frame(
        &mut send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let (tunnel_id, port) = match read_frame(&mut recv).await.unwrap() {
        ServerFrame::TunnelRegistered {
            tunnel_id,
            public_port: Some(p),
            ..
        } => (tunnel_id, p),
        other => panic!("expected TunnelRegistered, got {other:?}"),
    };

    // Set up an echo task on the client side that swallows everything.
    let conn_task = conn.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut ssend, mut srecv)) = conn_task.accept_bi().await else {
                return;
            };
            let mut header = [0u8; DATA_HEADER_SIZE];
            if srecv.read_exact(&mut header).await.is_err() {
                return;
            }
            // Drain and echo until EOF or error.
            let mut buf = [0u8; 512];
            loop {
                let n = match srecv.read(&mut buf).await {
                    Ok(Some(0) | None) | Err(_) => break,
                    Ok(Some(n)) => n,
                };
                if ssend.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = ssend.finish();
        }
    });

    // Push more bytes than the quota through the public port. Cap is
    // 1KB/day = 1000 bytes; we shove 4KB and expect a RateLimit frame
    // to arrive on the control stream soon after.
    let mut ext = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    let payload = vec![b'x'; 4096];
    // A best-effort write — the server may reset the stream mid-write
    // once the quota trips. Errors here are expected.
    let _ = ext.write_all(&payload).await;
    let _ = ext.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = Vec::new();
        let _ = ext.read_to_end(&mut buf).await;
    })
    .await;

    // Wait for the RateLimit frame on the control stream (up to 3 s).
    let rl = tokio::time::timeout(Duration::from_secs(3), read_frame::<ServerFrame>(&mut recv))
        .await
        .expect("timed out waiting for RateLimit frame")
        .expect("read_frame failed");

    match rl {
        ServerFrame::RateLimit {
            tunnel_id: Some(tid),
            retry_after_ms,
        } => {
            assert_eq!(tid, tunnel_id, "RateLimit references the exhausted tunnel");
            assert!(
                retry_after_ms > 0,
                "retry_after_ms should be non-zero for a day-scoped quota"
            );
        }
        other => panic!("expected RateLimit frame, got {other:?}"),
    }

    write_frame(&mut send, &ClientFrame::Bye).await.unwrap();
    let _ = send.finish();
    server_task.abort();
}
