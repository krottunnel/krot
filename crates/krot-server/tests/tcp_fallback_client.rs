//! §16.1.5 client-side auto-fallback + §16.1.6 resume across transports.
//!
//! Two scenarios:
//!
//! 1. `auto_fallback_prefers_quic_and_falls_back`: server offers only
//!    the TCP listener (no QUIC endpoint on the ports the client
//!    reaches). Client's `AuthenticatedSession::connect` tries QUIC
//!    first, times out / fails, then retries `krot-tcp/1` and
//!    succeeds. Asserts `session.transport == TcpFallback`.
//!
//! 2. `session_resume_across_transports`: registers a TCP tunnel via
//!    QUIC, disconnects, resumes via `krot-tcp/1` presenting the old
//!    `session_id`, and asserts the same `tunnel_id` + `public_port`
//!    are handed back — proving §7.3 works uniformly across
//!    transports.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use krot_client::ServerPin;
use krot_client::{AuthenticatedSession, Identity, SessionTransport};
use krot_proto::{
    ClientFrame, DataHeader, PubKey, ServerFrame, StreamKind, TunnelKind, DATA_HEADER_SIZE,
};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame};

const SERVER_HOST: &str = "krot.test";

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

async fn enroll_and_get_identity(dir: &TempDir, tcp_addr: SocketAddr, token: String) -> Identity {
    // Enroll over krot-tcp/1 to produce a persisted Identity + fingerprint.
    // This drives the same wire the client library would use during
    // `enroll`, but does it manually so we don't need a fingerprint
    // pre-registered.
    use krot_transport::connect_tcp_fallback;
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());
    let connection = connect_tcp_fallback(tcp_addr, SERVER_HOST, client_tls())
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(
        &mut send,
        &ClientFrame::Enroll {
            admin_token: token,
            pubkey,
            label_hint: Some("tcp-fallback-client-test".into()),
        },
    )
    .await
    .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, ServerFrame::EnrollOk { .. }));
    drop(connection);
    let _ = dir;
    Identity {
        private_key: hex::encode(signing.to_bytes()),
        public_key: hex::encode(signing.verifying_key().to_bytes()),
    }
}

fn pin_for(host: &str, quic_port: u16, tcp_port: u16, fingerprint: &str) -> ServerPin {
    ServerPin {
        host: host.into(),
        quic_port,
        tcp_port: Some(tcp_port),
        sni: Some(SERVER_HOST.into()),
        fingerprint: Some(format!("sha256:{fingerprint}")),
    }
}

fn server_fingerprint(server: &Server) -> String {
    server.fingerprint_hex().expect("IpMode fingerprint").into()
}

// ==================================================================
// §16.1.5
// ==================================================================

#[tokio::test]
async fn auto_fallback_prefers_quic_and_falls_back() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_client=info,krot_server=info,warn")
        .try_init();
    install_crypto_provider();

    let dir = TempDir::new().unwrap();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 23_500..=23_510,
        })
        .with_tcp_fallback_bind(loopback());
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let tcp_addr = server.tcp_fallback_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let fingerprint = server_fingerprint(&server);
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let identity = enroll_and_get_identity(&dir, tcp_addr, token).await;

    // Point the client at a QUIC port that IS NOT bound (empty UDP
    // socket → connect will timeout). Real QUIC is at `quic_addr` but
    // we deliberately give the pin a different QUIC port to force
    // the fallback. The TCP port IS the real one.
    let dead_udp_port = quic_addr.port().wrapping_add(1);
    let pin = pin_for("127.0.0.1", dead_udp_port, tcp_addr.port(), &fingerprint);

    // AuthenticatedSession::connect should try QUIC (fail with
    // timeout), then retry TCP (succeed). We race it against a
    // shorter test-side timeout so a bug that hangs the fallback
    // fails the test loudly instead of running forever.
    let session = tokio::time::timeout(
        Duration::from_secs(25),
        AuthenticatedSession::connect(&pin, &identity),
    )
    .await
    .expect("connect timed out at test level")
    .expect("connect should succeed via TCP fallback");

    assert_eq!(
        session.transport,
        SessionTransport::TcpFallback,
        "expected fallback path, got {:?}",
        session.transport
    );

    session.shutdown().await;
    server_task.abort();
}

// ==================================================================
// §16.1.6
// ==================================================================

#[tokio::test]
async fn session_resume_across_transports() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_client=info,krot_server=info,warn")
        .try_init();
    install_crypto_provider();

    let dir = TempDir::new().unwrap();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 23_600..=23_610,
        })
        .with_tcp_fallback_bind(loopback());
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let tcp_addr = server.tcp_fallback_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let fingerprint = server_fingerprint(&server);
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let identity = enroll_and_get_identity(&dir, tcp_addr, token).await;

    // === phase 1: register over QUIC ===
    let pin = pin_for("127.0.0.1", quic_addr.port(), tcp_addr.port(), &fingerprint);
    let mut session = AuthenticatedSession::connect_quic(&pin, &identity)
        .await
        .unwrap();
    assert_eq!(session.transport, SessionTransport::Quic);
    let old_session_id = session.session_id;

    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let ServerFrame::TunnelRegistered {
        tunnel_id,
        public_port: Some(port),
        ..
    } = read_frame(&mut session.recv).await.unwrap()
    else {
        panic!("TunnelRegistered over QUIC");
    };

    // === phase 2: abrupt disconnect (no Bye) ===
    session.connection.close(0, b"simulated drop");
    drop(session);
    // Give the server a beat to mark tunnels Dangling.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // === phase 3: reconnect via TCP fallback + resume ===
    let mut resumed = AuthenticatedSession::connect_tcp(&pin, &identity)
        .await
        .unwrap();
    assert_eq!(resumed.transport, SessionTransport::TcpFallback);
    assert_ne!(
        resumed.session_id, old_session_id,
        "server MUST mint a fresh session_id post-resume"
    );

    write_frame(
        &mut resumed.send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: Some(old_session_id),
            inspect: false,
        },
    )
    .await
    .unwrap();
    let ServerFrame::TunnelRegistered {
        tunnel_id: resumed_tunnel_id,
        public_port: Some(resumed_port),
        ..
    } = read_frame(&mut resumed.recv).await.unwrap()
    else {
        panic!("TunnelRegistered on resume");
    };
    assert_eq!(
        resumed_tunnel_id, tunnel_id,
        "§7.3 resume MUST preserve tunnel_id across transports"
    );
    assert_eq!(
        resumed_port, port,
        "§7.3 resume MUST preserve public port across transports"
    );

    // === phase 4: prove the resumed tunnel actually forwards ===
    // Accept the server-initiated data stream on the client side
    // (this exercises the TCP-mux data-stream path — §16.1.7).
    let conn_for_task = resumed.connection.clone();
    let echo_task = tokio::spawn(async move {
        let (mut ssend, mut srecv) = conn_for_task.accept_bi().await.unwrap();
        let mut header = [0u8; DATA_HEADER_SIZE];
        srecv.read_exact(&mut header).await.unwrap();
        let hdr = DataHeader::decode(&header).unwrap();
        assert_eq!(hdr.tunnel_id, tunnel_id);
        let mut buf = [0u8; 1024];
        loop {
            let n = match srecv.read(&mut buf).await.unwrap() {
                Some(0) | None => break,
                Some(n) => n,
            };
            ssend.write_all(&buf[..n]).await.unwrap();
        }
        ssend.finish().unwrap();
        let _ = ssend.stopped().await;
    });

    let mut ext = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    ext.write_all(b"through-tcp-fallback").await.unwrap();
    ext.shutdown().await.unwrap();
    let mut got = Vec::new();
    use tokio::io::AsyncReadExt;
    ext.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"through-tcp-fallback");
    echo_task.await.unwrap();

    resumed.shutdown().await;
    server_task.abort();
    let _ = PathBuf::from(dir.path());
}
