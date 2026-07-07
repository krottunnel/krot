//! §7.3 session-resume tests.
//!
//! Verifies that a TCP tunnel survives an abnormal QUIC disconnect: after
//! the client reconnects and presents its previous `session_id`, the
//! server re-attaches the SAME `tunnel_id` and public port to the new
//! connection instead of allocating a fresh one.

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
    sign_challenge, ClientFrame, DataHeader, ErrorCode, PubKey, ServerFrame, SessionId, StreamKind,
    TunnelId, TunnelKind, DATA_HEADER_SIZE,
};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

const SERVER_HOST: &str = "krot.test";
// The two tests in this file may run concurrently; each gets its
// own disjoint port pool so the underlying `TcpListener::bind` on
// `0.0.0.0:<port>` doesn't collide across processes' shared kernel.
const HAPPY_PATH_POOL_LO: u16 = 19_100;
const HAPPY_PATH_POOL_HI: u16 = 19_120;
const IDENTITY_MISMATCH_POOL_LO: u16 = 19_130;
const IDENTITY_MISMATCH_POOL_HI: u16 = 19_150;

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

async fn boot_server_with_pool(dir: &TempDir, pool: std::ops::RangeInclusive<u16>) -> Server {
    install_crypto_provider();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: pool,
        });
    Server::start(config).await.unwrap()
}

async fn enroll(endpoint: &KrotEndpoint, server_addr: SocketAddr, token: String, pubkey: PubKey) {
    let conn = endpoint
        .connect(server_addr, SERVER_HOST)
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(
        &mut send,
        &ClientFrame::Enroll {
            admin_token: token,
            pubkey,
            label_hint: Some("resume-test".into()),
        },
    )
    .await
    .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::EnrollOk { .. }),
        "got {reply:?}"
    );
    drop(conn);
}

/// Open a control stream, run auth, and return
/// `(connection, send, recv, session_id)`.
async fn auth(
    endpoint: &KrotEndpoint,
    server_addr: SocketAddr,
    signing: &SigningKey,
    pubkey: PubKey,
) -> (
    krot_transport::Connection,
    krot_transport::SendStream,
    krot_transport::RecvStream,
    SessionId,
) {
    let conn = endpoint
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
    let signature = sign_challenge(signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let ServerFrame::AuthOk { session_id } = read_frame(&mut recv).await.unwrap() else {
        panic!("expected AuthOk");
    };
    (conn, send, recv, session_id)
}

async fn register_tcp(
    send: &mut krot_transport::SendStream,
    recv: &mut krot_transport::RecvStream,
    label: &str,
    resume: Option<SessionId>,
) -> ServerFrame {
    write_frame(
        send,
        &ClientFrame::RegisterTunnel {
            label: label.into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: resume,
            inspect: false,
        },
    )
    .await
    .unwrap();
    read_frame(recv).await.unwrap()
}

/// Spawn an echo task on the client side: accept ONE server-opened bi
/// stream, verify header, echo bytes until EOF.
fn spawn_echo(
    conn: krot_transport::Connection,
    expected_id: TunnelId,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut ssend, mut srecv) = conn.accept_bi().await.unwrap();
        let mut header = [0u8; DATA_HEADER_SIZE];
        srecv.read_exact(&mut header).await.unwrap();
        let hdr = DataHeader::decode(&header).unwrap();
        assert_eq!(hdr.kind, StreamKind::DataTcp);
        assert_eq!(hdr.tunnel_id, expected_id);

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
    })
}

#[tokio::test]
async fn tcp_tunnel_resume_preserves_id_and_port() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,warn")
        .try_init();

    let dir = TempDir::new().unwrap();
    let server = boot_server_with_pool(&dir, HAPPY_PATH_POOL_LO..=HAPPY_PATH_POOL_HI).await;
    let server_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();

    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
    enroll(&client_ep, server_addr, token, pubkey).await;

    // ==== phase 1: register + verify tunnel works ====
    let (conn1, mut send1, mut recv1, session_id_1) =
        auth(&client_ep, server_addr, &signing, pubkey).await;
    let reply = register_tcp(&mut send1, &mut recv1, "svc", None).await;
    let (tunnel_id, port) = match reply {
        ServerFrame::TunnelRegistered {
            tunnel_id,
            public_port: Some(p),
            ..
        } => (tunnel_id, p),
        other => panic!("expected TunnelRegistered, got {other:?}"),
    };

    // Prove the first connection routes traffic.
    let echo1 = spawn_echo(conn1.clone(), tunnel_id);
    let mut ext = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    ext.write_all(b"round-one").await.unwrap();
    ext.shutdown().await.unwrap();
    let mut got = Vec::new();
    ext.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"round-one");
    echo1.await.unwrap();

    // ==== phase 2: abrupt disconnect (no Bye) ====
    conn1.close(0, b"simulated wifi drop");
    drop((send1, recv1, conn1));

    // Give the server a moment to notice and mark the tunnels Dangling.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ==== phase 3: reconnect + resume ====
    let (conn2, mut send2, mut recv2, session_id_2) =
        auth(&client_ep, server_addr, &signing, pubkey).await;
    assert_ne!(
        session_id_1.0, session_id_2.0,
        "server MUST issue a fresh session_id"
    );

    let reply = register_tcp(&mut send2, &mut recv2, "svc", Some(session_id_1)).await;
    let (tunnel_id_2, port_2) = match reply {
        ServerFrame::TunnelRegistered {
            tunnel_id,
            public_port: Some(p),
            ..
        } => (tunnel_id, p),
        other => panic!("expected TunnelRegistered, got {other:?}"),
    };
    assert_eq!(tunnel_id_2, tunnel_id, "resume MUST preserve tunnel_id");
    assert_eq!(port_2, port, "resume MUST preserve public port");

    // ==== phase 4: prove the resumed tunnel actually forwards ====
    let echo2 = spawn_echo(conn2.clone(), tunnel_id);
    let mut ext = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    ext.write_all(b"round-two").await.unwrap();
    ext.shutdown().await.unwrap();
    let mut got = Vec::new();
    ext.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"round-two");
    echo2.await.unwrap();

    // Clean shutdown.
    write_frame(&mut send2, &ClientFrame::Bye).await.unwrap();
    let _ = send2.finish();
    let _ = send2.stopped().await;
    server_task.abort();
}

#[tokio::test]
async fn resume_with_wrong_pubkey_gets_identity_mismatch() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,warn")
        .try_init();

    let dir = TempDir::new().unwrap();
    let server =
        boot_server_with_pool(&dir, IDENTITY_MISMATCH_POOL_LO..=IDENTITY_MISMATCH_POOL_HI).await;
    let server_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    // Issuing a second admin token requires the explicit flag on
    // startup. For this test we work around it by pre-populating
    // authorized_keys with the second identity through enrollment
    // BEFORE the first tunnel is registered (both identities enroll
    // before the resume attempt).
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let signing_a = SigningKey::generate(&mut OsRng);
    let pubkey_a = PubKey(signing_a.verifying_key().to_bytes());
    let signing_b = SigningKey::generate(&mut OsRng);
    let pubkey_b = PubKey(signing_b.verifying_key().to_bytes());

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();

    // Enroll A with the admin token.
    enroll(&client_ep, server_addr, token, pubkey_a).await;
    // Enroll B by manually appending to authorized_keys — the admin
    // token was consumed above and the server won't issue a fresh one
    // without an explicit restart flag.
    {
        use base64::Engine as _;
        let line = format!(
            "ed25519 {} subdomain=*\n",
            base64::engine::general_purpose::STANDARD.encode(pubkey_b.0),
        );
        let path = dir.path().join("authorized_keys");
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::write(&path, format!("{existing}{line}")).unwrap();
        // Let the hot-reloader pick it up.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // A registers a tunnel, then vanishes.
    let (conn_a, mut sa, mut ra, sid_a) = auth(&client_ep, server_addr, &signing_a, pubkey_a).await;
    let reply = register_tcp(&mut sa, &mut ra, "svc", None).await;
    assert!(matches!(reply, ServerFrame::TunnelRegistered { .. }));
    conn_a.close(0, b"drop");
    drop((sa, ra, conn_a));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // B tries to resume A's session_id.
    let (_conn_b, mut sb, mut rb, _sid_b) =
        auth(&client_ep, server_addr, &signing_b, pubkey_b).await;
    let reply = register_tcp(&mut sb, &mut rb, "svc", Some(sid_a)).await;
    match reply {
        ServerFrame::TunnelRejected { code, .. } => {
            assert_eq!(code, ErrorCode::RESUME_IDENTITY_MISMATCH, "wrong code");
        }
        other => panic!("expected TunnelRejected(RESUME_IDENTITY_MISMATCH), got {other:?}"),
    }

    server_task.abort();
}
