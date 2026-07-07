//! §16.2 passive HTTP inspection: prelude round-trip test.
//!
//! Registers a TCP tunnel with `inspect = true`, opens a public TCP
//! connection, and asserts the client-side reads (a) the DataHeader
//! and then (b) an `InspectionPrelude` carrying the observed peer
//! address before the tunneled payload starts.

use std::net::{Ipv4Addr, SocketAddr};
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

use krot_proto::{
    sign_challenge, ClientFrame, DataHeader, InspectionPrelude, PubKey, ServerFrame, StreamKind,
    TunnelKind, DATA_HEADER_SIZE,
};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

const SERVER_HOST: &str = "krot.test";
const PORT_POOL_LO: u16 = 19_300;
const PORT_POOL_HI: u16 = 19_320;

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

#[tokio::test]
async fn tcp_tunnel_inspect_prepends_prelude() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,warn")
        .try_init();

    let dir = TempDir::new().unwrap();
    let server = boot_server(&dir).await;
    let server_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();

    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();

    // Enroll.
    {
        let conn = client_ep
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
                label_hint: Some("inspect-test".into()),
            },
        )
        .await
        .unwrap();
        let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
        assert!(matches!(reply, ServerFrame::EnrollOk { .. }));
    }

    // Auth + register with inspect: true.
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

    write_frame(
        &mut send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: None,
            inspect: true,
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

    // Client side: accept a data stream, read header + prelude + first
    // byte, echo. Send back the observed prelude on a channel so the
    // driver can assert.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<InspectionPrelude>();
    let conn_task = conn.clone();
    let echo_task = tokio::spawn(async move {
        let (mut ssend, mut srecv) = conn_task.accept_bi().await.unwrap();
        // DataHeader.
        let mut hbuf = [0u8; DATA_HEADER_SIZE];
        srecv.read_exact(&mut hbuf).await.unwrap();
        let hdr = DataHeader::decode(&hbuf).unwrap();
        assert_eq!(hdr.tunnel_id, tunnel_id);
        // Length-prefixed InspectionPrelude.
        let prelude: InspectionPrelude = read_frame(&mut srecv).await.unwrap();
        let _ = tx.send(prelude);
        // Drain and echo until EOF.
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
    });

    // Drive a public-side connection.
    let mut ext = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    ext.write_all(b"hello").await.unwrap();
    ext.shutdown().await.unwrap();

    // Grab the prelude the client saw and assert it looks right.
    let prelude = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("prelude channel timed out")
        .expect("prelude channel closed");
    assert!(prelude.accept_unix_secs > 1_700_000_000);
    assert!(
        prelude.peer.starts_with("127.0.0.1:"),
        "unexpected peer {}",
        prelude.peer
    );
    assert!(
        prelude.http.is_none(),
        "TCP tunnel MUST NOT carry HTTP metadata"
    );

    // Clean up.
    let _ = echo_task.await;
    write_frame(&mut send, &ClientFrame::Bye).await.unwrap();
    let _ = send.finish();
    server_task.abort();
}
