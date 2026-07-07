//! §16.1.4 end-to-end test: a full auth handshake over the
//! `krot-tcp/1` fallback transport.
//!
//! IpMode server binds both QUIC and the TCP fallback listener; the
//! client dials the TCP fallback via `connect_tcp_fallback`, gets a
//! `Connection`, opens the Control stream with the same code path a
//! QUIC client uses, and completes enrollment + auth. This proves
//! the wrapper enum plumbing is byte-transparent — the same
//! `handle_connection` / `Session` code drives both transports.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

use krot_proto::{sign_challenge, ClientFrame, PubKey, ServerFrame, StreamKind};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{connect_tcp_fallback, install_crypto_provider, read_frame, write_frame};

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

#[tokio::test]
async fn krot_tcp_1_auth_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,krot_transport=info,warn")
        .try_init();
    install_crypto_provider();

    let dir = TempDir::new().unwrap();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 22_500..=22_510,
        })
        .with_tcp_fallback_bind(loopback());
    let server = Server::start(config).await.unwrap();
    let tcp_addr = server
        .tcp_fallback_addr()
        .expect("TCP fallback listener should be bound");
    let token = server.issue_admin_token().unwrap();

    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    // Phase 1: enrollment over krot-tcp/1.
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());

    let connection = connect_tcp_fallback(tcp_addr, SERVER_HOST, client_tls())
        .await
        .expect("krot-tcp/1 dial succeeds");
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(
        &mut send,
        &ClientFrame::Enroll {
            admin_token: token,
            pubkey,
            label_hint: Some("tcp-fallback-test".into()),
        },
    )
    .await
    .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::EnrollOk { .. }),
        "expected EnrollOk over TCP fallback, got {reply:?}"
    );
    drop(connection);

    // Phase 2: auth on a fresh krot-tcp/1 connection.
    let connection = connect_tcp_fallback(tcp_addr, SERVER_HOST, client_tls())
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(&mut send, &ClientFrame::AuthRequest { pubkey })
        .await
        .unwrap();
    let ServerFrame::AuthChallenge { nonce } = read_frame(&mut recv).await.unwrap() else {
        panic!("expected AuthChallenge over TCP fallback");
    };
    let signature = sign_challenge(&signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::AuthOk { .. }),
        "expected AuthOk over TCP fallback, got {reply:?}"
    );

    server_task.abort();
}
