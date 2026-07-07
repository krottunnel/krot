//! §16.1.8 test: DomainMode HTTPS listener dispatches `krot-tcp/1`
//! ALPN connections to the mux path.
//!
//! Boots a DomainMode server with only the QUIC UDP and HTTPS
//! listener (no separate `--tcp-fallback-bind`). Client dials
//! `https_addr` (443/tcp in prod), advertises ALPN `krot-tcp/1`, and
//! completes an Enroll handshake — proving the HTTPS listener
//! successfully split traffic between SNI-passthrough and mux-control.

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
use krot_server::{DomainTls, Mode, Server, ServerConfig};
use krot_transport::{connect_tcp_fallback, install_crypto_provider, read_frame, write_frame};

const APEX: &str = "krot.test";

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

fn self_signed_apex(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![APEX.into(), format!("*.{APEX}")]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = dir.join("apex-cert.pem");
    let key_path = dir.join("apex-key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

#[tokio::test]
async fn https_listener_dispatches_krot_tcp_alpn() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=info,krot_transport=info,warn")
        .try_init();
    install_crypto_provider();

    let dir = TempDir::new().unwrap();
    let (cert_path, key_path) = self_signed_apex(dir.path());

    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Domain {
            apex: APEX.into(),
            tls: DomainTls::PemFile {
                cert: cert_path,
                key: key_path,
            },
            http_bind: loopback(),
            https_bind: loopback(),
            tcp_port_pool: 24_000..=24_010,
        });
    let server = Server::start(config).await.unwrap();
    let https_addr = server.https_addr().unwrap();
    let token = server.issue_admin_token().unwrap();

    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    // Enroll over the HTTPS port using ALPN `krot-tcp/1` — the
    // dispatcher inside `run_https_router::handle` should route this
    // to the mux path instead of the SNI-passthrough branch.
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());
    let connection = connect_tcp_fallback(https_addr, APEX, client_tls())
        .await
        .expect("HTTPS listener should accept krot-tcp/1 ALPN");

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();
    write_frame(
        &mut send,
        &ClientFrame::Enroll {
            admin_token: token,
            pubkey,
            label_hint: Some("krot-tcp-on-443".into()),
        },
    )
    .await
    .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::EnrollOk { .. }),
        "expected EnrollOk over krot-tcp/1 on the HTTPS port, got {reply:?}"
    );

    // Phase 2: auth on a second krot-tcp/1 connection to the same
    // HTTPS port — confirms the split-listener path is durable
    // across multiple connections.
    let connection = connect_tcp_fallback(https_addr, APEX, client_tls())
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
        panic!("expected AuthChallenge over 443/tcp");
    };
    let signature = sign_challenge(&signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, ServerFrame::AuthOk { .. }));

    server_task.abort();
}
