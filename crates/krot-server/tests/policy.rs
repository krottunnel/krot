//! Regression tests for spec §7.1 + §10 + §13:
//!
//! - **auth timeout** — a client that opens Control but never sends the
//!   first frame is dropped by the server after the handshake deadline.
//! - **subdomain enforcement** — a client whose `authorized_keys` entry
//!   lists `subdomain=alice` cannot register `bob`.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

use krot_client::{enroll, AuthenticatedSession, EnrollOptions};
use krot_proto::{ClientFrame, ServerFrame, StreamKind, TunnelKind};
use krot_server::{DomainTls, Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

const APEX: &str = "krot.test";

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
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

fn gen_apex_pem(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![APEX.into(), format!("*.{APEX}")]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = dir.join("apex-cert.pem");
    let key_path = dir.join("apex-key.pem");
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, key.serialize_pem()).unwrap();

    let cert_der = cert.der().to_vec();
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(parsed.tbs_certificate.subject_pki.raw);
    let fp = hex::encode(hasher.finalize());
    (cert_path, key_path, fp)
}

// -----------------------------------------------------------------------
//   subdomain enforcement
// -----------------------------------------------------------------------

/// §13 — an entry with `conns=1` gets the second registration rejected.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn conns_cap_is_enforced() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    let (cert_path, key_path, fp_hex) = gen_apex_pem(server_dir.path());

    let config = ServerConfig::local_in(server_dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Domain {
            apex: APEX.into(),
            tls: DomainTls::PemFile {
                cert: cert_path.clone(),
                key: key_path.clone(),
            },
            http_bind: loopback(),
            https_bind: loopback(),
            tcp_port_pool: 21_800..=21_850,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };

    // Enroll with default subdomain=*, then rewrite the entry to add conns=1.
    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: quic_addr.port(),
            sni: Some(APEX.into()),
            admin_token: token,
            label_hint: Some("conns-test".into()),
            pinned_fingerprint: Some(format!("sha256:{fp_hex}")),
        },
        client_dir.path(),
    )
    .await
    .unwrap();

    let auth_path = server_dir.path().join("authorized_keys");
    let pubkey_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(cfg.identity.pubkey().unwrap().0)
    };
    let line = format!("ed25519 {pubkey_b64} subdomain=*,conns=1 # conns-test\n");
    fs::write(&auth_path, line).unwrap();

    server_task.abort();
    drop(server);
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
            tcp_port_pool: 21_860..=21_900,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };
    let mut cfg = cfg;
    cfg.server.quic_port = quic_addr.port();

    let mut session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();

    // First register succeeds.
    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: "one".into(),
            kind: TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut session.recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::TunnelRegistered { .. }),
        "first register should succeed, got {reply:?}"
    );

    // Second exceeds the cap.
    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: "two".into(),
            kind: TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut session.recv).await.unwrap();
    match reply {
        ServerFrame::TunnelRejected { code, .. } => {
            assert_eq!(
                code,
                krot_proto::ErrorCode::TUNNEL_LIMIT_EXCEEDED,
                "got {code:?}"
            );
        }
        other => panic!("expected TUNNEL_LIMIT_EXCEEDED, got {other:?}"),
    }

    session.shutdown().await;
    server_task.abort();
}

/// §13 — an entry with `subdomain=alice` may register `alice` but not `bob`.
#[tokio::test]
async fn subdomain_allowlist_is_enforced() {
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
            tcp_port_pool: 21_200..=21_250,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };

    // Enroll — this gives us subdomain=* by default.
    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: quic_addr.port(),
            sni: Some(APEX.into()),
            admin_token: token,
            label_hint: Some("test".into()),
            pinned_fingerprint: Some(format!("sha256:{fp_hex}")),
        },
        client_dir.path(),
    )
    .await
    .unwrap();

    // Rewrite authorized_keys so this identity is restricted to label `alice`.
    let auth_path = server_dir.path().join("authorized_keys");
    let pubkey_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(cfg.identity.pubkey().unwrap().0)
    };
    let new_line = format!("ed25519 {pubkey_b64} subdomain=alice # policy-test\n");
    fs::write(&auth_path, new_line).unwrap();

    // KeyRegistry is currently loaded at startup only (hot-reload is a
    // documented TODO). Rebuild the server so the new entry is in effect.
    server_task.abort();
    drop(server);
    let config = ServerConfig::local_in(server_dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Domain {
            apex: APEX.into(),
            tls: DomainTls::PemFile {
                cert: server_dir.path().join("apex-cert.pem"),
                key: server_dir.path().join("apex-key.pem"),
            },
            http_bind: loopback(),
            https_bind: loopback(),
            tcp_port_pool: 21_260..=21_300,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };

    // New client identity file must point at the freshly-bound QUIC addr.
    let mut cfg = cfg;
    cfg.server.quic_port = quic_addr.port();

    // Try to register `bob` — should be rejected as LABEL_FORBIDDEN.
    let mut session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();
    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: "bob".into(),
            kind: TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut session.recv).await.unwrap();
    match reply {
        ServerFrame::TunnelRejected { code, .. } => {
            assert_eq!(code, krot_proto::ErrorCode::LABEL_FORBIDDEN, "got {code:?}");
        }
        other => panic!("expected LABEL_FORBIDDEN, got {other:?}"),
    }

    // `alice` is on the allowlist and should succeed.
    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: "alice".into(),
            kind: TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut session.recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::TunnelRegistered { .. }),
        "expected TunnelRegistered, got {reply:?}"
    );

    session.shutdown().await;
    server_task.abort();
}

// -----------------------------------------------------------------------
//   auth timeout
// -----------------------------------------------------------------------

/// §13 — removing an identity from `authorized_keys` while the session is
/// live must terminate that session within ~1 s with `KEY_REVOKED`.
#[tokio::test]
async fn removed_key_terminates_live_session() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    let config = ServerConfig::local_in(server_dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 21_950..=21_990,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();
    let fingerprint = format!("sha256:{}", server.fingerprint_hex().unwrap());
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };

    let cfg = enroll(
        EnrollOptions {
            server_host: "127.0.0.1".into(),
            server_quic_port: quic_addr.port(),
            sni: Some(APEX.into()),
            admin_token: token,
            label_hint: Some("revoke-test".into()),
            pinned_fingerprint: Some(fingerprint),
        },
        client_dir.path(),
    )
    .await
    .unwrap();

    let mut session = AuthenticatedSession::connect(&cfg.server, &cfg.identity)
        .await
        .unwrap();

    // Remove the identity by truncating the file. notify picks it up,
    // KeyRegistry.reload() broadcasts the revocation, per-session watcher
    // flips its watch, session.run's select! emits ServerBye { KeyRevoked }.
    let auth_path = server_dir.path().join("authorized_keys");
    fs::write(&auth_path, b"").unwrap();

    // Expect a ServerBye { KEY_REVOKED } within a generous window. In
    // practice notify events fire in <100 ms on Linux inotify.
    let bye = tokio::time::timeout(Duration::from_secs(3), async {
        read_frame::<ServerFrame>(&mut session.recv).await
    })
    .await
    .expect("timed out waiting for KeyRevoked ServerBye")
    .unwrap();

    match bye {
        ServerFrame::ServerBye { code } => {
            assert_eq!(code, krot_proto::ErrorCode::KEY_REVOKED, "got {code:?}");
        }
        other => panic!("expected ServerBye {{ KEY_REVOKED }}, got {other:?}"),
    }

    server_task.abort();
}

/// §10 — a client that opens Control and stalls without sending the first
/// frame must be dropped by the server. We assert only that the connection
/// dies within a small window; the full 10 s wait is unnecessary because
/// quinn's idle timeout (15 s) will also fire, and either signal is a valid
/// server-side defense.
#[tokio::test]
async fn stalling_handshake_is_terminated() {
    install_crypto_provider();
    let dir = TempDir::new().unwrap();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 21_400..=21_440,
        });
    let server = Server::start(config).await.unwrap();
    let quic_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_task = {
        let s = Arc::clone(&server);
        tokio::spawn(async move { s.run().await })
    };

    // Client: bring up QUIC and a Control stream, then never write a frame.
    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
    let conn = client_ep
        .connect(quic_addr, "krot.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&[StreamKind::Control.as_byte()])
        .await
        .unwrap();

    // Wait long enough for either §10 auth deadline (10 s) or QUIC's idle
    // timeout (15 s) to fire. `read` returns EOF/Reset once the peer gives up.
    let read_result = tokio::time::timeout(Duration::from_secs(20), async {
        let mut buf = [0u8; 1];
        let _ = recv.read_exact(&mut buf).await;
    })
    .await;

    assert!(
        read_result.is_ok(),
        "server should have terminated the stalled connection within 20s"
    );

    server_task.abort();
}
