//! §16.3.2 + §16.3.3 integration test.
//!
//! Seeds an `authorized_keys` entry with a `federation=` allowlist,
//! writes a static `peers.txt` on disk, boots the server, authenticates
//! as that identity, and issues `ClientFrame::ListPeers`. Asserts the
//! response is the exact intersection of the two lists.

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
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

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

fn seed_authorized_keys(dir: &TempDir, pubkey: PubKey, options: &str) {
    use base64::Engine as _;
    let line = format!(
        "ed25519 {} {}\n",
        base64::engine::general_purpose::STANDARD.encode(pubkey.0),
        options,
    );
    std::fs::write(dir.path().join("authorized_keys"), line).unwrap();
}

fn seed_peers(dir: &TempDir, peers: &[&str]) {
    let body = peers.join("\n") + "\n";
    std::fs::write(dir.path().join("peers.txt"), body).unwrap();
}

async fn boot(dir: &TempDir) -> Server {
    install_crypto_provider();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 21_500..=21_510,
        });
    Server::start(config).await.unwrap()
}

async fn drive_list_peers(dir: &TempDir) -> Vec<String> {
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());
    // Seed authorized_keys BEFORE booting so the KeyRegistry reads it.
    // The signing identity here needs `subdomain=*` to auth (parse
    // succeeds without it; the allowlist doesn't gate ListPeers).
    seed_authorized_keys(dir, pubkey, "subdomain=* federation=a.example,c.example");

    let server = boot(dir).await;
    let server_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
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

    write_frame(&mut send, &ClientFrame::ListPeers)
        .await
        .unwrap();
    let ServerFrame::Peers { relays } = read_frame(&mut recv).await.unwrap() else {
        panic!("expected Peers response");
    };

    write_frame(&mut send, &ClientFrame::Bye).await.unwrap();
    let _ = send.finish();
    server_task.abort();
    relays
}

#[tokio::test]
async fn list_peers_returns_intersection() {
    let dir = TempDir::new().unwrap();
    seed_peers(&dir, &["a.example", "b.example", "c.example"]);
    // identity is authorized for a and c; b is on the server but
    // not in the identity's federation=.
    let relays = drive_list_peers(&dir).await;
    assert_eq!(
        relays,
        vec!["a.example".to_string(), "c.example".to_string()]
    );
}

#[tokio::test]
async fn list_peers_empty_when_no_overlap() {
    let dir = TempDir::new().unwrap();
    // Server has peers, but none match the identity's federation=.
    seed_peers(&dir, &["x.example", "y.example"]);
    let relays = drive_list_peers(&dir).await;
    assert!(
        relays.is_empty(),
        "expected empty relay list, got {relays:?}"
    );
}

#[tokio::test]
async fn list_peers_empty_when_no_static_list() {
    let dir = TempDir::new().unwrap();
    // No peers.txt at all → server has nothing to offer.
    let relays = drive_list_peers(&dir).await;
    assert!(relays.is_empty());
}

// ==================================================================
// §16.3.4 cross-relay collision detection
// ==================================================================

use async_trait::async_trait;
use krot_server::peer_lookup::{PeerLabelLookup, PeerLookupOutcome};
use std::sync::Mutex;

#[derive(Debug, Default)]
struct MockPeerLookup {
    // (peer, label) → outcome. Anything not preset is NotFound.
    table: Mutex<std::collections::HashMap<(String, String), PeerLookupOutcome>>,
}

impl MockPeerLookup {
    fn insert(&self, peer: &str, label: &str, outcome: PeerLookupOutcome) {
        self.table
            .lock()
            .unwrap()
            .insert((peer.into(), label.into()), outcome);
    }
}

#[async_trait]
impl PeerLabelLookup for MockPeerLookup {
    async fn find_owner(&self, peer: &str, label: &str) -> PeerLookupOutcome {
        self.table
            .lock()
            .unwrap()
            .get(&(peer.into(), label.into()))
            .copied()
            .unwrap_or(PeerLookupOutcome::NotFound)
    }
}

async fn boot_domain(dir: &TempDir, apex: &str, lookup: Arc<dyn PeerLabelLookup>) -> Server {
    install_crypto_provider();
    // Generate self-signed cert for the apex so DomainMode can boot
    // without ACME.
    let (cert_pem, key_pem) = self_signed_pem(apex);
    let cert_path = dir.path().join("apex.pem");
    let key_path = dir.path().join("apex.key");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let http_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let https_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = krot_server::ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(krot_server::Mode::Domain {
            apex: apex.into(),
            tls: krot_server::DomainTls::PemFile {
                cert: cert_path,
                key: key_path,
            },
            http_bind,
            https_bind,
            tcp_port_pool: 22_000..=22_010,
        });
    Server::start(config)
        .await
        .unwrap()
        .with_peer_lookup(lookup)
}

fn self_signed_pem(apex: &str) -> (String, String) {
    let params = rcgen::CertificateParams::new(vec![apex.to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn register_http_rejects_when_peer_has_different_owner() {
    let dir = TempDir::new().unwrap();

    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());
    seed_authorized_keys(&dir, pubkey, "subdomain=* federation=peer.example");
    seed_peers(&dir, &["peer.example"]);

    // Mock: peer.example claims `svc` is owned by a DIFFERENT pubkey.
    let lookup = Arc::new(MockPeerLookup::default());
    lookup.insert(
        "peer.example",
        "svc",
        PeerLookupOutcome::Found(PubKey([0xFF; 32])),
    );
    let server = boot_domain(&dir, "krot.test", lookup).await;
    let server_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
    let conn = client_ep
        .connect(server_addr, "krot.test")
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
        panic!("AuthChallenge");
    };
    let signature = sign_challenge(&signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let ServerFrame::AuthOk { .. } = read_frame(&mut recv).await.unwrap() else {
        panic!("AuthOk");
    };

    write_frame(
        &mut send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: krot_proto::TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut recv).await.unwrap();
    let ServerFrame::TunnelRejected { code, detail } = reply else {
        panic!("expected TunnelRejected, got {reply:?}");
    };
    assert_eq!(code, krot_proto::ErrorCode::LABEL_UNAVAILABLE);
    assert!(
        detail.contains("peer.example"),
        "expected conflicting peer in detail, got {detail:?}"
    );

    server_task.abort();
}

#[tokio::test]
async fn register_http_allowed_when_peer_has_same_owner() {
    let dir = TempDir::new().unwrap();

    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());
    seed_authorized_keys(&dir, pubkey, "subdomain=* federation=peer.example");
    seed_peers(&dir, &["peer.example"]);

    // Mock: peer.example has `svc`, owned by the SAME identity — this
    // is the "additional destination" case, so registration proceeds.
    let lookup = Arc::new(MockPeerLookup::default());
    lookup.insert("peer.example", "svc", PeerLookupOutcome::Found(pubkey));
    let server = boot_domain(&dir, "krot.test", lookup).await;
    let server_addr = server.local_addr().unwrap();
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
    let conn = client_ep
        .connect(server_addr, "krot.test")
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
        panic!("AuthChallenge");
    };
    let signature = sign_challenge(&signing, &nonce);
    write_frame(&mut send, &ClientFrame::AuthResponse { signature })
        .await
        .unwrap();
    let ServerFrame::AuthOk { .. } = read_frame(&mut recv).await.unwrap() else {
        panic!("AuthOk");
    };

    write_frame(
        &mut send,
        &ClientFrame::RegisterTunnel {
            label: "svc".into(),
            kind: krot_proto::TunnelKind::Http,
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let reply = read_frame::<ServerFrame>(&mut recv).await.unwrap();
    assert!(
        matches!(reply, ServerFrame::TunnelRegistered { .. }),
        "expected TunnelRegistered, got {reply:?}"
    );

    server_task.abort();
}
