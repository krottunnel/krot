//! End-to-end transport tests.
//!
//! Boots a real `KrotEndpoint` server + client on loopback with a
//! self-signed certificate, then exercises:
//!
//! - QUIC handshake with the `krot/1` ALPN (implicit: `connect().await`
//!   succeeds only when both sides advertise the same protocol)
//! - length-prefixed frame round-trip on a bidirectional stream
//! - byte-level relay through [`BidiStream`]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use krot_proto::{ClientFrame, ServerFrame};
use krot_transport::{
    install_crypto_provider, read_frame, run_bidirectional, write_frame, BidiStream, KrotEndpoint,
};

const TEST_HOST: &str = "krot.test";

fn init() {
    install_crypto_provider();
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn server_tls() -> rustls::ServerConfig {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![TEST_HOST.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .unwrap()
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

/// Result of [`dial`]. All four handles MUST stay alive for the duration of
/// the test: dropping either endpoint tears down its UDP socket and every
/// connection routed through it.
struct Wire {
    _server_ep: KrotEndpoint,
    _client_ep: KrotEndpoint,
    server_conn: krot_transport::Connection,
    client_conn: krot_transport::Connection,
}

async fn dial() -> Wire {
    let server = KrotEndpoint::server(loopback(), server_tls()).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = KrotEndpoint::client(loopback(), client_tls()).unwrap();

    let server_side = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.expect("no incoming");
            incoming.accept().await.expect("server handshake failed")
        }
    });

    let client_conn = client
        .connect(server_addr, TEST_HOST)
        .unwrap()
        .await
        .expect("client handshake failed");

    let server_conn = server_side.await.unwrap();

    Wire {
        _server_ep: server,
        _client_ep: client,
        server_conn,
        client_conn,
    }
}

/// §2.1 — a client advertising both a future `krot/99` and the current
/// `krot/1` still connects; rustls picks the highest common entry.
#[tokio::test]
async fn alpn_list_negotiates_highest_common() {
    init();

    let server = KrotEndpoint::server(loopback(), server_tls()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_side = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.expect("no incoming");
            incoming.accept().await.expect("server handshake failed")
        }
    });

    // Client claims to prefer krot/99 (a future version this server has
    // never heard of); it MUST fall back to krot/1 because the server only
    // advertises that.
    let client = KrotEndpoint::client_with_alpn(
        loopback(),
        client_tls(),
        &[b"krot/99", krot_proto::consts::ALPN],
    )
    .unwrap();

    let _client_conn = client
        .connect(server_addr, TEST_HOST)
        .unwrap()
        .await
        .expect("client handshake failed");
    let _server_conn = server_side.await.unwrap();
    // If we got here the handshake succeeded — rustls picked `krot/1` for us.
}

/// §2.1 — a client whose advertised list has no overlap with the server's
/// MUST fail the TLS handshake with `no_application_protocol`.
#[tokio::test]
async fn alpn_mismatch_rejects_handshake() {
    init();

    let server = KrotEndpoint::server(loopback(), server_tls()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_side = tokio::spawn({
        let server = server.clone();
        async move {
            // The accept task should either not complete or the resulting
            // connection should error out; either way is fine for this test.
            server.accept().await
        }
    });

    let client = KrotEndpoint::client_with_alpn(loopback(), client_tls(), &[b"krot/99"]).unwrap();

    let result = client.connect(server_addr, TEST_HOST).unwrap().await;
    assert!(
        result.is_err(),
        "handshake should have failed on ALPN mismatch, got Ok"
    );
    server_side.abort();
}

#[tokio::test]
async fn frame_roundtrip_over_quic() {
    init();
    let wire = dial().await;
    let server_conn = wire.server_conn.clone();
    let client_conn = wire.client_conn.clone();

    // Server: accept one bi-stream, read Ping, write Pong, close send.
    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server_conn.accept_bi().await.unwrap();
        let frame: ClientFrame = read_frame(&mut recv).await.unwrap();
        assert!(matches!(frame, ClientFrame::Ping { nonce: 42 }));
        write_frame(&mut send, &ServerFrame::Pong { nonce: 42 })
            .await
            .unwrap();
        send.finish().unwrap();
        // Wait for the peer to acknowledge the close so the stream is fully torn down.
        let _ = send.stopped().await;
    });

    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
    write_frame(&mut send, &ClientFrame::Ping { nonce: 42 })
        .await
        .unwrap();
    send.finish().unwrap();

    let reply: ServerFrame = read_frame(&mut recv).await.unwrap();
    assert!(matches!(reply, ServerFrame::Pong { nonce: 42 }));

    server_task.await.unwrap();
}

#[tokio::test]
async fn bidi_relay_echoes_bytes() {
    init();
    let wire = dial().await;
    let server_conn = wire.server_conn.clone();
    let client_conn = wire.client_conn.clone();

    // Server: manual echo — read until EOF, write back, finish.
    let server_task = tokio::spawn(async move {
        let (mut send, mut recv) = server_conn.accept_bi().await.unwrap();
        let mut buf = Vec::new();
        AsyncReadExt::read_to_end(&mut recv, &mut buf)
            .await
            .unwrap();
        send.write_all(&buf).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
    });

    // Client: use BidiStream (the type under test) for reads and writes.
    let (send, recv) = client_conn.open_bi().await.unwrap();
    let mut bidi = BidiStream::new(send, recv);

    let payload = b"hello krot".to_vec();
    bidi.write_all(&payload).await.unwrap();
    // Close write half so server's read_to_end can complete.
    bidi.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    bidi.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    server_task.await.unwrap();
}

#[tokio::test]
async fn run_bidirectional_bridges_two_streams() {
    init();
    let wire = dial().await;
    let server_conn = wire.server_conn.clone();
    let client_conn = wire.client_conn.clone();

    // Server: bridge stream A ↔ stream B via run_bidirectional.
    let server_task = tokio::spawn(async move {
        let (send_a, recv_a) = server_conn.accept_bi().await.unwrap();
        let (send_b, recv_b) = server_conn.accept_bi().await.unwrap();
        let mut a = BidiStream::new(send_a, recv_a);
        let mut b = BidiStream::new(send_b, recv_b);
        run_bidirectional(&mut a, &mut b).await.unwrap();
    });

    let (mut send_a, mut recv_a) = client_conn.open_bi().await.unwrap();
    let (mut send_b, mut recv_b) = client_conn.open_bi().await.unwrap();

    // Bytes written on A must appear on B, and vice versa.
    send_a.write_all(b"ping").await.unwrap();
    send_a.finish().unwrap();
    send_b.write_all(b"pong").await.unwrap();
    send_b.finish().unwrap();

    let mut buf_b = Vec::new();
    AsyncReadExt::read_to_end(&mut recv_b, &mut buf_b)
        .await
        .unwrap();
    let mut buf_a = Vec::new();
    AsyncReadExt::read_to_end(&mut recv_a, &mut buf_a)
        .await
        .unwrap();

    assert_eq!(buf_b, b"ping");
    assert_eq!(buf_a, b"pong");

    server_task.await.unwrap();
}
