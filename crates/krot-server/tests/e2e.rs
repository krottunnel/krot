//! Full end-to-end IpMode test:
//! Enroll → Auth → RegisterTunnel{Tcp} → external TCP → local echo.

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
    sign_challenge, ClientFrame, DataHeader, PubKey, ServerFrame, StreamKind, TunnelKind,
    DATA_HEADER_SIZE,
};
use krot_server::{Mode, Server, ServerConfig};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

const SERVER_HOST: &str = "krot.test";
const PORT_POOL_LO: u16 = 19_000;
const PORT_POOL_HI: u16 = 19_050;

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

async fn open_control(
    endpoint: &KrotEndpoint,
    server_addr: SocketAddr,
) -> krot_transport::Connection {
    endpoint
        .connect(server_addr, SERVER_HOST)
        .unwrap()
        .await
        .unwrap()
}

#[tokio::test]
async fn ipmode_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krot_server=debug,krot_transport=warn,warn")
        .try_init();

    let dir = TempDir::new().unwrap();
    let server = boot_server(&dir).await;
    let server_addr = server.local_addr().unwrap();
    let token = server.issue_admin_token().unwrap();

    // Drive the server's accept loop in the background.
    let server = Arc::new(server);
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move {
        server_run.run().await;
    });

    // ==== phase 1: enrollment ====

    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = PubKey(signing.verifying_key().to_bytes());

    let client_ep = KrotEndpoint::client(loopback(), client_tls()).unwrap();
    {
        let conn = open_control(&client_ep, server_addr).await;
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[StreamKind::Control.as_byte()])
            .await
            .unwrap();
        write_frame(
            &mut send,
            &ClientFrame::Enroll {
                admin_token: token,
                pubkey,
                label_hint: Some("test".into()),
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

    // ==== phase 2: auth + tunnel registration ====

    let conn = open_control(&client_ep, server_addr).await;
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
            label: "echo".into(),
            kind: TunnelKind::Tcp { remote_port: None },
            resume_session_id: None,
            inspect: false,
        },
    )
    .await
    .unwrap();
    let ServerFrame::TunnelRegistered {
        public_port: Some(public_port),
        tunnel_id,
        ..
    } = read_frame(&mut recv).await.unwrap()
    else {
        panic!("expected TunnelRegistered");
    };
    assert!((PORT_POOL_LO..=PORT_POOL_HI).contains(&public_port));

    // ==== phase 3: client acts as a local echo ====

    // Accept the server-opened bi stream (one per incoming TCP connection).
    let conn_for_task = conn.clone();
    let echo_task = tokio::spawn(async move {
        let (mut ssend, mut srecv) = conn_for_task.accept_bi().await.unwrap();
        let mut header = [0u8; DATA_HEADER_SIZE];
        srecv.read_exact(&mut header).await.unwrap();
        let hdr = DataHeader::decode(&header).unwrap();
        assert_eq!(hdr.kind, StreamKind::DataTcp);
        assert_eq!(hdr.tunnel_id, tunnel_id);

        // Echo bytes back until EOF.
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

    // ==== phase 4: external TCP client ====

    let mut external = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)))
        .await
        .unwrap();
    external.write_all(b"hello krot").await.unwrap();
    external.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    external.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello krot");

    // Give the echo task a moment to finalise; then tear the session down.
    tokio::time::timeout(Duration::from_secs(2), echo_task)
        .await
        .unwrap()
        .unwrap();

    write_frame(&mut send, &ClientFrame::Bye).await.unwrap();
    let _ = send.finish();

    // The server task loops forever; abort it now that the test is done.
    server_task.abort();
}
