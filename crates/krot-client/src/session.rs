//! Authenticated Control-stream session state on the client side.

use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::lookup_host;
use tracing::{debug, info, warn};

use krot_proto::{sign_challenge, ClientFrame, ServerFrame, SessionId, StreamKind};
use krot_transport::{
    connect_tcp_fallback, install_crypto_provider, read_frame, write_frame, Connection,
    KrotEndpoint,
};

use crate::config::{ClientConfig, Identity, ServerPin};
use crate::error::ClientError;
use crate::tls;

/// Which transport landed us on the server. Exposed on
/// [`AuthenticatedSession::transport`] so callers can log or drive
/// per-transport telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTransport {
    Quic,
    TcpFallback,
}

/// A fully-authenticated Control stream on top of a live connection —
/// either QUIC (`krot/1`) or TLS-over-TCP (`krot-tcp/1`, §16.1).
#[derive(Debug)]
pub struct AuthenticatedSession {
    pub connection: krot_transport::Connection,
    pub send: krot_transport::SendStream,
    pub recv: krot_transport::RecvStream,
    pub session_id: SessionId,
    pub transport: SessionTransport,
    /// Kept alive for the lifetime of the session so the QUIC UDP
    /// socket doesn't drop while streams are in flight. `None` for
    /// the TCP fallback path — the TCP socket lives inside
    /// `connection`.
    _endpoint: Option<KrotEndpoint>,
}

impl AuthenticatedSession {
    /// Connect to `pin` with §16.1 auto-fallback: try QUIC first,
    /// and on any transport-level failure retry once against the same
    /// host over `krot-tcp/1`. On success runs the Ed25519
    /// challenge-response and returns the resulting session with its
    /// Control stream ready for tunnel frames.
    pub async fn connect(pin: &ServerPin, identity: &Identity) -> Result<Self, ClientError> {
        install_crypto_provider();

        // First attempt: QUIC.
        match Self::connect_quic(pin, identity).await {
            Ok(sess) => {
                info!(transport = ?sess.transport, "session established");
                Ok(sess)
            }
            Err(e) if is_transport_failure(&e) => {
                warn!("QUIC connect failed ({e}); falling back to krot-tcp/1");
                let sess = Self::connect_tcp(pin, identity).await?;
                info!(transport = ?sess.transport, "session established via fallback");
                Ok(sess)
            }
            // Non-transport errors (bad config, protocol violation
            // after handshake) propagate as-is — they'd fail the same
            // way over TCP.
            Err(e) => Err(e),
        }
    }

    /// Force the QUIC transport. Skips the §16.1.5 fallback; useful
    /// for tests that want to isolate one code path.
    pub async fn connect_quic(pin: &ServerPin, identity: &Identity) -> Result<Self, ClientError> {
        install_crypto_provider();
        let server_addr = resolve_server(pin, pin.quic_port).await?;
        let endpoint = build_endpoint(pin)?;
        let connection = endpoint.connect(server_addr, pin.effective_sni())?.await?;
        debug!(?server_addr, "QUIC connection established");
        Self::finish_auth(connection, identity, SessionTransport::Quic, Some(endpoint)).await
    }

    /// Force the TCP fallback transport. Skips the §16.1.5 fallback
    /// preference; useful for tests and for operators who KNOW their
    /// network blocks UDP.
    pub async fn connect_tcp(pin: &ServerPin, identity: &Identity) -> Result<Self, ClientError> {
        install_crypto_provider();
        let server_addr = resolve_server(pin, pin.effective_tcp_port()).await?;
        let tls_cfg = build_client_tls(pin)?;
        let connection = connect_tcp_fallback(server_addr, pin.effective_sni(), tls_cfg).await?;
        debug!(?server_addr, "krot-tcp/1 connection established");
        Self::finish_auth(connection, identity, SessionTransport::TcpFallback, None).await
    }

    async fn finish_auth(
        connection: Connection,
        identity: &Identity,
        transport: SessionTransport,
        endpoint: Option<KrotEndpoint>,
    ) -> Result<Self, ClientError> {
        let (mut send, mut recv) = connection.open_bi().await?;

        // Every stream begins with a StreamKind byte.
        send.write_all(&[StreamKind::Control.as_byte()]).await?;

        let pubkey = identity.pubkey()?;
        write_frame(&mut send, &ClientFrame::AuthRequest { pubkey }).await?;

        let ServerFrame::AuthChallenge { nonce } = read_frame(&mut recv).await? else {
            return match read_reject(&mut recv).await {
                Some(code) => Err(ClientError::AuthRejected(code)),
                None => Err(ClientError::Protocol("expected AuthChallenge")),
            };
        };

        let signing = identity.signing_key()?;
        let signature = sign_challenge(&signing, &nonce);
        write_frame(&mut send, &ClientFrame::AuthResponse { signature }).await?;

        let session_id = match read_frame(&mut recv).await? {
            ServerFrame::AuthOk { session_id } => session_id,
            ServerFrame::AuthReject { code } => return Err(ClientError::AuthRejected(code)),
            _ => return Err(ClientError::Protocol("expected AuthOk")),
        };

        Ok(Self {
            connection,
            send,
            recv,
            session_id,
            transport,
            _endpoint: endpoint,
        })
    }

    /// Send `Bye` and finish the Control stream.
    pub async fn shutdown(mut self) {
        let _ = write_frame(&mut self.send, &ClientFrame::Bye).await;
        let _ = self.send.finish();
        let _ = self.send.stopped().await;
        self.connection.close(0, b"bye");
    }

    /// §16.3.5: ask the server for the federated peer relays this
    /// identity is authorized to publish on. The response is the
    /// intersection of the server's static peer list (§16.3.2) and
    /// this identity's `federation=` allowlist (§16.3.1).
    ///
    /// Callers use the returned apex list to open additional sessions
    /// (one per peer) and re-publish the same tunnel on each — the
    /// operator gets one URL per relay.
    pub async fn list_peers(&mut self) -> Result<Vec<String>, ClientError> {
        write_frame(&mut self.send, &ClientFrame::ListPeers).await?;
        match read_frame(&mut self.recv).await? {
            ServerFrame::Peers { relays } => Ok(relays),
            _ => Err(ClientError::Protocol("expected Peers response")),
        }
    }
}

pub(crate) fn build_endpoint(pin: &ServerPin) -> Result<KrotEndpoint, ClientError> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let tls_cfg = build_client_tls(pin)?;
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    Ok(KrotEndpoint::client(bind, tls_cfg)?)
}

fn build_client_tls(pin: &ServerPin) -> Result<rustls::ClientConfig, ClientError> {
    if let Some(pin_bytes) = pin.fingerprint_bytes()? {
        Ok(tls::client_config(pin_bytes)?)
    } else {
        Err(ClientError::Config(
            "server pin has no fingerprint (only IpMode is supported today)".into(),
        ))
    }
}

pub(crate) async fn resolve_server(pin: &ServerPin, port: u16) -> Result<SocketAddr, ClientError> {
    let target = format!("{}:{}", pin.host, port);
    let first = {
        let mut addrs = lookup_host(target.as_str())
            .await
            .map_err(|e| ClientError::BadServerAddr(format!("{target}: {e}")))?;
        addrs.next()
    };
    first.ok_or_else(|| ClientError::BadServerAddr(target))
}

/// Decide whether `err` is a transport-level failure that warrants a
/// §16.1.5 fallback attempt. Errors that would recur over TCP (bad
/// config, protocol violation after handshake, auth reject) are NOT
/// eligible.
fn is_transport_failure(err: &ClientError) -> bool {
    match err {
        ClientError::Transport(_) => true,
        ClientError::BadServerAddr(_) => true,
        // Auth-level failures, config errors, protocol violations, etc.
        // will fail the same way over TCP.
        _ => false,
    }
}

async fn read_reject(recv: &mut krot_transport::RecvStream) -> Option<krot_proto::ErrorCode> {
    match read_frame::<ServerFrame>(recv).await.ok()? {
        ServerFrame::AuthReject { code } | ServerFrame::ServerBye { code } => Some(code),
        _ => None,
    }
}

/// Load the persisted [`ClientConfig`] from `dir`.
pub fn load_config(dir: &std::path::Path) -> Result<ClientConfig, ClientError> {
    ClientConfig::load_from(dir)
}
