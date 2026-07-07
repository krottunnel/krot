//! §16.1.4 server-side TCP+TLS listener for the `krot-tcp/1`
//! fallback transport.
//!
//! Binds a `tokio::net::TcpListener`, terminates TLS with the same
//! `rustls::ServerConfig` the QUIC endpoint uses (ALPN forced to
//! `krot-tcp/1`), then wraps the resulting stream in a
//! [`TcpMuxConn`] and surfaces it via [`Incoming`] so the existing
//! `handle_connection` code path can drive it identically to a
//! QUIC-arrived control stream.
//!
//! Client-side dialing is symmetric — see
//! [`connect_tcp_fallback`].

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::warn;

use krot_proto::consts::ALPN_TCP;

use crate::conn::{Connection, Incoming};
use crate::error::TransportError;
use crate::tcp_mux::TcpMuxConn;

/// Bind a TCP listener on `addr` and return a stream of accepted
/// [`Incoming`]s. Every yielded item is a connection whose TLS
/// handshake has already completed (ALPN forced to `krot-tcp/1`) and
/// whose §16.1.3 mux is spun up ready to serve.
///
/// `tls` is the same server config the QUIC endpoint uses — the
/// listener replaces its ALPN list with `[krot-tcp/1]` so peers
/// choosing that ALPN complete the handshake and anything else
/// aborts with `no_application_protocol`.
pub struct TcpFallbackListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl std::fmt::Debug for TcpFallbackListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFallbackListener")
            .field("local_addr", &self.local_addr().ok())
            .finish()
    }
}

impl TcpFallbackListener {
    /// Bind on `addr` with the shared TLS config.
    pub async fn bind(
        addr: SocketAddr,
        mut tls: rustls::ServerConfig,
    ) -> Result<Self, TransportError> {
        tls.alpn_protocols = vec![ALPN_TCP.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, acceptor })
    }

    /// Local address the listener bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept the next TCP connection, complete its TLS handshake,
    /// and return a fully-armed [`Incoming`]. The mux tasks are
    /// already running when this method returns — callers just
    /// `incoming.accept().await` to obtain the [`Connection`].
    ///
    /// TLS handshake failures are logged and skipped so a single
    /// malformed peer doesn't stall the accept loop.
    pub async fn accept(&self) -> Result<Incoming, TransportError> {
        loop {
            let (tcp, peer) = self.listener.accept().await?;
            let tls_stream = match self.acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(?peer, "krot-tcp/1 TLS handshake failed: {e}");
                    continue;
                }
            };
            // Verify the ALPN the peer selected — rustls has already
            // rejected any mismatch, so this is defence-in-depth.
            let selected = tls_stream.get_ref().1.alpn_protocol();
            if selected != Some(ALPN_TCP) {
                warn!(
                    ?peer,
                    ?selected,
                    "krot-tcp/1 handshake completed with unexpected ALPN"
                );
                continue;
            }
            let mux = TcpMuxConn::new(tls_stream, true);
            return Ok(Incoming::from_tcp_mux(mux));
        }
    }
}

/// Client-side dial: open a TCP connection, run TLS with ALPN
/// `krot-tcp/1`, and return a live [`Connection`]. `sni` is the SNI
/// hostname the server certificate is expected to cover.
pub async fn connect_tcp_fallback(
    addr: SocketAddr,
    sni: &str,
    tls: rustls::ClientConfig,
) -> Result<Connection, TransportError> {
    let mut tls = tls;
    tls.alpn_protocols = vec![ALPN_TCP.to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| TransportError::UnexpectedEof)?;
    let tls_stream = connector.connect(server_name, tcp).await?;
    if tls_stream.get_ref().1.alpn_protocol() != Some(ALPN_TCP) {
        return Err(TransportError::UnexpectedEof);
    }
    let mux = TcpMuxConn::new(tls_stream, false);
    Ok(Connection::from_tcp_mux(mux))
}
