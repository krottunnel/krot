//! [`KrotEndpoint`]: a thin wrapper around [`quinn::Endpoint`] that
//! guarantees the ALPN identifier and transport parameters required by
//! wire protocol spec.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};

use krot_proto::consts::{
    KEEP_ALIVE_INTERVAL, MAX_IDLE_TIMEOUT, SUPPORTED_CLIENT_ALPN, SUPPORTED_SERVER_ALPN,
};

use crate::conn::{Connection, Incoming};
use crate::error::TransportError;

const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;
const SEND_WINDOW: u64 = 4 * 1024 * 1024;
const MAX_CONCURRENT_BIDI: u32 = 1024;
const MAX_CONCURRENT_UNI: u32 = 0;

/// A `quinn::Endpoint` pre-configured for the KROT protocol.
#[derive(Debug, Clone)]
pub struct KrotEndpoint {
    inner: Endpoint,
}

impl KrotEndpoint {
    /// Bind a server endpoint on `addr` using the supplied rustls config.
    ///
    /// The provided `tls` has its ALPN list replaced with
    /// [`SUPPORTED_SERVER_ALPN`] — the full set of protocol versions this
    /// build accepts, highest-preferred first (§2.1).
    pub fn server(addr: SocketAddr, tls: rustls::ServerConfig) -> Result<Self, TransportError> {
        Self::server_with_alpn(addr, tls, SUPPORTED_SERVER_ALPN)
    }

    /// Like [`Self::server`], but with an explicit ALPN preference list.
    /// Useful for interop tests that need to advertise a non-default set.
    pub fn server_with_alpn(
        addr: SocketAddr,
        mut tls: rustls::ServerConfig,
        alpn: &[&[u8]],
    ) -> Result<Self, TransportError> {
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let quic_crypto = QuicServerConfig::try_from(tls)?;
        let mut cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));
        cfg.transport_config(Arc::new(server_transport_config()));
        let inner = Endpoint::server(cfg, addr)?;
        Ok(Self { inner })
    }

    /// Adopt an already-bound `std::net::UdpSocket`. Useful when the caller
    /// needs to control socket options (SO_REUSEPORT for per-core sharding
    /// via socket2, custom buffer sizes, etc.).
    pub fn server_on_socket(
        socket: std::net::UdpSocket,
        mut tls: rustls::ServerConfig,
    ) -> Result<Self, TransportError> {
        tls.alpn_protocols = SUPPORTED_SERVER_ALPN.iter().map(|p| p.to_vec()).collect();
        let quic_crypto = QuicServerConfig::try_from(tls)?;
        let mut cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));
        cfg.transport_config(Arc::new(server_transport_config()));
        let inner = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(cfg),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Self { inner })
    }

    /// Bind a client endpoint on `addr` using the supplied rustls config.
    ///
    /// The provided `tls` has its ALPN list replaced with
    /// [`SUPPORTED_CLIENT_ALPN`] — every KROT protocol version this build
    /// speaks, highest-preferred first (§2.1). The server picks the
    /// highest common entry; if none match, the QUIC handshake fails with
    /// the `no_application_protocol` alert.
    pub fn client(addr: SocketAddr, tls: rustls::ClientConfig) -> Result<Self, TransportError> {
        Self::client_with_alpn(addr, tls, SUPPORTED_CLIENT_ALPN)
    }

    /// Like [`Self::client`], but with an explicit ALPN preference list.
    /// Useful for interop tests that need to advertise a non-default set.
    pub fn client_with_alpn(
        addr: SocketAddr,
        mut tls: rustls::ClientConfig,
        alpn: &[&[u8]],
    ) -> Result<Self, TransportError> {
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let quic_crypto = QuicClientConfig::try_from(Arc::new(tls))?;
        let mut cfg = ClientConfig::new(Arc::new(quic_crypto));
        cfg.transport_config(Arc::new(client_transport_config()));
        let mut inner = Endpoint::client(addr)?;
        inner.set_default_client_config(cfg);
        Ok(Self { inner })
    }

    /// Underlying `quinn::Endpoint`. Useful for advanced operations that
    /// are not surfaced by this wrapper (e.g. reconfiguration, stats).
    #[inline]
    pub fn inner(&self) -> &Endpoint {
        &self.inner
    }

    /// Local socket address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Await the next incoming connection attempt, wrapped for
    /// transport-neutral consumers.
    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await.map(Incoming::from_quic)
    }

    /// Initiate a connection to `addr`. `server_name` is the TLS SNI value
    /// and MUST match a subjectAltName on the server's certificate.
    ///
    /// The returned future resolves to a transport-neutral [`Connection`].
    pub fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<impl std::future::Future<Output = Result<Connection, TransportError>>, TransportError>
    {
        let connecting = self.inner.connect(addr, server_name)?;
        Ok(async move {
            let quic = connecting.await.map_err(TransportError::Connection)?;
            Ok(Connection::from_quic(quic))
        })
    }

    /// Trigger a graceful shutdown of the endpoint.
    pub fn close(&self, code: VarInt, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

/// [`TransportConfig`] recommended by §11 for the server side.
#[must_use]
pub fn server_transport_config() -> TransportConfig {
    let mut cfg = TransportConfig::default();
    apply_common(&mut cfg);
    cfg
}

/// [`TransportConfig`] recommended by §11 for the client side.
#[must_use]
pub fn client_transport_config() -> TransportConfig {
    let mut cfg = TransportConfig::default();
    apply_common(&mut cfg);
    cfg
}

fn apply_common(cfg: &mut TransportConfig) {
    cfg.stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW));
    cfg.receive_window(VarInt::from_u32(RECEIVE_WINDOW));
    cfg.send_window(SEND_WINDOW);
    cfg.max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONCURRENT_BIDI));
    cfg.max_concurrent_uni_streams(VarInt::from_u32(MAX_CONCURRENT_UNI));
    cfg.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

    let idle = IdleTimeout::try_from(Duration::from_millis(MAX_IDLE_TIMEOUT.as_millis() as u64))
        .expect("MAX_IDLE_TIMEOUT fits IdleTimeout");
    cfg.max_idle_timeout(Some(idle));
}
