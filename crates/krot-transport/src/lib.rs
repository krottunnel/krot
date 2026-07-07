//! QUIC transport layer for KROT.
//!
//! Wires the byte-level protocol from [`krot_proto`] onto `quinn` streams
//! with the ALPN and transport parameters mandated by §2
//! and §11.
//!
//! ## Modules
//!
//! - [`endpoint`] — [`KrotEndpoint`] wrapper around [`quinn::Endpoint`],
//!   pre-configured with `krot/1` ALPN, 5s keep-alive, 15s idle timeout,
//!   and the recommended stream/connection windows.
//! - [`frame`] — asynchronous readers and writers for the length-prefixed
//!   `postcard` frames that flow on Control streams.
//! - [`relay`] — [`BidiStream`] adapter combining `quinn::SendStream` and
//!   `quinn::RecvStream` into a single `AsyncRead + AsyncWrite`, plus
//!   [`relay::run_bidirectional`] for the byte-shovel between a QUIC
//!   stream and a local TCP socket.
//!
//! ## rustls crypto provider
//!
//! rustls 0.23 requires a process-wide crypto provider to be installed
//! before any TLS configuration is constructed. Call
//! [`install_crypto_provider`] once at binary startup.

#![deny(missing_debug_implementations)]

pub mod conn;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod relay;
pub mod tcp_listener;
pub mod tcp_mux;

pub use conn::{Connection, Incoming, RecvStream, SendStream, TransportKind};
pub use endpoint::{client_transport_config, server_transport_config, KrotEndpoint};
pub use error::TransportError;
pub use frame::{read_frame, write_frame};
pub use relay::{run_bidirectional, run_bidirectional_with_first_byte_deadline, BidiStream};
pub use tcp_listener::{connect_tcp_fallback, TcpFallbackListener};
pub use tcp_mux::{TcpMuxConn, TcpMuxRecvStream, TcpMuxSendStream};

pub use krot_proto;

/// Install `rustls`'s ring-backed crypto provider as the process default.
///
/// Safe to call multiple times: subsequent calls after the first
/// successful install are no-ops. Must be called before constructing any
/// [`rustls::ClientConfig`] or [`rustls::ServerConfig`].
pub fn install_crypto_provider() {
    // Ignore the returned error: it means a provider is already installed,
    // which is what we want.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
