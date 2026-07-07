//! Transport-layer error type shared by the endpoint, frame and relay modules.

use thiserror::Error;

use krot_proto::FramingError;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quinn connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    #[error("quinn connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("quinn write: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("quinn read: {0}")]
    Read(#[from] quinn::ReadError),

    #[error("quinn read_exact: {0}")]
    ReadExact(#[from] quinn::ReadExactError),

    #[error("frame codec: {0}")]
    Framing(#[from] FramingError),

    #[error("stream closed unexpectedly")]
    UnexpectedEof,

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("quic crypto: {0}")]
    QuicCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}
