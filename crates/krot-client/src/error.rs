//! Client-side error type.

use thiserror::Error;

use krot_proto::ErrorCode;
use krot_transport::TransportError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    #[error("quinn write: {0}")]
    QuinnWrite(#[from] quinn::WriteError),

    #[error("quinn connect: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    #[error("quinn connection: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("bad fingerprint format (expected `sha256:HEX`)")]
    BadFingerprint,

    #[error("bad server address `{0}`")]
    BadServerAddr(String),

    #[error("server rejected enrollment: {0}")]
    EnrollRejected(ErrorCode),

    #[error("server rejected authentication: {0}")]
    AuthRejected(ErrorCode),

    #[error("server rejected tunnel: {0} — {1}")]
    TunnelRejected(ErrorCode, String),

    #[error("server did not confirm tunnel within the registration deadline")]
    RegistrationTimeout,

    #[error("unexpected frame: {0}")]
    Protocol(&'static str),
}
