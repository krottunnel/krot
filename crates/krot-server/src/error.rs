//! Unified server error type.

use thiserror::Error;

use krot_transport::TransportError;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("authorized_keys: {0}")]
    Keys(String),

    #[error("admin token: {0}")]
    AdminToken(&'static str),

    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    #[error("port pool exhausted")]
    PortPoolExhausted,
}
