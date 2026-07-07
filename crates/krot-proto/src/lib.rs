//! Wire types and framing for the KROT tunnel protocol.
//!
//! This crate is the single source of truth for the on-the-wire format
//! defined in wire protocol spec. Server and client implementations MUST route
//! all encoding and decoding through the types exposed here.

#![deny(missing_debug_implementations)]

pub mod auth;
pub mod consts;
pub mod error;
pub mod frames;
pub mod framing;
pub mod ids;
pub mod mux;
pub mod stream;

pub use auth::{sign_challenge, verify_challenge, AUTH_DOMAIN_SEPARATOR};
pub use consts::*;
pub use error::ErrorCode;
pub use frames::{ClientFrame, HttpMetadata, InspectionPrelude, ServerFrame, TunnelKind};
pub use framing::{decode_frame, encode_frame, FramingError};
pub use ids::{Nonce, PubKey, SessionId, Signature, TunnelId};
pub use mux::{
    is_client_opened, is_server_opened, MuxFlag, MuxHeader, MuxHeaderError, CONTROL_STREAM_ID,
    MUX_HEADER_SIZE,
};
pub use stream::{DataHeader, StreamKind, StreamKindError};
