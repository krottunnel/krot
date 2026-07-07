//! KROT relay server library.
//!
//! Public API mirrors what the `krot-server` binary uses at startup: a
//! [`Server`] struct that owns the QUIC endpoint, the persistent identity,
//! the tunnel registry and the authorized-keys index. Tests and embeddings
//! construct one via [`Server::start`] with a [`ServerConfig`].

#![deny(missing_debug_implementations)]

pub mod admin;
pub mod admin_api;
pub mod config;
pub mod domain;
pub mod error;
pub mod fsync;
pub mod handshake;
pub mod identity;
pub mod keys;
pub mod metrics;
pub mod peer_lookup;
pub mod peers;
pub mod rate;
pub mod registry;
pub mod server;
pub mod session;
pub mod sockets;
pub mod tunnel;

pub use config::{DomainTls, Mode, ServerConfig};
pub use error::ServerError;
pub use identity::ServerIdentity;
pub use server::Server;
