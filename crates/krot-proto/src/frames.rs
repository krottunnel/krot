//! Control-stream frames (§7, §14.2).
//!
//! Every variant is encoded with `postcard`; the outer framing (varint
//! length prefix) is handled by [`crate::framing`].

use serde::{Deserialize, Serialize};

use crate::error::ErrorCode;
use crate::ids::{Nonce, PubKey, SessionId, Signature, TunnelId};

/// Kind of tunnel a client wants to register.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TunnelKind {
    /// HTTP(S) tunnel, routed by subdomain. Valid only in DomainMode (§15.1).
    Http,
    /// Raw TCP tunnel. `remote_port` MAY request a specific server port; if
    /// unset the server picks one from its pool.
    Tcp { remote_port: Option<u16> },
}

/// A frame sent by the client on the Control stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Begin authenticated session by presenting a public key (§7.1 step 1).
    AuthRequest { pubkey: PubKey },
    /// Sign the challenge returned by the server (§7.1 step 3).
    AuthResponse { signature: Signature },

    /// Register a tunnel or resume a previous session (§7.2, §7.3).
    ///
    /// `inspect` opts into the server-provided passive inspection
    /// prelude on every server-opened Data stream (§16.2). When
    /// `false` the server MUST NOT emit a prelude.
    RegisterTunnel {
        label: String,
        kind: TunnelKind,
        resume_session_id: Option<SessionId>,
        inspect: bool,
    },
    /// Explicitly close a previously registered tunnel.
    UnregisterTunnel { tunnel_id: TunnelId },

    /// Application-level ping. Server echoes with the same nonce.
    Ping { nonce: u64 },

    /// Graceful shutdown signal. Prevents lease resumption for open tunnels.
    Bye,

    /// Bootstrap: exchange an admin token for enrollment (§14.2).
    ///
    /// A connection presenting this frame is treated as bootstrap-only:
    /// the server closes it immediately after enrollment succeeds or fails.
    Enroll {
        admin_token: String,
        pubkey: PubKey,
        label_hint: Option<String>,
    },

    /// Ask the server for the list of federated peer relays that this
    /// identity is authorized to publish tunnels on (§16.3.3).
    ///
    /// The response is a [`ServerFrame::Peers`] whose `relays` is the
    /// intersection of the server's static peer list (§16.3.2) and the
    /// identity's `federation=` allowlist (§16.3.1).
    ListPeers,
}

/// A frame sent by the server on the Control stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    /// Challenge to be signed by the client (§7.1 step 2).
    AuthChallenge {
        nonce: Nonce,
    },
    /// Successful authentication; the enclosed session id may be used for resume.
    AuthOk {
        session_id: SessionId,
    },
    /// Authentication failed.
    AuthReject {
        code: ErrorCode,
    },

    /// Confirms a tunnel registration.
    TunnelRegistered {
        tunnel_id: TunnelId,
        public_url: String,
        public_port: Option<u16>,
    },
    /// Rejects a tunnel registration.
    TunnelRejected {
        code: ErrorCode,
        detail: String,
    },

    /// Echo of a client `Ping`.
    Pong {
        nonce: u64,
    },

    /// Notifies the client that quota or bandwidth limits were hit.
    RateLimit {
        tunnel_id: Option<TunnelId>,
        retry_after_ms: u32,
    },

    /// Server-initiated shutdown of the session.
    ServerBye {
        code: ErrorCode,
    },

    /// Enrollment outcome (§14.3).
    EnrollOk {
        authorized_line: String,
    },
    EnrollRejected {
        code: ErrorCode,
    },

    /// Response to [`ClientFrame::ListPeers`] (§16.3.3).
    ///
    /// `relays` carries apex domains (optionally with an explicit
    /// `<apex>:<quic_port>` when the peer is on a non-default port).
    /// May be empty if the identity has no `federation=` overlap with
    /// the server's static peer list.
    Peers {
        relays: Vec<String>,
    },
}

/// Passive inspection prelude (§16.2). Emitted by the server between
/// the §5.1 Data-stream header and the first byte of tunneled payload,
/// but only when the tunnel was registered with `inspect = true`.
///
/// Wire layout: length-prefixed postcard value (same framing as
/// Control frames — see §6).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InspectionPrelude {
    /// Wall-clock timestamp of the public-side accept, seconds since
    /// UNIX epoch. Coarse enough to survive replay ordering.
    pub accept_unix_secs: u64,
    /// Peer address that hit the public port, formatted as
    /// `<ip>:<port>`.
    pub peer: String,
    /// Present for HTTP tunnels; None for raw TCP.
    pub http: Option<HttpMetadata>,
}

/// Router-derived metadata for HTTP tunnels. The server extracts this
/// from bytes it already parses for routing (Host header for plain HTTP,
/// SNI for HTTPS); it never re-parses the tunneled payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HttpMetadata {
    /// Best available host string: Host header (plain HTTP) or SNI
    /// (HTTPS passthrough). Empty when neither was extractable.
    pub host: String,
    /// TLS ClientHello SNI, when the traffic is HTTPS-passthrough.
    /// `None` for plain HTTP.
    pub sni: Option<String>,
}
