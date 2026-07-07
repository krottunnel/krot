//! Protocol-level constants. Mirrors wire protocol spec Appendix A.

use core::time::Duration;

/// ALPN identifier for the primary QUIC transport (§1, §2).
pub const ALPN: &[u8] = b"krot/1";

/// ALPN identifier for the TCP fallback transport (§16.1).
///
/// Same wire semantics above the transport, but mux'd on a single
/// TLS-over-TCP connection instead of QUIC.
pub const ALPN_TCP: &[u8] = b"krot-tcp/1";

/// ALPN identifiers the reference client advertises, highest-preferred first.
///
/// The client sends this full list in its TLS ClientHello ALPN extension
/// (§2.1). Highest preference is QUIC; TCP fallback follows.
pub const SUPPORTED_CLIENT_ALPN: &[&[u8]] = &[ALPN, ALPN_TCP];

/// ALPN identifiers the reference server accepts, highest-preferred first.
///
/// `rustls` picks the highest server-side entry that also appears in the
/// client's advertised list; if none matches the handshake fails with the
/// `no_application_protocol` alert as required by §2.1.
pub const SUPPORTED_SERVER_ALPN: &[&[u8]] = &[ALPN, ALPN_TCP];

/// Default UDP port for the QUIC control endpoint.
pub const DEFAULT_UDP_PORT: u16 = 7853;

/// Default TCP port for the `krot-tcp/1` fallback transport
/// (§16.1). Same numeric value as the QUIC port —
/// operators expose them together and the transport is picked by ALPN.
pub const DEFAULT_TCP_PORT: u16 = 7853;

/// TCP port used by the built-in ACME HTTP-01 responder (DomainMode).
pub const ACME_HTTP_PORT: u16 = 80;

/// Maximum size of a Control-stream frame payload (excluding the varint length prefix).
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Fixed size of the Data-stream header (`[kind:u8][tunnel_id:u64 LE]`).
pub const DATA_HEADER_SIZE: usize = 9;

/// Length in bytes of a session identifier.
pub const SESSION_ID_LEN: usize = 16;

/// Length in bytes of the authentication challenge nonce.
pub const AUTH_NONCE_LEN: usize = 32;

/// Length in bytes of a raw admin token before Crockford base32 encoding.
pub const ADMIN_TOKEN_RAW_LEN: usize = 32;

/// Time-to-live for an issued admin token.
pub const ADMIN_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);

/// Default lease grace period before a dangling tunnel is reclaimed.
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Recommended QUIC keep-alive interval.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Recommended QUIC idle timeout.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// §10 client-side deadline for waiting on `TunnelRegistered` after
/// sending `RegisterTunnel`. Bounds a DoS-by-idle-server failure mode.
pub const REGISTRATION_DEADLINE: Duration = Duration::from_secs(10);

/// §10 server-side deadline from `open_bi()` to the first byte of
/// tunneled data (in either direction) on a Data stream. Once any byte
/// flows the timer is done; long-lived streams (SSH, DB sessions) are
/// unaffected.
pub const DATA_FIRST_BYTE_DEADLINE: Duration = Duration::from_secs(30);
