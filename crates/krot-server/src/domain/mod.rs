//! DomainMode routing plane: plain HTTP on port 80 (Host-header based) and
//! HTTPS on port 443 (SNI-passthrough).
//!
//! Neither module terminates TLS on subdomains. The apex TLS is only used
//! by the QUIC control endpoint; port 80/443 listeners either route raw
//! bytes to the owning client's QUIC connection or respond to ACME
//! challenges (port 80 only, currently a placeholder).

pub mod acme;
pub mod http;
pub mod https;
pub mod replay;
pub mod sni;
pub mod tls_source;

pub use acme::{new_store as new_challenge_store, ChallengeStore};
pub use http::run_http_router;
pub use https::run_https_router;
pub use tls_source::{load_tls_from_pem, TlsSource};
