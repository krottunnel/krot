//! Apex-domain TLS acquisition.
//!
//! Currently only [`TlsSource::PemFile`] is wired to a working code path.
//! ACME support is scaffolded in [`crate::config::DomainTls::Acme`] but
//! the server rejects it at startup with a clear error.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::DomainTls;
use crate::error::ServerError;

/// Fully materialised apex TLS config, ready to hand to the QUIC endpoint.
#[derive(Clone)]
pub struct TlsSource {
    pub server_config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for TlsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSource").finish_non_exhaustive()
    }
}

impl TlsSource {
    /// Load a static TLS source from `DomainTls::PemFile`. For
    /// `DomainTls::Acme` the server orchestrates cert acquisition in
    /// [`crate::server`] because it needs the port-80 listener up first.
    pub fn from_domain_tls(tls: &DomainTls) -> Result<Self, ServerError> {
        match tls {
            DomainTls::PemFile { cert, key } => load_tls_from_pem(cert, key),
            DomainTls::Acme { .. } => Err(ServerError::Keys(
                "TlsSource::from_domain_tls does not handle ACME; \
                 use domain::acme::acquire_cert via Server::start"
                    .into(),
            )),
        }
    }

    pub fn from_pem_files(cert: &Path, key: &Path) -> Result<Self, ServerError> {
        load_tls_from_pem(cert, key)
    }
}

/// Load a PEM-encoded certificate chain + PKCS#8 key from disk.
pub fn load_tls_from_pem(cert_path: &Path, key_path: &Path) -> Result<TlsSource, ServerError> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;
    let certs = pem_bundle(&cert_pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(ServerError::Keys(format!(
            "no CERTIFICATE blocks in {}",
            cert_path.display()
        )));
    }
    let key = pem_bundle(&key_pem, "PRIVATE KEY")?
        .into_iter()
        .next()
        .ok_or_else(|| {
            ServerError::Keys(format!("no PRIVATE KEY block in {}", key_path.display()))
        })?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsSource {
        server_config: Arc::new(cfg),
    })
}

fn pem_bundle(pem: &str, expected_tag: &str) -> Result<Vec<Vec<u8>>, ServerError> {
    let begin = format!("-----BEGIN {expected_tag}-----");
    let end = format!("-----END {expected_tag}-----");
    let mut out = Vec::new();
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with(&begin) {
            in_block = true;
            b64.clear();
            continue;
        }
        if line.starts_with(&end) {
            in_block = false;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| ServerError::Keys(format!("bad base64: {e}")))?;
            out.push(bytes);
            continue;
        }
        if in_block {
            b64.push_str(line.trim());
        }
    }
    Ok(out)
}
