//! rustls `ClientConfig` with SPKI-fingerprint pinning.
//!
//! When the server runs in IpMode the client stores the SPKI SHA-256 of the
//! server's self-signed certificate at first `krot init`. Every subsequent
//! connection presents this pinned value; if the server ever hands over a
//! certificate whose SPKI hash differs, the handshake is rejected.
//!
//! Signature verification is delegated to `rustls`'s ring-backed
//! [`WebPkiSupportedAlgorithms`] so this is not a "trust anything" verifier —
//! only the trust anchor (the pinned SPKI) is short-circuited.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::ClientError;

/// Build a rustls `ClientConfig` that pins a specific server SPKI hash.
pub fn client_config(pinned_sha256: [u8; 32]) -> Result<rustls::ClientConfig, ClientError> {
    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;

    let verifier = Arc::new(SpkiPinVerifier {
        expected: pinned_sha256,
        algs,
    });

    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug)]
struct SpkiPinVerifier {
    expected: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|e| rustls::Error::General(format!("cert parse: {e}")))?;
        let spki = cert.tbs_certificate.subject_pki.raw;
        let mut hasher = Sha256::new();
        hasher.update(spki);
        let actual: [u8; 32] = hasher.finalize().into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server SPKI fingerprint does not match pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
