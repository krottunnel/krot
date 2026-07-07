//! Bootstrap enrollment: send an `Enroll` frame with an admin token, obtain
//! the server's `EnrollOk`, and persist the identity + server pin locally.

use std::path::Path;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tracing::info;

use krot_proto::{ClientFrame, ServerFrame, StreamKind};
use krot_transport::{install_crypto_provider, read_frame, write_frame, KrotEndpoint};

use crate::config::{ClientConfig, Identity, ServerPin};
use crate::error::ClientError;
use crate::session::resolve_server;
use crate::tls;

/// Options for [`enroll`].
#[derive(Debug, Clone)]
pub struct EnrollOptions {
    /// Human-friendly host or dotted-IP the server is reachable at.
    pub server_host: String,
    /// UDP port for the server's QUIC endpoint.
    pub server_quic_port: u16,
    /// SNI to present. Defaults to `server_host` when None.
    pub sni: Option<String>,
    /// Admin token as printed by the server.
    pub admin_token: String,
    /// Human hint stored in the `authorized_keys` comment column.
    pub label_hint: Option<String>,
    /// Pre-known SPKI fingerprint. When None, the client uses TOFU:
    /// records whatever the server presents and pins it into the config.
    pub pinned_fingerprint: Option<String>,
}

/// Perform enrollment against a KROT server and persist the resulting
/// [`ClientConfig`] to `dir`.
pub async fn enroll(opts: EnrollOptions, dir: &Path) -> Result<ClientConfig, ClientError> {
    install_crypto_provider();

    // The identity is generated fresh unless the config file already carries
    // one (previous partial init). Re-using a known key on retry is fine.
    let identity = if let Ok(existing) = ClientConfig::load_from(dir) {
        existing.identity
    } else {
        Identity::generate()
    };

    let learned = Arc::new(Mutex::new(None));
    let tls_cfg = build_enroll_tls(&opts, Arc::clone(&learned))?;

    let bind = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
    let endpoint = KrotEndpoint::client(bind, tls_cfg)?;

    let sni = opts.sni.clone().unwrap_or_else(|| opts.server_host.clone());

    let tmp_pin = ServerPin {
        host: opts.server_host.clone(),
        quic_port: opts.server_quic_port,
        tcp_port: None,
        sni: opts.sni.clone(),
        fingerprint: opts.pinned_fingerprint.clone(),
    };
    let quic_port = tmp_pin.quic_port;
    let server_addr = resolve_server(&tmp_pin, quic_port).await?;

    let connection = endpoint.connect(server_addr, &sni)?.await?;

    let (mut send, mut recv) = connection.open_bi().await?;

    send.write_all(&[StreamKind::Control.as_byte()]).await?;
    write_frame(
        &mut send,
        &ClientFrame::Enroll {
            admin_token: opts.admin_token.clone(),
            pubkey: identity.pubkey()?,
            label_hint: opts.label_hint.clone(),
        },
    )
    .await?;

    let reply = read_frame::<ServerFrame>(&mut recv).await?;
    let _ = send.finish();
    let _ = send.stopped().await;
    connection.close(0, b"enrolled");

    let stored_line = match reply {
        ServerFrame::EnrollOk { authorized_line } => authorized_line,
        ServerFrame::EnrollRejected { code } => return Err(ClientError::EnrollRejected(code)),
        _ => return Err(ClientError::Protocol("expected EnrollOk")),
    };
    info!("enrolled: {stored_line}");

    // If we did TOFU pinning, capture whatever fingerprint we saw. Otherwise
    // preserve the user-supplied value so it round-trips into config.toml.
    let fingerprint = match opts.pinned_fingerprint {
        Some(fp) => Some(fp),
        None => learned.lock().unwrap().take(),
    };

    let config = ClientConfig {
        identity,
        server: ServerPin {
            host: opts.server_host,
            quic_port: opts.server_quic_port,
            tcp_port: None,
            sni: opts.sni,
            fingerprint,
        },
    };
    config.save_to(dir)?;
    Ok(config)
}

fn build_enroll_tls(
    opts: &EnrollOptions,
    learned: Arc<Mutex<Option<String>>>,
) -> Result<rustls::ClientConfig, ClientError> {
    if let Some(fp) = &opts.pinned_fingerprint {
        let raw = fp
            .strip_prefix("sha256:")
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|v| v.try_into().ok())
            .ok_or(ClientError::BadFingerprint)?;
        return tls::client_config(raw);
    }

    // TOFU: accept whatever's presented, but remember its SPKI hash so we can
    // pin it in the config file we're about to write.
    let provider = rustls::crypto::ring::default_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(TofuVerifier { learned, algs });
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug)]
struct TofuVerifier {
    learned: Arc<Mutex<Option<String>>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|e| rustls::Error::General(format!("cert parse: {e}")))?;
        let spki = cert.tbs_certificate.subject_pki.raw;
        let mut hasher = Sha256::new();
        hasher.update(spki);
        let hash: [u8; 32] = hasher.finalize().into();
        *self.learned.lock().unwrap() = Some(format!("sha256:{}", hex::encode(hash)));
        Ok(ServerCertVerified::assertion())
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
