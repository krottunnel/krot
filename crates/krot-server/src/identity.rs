//! Persistent server identity for IpMode (§15.3).
//!
//! On first startup a fresh Ed25519 keypair and a self-signed X.509
//! certificate valid for 10 years are generated and stored under the
//! server's data directory. The SPKI SHA-256 fingerprint is exposed to
//! stdout so clients can pin it via `krot init --fingerprint`.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::error::ServerError;

const CERT_FILE: &str = "self.pem";
const KEY_FILE: &str = "self.key.pem";

/// A loaded (or freshly created) server identity.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// Hex-encoded SHA-256 of the certificate's SubjectPublicKeyInfo.
    pub spki_sha256: String,
}

impl ServerIdentity {
    /// Load an identity from `data_dir`, generating one on first use.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, ServerError> {
        fs::create_dir_all(data_dir)?;
        let cert_path = data_dir.join(CERT_FILE);
        let key_path = data_dir.join(KEY_FILE);

        let (cert_der, key_der) = if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            (pem_to_der(&cert_pem)?, pem_to_der(&key_pem)?)
        } else {
            let (cert_der, key_der, cert_pem, key_pem) = generate()?;
            atomic_write(&cert_path, cert_pem.as_bytes(), 0o644)?;
            atomic_write(&key_path, key_pem.as_bytes(), 0o600)?;
            (cert_der, key_der)
        };

        let spki_sha256 = compute_spki_fingerprint(&cert_der)?;
        Ok(Self {
            cert_der,
            key_der,
            spki_sha256,
        })
    }

    /// Convert into `rustls::ServerConfig` accepting no client authentication.
    pub fn into_rustls(self) -> Result<rustls::ServerConfig, ServerError> {
        let cert = CertificateDer::from(self.cert_der);
        let key = PrivatePkcs8KeyDer::from(self.key_der);
        Ok(rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())?)
    }
}

fn generate() -> Result<(Vec<u8>, Vec<u8>, String, String), ServerError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "krot server");
    params.distinguished_name = dn;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(365 * 10);

    let cert = params.self_signed(&key)?;
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    Ok((cert_der, key_der, cert_pem, key_pem))
}

fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<String, ServerError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| ServerError::Keys(format!("cert parse: {e}")))?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    let mut hasher = Sha256::new();
    hasher.update(spki);
    Ok(hex::encode(hasher.finalize()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, ServerError> {
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| ServerError::Keys(format!("bad PEM base64: {e}")))
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), ServerError> {
    let mut tmp: PathBuf = path.to_path_buf();
    tmp.set_extension("tmp");
    write_and_sync(&tmp, contents, mode)?;
    fs::rename(&tmp, path)?;
    crate::fsync::sync_parent(path)?;
    Ok(())
}

fn write_and_sync(path: &Path, contents: &[u8], mode: u32) -> Result<(), ServerError> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?; // fsync — data hits disk before the rename below sees it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}
