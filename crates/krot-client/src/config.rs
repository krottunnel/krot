//! Persistent client configuration: identity + server pin.
//!
//! Layout of `~/.krot/config.toml`:
//!
//! ```toml
//! [identity]
//! private_key = "<hex-32>"   # Ed25519 seed
//! public_key  = "<hex-32>"
//!
//! [server]
//! host        = "192.0.2.10"
//! quic_port   = 7853
//! sni         = "krot.example"   # SNI to present, defaults to host
//! fingerprint = "sha256:abcd..." # SPKI SHA-256, IpMode pin
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use krot_proto::PubKey;

use crate::error::ClientError;

/// Config filename inside the client's data directory.
const CONFIG_FILE: &str = "config.toml";

/// Default directory (`~/.krot`) — separated so tests can override it.
#[must_use]
pub fn default_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".krot"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Hex-encoded Ed25519 seed (private key), 32 bytes.
    pub private_key: String,
    /// Hex-encoded Ed25519 public key, 32 bytes.
    pub public_key: String,
}

impl Identity {
    /// Generate a fresh keypair from OS randomness.
    #[must_use]
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Self {
            private_key: hex::encode(sk.to_bytes()),
            public_key: hex::encode(vk.to_bytes()),
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey, ClientError> {
        let seed: [u8; 32] = hex::decode(&self.private_key)
            .map_err(|e| ClientError::Config(format!("bad private_key hex: {e}")))?
            .try_into()
            .map_err(|_| ClientError::Config("private_key not 32 bytes".into()))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    pub fn pubkey(&self) -> Result<PubKey, ClientError> {
        let raw: [u8; 32] = hex::decode(&self.public_key)
            .map_err(|e| ClientError::Config(format!("bad public_key hex: {e}")))?
            .try_into()
            .map_err(|_| ClientError::Config("public_key not 32 bytes".into()))?;
        Ok(PubKey(raw))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPin {
    pub host: String,
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,
    /// §16.1.5 optional TCP port for the `krot-tcp/1` fallback. When
    /// unset, [`Self::effective_tcp_port`] falls back to `quic_port`
    /// (matching the spec's Appendix A which uses the same numeric
    /// value for both).
    #[serde(default)]
    pub tcp_port: Option<u16>,
    #[serde(default)]
    pub sni: Option<String>,
    /// `sha256:<hex>` — mandatory in IpMode; may be absent when a real CA is trusted.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

fn default_quic_port() -> u16 {
    krot_proto::consts::DEFAULT_UDP_PORT
}

impl ServerPin {
    /// SNI to present in the TLS handshake. Defaults to `host` if unset.
    pub fn effective_sni(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }

    /// Numeric TCP port for the `krot-tcp/1` fallback. Falls back to
    /// `quic_port` per §16.1 (Appendix A uses the same numeric value
    /// for both UDP and TCP).
    #[must_use]
    pub fn effective_tcp_port(&self) -> u16 {
        self.tcp_port.unwrap_or(self.quic_port)
    }

    /// Parse the pinned fingerprint into raw bytes, expecting `sha256:<hex>`.
    pub fn fingerprint_bytes(&self) -> Result<Option<[u8; 32]>, ClientError> {
        let Some(fp) = &self.fingerprint else {
            return Ok(None);
        };
        let rest = fp
            .strip_prefix("sha256:")
            .ok_or(ClientError::BadFingerprint)?;
        let raw = hex::decode(rest).map_err(|_| ClientError::BadFingerprint)?;
        raw.try_into()
            .map(Some)
            .map_err(|_| ClientError::BadFingerprint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub identity: Identity,
    pub server: ServerPin,
}

impl ClientConfig {
    /// Full path to the config file inside a data directory.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(CONFIG_FILE)
    }

    pub fn load_from(dir: &Path) -> Result<Self, ClientError> {
        let path = Self::path_in(dir);
        let text = fs::read_to_string(&path)
            .map_err(|e| ClientError::Config(format!("read {}: {e}", path.display())))?;
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| ClientError::Config(format!("parse {}: {e}", path.display())))?;
        Ok(cfg)
    }

    pub fn save_to(&self, dir: &Path) -> Result<(), ClientError> {
        fs::create_dir_all(dir)?;
        let path = Self::path_in(dir);
        let text = toml::to_string_pretty(self)
            .map_err(|e| ClientError::Config(format!("serialize: {e}")))?;
        let mut tmp = path.clone();
        tmp.set_extension("tmp");
        fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}
