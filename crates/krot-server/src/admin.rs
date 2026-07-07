//! Admin-token issuance and single-use consumption (§14).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use base32::Alphabet;
use rand::rngs::OsRng;
use rand::RngCore;

use krot_proto::consts::{ADMIN_TOKEN_RAW_LEN, ADMIN_TOKEN_TTL};

use crate::error::ServerError;

const HASH_FILE: &str = "admin_token.hash";
/// Crockford base32, unpadded — matches §14.1.
const ALPHABET: Alphabet = Alphabet::Crockford;

/// Handle to the (optional) currently-valid admin token.
#[derive(Debug)]
pub struct AdminTokenStore {
    data_dir: PathBuf,
    state: Mutex<Option<TokenState>>,
}

#[derive(Debug)]
struct TokenState {
    hash: [u8; 32],
    expires_at: Instant,
}

impl AdminTokenStore {
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            state: Mutex::new(None),
        }
    }

    /// Generate, persist, and print a fresh admin token.
    ///
    /// The returned string is the token in its user-facing form and should
    /// be exposed to the operator (typically via stdout).
    pub fn issue(&self) -> Result<String, ServerError> {
        let mut raw = [0u8; ADMIN_TOKEN_RAW_LEN];
        OsRng.fill_bytes(&mut raw);
        let token = base32::encode(ALPHABET, &raw);
        let hash = blake3::hash(token.as_bytes());

        fs::create_dir_all(&self.data_dir)?;
        let path = self.hash_path();
        write_secret(&path, hash.as_bytes())?;

        *self.state.lock().unwrap() = Some(TokenState {
            hash: *hash.as_bytes(),
            expires_at: Instant::now() + ADMIN_TOKEN_TTL,
        });
        Ok(token)
    }

    /// Verify `presented` against the currently-valid token.
    ///
    /// On success the token is invalidated (single-use) and its hash file
    /// removed, and the caller can proceed with enrollment.
    pub fn consume(&self, presented: &str) -> Result<(), ServerError> {
        let mut guard = self.state.lock().unwrap();
        let Some(state) = guard.as_ref() else {
            return Err(ServerError::AdminToken("no admin token issued"));
        };
        if Instant::now() >= state.expires_at {
            *guard = None;
            let _ = fs::remove_file(self.hash_path());
            return Err(ServerError::AdminToken("admin token expired"));
        }
        let candidate = blake3::hash(presented.as_bytes());
        if !constant_time_eq(candidate.as_bytes(), &state.hash) {
            return Err(ServerError::AdminToken("admin token mismatch"));
        }
        *guard = None;
        let _ = fs::remove_file(self.hash_path());
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    fn hash_path(&self) -> PathBuf {
        self.data_dir.join(HASH_FILE)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq_public(a, b)
}

/// Same as [`constant_time_eq`] but visible outside this module.
/// Used by the §16.4 admin API for session-token comparison.
pub fn constant_time_eq_public(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<(), ServerError> {
    use std::io::Write as _;
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?; // fsync before rename so a crash mid-issue leaves us consistent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    crate::fsync::sync_parent(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn issue_and_consume_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let token = store.issue().unwrap();
        assert!(store.is_active());
        store.consume(&token).unwrap();
        assert!(!store.is_active());
    }

    #[test]
    fn double_consume_rejected() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let token = store.issue().unwrap();
        store.consume(&token).unwrap();
        assert!(store.consume(&token).is_err());
    }

    #[test]
    fn wrong_token_rejected() {
        let dir = TempDir::new().unwrap();
        let store = AdminTokenStore::new(dir.path().to_path_buf());
        let _real = store.issue().unwrap();
        assert!(store.consume("WRONG").is_err());
        assert!(store.is_active()); // still active until real token or expiry
    }
}
