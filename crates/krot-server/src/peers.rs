//! §16.3.2 static federated-peer list.
//!
//! One-file registry, one apex per line, `#` comments and blank lines
//! ignored. Hot-reloaded via `notify` — same pattern as
//! [`crate::keys::KeyRegistry`] — so an operator can rotate the peer
//! set without a server restart.
//!
//! The list is *authoritative* per-relay — a peer that vanishes from
//! the file is instantly excluded from every subsequent
//! [`ClientFrame::ListPeers`] response (§16.3.3).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use tracing::{info, warn};

use crate::error::ServerError;

/// In-memory copy of the on-disk peer list. Cheap to clone via `Arc`.
#[derive(Debug)]
pub struct PeerRegistry {
    path: PathBuf,
    peers: RwLock<Vec<String>>,
}

impl PeerRegistry {
    /// Open the peer list at `path`. Missing file is treated as an
    /// empty list (no peers configured) — same forgiving policy as
    /// [`KeyRegistry::open`].
    pub fn open(path: PathBuf) -> Result<Self, ServerError> {
        let peers = if path.exists() {
            parse_file(&path)?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            peers: RwLock::new(peers),
        })
    }

    /// Snapshot of the currently-configured peers. Order matches file
    /// order; duplicates are already de-duped at parse time.
    pub fn snapshot(&self) -> Vec<String> {
        self.peers.read().unwrap().clone()
    }

    /// Number of configured peers.
    pub fn len(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Re-parse the file and swap the in-memory list. Called by the
    /// hot-reload watcher, but also exposed for tests.
    pub fn reload(&self) -> Result<(), ServerError> {
        if !self.path.exists() {
            *self.peers.write().unwrap() = Vec::new();
            info!("peer list file missing; treating as empty");
            return Ok(());
        }
        let new = parse_file(&self.path)?;
        let mut current = self.peers.write().unwrap();
        if *current != new {
            info!(
                before = current.len(),
                after = new.len(),
                "peer list reloaded"
            );
            *current = new;
        }
        Ok(())
    }

    /// Spawn a filesystem watcher that reloads on any change to the
    /// underlying file. Detached — its lifetime is the runtime's.
    pub fn spawn_watcher(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = watch_loop(self).await {
                warn!("peers watcher exited: {e}");
            }
        })
    }
}

async fn watch_loop(reg: Arc<PeerRegistry>) -> Result<(), ServerError> {
    use notify::{EventKind, RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| ServerError::Keys(format!("peers notify init: {e}")))?;

    // Watch the parent directory (survives atomic-rename replacements)
    // so `echo apex > peers.txt.tmp && mv peers.txt.tmp peers.txt`
    // still triggers a reload.
    let parent = reg
        .path
        .parent()
        .ok_or_else(|| ServerError::Keys("peers path has no parent".into()))?;
    // If the parent directory doesn't exist yet, still succeed but
    // don't watch — the operator can create it later.
    if parent.exists() {
        watcher
            .watch(parent, RecursiveMode::NonRecursive)
            .map_err(|e| ServerError::Keys(format!("peers notify watch: {e}")))?;
    }

    let target_filename = reg.path.file_name();
    while let Some(res) = rx.recv().await {
        let Ok(event) = res else { continue };
        let touches_target = event.paths.iter().any(|p| p.file_name() == target_filename);
        if !touches_target {
            continue;
        }
        if !matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
        ) {
            continue;
        }
        if let Err(e) = reg.reload() {
            warn!("peers reload failed: {e}");
        }
    }
    drop(watcher);
    Ok(())
}

fn parse_file(path: &Path) -> Result<Vec<String>, ServerError> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // De-dup on the fly — an operator listing the same peer twice
        // is more likely a mistake than intent.
        if !out.iter().any(|existing: &String| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let reg = PeerRegistry::open(dir.path().join("peers.txt")).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn parses_apex_list() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.txt");
        fs::write(
            &path,
            "# federated relays\n\
             krot.us-east.example\n\
             \n\
             krot.eu-west.example:7854\n",
        )
        .unwrap();
        let reg = PeerRegistry::open(path).unwrap();
        assert_eq!(
            reg.snapshot(),
            vec![
                "krot.us-east.example".to_string(),
                "krot.eu-west.example:7854".to_string(),
            ]
        );
    }

    #[test]
    fn de_duplicates_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.txt");
        fs::write(&path, "a.example\na.example\nb.example\n").unwrap();
        let reg = PeerRegistry::open(path).unwrap();
        assert_eq!(
            reg.snapshot(),
            vec!["a.example".to_string(), "b.example".to_string()]
        );
    }

    #[test]
    fn reload_reflects_edit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.txt");
        fs::write(&path, "a.example\n").unwrap();
        let reg = PeerRegistry::open(path.clone()).unwrap();
        assert_eq!(reg.snapshot(), vec!["a.example".to_string()]);
        fs::write(&path, "a.example\nb.example\n").unwrap();
        reg.reload().unwrap();
        assert_eq!(
            reg.snapshot(),
            vec!["a.example".to_string(), "b.example".to_string()]
        );
    }

    #[test]
    fn reload_missing_file_empties_list() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("peers.txt");
        fs::write(&path, "a.example\n").unwrap();
        let reg = PeerRegistry::open(path.clone()).unwrap();
        assert_eq!(reg.len(), 1);
        fs::remove_file(&path).unwrap();
        reg.reload().unwrap();
        assert!(reg.is_empty());
    }
}
