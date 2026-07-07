//! `authorized_keys` parser and in-memory index (§13).
//!
//! Format (one entry per line):
//! ```text
//! ed25519 <base64-pubkey> [key=value,key=value] [# comment]
//! ```
//!
//! Recognised options (unknown keys are stored verbatim but ignored):
//! `subdomain=<name[,name...]|*>`, `ports=<p[,p...]>`, `conns=<n>`,
//! `bw=<n><unit>/<period>`, `quota=<n><unit>/<period>`.
//!
//! Only `subdomain` and `conns` are consulted by the current MVP; the rest
//! are parsed so that a config authored today remains valid tomorrow.
//!
//! **Hot-reload.** [`KeyRegistry::spawn_watcher`] runs a `notify` watcher
//! on the parent directory (so atomic-rename replacements are picked up)
//! and re-parses on any relevant filesystem event. When keys are removed
//! or their authorization data changes, their public keys are broadcast on
//! [`KeyRegistry::subscribe_revocations`]; each authenticated session
//! subscribes and terminates itself with `ServerBye { KeyRevoked }` on a
//! match (§13, 1-second SLA — `notify` events fire in <100 ms and the
//! session's `select!` reacts immediately).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use base64::Engine as _;
use tokio::sync::broadcast;
use tracing::{info, warn};

use krot_proto::PubKey;

use crate::error::ServerError;
use crate::rate::{parse_rate_per, RatePer};

/// Capacity of the revocation broadcast channel. Enough headroom that a
/// slow subscriber missing a few events still recovers — subscribers only
/// really matter until they observe *their own* pubkey.
const REVOCATION_CAPACITY: usize = 256;

/// A single trust entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizedEntry {
    pub allow_any_subdomain: bool,
    pub allowed_subdomains: Vec<String>,
    pub max_conns: Option<u32>,
    /// Allowed remote TCP ports (§13). `None` = no restriction.
    /// A tunnel `RegisterTunnel { kind: Tcp { remote_port: Some(p) } }`
    /// is rejected with `LABEL_FORBIDDEN` if `p` is not in this list.
    pub allowed_ports: Option<Vec<u16>>,
    /// Bandwidth cap (§9). `50MB/s`, `100MB/s`, etc.
    pub bw: Option<RatePer>,
    /// Period quota (§9). `500GB/month`, `10GB/day`, etc.
    pub quota: Option<RatePer>,
    /// Federated relays this identity may publish the same tunnel on
    /// (§16.3.1). Empty when the option is absent. Values are apex
    /// domains (e.g. `krot.us-east.example`); no validation of the
    /// domain grammar here — the relay list is admin-authored trust
    /// data, malformed entries just become non-matches at §16.3.4
    /// lookup time.
    pub federation: Vec<String>,
    pub comment: Option<String>,
}

impl AuthorizedEntry {
    /// Whether two entries carry equivalent *authorization* — the trailing
    /// comment is ignored so a docstring edit doesn't cause a revocation.
    fn authorization_equal(&self, other: &Self) -> bool {
        self.allow_any_subdomain == other.allow_any_subdomain
            && self.allowed_subdomains == other.allowed_subdomains
            && self.max_conns == other.max_conns
            && self.allowed_ports == other.allowed_ports
            && self.bw == other.bw
            && self.quota == other.quota
            && self.federation == other.federation
    }
}

/// In-memory index over the on-disk `authorized_keys` file.
#[derive(Debug)]
pub struct KeyRegistry {
    path: PathBuf,
    entries: RwLock<HashMap<PubKey, AuthorizedEntry>>,
    revocation: broadcast::Sender<PubKey>,
}

impl KeyRegistry {
    /// Open (creating an empty file if missing) and load the registry.
    pub fn open(path: PathBuf) -> Result<Self, ServerError> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, b"")?;
        }
        let entries = parse_file(&path)?;
        let (revocation, _) = broadcast::channel(REVOCATION_CAPACITY);
        Ok(Self {
            path,
            entries: RwLock::new(entries),
            revocation,
        })
    }

    pub fn contains(&self, pubkey: &PubKey) -> bool {
        self.entries.read().unwrap().contains_key(pubkey)
    }

    pub fn get(&self, pubkey: &PubKey) -> Option<AuthorizedEntry> {
        self.entries.read().unwrap().get(pubkey).cloned()
    }

    /// Snapshot of every entry currently in the registry. Cloned; safe to
    /// return across await points.
    pub fn snapshot(&self) -> Vec<(PubKey, AuthorizedEntry)> {
        self.entries
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Rewrite the on-disk `authorized_keys` file with the given pubkey
    /// removed and reload the in-memory index. Used by the §16.4 admin
    /// API's `DELETE /admin/v1/keys/<pubkey_b64>` endpoint.
    ///
    /// The revocation broadcast fires on the subsequent `reload()`, so
    /// live sessions for that pubkey terminate within 1 s (§13 SLA).
    pub fn remove_pubkey(&self, target: &PubKey) -> Result<bool, ServerError> {
        let contents = fs::read_to_string(&self.path).unwrap_or_default();
        let mut out = String::new();
        let mut removed = false;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out.push_str(line);
                out.push('\n');
                continue;
            }
            match parse_line(trimmed) {
                Some((pk, _)) if pk == *target => {
                    removed = true;
                    // drop the line
                }
                _ => {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        if removed {
            atomic_write(&self.path, out.as_bytes())?;
            self.reload()?;
        }
        Ok(removed)
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Subscribe to the revocation stream. Each item is a `PubKey` whose
    /// authorization was removed or materially changed on the last reload.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<PubKey> {
        self.revocation.subscribe()
    }

    /// Append a new entry to disk and update the in-memory index.
    ///
    /// Returns the line as written for logging/echo to the client.
    pub fn append_line(&self, line: &str) -> Result<String, ServerError> {
        let (pubkey, entry) =
            parse_line(line).ok_or_else(|| ServerError::Keys(format!("cannot parse: {line}")))?;

        let contents = fs::read_to_string(&self.path).unwrap_or_default();
        let mut new = contents;
        if !new.is_empty() && !new.ends_with('\n') {
            new.push('\n');
        }
        new.push_str(line);
        if !line.ends_with('\n') {
            new.push('\n');
        }
        atomic_write(&self.path, new.as_bytes())?;
        self.entries.write().unwrap().insert(pubkey, entry);
        Ok(line.trim_end().to_string())
    }

    /// Re-parse the file, diff against the in-memory index, and broadcast
    /// revocations for any pubkey that was removed or materially changed.
    pub fn reload(&self) -> Result<(), ServerError> {
        let new_entries = parse_file(&self.path)?;
        let mut current = self.entries.write().unwrap();

        let removed: Vec<PubKey> = current
            .keys()
            .filter(|k| !new_entries.contains_key(k))
            .copied()
            .collect();

        let modified: Vec<PubKey> = new_entries
            .iter()
            .filter(|(k, new)| {
                current
                    .get(k)
                    .is_some_and(|old| !old.authorization_equal(new))
            })
            .map(|(k, _)| *k)
            .collect();

        *current = new_entries;
        drop(current);

        for pk in removed.iter().chain(modified.iter()) {
            // Ignore send errors — no active receivers is fine, no one to
            // notify. The next auth for a removed key will fail at
            // handshake anyway.
            let _ = self.revocation.send(*pk);
        }
        if !removed.is_empty() || !modified.is_empty() {
            info!(
                removed = removed.len(),
                modified = modified.len(),
                "authorized_keys reloaded"
            );
        }
        Ok(())
    }

    /// Spawn a filesystem watcher that reloads the registry on any change
    /// to `path`. Watches the parent directory so atomic-rename updates
    /// (our own `append_line`, or `sed -i`, etc.) are captured.
    pub fn spawn_watcher(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = watch_loop(self).await {
                warn!("authorized_keys watcher exited: {e}");
            }
        })
    }
}

async fn watch_loop(reg: Arc<KeyRegistry>) -> Result<(), ServerError> {
    use notify::{EventKind, RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // `move` the sender into notify's sync callback; notify runs it on
    // its own thread so bridging via an unbounded mpsc is idiomatic.
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| ServerError::Keys(format!("notify init: {e}")))?;

    let parent = reg
        .path
        .parent()
        .ok_or_else(|| ServerError::Keys("authorized_keys has no parent dir".into()))?;
    watcher
        .watch(parent, RecursiveMode::NonRecursive)
        .map_err(|e| ServerError::Keys(format!("notify watch: {e}")))?;

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
            warn!("authorized_keys reload failed: {e}");
        }
    }
    // Keep the watcher alive until the channel closes.
    drop(watcher);
    Ok(())
}

fn parse_file(path: &Path) -> Result<HashMap<PubKey, AuthorizedEntry>, ServerError> {
    let text = fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((pk, entry)) = parse_line(trimmed) else {
            return Err(ServerError::Keys(format!("line {}: {line}", idx + 1)));
        };
        out.insert(pk, entry);
    }
    Ok(out)
}

fn parse_line(line: &str) -> Option<(PubKey, AuthorizedEntry)> {
    // Strip trailing comment.
    let bare = line.split('#').next().unwrap().trim();
    let mut it = bare.split_whitespace();
    let algo = it.next()?;
    let b64 = it.next()?;
    if algo != "ed25519" {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let arr: [u8; 32] = raw.try_into().ok()?;
    let pubkey = PubKey(arr);
    let mut entry = AuthorizedEntry::default();
    // §13 options grammar is ambiguous: the prose says "comma-separated
    // key=value pairs" but the worked example uses whitespace between
    // top-level options (`subdomain=alice,alice-staging bw=50MB/s
    // conns=5`). We accept both: collect all remaining tokens after
    // the pubkey, join by comma, then re-split with lookahead so that
    // any comma-separated fragment NOT starting with `<known>=`
    // continues the previous value.
    let joined: Vec<String> = it.map(str::to_string).collect();
    let joined = joined.join(",");
    let known = ["subdomain", "conns", "bw", "quota", "ports", "federation"];
    let mut pairs: Vec<(String, String)> = Vec::new();
    for tok in joined.split(',') {
        if let Some((k, v)) = tok.split_once('=') {
            if known.contains(&k) {
                pairs.push((k.to_string(), v.to_string()));
                continue;
            }
        }
        // Continuation of the previous value (list item).
        if let Some(last) = pairs.last_mut() {
            last.1.push(',');
            last.1.push_str(tok);
        }
    }
    for (k, v) in pairs {
        match k.as_str() {
            "subdomain" => {
                if v == "*" {
                    entry.allow_any_subdomain = true;
                } else {
                    entry.allowed_subdomains = v.split(',').map(str::to_string).collect();
                }
            }
            "conns" => {
                entry.max_conns = v.parse().ok();
            }
            "bw" => {
                entry.bw = parse_rate_per(&v);
            }
            "quota" => {
                entry.quota = parse_rate_per(&v);
            }
            "ports" => {
                entry.allowed_ports = parse_ports(&v);
            }
            "federation" => {
                // §16.3.1: comma-separated apex domains.
                entry.federation = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            _ => {}
        }
    }
    let comment_start = line.find('#').map(|i| line[i + 1..].trim().to_string());
    entry.comment = comment_start.filter(|s| !s.is_empty());
    Some((pubkey, entry))
}

/// Parse a `ports=` value. Accepts a comma-separated list
/// (`8080,8443`), a range (`10000-19999`), or a mix (`8080,10000-10099`).
/// Returns `None` on any parse error so an unrecognised value falls back
/// to "no restriction" (safer than silently rejecting).
fn parse_ports(s: &str) -> Option<Vec<u16>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo.trim().parse().ok()?;
            let hi: u16 = hi.trim().parse().ok()?;
            if hi < lo {
                return None;
            }
            for p in lo..=hi {
                out.push(p);
            }
        } else {
            out.push(part.parse().ok()?);
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ServerError> {
    use std::io::Write as _;
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?; // fsync — spec §13 requires the append to be durable before rename.
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
    fn parses_pubkey_only() {
        let (pk, entry) =
            parse_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(pk.0.len(), 32);
        assert!(!entry.allow_any_subdomain);
    }

    #[test]
    fn parses_options() {
        let (_, entry) =
            parse_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=* conns=5")
                .unwrap();
        assert!(entry.allow_any_subdomain);
        assert_eq!(entry.max_conns, Some(5));
    }

    #[test]
    fn parses_multivalue_subdomain() {
        let (_, entry) = parse_line(
            "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=alice,alice-staging",
        )
        .unwrap();
        assert!(!entry.allow_any_subdomain);
        assert_eq!(
            entry.allowed_subdomains,
            vec!["alice".to_string(), "alice-staging".to_string()]
        );
    }

    #[test]
    fn parses_ports_list_and_range() {
        assert_eq!(parse_ports("8080"), Some(vec![8080]));
        assert_eq!(parse_ports("8080,8443"), Some(vec![8080, 8443]));
        assert_eq!(parse_ports("10000-10002"), Some(vec![10000, 10001, 10002]));
        assert_eq!(parse_ports("80,10000-10001"), Some(vec![80, 10000, 10001]));
        assert!(parse_ports("bogus").is_none());
        assert!(parse_ports("").is_none());
        assert!(parse_ports("100-50").is_none());
    }

    #[test]
    fn parses_ports_in_authorized_line() {
        let (_, entry) = parse_line(
            "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=* ports=8080,8443",
        )
        .unwrap();
        assert!(entry.allow_any_subdomain);
        assert_eq!(entry.allowed_ports, Some(vec![8080, 8443]));
    }

    #[test]
    fn parses_federation_list() {
        let (_, entry) = parse_line(
            "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=* federation=krot.us-east.example,krot.eu-west.example",
        )
        .unwrap();
        assert_eq!(
            entry.federation,
            vec![
                "krot.us-east.example".to_string(),
                "krot.eu-west.example".to_string(),
            ]
        );
    }

    #[test]
    fn parses_federation_single_apex() {
        let (_, entry) = parse_line(
            "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= federation=peer.example",
        )
        .unwrap();
        assert_eq!(entry.federation, vec!["peer.example".to_string()]);
    }

    #[test]
    fn federation_defaults_empty() {
        let (_, entry) =
            parse_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=*").unwrap();
        assert!(entry.federation.is_empty());
    }

    #[test]
    fn federation_change_triggers_revocation() {
        // §13: authorization_equal MUST diff federation= so a peer-list
        // rotation kicks live sessions (they'd otherwise keep the old
        // peer list and register on de-authorised relays).
        let base = "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let (_, a) = parse_line(&format!("{base} subdomain=* federation=x.example")).unwrap();
        let (_, b) = parse_line(&format!(
            "{base} subdomain=* federation=x.example,y.example"
        ))
        .unwrap();
        assert!(!a.authorization_equal(&b));
    }

    #[test]
    fn appends_and_reads_back() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authorized_keys");
        let reg = KeyRegistry::open(path).unwrap();
        assert!(reg.is_empty());
        reg.append_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=*")
            .unwrap();
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn reload_removes_and_broadcasts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authorized_keys");
        let reg = KeyRegistry::open(path.clone()).unwrap();
        reg.append_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=*")
            .unwrap();
        let mut rx = reg.subscribe_revocations();
        // Empty out the file — one entry should be revoked.
        fs::write(&path, b"").unwrap();
        reg.reload().unwrap();
        assert_eq!(reg.len(), 0);
        let pk = rx.try_recv().unwrap();
        assert_eq!(pk.0.len(), 32);
    }

    #[test]
    fn reload_broadcasts_material_changes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("authorized_keys");
        let reg = KeyRegistry::open(path.clone()).unwrap();
        reg.append_line("ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=*")
            .unwrap();
        let mut rx = reg.subscribe_revocations();
        // Restrict subdomain — should broadcast.
        fs::write(
            &path,
            b"ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=alice\n",
        )
        .unwrap();
        reg.reload().unwrap();
        assert!(rx.try_recv().is_ok());
    }

    // -------- Property tests: parsers MUST NOT panic --------

    proptest::proptest! {
        /// `parse_line` on arbitrary text — expected result is
        /// either `Some(_)` (valid entry) or `None` (rejected), no
        /// panic.
        #[test]
        fn parse_line_never_panics(s in ".{0,2048}") {
            let _ = parse_line(&s);
        }

        /// `parse_ports` on arbitrary text.
        #[test]
        fn parse_ports_never_panics(s in ".{0,512}") {
            let _ = parse_ports(&s);
        }

        /// `KeyRegistry::open` on a file with arbitrary bytes.
        /// Anything from a random blob to a nearly-valid line MUST
        /// yield either an error or an empty registry, never a
        /// panic.
        #[test]
        fn key_registry_open_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
        ) {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("authorized_keys");
            fs::write(&path, &bytes).unwrap_or(());
            let _ = KeyRegistry::open(path);
        }
    }
}
