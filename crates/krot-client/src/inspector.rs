//! Local HTTP inspector: a bounded ring of parsed first-line request /
//! response pairs, plus a tiny embedded web UI on `127.0.0.1:4040` for
//! browsing them.
//!
//! The inspector is deliberately best-effort. It only ever peeks the first
//! chunk of each direction (see [`crate::proxy`]) and never blocks the
//! byte-shovel path — if parsing fails or the buffer overflows before
//! headers end, we simply skip recording that entry.

// Embedded UI HTML lives at the bottom of the file for readability.
#![allow(clippy::items_after_test_module)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use krot_proto::InspectionPrelude;

/// Maximum number of entries retained. Older entries are evicted.
pub const HISTORY_CAP: usize = 200;

pub type EntryId = u64;

/// One captured request/response pair.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: EntryId,
    /// UNIX epoch, milliseconds.
    pub time_ms: u128,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    /// Peer address the server observed on the public port (§16.2).
    /// Only populated when the server sent an `InspectionPrelude`.
    pub peer: Option<String>,
    /// Best-guess host (Host header for HTTP, SNI for HTTPS
    /// passthrough). Populated from the prelude.
    pub host: Option<String>,
}

#[derive(Debug)]
pub struct Inspector {
    state: RwLock<State>,
}

#[derive(Debug)]
struct State {
    next_id: u64,
    entries: VecDeque<Entry>,
    pending_start: std::collections::HashMap<EntryId, Instant>,
    /// Prelude data waiting to attach to the next `record_request` on
    /// this stream. Populated by `record_accept`; consumed on the
    /// following `record_request`. On HTTPS-passthrough there is no
    /// subsequent request-line to record, so an unclaimed prelude is
    /// emitted as its own header-less entry after a short debounce.
    pending_accept: Option<PendingAccept>,
}

#[derive(Debug, Clone)]
struct PendingAccept {
    peer: String,
    host: Option<String>,
}

impl Default for Inspector {
    fn default() -> Self {
        Self::new()
    }
}

fn flush_pending_accept_locked(state: &mut State) {
    let Some(pending) = state.pending_accept.take() else {
        return;
    };
    let id = state.next_id;
    state.next_id = state.next_id.wrapping_add(1);
    let entry = Entry {
        id,
        time_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        method: None,
        path: None,
        status: None,
        duration_ms: None,
        peer: Some(pending.peer),
        host: pending.host,
    };
    if state.entries.len() == HISTORY_CAP {
        state.entries.pop_front();
    }
    state.entries.push_back(entry);
}

impl Inspector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(State {
                next_id: 1,
                entries: VecDeque::with_capacity(HISTORY_CAP),
                pending_start: std::collections::HashMap::new(),
                pending_accept: None,
            }),
        }
    }

    /// §16.2: record a fresh server-provided acceptance event. For
    /// HTTP tunnels the prelude will be attached to the following
    /// `record_request` on the same stream; for HTTPS-passthrough
    /// (where the client cannot parse the request-line) we
    /// synthesise an entry immediately so the accept still appears in
    /// the UI.
    pub fn record_accept(&self, prelude: &InspectionPrelude) {
        let mut state = self.state.write().unwrap();
        let host = prelude.http.as_ref().map(|h| {
            if h.host.is_empty() {
                h.sni.clone().unwrap_or_default()
            } else {
                h.host.clone()
            }
        });
        let is_passthrough = prelude.http.as_ref().is_some_and(|h| h.sni.is_some());
        state.pending_accept = Some(PendingAccept {
            peer: prelude.peer.clone(),
            host,
        });
        // HTTPS-passthrough streams never yield a plaintext
        // request-line, so record the accept as a stand-alone entry
        // right away.
        if is_passthrough {
            flush_pending_accept_locked(&mut state);
        }
    }

    /// Record the start of a request. Returns the new entry id so the
    /// caller can call [`Self::record_response`] later.
    pub fn record_request(&self, method: Option<String>, path: Option<String>) -> EntryId {
        let mut state = self.state.write().unwrap();
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.pending_start.insert(id, Instant::now());
        // Attach any pending §16.2 accept metadata that arrived on this
        // stream just before the request line.
        let (peer, host) = match state.pending_accept.take() {
            Some(p) => (Some(p.peer), p.host),
            None => (None, None),
        };
        let entry = Entry {
            id,
            time_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            method,
            path,
            status: None,
            duration_ms: None,
            peer,
            host,
        };
        if state.entries.len() == HISTORY_CAP {
            let evicted = state.entries.pop_front();
            if let Some(e) = evicted {
                state.pending_start.remove(&e.id);
            }
        }
        state.entries.push_back(entry);
        id
    }

    /// Attach a response status and elapsed time to a previously-recorded
    /// request.
    pub fn record_response(&self, id: EntryId, status: u16) {
        let mut state = self.state.write().unwrap();
        let start = state.pending_start.remove(&id);
        if let Some(e) = state.entries.iter_mut().find(|e| e.id == id) {
            e.status = Some(status);
            // Sub-ms responses (common on localhost) round to 0 —
            // clamp to 1 so the UI shows a real number, not "0".
            e.duration_ms =
                start.map(|s| Instant::now().duration_since(s).as_millis().max(1) as u64);
        }
    }

    fn snapshot(&self) -> Vec<Entry> {
        let state = self.state.read().unwrap();
        state.entries.iter().rev().cloned().collect()
    }
}

/// Run the inspector's tiny HTTP UI on `bind` until the returned task exits.
pub fn spawn_ui(inspector: Arc<Inspector>, bind: SocketAddr) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                warn!(?bind, "inspector UI cannot bind: {e}");
                return;
            }
        };
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let inspector = Arc::clone(&inspector);
            tokio::spawn(async move {
                if let Err(e) = handle(sock, &inspector).await {
                    debug!("inspector http error: {e}");
                }
            });
        }
    })
}

async fn handle(
    mut sock: tokio::net::TcpStream,
    inspector: &Inspector,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::with_capacity(1024);
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let mut tmp = [0u8; 1024];
        let n = tokio::time::timeout_at(deadline.into(), sock.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8 * 1024 {
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(&buf);
    let path = req.path.unwrap_or("/");

    if path == "/api/entries" {
        let body = serde_json::to_string(&inspector.snapshot())?;
        write_response(&mut sock, "200 OK", "application/json", body.as_bytes()).await?;
    } else {
        write_response(
            &mut sock,
            "200 OK",
            "text/html; charset=utf-8",
            HTML.as_bytes(),
        )
        .await?;
    }
    Ok(())
}

async fn write_response(
    sock: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_request_then_response() {
        let insp = Inspector::new();
        let id = insp.record_request(Some("GET".into()), Some("/hello".into()));
        insp.record_response(id, 200);
        let snap = insp.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].method.as_deref(), Some("GET"));
        assert_eq!(snap[0].path.as_deref(), Some("/hello"));
        assert_eq!(snap[0].status, Some(200));
        assert!(snap[0].duration_ms.is_some());
    }

    #[test]
    fn snapshot_returns_newest_first() {
        let insp = Inspector::new();
        insp.record_request(Some("GET".into()), Some("/a".into()));
        insp.record_request(Some("GET".into()), Some("/b".into()));
        let snap = insp.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].path.as_deref(), Some("/b"));
        assert_eq!(snap[1].path.as_deref(), Some("/a"));
    }

    #[test]
    fn ring_evicts_oldest() {
        let insp = Inspector::new();
        for i in 0..(HISTORY_CAP + 5) {
            insp.record_request(Some("GET".into()), Some(format!("/{i}")));
        }
        assert_eq!(insp.state.read().unwrap().entries.len(), HISTORY_CAP);
        let snap = insp.snapshot();
        // Newest first — path should be the last-inserted index.
        assert_eq!(
            snap[0].path.as_deref(),
            Some(format!("/{}", HISTORY_CAP + 4)).as_deref()
        );
    }
}

const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>krot · inspector</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: #1a1410;
    color: #f5ece0;
    font-family: "JetBrains Mono", "Cascadia Code", "SF Mono", "Fira Code",
                 "DejaVu Sans Mono", ui-monospace, Menlo, Consolas, monospace;
    font-size: 14px;
    font-weight: 500;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
  header {
    padding: 16px 24px 14px;
    border-bottom: 1px solid #3a2a20;
    display: flex; align-items: center; gap: 14px;
    background: #221913;
  }
  header svg { width: 42px; height: 42px; flex: 0 0 auto; }
  header .brand { font-size: 20px; font-weight: 800; letter-spacing: -0.4px; }
  header .brand em { font-style: normal; color: #e89a9a; }
  header .sub { color: #a89a8a; font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; margin-left: auto; }
  main { padding: 16px 24px 40px; }
  .empty {
    padding: 60px 0; text-align: center; color: #8a7a6a; font-size: 14px; font-weight: 600;
  }
  .empty em { color: #e89a9a; font-style: normal; }
  table { border-collapse: collapse; width: 100%; }
  thead th {
    text-align: left; padding: 10px 12px;
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: #a89a8a; font-weight: 800;
    border-bottom: 1px solid #3a2a20;
  }
  tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #2b1a12;
    font-variant-numeric: tabular-nums;
    font-weight: 600;
  }
  tbody tr:hover td { background: #221913; }
  .time { color: #a89a8a; }
  .method { font-weight: 800; color: #f5ece0; letter-spacing: 0.3px; }
  .method.GET    { color: #8dd08d; }
  .method.POST   { color: #f0a8a8; }
  .method.PUT    { color: #f0b060; }
  .method.DELETE { color: #e07070; }
  .method.PATCH  { color: #c090e0; }
  .path { color: #f5ece0; word-break: break-all; font-weight: 600; }
  .status { text-align: right; font-weight: 800; }
  .status.s2 { color: #8dd08d; }
  .status.s3 { color: #8ab0d0; }
  .status.s4 { color: #f0b060; }
  .status.s5 { color: #e07070; }
  .ms { text-align: right; color: #c8b8a8; font-weight: 600; }
  th.right, td.right { text-align: right; }
</style>
</head>
<body>
  <header>
    <svg viewBox="0 0 120 120" aria-hidden="true">
      <ellipse cx="60" cy="70" rx="42" ry="34" fill="#5a3a28"/>
      <circle cx="60" cy="50" r="30" fill="#6a4a34"/>
      <path d="M42 46 h10 M68 46 h10" stroke="#2b1a12" stroke-width="3" stroke-linecap="round"/>
      <path d="M55 62 L60 70 L65 62 Z" fill="#e89a9a"/>
      <circle cx="60" cy="66" r="1.6" fill="#2b1a12"/>
      <ellipse cx="34" cy="82" rx="10" ry="8" fill="#e89a9a"/>
      <ellipse cx="86" cy="82" rx="10" ry="8" fill="#e89a9a"/>
    </svg>
    <span class="brand">kr<em>o</em>t · inspector</span>
    <span class="sub" id="count">— requests</span>
  </header>
  <main>
    <div id="empty" class="empty" style="display:none">
      Waiting for requests through the tunnel<em>.</em><em>.</em><em>.</em>
    </div>
    <table id="t" style="display:none">
      <thead><tr>
        <th>Time</th>
        <th>Method</th>
        <th>Path</th>
        <th class="right">Status</th>
        <th class="right">ms</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </main>
<script>
async function refresh(){
  try {
    const r = await fetch('/api/entries',{cache:'no-store'});
    const rows = await r.json();
    const tb = document.querySelector('#t tbody');
    const empty = document.getElementById('empty');
    const table = document.getElementById('t');
    const count = document.getElementById('count');
    count.textContent = rows.length + ' request' + (rows.length === 1 ? '' : 's');
    if (rows.length === 0) {
      empty.style.display = '';
      table.style.display = 'none';
      return;
    }
    empty.style.display = 'none';
    table.style.display = '';
    tb.innerHTML = '';
    for (const e of rows) {
      const tr = document.createElement('tr');
      const t  = new Date(e.time_ms).toISOString().slice(11,23);
      const m  = e.method || '';
      const p  = e.path || '-';
      const s  = e.status;
      const ms = e.duration_ms;
      const scls = s ? 's' + Math.floor(s/100) : '';
      const mcls = m ? m.toUpperCase() : '';
      tr.innerHTML = `
        <td class="time">${t}</td>
        <td class="method ${mcls}">${m || '-'}</td>
        <td class="path">${p.replace(/</g,'&lt;')}</td>
        <td class="status ${scls}">${s || '-'}</td>
        <td class="ms">${ms == null ? '-' : ms}</td>`;
      tb.appendChild(tr);
    }
  } catch (err) {
    // just wait for next poll
  }
}
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>"##;
