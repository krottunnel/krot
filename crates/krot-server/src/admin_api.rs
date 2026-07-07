//! §16.4 Structured admin API.
//!
//! Small hand-rolled HTTP/1.1 server bound (by default) on
//! `127.0.0.1:9700`. Uses `httparse` for request parsing and
//! `serde_json` for bodies — same pattern as the client-side inspector
//! UI and the ACME HTTP-01 responder, so we don't pull in a full HTTP
//! framework.
//!
//! Auth: `Authorization: Bearer <session_token>`. Session tokens are
//! minted by exchanging the enrollment `admin_token` (§14.1) at
//! `POST /admin/v1/session`. The exchange consumes the enrollment
//! token (single-use) and returns a fresh 32-byte session token
//! (Crockford base32, `KROT_SESSION_TOKEN_RAW_LEN`), valid for
//! `session_ttl` (default 24 h).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base32::Alphabet;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use krot_proto::PubKey;

use crate::admin::AdminTokenStore;
use crate::keys::KeyRegistry;
use crate::rate::RateLimitState;
use crate::registry::{TunnelRegistry, TunnelSnapshot, TunnelSnapshotKind};

const SESSION_TOKEN_RAW_LEN: usize = 32;
const CROCKFORD: Alphabet = Alphabet::Crockford;

/// Default admin API bind — loopback only. Operators exposing this
/// publicly are expected to front it with a TLS reverse-proxy.
pub const DEFAULT_ADMIN_BIND: &str = "127.0.0.1:9700";
/// Default session token lifetime — 24 h.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// Cap on how many bytes we buffer while looking for the end of the
/// request headers.
const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Cap on request body length. Admin API payloads are tiny; anything
/// larger is malformed.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Shared per-server state consumed by the admin API. Held behind an
/// `Arc` and shared with the KROT session/data-path via existing
/// `SharedState` handles.
#[derive(Debug)]
pub struct AdminApiState {
    pub keys: Arc<KeyRegistry>,
    pub registry: Arc<TunnelRegistry>,
    pub admin_tokens: Arc<AdminTokenStore>,
    /// Active session tokens: BLAKE3 hash → expiry.
    sessions: Mutex<HashMap<[u8; 32], Instant>>,
    session_ttl: Duration,
    /// Per-identity rate-limit state map. Cloned from
    /// `SharedState.rates` so the metrics endpoint can walk it.
    pub rates: Arc<Mutex<HashMap<PubKey, Arc<RateLimitState>>>>,
    pub metrics: Arc<crate::metrics::ServerMetrics>,
}

impl AdminApiState {
    #[must_use]
    pub fn new(
        keys: Arc<KeyRegistry>,
        registry: Arc<TunnelRegistry>,
        admin_tokens: Arc<AdminTokenStore>,
        rates: Arc<Mutex<HashMap<PubKey, Arc<RateLimitState>>>>,
        session_ttl: Duration,
        metrics: Arc<crate::metrics::ServerMetrics>,
    ) -> Self {
        Self {
            keys,
            registry,
            admin_tokens,
            sessions: Mutex::new(HashMap::new()),
            session_ttl,
            rates,
            metrics,
        }
    }

    /// Mint a fresh session token, store its BLAKE3 hash with the
    /// configured TTL, and return the plaintext token exactly once.
    fn mint_session(&self) -> (String, u64) {
        let mut raw = [0u8; SESSION_TOKEN_RAW_LEN];
        OsRng.fill_bytes(&mut raw);
        let token = base32::encode(CROCKFORD, &raw);
        let hash = blake3::hash(token.as_bytes());
        let expires_at = Instant::now() + self.session_ttl;
        self.sessions
            .lock()
            .unwrap()
            .insert(*hash.as_bytes(), expires_at);
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .saturating_add(self.session_ttl.as_secs());
        (token, expires_at_unix)
    }

    /// Constant-time check that `presented` matches a live session and
    /// clear expired sessions. Returns `true` on match.
    fn check_session(&self, presented: &str) -> bool {
        let candidate = blake3::hash(presented.as_bytes());
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, exp| *exp > now);
        // Constant-time comparison of the candidate against every live
        // session hash so a timing side-channel can't reveal which slot
        // matched. Bail early only on the aggregate result.
        let mut hit = false;
        for known in sessions.keys() {
            hit |= crate::admin::constant_time_eq_public(candidate.as_bytes(), known);
        }
        hit
    }
}

/// Run the admin API accept loop until the listener errors.
pub async fn run_admin_api(listener: TcpListener, state: Arc<AdminApiState>) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle(tcp, state).await {
                        debug!(?peer, "admin api error: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("admin api accept: {e}");
                return;
            }
        }
    }
}

async fn handle(
    mut tcp: TcpStream,
    state: Arc<AdminApiState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let req = read_request(&mut tcp).await?;
    let auth = req.auth_bearer();
    let (status, body) = route(&req, auth, &state);
    write_response(&mut tcp, status, &body).await?;
    Ok(())
}

fn route(req: &Request, auth: Option<&str>, state: &AdminApiState) -> (&'static str, Vec<u8>) {
    // `POST /admin/v1/session` is the only unauthenticated endpoint —
    // handled before the bearer-token check.
    if req.method == "POST" && req.path == "/admin/v1/session" {
        return handle_session(req, state);
    }
    let Some(token) = auth else {
        state
            .metrics
            .admin_api_auth_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return error(401, "missing Authorization: Bearer");
    };
    if !state.check_session(token) {
        state
            .metrics
            .admin_api_auth_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return error(401, "invalid or expired session token");
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/admin/v1/tunnels") => handle_list_tunnels(state),
        ("GET", "/admin/v1/keys") => handle_list_keys(state),
        ("POST", "/admin/v1/keys") => handle_append_key(req, state),
        ("GET", "/admin/v1/metrics") => handle_metrics(state),
        ("DELETE", p) if p.starts_with("/admin/v1/keys/") => {
            let b64 = &p["/admin/v1/keys/".len()..];
            handle_delete_key(b64, state)
        }
        _ => error(404, "no such route"),
    }
}

// ---------- handlers ----------

fn handle_session(req: &Request, state: &AdminApiState) -> (&'static str, Vec<u8>) {
    #[derive(Deserialize)]
    struct Body {
        admin_token: String,
    }
    #[derive(Serialize)]
    struct Reply {
        session_token: String,
        expires_at_unix: u64,
    }
    let Ok(body) = serde_json::from_slice::<Body>(&req.body) else {
        return error(400, "expected {\"admin_token\": \"...\"}");
    };
    use std::sync::atomic::Ordering::Relaxed;
    if state.admin_tokens.consume(&body.admin_token).is_err() {
        state
            .metrics
            .admin_api_session_rejected
            .fetch_add(1, Relaxed);
        return error(401, "admin token rejected");
    }
    state.metrics.admin_api_session_minted.fetch_add(1, Relaxed);
    let (token, expires_at_unix) = state.mint_session();
    let reply = Reply {
        session_token: token,
        expires_at_unix,
    };
    json(200, &reply)
}

#[derive(Serialize)]
struct TunnelDto {
    tunnel_id: u64,
    owner_pubkey_b64: String,
    session_id_b64: String,
    state: &'static str,
    inspect: bool,
    kind: &'static str,
    label: Option<String>,
    public_port: Option<u16>,
}

fn dto_of(t: TunnelSnapshot) -> TunnelDto {
    let (kind, label, port) = match t.kind {
        TunnelSnapshotKind::Http { label } => ("http", Some(label), None),
        TunnelSnapshotKind::Tcp { public_port } => ("tcp", None, Some(public_port)),
    };
    TunnelDto {
        tunnel_id: t.tunnel_id.0,
        owner_pubkey_b64: b64(&t.owner.0),
        session_id_b64: b64(&t.session_id.0),
        state: if t.live { "live" } else { "dangling" },
        inspect: t.inspect,
        kind,
        label,
        public_port: port,
    }
}

fn handle_list_tunnels(state: &AdminApiState) -> (&'static str, Vec<u8>) {
    let snap: Vec<TunnelDto> = state.registry.snapshot().into_iter().map(dto_of).collect();
    json(200, &snap)
}

fn handle_list_keys(state: &AdminApiState) -> (&'static str, Vec<u8>) {
    #[derive(Serialize)]
    struct Dto {
        pubkey_b64: String,
        allow_any_subdomain: bool,
        allowed_subdomains: Vec<String>,
        max_conns: Option<u32>,
        allowed_ports: Option<Vec<u16>>,
        bw: Option<String>,
        quota: Option<String>,
        comment: Option<String>,
    }
    let entries: Vec<Dto> = state
        .keys
        .snapshot()
        .into_iter()
        .map(|(pk, e)| Dto {
            pubkey_b64: b64(&pk.0),
            allow_any_subdomain: e.allow_any_subdomain,
            allowed_subdomains: e.allowed_subdomains,
            max_conns: e.max_conns,
            allowed_ports: e.allowed_ports,
            bw: e.bw.map(format_rate),
            quota: e.quota.map(format_rate),
            comment: e.comment,
        })
        .collect();
    json(200, &entries)
}

fn handle_append_key(req: &Request, state: &AdminApiState) -> (&'static str, Vec<u8>) {
    #[derive(Deserialize)]
    struct Body {
        line: String,
    }
    let Ok(body) = serde_json::from_slice::<Body>(&req.body) else {
        return error(400, "expected {\"line\": \"...\"}");
    };
    use std::sync::atomic::Ordering::Relaxed;
    match state.keys.append_line(&body.line) {
        Ok(stored) => {
            state.metrics.admin_api_key_appended.fetch_add(1, Relaxed);
            let obj = serde_json::json!({ "appended": stored });
            ("200 OK", serde_json::to_vec(&obj).unwrap_or_default())
        }
        Err(e) => error(400, &format!("append_line: {e}")),
    }
}

fn handle_delete_key(pubkey_b64: &str, state: &AdminApiState) -> (&'static str, Vec<u8>) {
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(pubkey_b64) else {
        return error(400, "pubkey is not standard base64");
    };
    let Ok(arr): Result<[u8; 32], _> = raw.try_into() else {
        return error(400, "pubkey must be 32 bytes");
    };
    let pk = PubKey(arr);
    use std::sync::atomic::Ordering::Relaxed;
    match state.keys.remove_pubkey(&pk) {
        Ok(true) => {
            state.metrics.admin_api_key_removed.fetch_add(1, Relaxed);
            info!(pubkey = ?pk, "admin api: key removed");
            ("204 No Content", Vec::new())
        }
        Ok(false) => {
            state
                .metrics
                .admin_api_key_remove_not_found
                .fetch_add(1, Relaxed);
            error(404, "no such key")
        }
        Err(e) => error(500, &format!("remove_pubkey: {e}")),
    }
}

fn handle_metrics(state: &AdminApiState) -> (&'static str, Vec<u8>) {
    let snapshot = state.registry.snapshot();
    let live = snapshot.iter().filter(|t| t.live).count();
    let dangling = snapshot.iter().filter(|t| !t.live).count();

    // Per-identity byte snapshot from `SharedState.rates`.
    let per_identity_bytes: Vec<(String, u64)> = {
        let rates = state.rates.lock().unwrap();
        rates
            .iter()
            .map(|(pk, r)| (b64(&pk.0), r.quota_used_snapshot()))
            .collect()
    };

    let text = state
        .metrics
        .to_prometheus_text(live, dangling, &per_identity_bytes);
    ("200 OK", text.into_bytes())
}

// ---------- helpers ----------

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn format_rate(r: crate::rate::RatePer) -> String {
    let period = match r.period {
        crate::rate::Period::Second => "s",
        crate::rate::Period::Minute => "m",
        crate::rate::Period::Hour => "h",
        crate::rate::Period::Day => "day",
        crate::rate::Period::Week => "week",
        crate::rate::Period::Month => "month",
    };
    format!("{}B/{period}", r.bytes)
}

fn json<T: Serialize>(status_code: u16, body: &T) -> (&'static str, Vec<u8>) {
    let status = status_line(status_code);
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    (status, bytes)
}

fn error(status_code: u16, message: &str) -> (&'static str, Vec<u8>) {
    let status = status_line(status_code);
    let obj = serde_json::json!({ "error": message });
    (status, serde_json::to_vec(&obj).unwrap_or_default())
}

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        204 => "204 No Content",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    }
}

// ---------- HTTP parsing ----------

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn auth_bearer(&self) -> Option<&str> {
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("authorization") {
                if let Some(rest) = v.strip_prefix("Bearer ") {
                    return Some(rest.trim());
                }
                if let Some(rest) = v.strip_prefix("bearer ") {
                    return Some(rest.trim());
                }
            }
        }
        None
    }
}

async fn read_request(tcp: &mut TcpStream) -> std::io::Result<Request> {
    let mut buf = Vec::with_capacity(1024);
    // Read until end-of-headers or the header cap.
    let (method, path, headers, header_end, content_length) = loop {
        let mut tmp = [0u8; 1024];
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof reading headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        let mut heads = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut heads);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(end)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let mut hs = Vec::new();
                let mut cl: usize = 0;
                for h in req.headers.iter() {
                    let name = h.name.to_string();
                    let value = std::str::from_utf8(h.value).unwrap_or("").to_string();
                    if name.eq_ignore_ascii_case("content-length") {
                        cl = value.parse().unwrap_or(0);
                    }
                    hs.push((name, value));
                }
                break (method, path, hs, end, cl);
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() > MAX_HEADER_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "headers exceed cap",
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        }
    };
    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "body exceeds cap",
        ));
    }
    // Any body bytes captured after the headers.
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let mut tmp = [0u8; 4096];
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

async fn write_response(tcp: &mut TcpStream, status: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        tcp.write_all(body).await?;
    }
    let _ = tcp.shutdown().await;
    Ok(())
}

/// Bind the admin API listener on `bind` and spawn the accept loop.
/// Returns the actually-bound address so tests can discover ephemeral
/// ports.
pub async fn spawn_admin_api(
    bind: SocketAddr,
    state: Arc<AdminApiState>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(run_admin_api(listener, state));
    Ok(addr)
}
