//! §16.4 Structured admin API end-to-end tests.
//!
//! Boots an IpMode server with the admin API bound on an ephemeral
//! loopback port, exchanges the enrollment `admin_token` for a
//! session token, and drives every documented endpoint via a
//! hand-rolled HTTP/1.1 client (`tokio::net::TcpStream` +
//! serde_json). Third-party HTTP clients are intentionally avoided
//! to keep the dep tree lean and mirror the server's own approach.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use krot_server::{Mode, Server, ServerConfig};

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

async fn boot(dir: &TempDir) -> (Arc<Server>, SocketAddr, String) {
    krot_transport::install_crypto_provider();
    let config = ServerConfig::local_in(dir.path().to_path_buf())
        .with_bind(loopback())
        .with_mode(Mode::Ip {
            public_host: "127.0.0.1".into(),
            port_pool: 21_000..=21_010,
        });
    let server = Server::start(config).await.unwrap();
    let admin_addr = server.admin_api_addr().expect("admin API not bound");
    let token = server.issue_admin_token().unwrap();
    (Arc::new(server), admin_addr, token)
}

/// Minimal HTTP/1.1 request helper. `body` is sent verbatim when
/// `content_type` is `Some`; the `Authorization` header is added when
/// `bearer` is `Some`. Returns `(status_code, response_body_bytes)`.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: admin\r\n");
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    } else {
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(req.as_bytes()).await.unwrap();
    if !body.is_empty() {
        sock.write_all(body).await.unwrap();
    }
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.unwrap();
    // Parse status line.
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no CRLFCRLF in response");
    let head = std::str::from_utf8(&buf[..head_end]).expect("non-utf8 headers");
    let first_line = head.lines().next().unwrap();
    let status: u16 = first_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = buf[head_end + 4..].to_vec();
    (status, body)
}

#[derive(Deserialize, Debug)]
struct SessionReply {
    session_token: String,
    expires_at_unix: u64,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)] // Deserialised so we can assert emptiness.
struct TunnelDto {
    tunnel_id: u64,
    kind: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    public_port: Option<u16>,
    state: String,
    inspect: bool,
    owner_pubkey_b64: String,
    session_id_b64: String,
}

#[derive(Deserialize, Debug)]
struct KeyDto {
    pubkey_b64: String,
    allow_any_subdomain: bool,
    #[serde(default)]
    allowed_ports: Option<Vec<u16>>,
}

#[tokio::test]
async fn session_mint_and_bearer_gate() {
    let dir = TempDir::new().unwrap();
    let (server, addr, token) = boot(&dir).await;
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    // Unauthenticated GET is rejected.
    let (status, _) = http(addr, "GET", "/admin/v1/tunnels", None, None, b"").await;
    assert_eq!(status, 401, "unauthenticated request should get 401");

    // Bogus bearer is rejected.
    let (status, _) = http(addr, "GET", "/admin/v1/tunnels", Some("garbage"), None, b"").await;
    assert_eq!(status, 401);

    // Exchange the admin_token for a session token.
    let body = serde_json::json!({ "admin_token": token }).to_string();
    let (status, resp) = http(
        addr,
        "POST",
        "/admin/v1/session",
        None,
        Some("application/json"),
        body.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "session mint should succeed");
    let session: SessionReply = serde_json::from_slice(&resp).expect("bad session json");
    assert!(!session.session_token.is_empty());
    assert!(session.expires_at_unix > 1_700_000_000);

    // Authenticated GET now works.
    let (status, resp) = http(
        addr,
        "GET",
        "/admin/v1/tunnels",
        Some(&session.session_token),
        None,
        b"",
    )
    .await;
    assert_eq!(status, 200);
    let tunnels: Vec<TunnelDto> = serde_json::from_slice(&resp).unwrap();
    assert!(tunnels.is_empty(), "no tunnels yet");

    // A second /session exchange must fail — the enrollment admin_token
    // was consumed on the first mint.
    let (status, _) = http(
        addr,
        "POST",
        "/admin/v1/session",
        None,
        Some("application/json"),
        body.as_bytes(),
    )
    .await;
    assert_eq!(status, 401, "second exchange should fail — token consumed");

    server_task.abort();
}

#[tokio::test]
async fn keys_lifecycle() {
    let dir = TempDir::new().unwrap();
    let (server, addr, token) = boot(&dir).await;
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    // Mint session.
    let body = serde_json::json!({ "admin_token": token }).to_string();
    let (_, resp) = http(
        addr,
        "POST",
        "/admin/v1/session",
        None,
        Some("application/json"),
        body.as_bytes(),
    )
    .await;
    let session: SessionReply = serde_json::from_slice(&resp).unwrap();
    let bearer = session.session_token;

    // Initially empty.
    let (status, resp) = http(addr, "GET", "/admin/v1/keys", Some(&bearer), None, b"").await;
    assert_eq!(status, 200);
    let list: Vec<KeyDto> = serde_json::from_slice(&resp).unwrap();
    assert!(list.is_empty());

    // Append a key.
    let line = "ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= subdomain=* ports=8080,8443";
    let body = serde_json::json!({ "line": line }).to_string();
    let (status, _) = http(
        addr,
        "POST",
        "/admin/v1/keys",
        Some(&bearer),
        Some("application/json"),
        body.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "append should succeed");

    // List includes it.
    let (_, resp) = http(addr, "GET", "/admin/v1/keys", Some(&bearer), None, b"").await;
    let list: Vec<KeyDto> = serde_json::from_slice(&resp).unwrap();
    assert_eq!(list.len(), 1, "one key present");
    let entry = &list[0];
    assert!(entry.allow_any_subdomain);
    assert_eq!(entry.allowed_ports, Some(vec![8080, 8443]));
    let pubkey_b64 = entry.pubkey_b64.clone();

    // Delete it. `+`, `/`, `=` in standard-base64 are all valid in an
    // HTTP path segment per RFC 3986, so no percent-encoding is
    // needed.
    let path = format!("/admin/v1/keys/{pubkey_b64}");
    let (status, _) = http(addr, "DELETE", &path, Some(&bearer), None, b"").await;
    assert_eq!(status, 204);

    // Give the §13 hot-reloader a beat to observe the file change (the
    // in-memory index is updated synchronously by remove_pubkey, so
    // this pause is defensive only).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, resp) = http(addr, "GET", "/admin/v1/keys", Some(&bearer), None, b"").await;
    let list: Vec<KeyDto> = serde_json::from_slice(&resp).unwrap();
    assert!(list.is_empty(), "key list empty after delete");

    // Second delete → 404.
    let (status, _) = http(addr, "DELETE", &path, Some(&bearer), None, b"").await;
    assert_eq!(status, 404);

    server_task.abort();
}

// urlencode helper is no longer needed once the pubkey path segment
// is passed raw; keep it around so a future test with non-b64 IDs can
// reuse it.
#[tokio::test]
async fn metrics_endpoint_serves_prometheus_text() {
    let dir = TempDir::new().unwrap();
    let (server, addr, token) = boot(&dir).await;
    let server_run = Arc::clone(&server);
    let server_task = tokio::spawn(async move { server_run.run().await });

    let body = serde_json::json!({ "admin_token": token }).to_string();
    let (_, resp) = http(
        addr,
        "POST",
        "/admin/v1/session",
        None,
        Some("application/json"),
        body.as_bytes(),
    )
    .await;
    let session: SessionReply = serde_json::from_slice(&resp).unwrap();

    let (status, body) = http(
        addr,
        "GET",
        "/admin/v1/metrics",
        Some(&session.session_token),
        None,
        b"",
    )
    .await;
    assert_eq!(status, 200);
    let body = std::str::from_utf8(&body).unwrap();
    // Old gauges we've always exposed.
    assert!(
        body.contains("krot_tunnels_total 0"),
        "expected zero-tunnel gauge in Prometheus body, got: {body}"
    );
    assert!(body.contains("# TYPE krot_tunnels_total gauge"));
    // New counters from the Observability pass.
    for name in [
        "krot_uptime_seconds",
        "krot_build_info",
        "krot_handshake_auth_ok_total",
        "krot_handshake_unknown_identity_total",
        "krot_enrollment_ok_total",
        "krot_session_bye_total",
        "krot_resume_reattached_total",
        "krot_tunnel_registered_http_total",
        "krot_rate_limit_quota_exceeded_total",
        "krot_transport_quic_accepted_total",
        "krot_transport_tcp_fallback_accepted_total",
        "krot_admin_api_session_minted_total",
    ] {
        assert!(
            body.contains(name),
            "expected metric {name} in exposition, got: {body}"
        );
    }
    // Session mint counter should be at least 1 because we minted
    // one above to reach this endpoint.
    let minted_line = body
        .lines()
        .find(|l| l.starts_with("krot_admin_api_session_minted_total"))
        .expect("session minted line");
    let val: u64 = minted_line
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap();
    assert!(val >= 1, "expected session_minted >= 1, got {val}");

    server_task.abort();
}

/// Percent-encode `+` and `/` in a base64 pubkey so it survives the URL
/// path segment cleanly. Standard base64 also uses `=`, which is fine
/// in a path segment but let's escape it too for symmetry.
#[allow(dead_code)] // kept for future tests that use non-b64-safe IDs
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '+' => out.push_str("%2B"),
            '/' => out.push_str("%2F"),
            '=' => out.push_str("%3D"),
            other => out.push(other),
        }
    }
    out
}
