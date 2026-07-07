//! Plain HTTP router bound on `--http-bind`.
//!
//! For every accepted TCP connection:
//! 1. Read bytes until the request-line + headers are terminated by
//!    `\r\n\r\n` (or a small cap is hit).
//! 2. If the path is `/.well-known/acme-challenge/<token>` and the token
//!    is present in the [`ChallengeStore`], reply with the stored key
//!    authorization.
//! 3. Otherwise parse the `Host` header via `httparse`, strip the apex
//!    suffix to derive the label, look it up in the registry, open a
//!    bi-stream to the owning client, write the [`DataHeader`], replay
//!    the buffered bytes, and copy in both directions.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use std::time::{SystemTime, UNIX_EPOCH};

use krot_proto::consts::DATA_FIRST_BYTE_DEADLINE;
use krot_proto::{DataHeader, HttpMetadata, InspectionPrelude, StreamKind};
use krot_transport::{write_frame, BidiStream};

use super::acme::{lookup_challenge, ChallengeStore};
use crate::rate::run_metered;
use crate::registry::TunnelRegistry;

/// Cap on the number of bytes we buffer while looking for end-of-headers.
const MAX_HEADER_BYTES: usize = 8 * 1024;
const ACME_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

pub async fn run_http_router(
    listener: TcpListener,
    apex: String,
    registry: Arc<TunnelRegistry>,
    challenges: ChallengeStore,
) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let apex = apex.clone();
                let registry = Arc::clone(&registry);
                let challenges = Arc::clone(&challenges);
                tokio::spawn(async move {
                    if let Err(e) = handle(tcp, apex, registry, challenges).await {
                        debug!(?peer, "http request ended: {e}");
                    }
                });
            }
            Err(e) => {
                // Transient accept errors (EMFILE, ECONNABORTED,
                // ENOBUFS) must not permanently kill the listener.
                warn!("http listener accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(
    mut tcp: TcpStream,
    apex: String,
    registry: Arc<TunnelRegistry>,
    challenges: ChallengeStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = tcp.peer_addr().ok();
    let (buffered, host, path) = read_request(&mut tcp).await?;

    // Serve ACME HTTP-01 challenges regardless of Host.
    if let Some(token) = path.strip_prefix(ACME_PATH_PREFIX) {
        if let Some(response) = lookup_challenge(&challenges, token) {
            write_body(&mut tcp, "200 OK", "text/plain", response.as_bytes()).await?;
        } else {
            write_body(
                &mut tcp,
                "404 Not Found",
                "text/plain",
                b"no such challenge",
            )
            .await?;
        }
        return Ok(());
    }

    let Some(label) = extract_label(&host, &apex) else {
        write_body(&mut tcp, "404 Not Found", "text/plain", b"unknown host").await?;
        return Ok(());
    };
    let Some(resolved) = registry.resolve_label(&label) else {
        write_body(&mut tcp, "404 Not Found", "text/plain", b"unknown tunnel").await?;
        return Ok(());
    };

    let (mut send, recv) = resolved.connection.open_bi().await?;
    let header = DataHeader {
        kind: StreamKind::DataHttp,
        tunnel_id: resolved.id,
    };
    send.write_all(&header.to_bytes()).await?;

    // §16.2 inspection prelude (plain-HTTP branch): Host header is
    // known, SNI is not applicable.
    if resolved.inspect {
        let prelude = InspectionPrelude {
            accept_unix_secs: unix_secs_now(),
            peer: peer.map(|p| p.to_string()).unwrap_or_default(),
            http: Some(HttpMetadata {
                host: host.clone(),
                sni: None,
            }),
        };
        write_frame(&mut send, &prelude).await?;
    }

    send.write_all(&buffered).await?;

    let bidi = BidiStream::new(send, recv);
    let _ = run_metered(
        tcp,
        bidi,
        &resolved.rate,
        resolved.id,
        DATA_FIRST_BYTE_DEADLINE,
    )
    .await?;
    Ok(())
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn read_request(tcp: &mut TcpStream) -> std::io::Result<(Vec<u8>, String, String)> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 1024];
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof reading headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .unwrap_or("")
                    .to_string();
                let path = req.path.unwrap_or("/").to_string();
                return Ok((buf, host, path));
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
    }
}

/// Given `Host: alice.krot.example[:port]` and apex `krot.example`, return
/// `alice`.
fn extract_label(host_header: &str, apex: &str) -> Option<String> {
    let host = host_header.split(':').next()?.trim().to_ascii_lowercase();
    let apex = apex.to_ascii_lowercase();
    if host == apex {
        return None;
    }
    let suffix = format!(".{apex}");
    host.strip_suffix(&suffix).map(str::to_string)
}

async fn write_body(
    tcp: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(body).await?;
    let _ = tcp.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::acme::new_store;

    #[test]
    fn extracts_labels() {
        assert_eq!(
            extract_label("alice.krot.example", "krot.example"),
            Some("alice".into())
        );
        assert_eq!(
            extract_label("Alice.KROT.Example:8080", "krot.example"),
            Some("alice".into())
        );
        assert_eq!(extract_label("krot.example", "krot.example"), None);
        assert_eq!(extract_label("other.com", "krot.example"), None);
        assert_eq!(
            extract_label("a.b.krot.example", "krot.example"),
            Some("a.b".into())
        );
    }

    #[tokio::test]
    async fn serves_acme_challenge() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let store = new_store();
        store
            .write()
            .unwrap()
            .insert("tokABC".into(), "tokABC.thumbprint".into());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let apex = "krot.test".to_string();
        let registry = Arc::new(TunnelRegistry::new(20_000..=20_010));

        tokio::spawn(run_http_router(listener, apex, registry, store));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /.well-known/acme-challenge/tokABC HTTP/1.1\r\nHost: anything\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let body = std::str::from_utf8(&buf).unwrap();
        assert!(body.starts_with("HTTP/1.1 200 OK"));
        assert!(body.ends_with("tokABC.thumbprint"), "got: {body:?}");
    }
}
