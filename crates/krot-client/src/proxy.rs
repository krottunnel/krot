//! Per-connection proxy: on each server-opened bi-stream, read the
//! `DataHeader`, dial the local target, then run bytes both ways.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use krot_proto::{DataHeader, InspectionPrelude, StreamKind, TunnelId, DATA_HEADER_SIZE};
use krot_transport::{read_frame, run_bidirectional, BidiStream};

use crate::error::ClientError;
use crate::inspector::Inspector;
use crate::local_auth::{self, AuthConfig, AuthPolicy, Outcome, SessionAction};
use crate::login_page;

/// Cap on how many bytes we buffer for header parsing before giving up on
/// inspection and forwarding whatever we've read verbatim.
const INSPECT_HEADER_CAP: usize = 8 * 1024;

/// Handle exactly one server-initiated bi-stream. Reads the mandatory
/// 9-byte header, opens a local TCP connection to `local_target`, and
/// runs a full-duplex relay until either side closes.
///
/// If `inspector` is provided AND the tunnel is HTTP, the first chunk of
/// each direction is parsed via `httparse` to extract the method/path/
/// status before falling through to the plain byte-shovel path.
pub async fn handle_bi(
    send: krot_transport::SendStream,
    recv: krot_transport::RecvStream,
    expected_tunnel: TunnelId,
    local_target: SocketAddr,
) -> Result<(), ClientError> {
    handle_bi_inspected(send, recv, expected_tunnel, local_target, None, false, None).await
}

pub async fn handle_bi_inspected(
    mut send: krot_transport::SendStream,
    mut recv: krot_transport::RecvStream,
    expected_tunnel: TunnelId,
    local_target: SocketAddr,
    inspector: Option<Arc<Inspector>>,
    inspect: bool,
    auth: Option<AuthConfig>,
) -> Result<(), ClientError> {
    let mut header_buf = [0u8; DATA_HEADER_SIZE];
    recv.read_exact(&mut header_buf)
        .await
        .map_err(ClientError::Transport)?;
    let header = DataHeader::decode(&header_buf)
        .map_err(|_| ClientError::Protocol("bad DataHeader from server"))?;
    if !matches!(header.kind, StreamKind::DataTcp | StreamKind::DataHttp) {
        return Err(ClientError::Protocol("unexpected data-stream kind"));
    }
    if header.tunnel_id != expected_tunnel {
        return Err(ClientError::Protocol("wrong tunnel id on data stream"));
    }

    // §16.2: if this tunnel was registered with `inspect = true`, the
    // server prepends an `InspectionPrelude` (length-prefixed postcard)
    // right after the DataHeader. Read it BEFORE dialing the local
    // target so the payload we shovel to localhost starts at the true
    // application byte.
    let prelude: Option<InspectionPrelude> = if inspect {
        Some(read_frame(&mut recv).await?)
    } else {
        None
    };

    // Client-side auth. Only applies to HTTP tunnels — TCP tunnels have
    // no header layer to inspect. Buffer the request headers, run the
    // configured policy (Session or ApiKey), and either write a reject/
    // login response or forward the buffered bytes to localhost.
    // HTTPS-passthrough streams (first byte 0x16, TLS ClientHello) are
    // opaque and pass through unauthenticated; the local target owns
    // its own auth on that path.
    let mut buffered_request: Vec<u8> = Vec::new();
    // If auth pre-buffered the request and inspector is active, we
    // record the request here so `--auth` + `--inspect` still populates
    // the UI. `record_response` is called either from the intercept
    // branch (login page / 302) or from the forward branch below
    // (after peeking the local target's status line).
    let mut pending_inspector_id: Option<crate::inspector::EntryId> = None;
    if let (Some(cfg), StreamKind::DataHttp) = (auth.as_ref(), header.kind) {
        let (buf, first_byte) = peek_first_byte(&mut recv).await?;
        buffered_request = buf;
        let is_tls = first_byte.is_some_and(local_auth::looks_like_tls);
        if !is_tls {
            let headers_end =
                peek_until_headers(&mut recv, &mut buffered_request, INSPECT_HEADER_CAP).await?;

            // Parse method/path once for the inspector, before auth
            // consumes / modifies the buffer.
            if let (Some(insp), Some(end)) = (inspector.as_ref(), headers_end) {
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut req = httparse::Request::new(&mut headers);
                if req.parse(&buffered_request[..end]).is_ok() {
                    let method = req.method.map(str::to_string);
                    let path = req.path.map(str::to_string);
                    pending_inspector_id = Some(insp.record_request(method, path));
                }
            }

            let response_bytes =
                decide_auth_response(cfg, &mut recv, &mut buffered_request, headers_end).await?;
            if let Some(bytes) = response_bytes {
                debug!(
                    tunnel = ?expected_tunnel,
                    "auth: intercepting request (login page / redirect / reject)"
                );
                // Extract status from our own response so the inspector
                // shows the true intercepted status (200 for login page,
                // 302 for redirect, 403 for API-key reject, etc).
                if let (Some(insp), Some(id)) = (inspector.as_ref(), pending_inspector_id) {
                    if let Some(status) = parse_status_line(&bytes) {
                        insp.record_response(id, status);
                    }
                }
                send.write_all(&bytes).await?;
                let _ = send.finish();
                let _ = send.stopped().await;
                return Ok(());
            }
        }
    }

    debug!(?local_target, tunnel = ?expected_tunnel, "dialing local target");
    let mut local = TcpStream::connect(local_target).await?;

    // Forward whatever we buffered while checking auth.
    if !buffered_request.is_empty() {
        local.write_all(&buffered_request).await?;
    }

    // Feed the prelude into the inspector as the ground-truth
    // acceptance record. This is authoritative for HTTPS-passthrough
    // (which peek_request cannot see through) and replaces the
    // plaintext peek for HTTP.
    if let (Some(p), Some(insp)) = (prelude.as_ref(), inspector.as_ref()) {
        insp.record_accept(p);
    }

    // Inspector integration:
    //   * If auth pre-buffered the request (buffered_request non-empty),
    //     `pending_inspector_id` already has an entry created above;
    //     we just peek the local target's status line and attach it.
    //   * Otherwise, peek both directions here (request + response).
    if let (StreamKind::DataHttp, Some(insp)) = (header.kind, inspector.as_ref()) {
        if let Some(id) = pending_inspector_id {
            let (resp_buf, status) = peek_response(&mut local).await?;
            if let Some(s) = status {
                insp.record_response(id, s);
            }
            send.write_all(&resp_buf).await?;
        } else if buffered_request.is_empty() {
            let (req_buf, req_meta) = peek_request(&mut recv).await?;
            let id = insp.record_request(req_meta.0, req_meta.1);
            local.write_all(&req_buf).await?;

            let (resp_buf, status) = peek_response(&mut local).await?;
            if let Some(s) = status {
                insp.record_response(id, s);
            }
            send.write_all(&resp_buf).await?;
        }
    }

    let mut bidi = BidiStream::new(send, recv);
    let _ = run_bidirectional(&mut local, &mut bidi).await?;
    Ok(())
}

/// Given the buffered request headers, compute the response the client
/// should send back to the browser (login page / 302 / 403) — or
/// `None` if the request is authorised and should be forwarded to the
/// local target.
///
/// When the policy is `Session` and the request is `POST /__krot/login`,
/// we also read the form body (up to `LOGIN_BODY_CAP`) so we can
/// validate credentials before responding.
async fn decide_auth_response(
    cfg: &AuthConfig,
    recv: &mut krot_transport::RecvStream,
    buffered_request: &mut Vec<u8>,
    headers_end: Option<usize>,
) -> Result<Option<Vec<u8>>, ClientError> {
    // Malformed / oversized headers → 400 Bad Request. We never forward
    // garbage to the local app.
    let Some(complete_at) = headers_end else {
        return Ok(Some(bad_request_response()));
    };
    // First parse: extract method, path, and (if a login POST) the
    // Content-Length. This borrow of `buffered_request` ends before we
    // mutate it in `read_exact_into`.
    let (method, path, content_length, api_key_outcome) = {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let parsed = req.parse(&buffered_request[..complete_at]);
        if parsed.is_err() {
            return Ok(Some(bad_request_response()));
        }
        let method = req.method.unwrap_or("").to_string();
        let path = req.path.unwrap_or("/").to_string();
        let content_length = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("content-length"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0)
            .min(login_page::LOGIN_BODY_CAP);
        let api_key_outcome = matches!(cfg.policy, AuthPolicy::ApiKey { .. })
            .then(|| cfg.policy.check_api_key(req.headers));
        (method, path, content_length, api_key_outcome)
    };

    match &cfg.policy {
        AuthPolicy::ApiKey { .. } => {
            if matches!(api_key_outcome, Some(Outcome::Ok)) {
                Ok(None)
            } else {
                Ok(Some(local_auth::api_key_reject_response()))
            }
        }
        AuthPolicy::Session { .. } => {
            let is_login_post = method.eq_ignore_ascii_case("POST")
                && path.split('?').next().unwrap_or("") == login_page::LOGIN_PATH;
            let body: Vec<u8> = if is_login_post {
                read_exact_into(recv, buffered_request, complete_at + content_length).await?;
                let end = (complete_at + content_length).min(buffered_request.len());
                buffered_request[complete_at..end].to_vec()
            } else {
                Vec::new()
            };
            let mut headers2 = [httparse::EMPTY_HEADER; 32];
            let mut req2 = httparse::Request::new(&mut headers2);
            let _ = req2.parse(&buffered_request[..complete_at]);
            let action = cfg
                .policy
                .decide_session(&method, &path, req2.headers, &body);
            match action {
                SessionAction::Forward => Ok(None),
                SessionAction::ServeLoginPage { next, error } => {
                    let html = login_page::render_login_page(&next, error);
                    Ok(Some(login_page::http_html_response(&html)))
                }
                SessionAction::Redirect {
                    location,
                    set_cookie,
                } => Ok(Some(login_page::http_redirect(
                    &location,
                    set_cookie.as_deref(),
                ))),
            }
        }
    }
}

/// Extract the numeric status code from an HTTP/1.x response's status
/// line. Returns `None` if the buffer does not start with an HTTP
/// response or the code isn't a 3-digit number.
fn parse_status_line(bytes: &[u8]) -> Option<u16> {
    // Fastest path: find the first space, then parse three ASCII digits.
    let head = bytes.get(..64.min(bytes.len()))?;
    let s = std::str::from_utf8(head).ok()?;
    let (_version, rest) = s.split_once(' ')?;
    let code: String = rest.chars().take(3).collect();
    code.parse::<u16>().ok()
}

fn bad_request_response() -> Vec<u8> {
    let body = b"Bad Request";
    let head = format!(
        "HTTP/1.1 400 Bad Request\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len(),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Extend `buf` from `recv` until it holds at least `target` bytes,
/// or EOF. No-op if `buf.len() >= target`.
async fn read_exact_into(
    recv: &mut krot_transport::RecvStream,
    buf: &mut Vec<u8>,
    target: usize,
) -> Result<(), ClientError> {
    let mut probe = [0u8; 1024];
    while buf.len() < target {
        let n = match recv.read(&mut probe).await {
            Ok(Some(0) | None) => return Ok(()),
            Ok(Some(n)) => n,
            Err(e) => return Err(ClientError::Transport(e)),
        };
        let take = n.min(target - buf.len());
        buf.extend_from_slice(&probe[..take]);
    }
    Ok(())
}

/// Read at least one byte from `recv`, returning the buffered bytes
/// and the very first byte (or `None` on immediate EOF). Used to
/// distinguish TLS ClientHello (first byte `0x16`) from plain HTTP.
async fn peek_first_byte(
    stream: &mut krot_transport::RecvStream,
) -> Result<(Vec<u8>, Option<u8>), ClientError> {
    let mut tmp = [0u8; 1024];
    let n = match stream.read(&mut tmp).await {
        Ok(Some(0) | None) => return Ok((Vec::new(), None)),
        Ok(Some(n)) => n,
        Err(e) => return Err(ClientError::Transport(e)),
    };
    let first = tmp[0];
    Ok((tmp[..n].to_vec(), Some(first)))
}

/// Continue reading from `stream` into `buf` until the CRLFCRLF
/// end-of-headers marker is found or `cap` is reached. Returns
/// `Some(offset_of_end_of_headers_exclusive)` on success, `None` if
/// `cap` was hit first (malformed / oversized).
async fn peek_until_headers(
    stream: &mut krot_transport::RecvStream,
    buf: &mut Vec<u8>,
    cap: usize,
) -> Result<Option<usize>, ClientError> {
    let mut probe = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Some(pos + 4));
        }
        if buf.len() >= cap {
            return Ok(None);
        }
        let n = match stream.read(&mut probe).await {
            Ok(Some(0) | None) => return Ok(None),
            Ok(Some(n)) => n,
            Err(e) => return Err(ClientError::Transport(e)),
        };
        buf.extend_from_slice(&probe[..n]);
    }
}

/// Peek up to [`INSPECT_HEADER_CAP`] bytes from `stream`, returning them
/// verbatim plus a parsed `(method, path)` pair if the request-line was
/// complete within the peeked window.
async fn peek_request(
    stream: &mut krot_transport::RecvStream,
) -> Result<(Vec<u8>, (Option<String>, Option<String>)), ClientError> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 1024];
        let n = match stream.read(&mut tmp).await {
            Ok(Some(n)) => n,
            Ok(None) => break,
            Err(e) => return Err(ClientError::Transport(e)),
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > INSPECT_HEADER_CAP {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let (method, path) = match req.parse(&buf) {
        Ok(_) => (req.method.map(str::to_string), req.path.map(str::to_string)),
        Err(_) => (None, None),
    };
    Ok((buf, (method, path)))
}

async fn peek_response(stream: &mut TcpStream) -> Result<(Vec<u8>, Option<u16>), ClientError> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut tmp = [0u8; 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > INSPECT_HEADER_CAP {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let status = match resp.parse(&buf) {
        Ok(_) => resp.code,
        Err(_) => None,
    };
    Ok((buf, status))
}
