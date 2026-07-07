//! HTTPS SNI-passthrough router bound on `--https-bind`.
//!
//! For every accepted TCP connection:
//! 1. Buffer the TLS `ClientHello` (see [`sni::peek_sni`]) and extract the
//!    SNI value.
//! 2. Strip the apex suffix to derive the label.
//! 3. Look up the label in the registry, open a bi-stream, write the
//!    [`DataHeader`] (kind=DataHttp — see §5 which uses this
//!    kind for both plain HTTP and HTTPS), replay the buffered ClientHello,
//!    and copy in both directions.
//!
//! The server NEVER terminates subdomain TLS. Encrypted bytes flow from the
//! browser through the relay to the client, which may or may not terminate
//! them locally.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use std::time::{SystemTime, UNIX_EPOCH};

use krot_proto::consts::{ALPN_TCP, DATA_FIRST_BYTE_DEADLINE};
use krot_proto::{DataHeader, HttpMetadata, InspectionPrelude, StreamKind};
use krot_transport::{write_frame, BidiStream, Incoming, TcpMuxConn};

use super::replay::ReplayStream;
use super::sni::peek_sni;
use crate::rate::run_metered;
use crate::server::{handle_connection_public, SharedState};

pub async fn run_https_router(
    listener: TcpListener,
    apex: String,
    shared: Arc<SharedState>,
    fallback_shutdown: watch::Receiver<bool>,
) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let apex = apex.clone();
                let shared = Arc::clone(&shared);
                let shutdown = fallback_shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(tcp, apex, shared, shutdown).await {
                        debug!(?peer, "https request ended: {e}");
                    }
                });
            }
            Err(e) => {
                // Transient accept errors (EMFILE, ECONNABORTED,
                // ENOBUFS) must not permanently kill the listener.
                warn!("https listener accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(
    mut tcp: TcpStream,
    apex: String,
    shared: Arc<SharedState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer = tcp.peer_addr().ok();
    let peeked = peek_sni(&mut tcp).await?;

    // §16.1.8 dispatch: if the peer advertised `krot-tcp/1` in ALPN,
    // this is a control-plane connection intended for the mux —
    // terminate TLS locally, spin up a TcpMuxConn, and hand off to
    // the same `handle_connection` code path used by QUIC and the
    // dedicated TCP-fallback listener.
    if peeked.alpn.iter().any(|a| a == ALPN_TCP) {
        info!(?peer, sni = %peeked.server_name, "dispatching to krot-tcp/1 mux");
        let mut tls_cfg = (*shared.tls).clone();
        tls_cfg.alpn_protocols = vec![ALPN_TCP.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
        // The ClientHello bytes are already buffered — replay them
        // into the acceptor so it can drive the handshake from byte 0.
        let replay = ReplayStream::new(peeked.buffered, tcp);
        let tls_stream = acceptor.accept(replay).await?;
        let mux = TcpMuxConn::new(tls_stream, true);
        let incoming = Incoming::from_tcp_mux(mux);
        handle_connection_public(incoming, shared, shutdown).await?;
        return Ok(());
    }

    // Otherwise: plain SNI-passthrough branch.
    let registry = Arc::clone(&shared.registry);
    let Some(label) = extract_label(&peeked.server_name, &apex) else {
        return Ok(());
    };
    let Some(resolved) = registry.resolve_label(&label) else {
        return Ok(());
    };

    let (mut send, recv) = resolved.connection.open_bi().await?;
    let header = DataHeader {
        kind: StreamKind::DataHttp,
        tunnel_id: resolved.id,
    };
    send.write_all(&header.to_bytes()).await?;

    // §16.2 inspection prelude (HTTPS-passthrough branch): host is
    // not readable from ciphertext, but SNI IS — surface it as both
    // `sni` (authoritative) and `host` (best-guess).
    if resolved.inspect {
        let prelude = InspectionPrelude {
            accept_unix_secs: unix_secs_now(),
            peer: peer.map(|p| p.to_string()).unwrap_or_default(),
            http: Some(HttpMetadata {
                host: peeked.server_name.clone(),
                sni: Some(peeked.server_name.clone()),
            }),
        };
        write_frame(&mut send, &prelude).await?;
    }

    // Replay the ClientHello so the client sees a valid TLS stream from
    // byte 0. Everything after that is copied verbatim.
    send.write_all(&peeked.buffered).await?;

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

fn extract_label(server_name: &str, apex: &str) -> Option<String> {
    let name = server_name.to_ascii_lowercase();
    let apex = apex.to_ascii_lowercase();
    if name == apex {
        return None;
    }
    let suffix = format!(".{apex}");
    name.strip_suffix(&suffix).map(str::to_string)
}
