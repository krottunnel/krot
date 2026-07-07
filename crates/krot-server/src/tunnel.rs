//! Public TCP listener for one IpMode tunnel.
//!
//! One task is spawned per registered tunnel. It binds a TCP socket on
//! the tunnel's public port, then for each accepted connection opens a
//! new `quinn` bidirectional stream toward the tunnel's owning client,
//! writes the mandatory [`DataHeader`] and shovels bytes in both
//! directions.
//!
//! The byte-shovel goes through [`crate::rate::run_metered`] so §9
//! bandwidth and quota limits are enforced per-identity. The §10
//! first-byte deadline is enforced inside `run_metered` — it drops
//! once any byte flows.
//!
//! When `inspect = true` (§16.2), a length-prefixed
//! [`InspectionPrelude`] is written after the DataHeader and before
//! any tunneled payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use krot_proto::consts::DATA_FIRST_BYTE_DEADLINE;
use krot_proto::{DataHeader, InspectionPrelude, StreamKind, TunnelId};
use krot_transport::{write_frame, BidiStream};

use crate::rate::{run_metered, RateLimitState};

/// Run the accept loop for one tunnel until either the listener errors,
/// the QUIC connection is closed, or the task is aborted.
///
/// The listener is passed as `Arc<TcpListener>` so a §7.3 `mark_dangling`
/// transition can abort this task without releasing the OS-level port —
/// the registry keeps its own clone alive across the grace window.
pub async fn run_tcp_tunnel(
    listener: Arc<TcpListener>,
    connection: krot_transport::Connection,
    tunnel_id: TunnelId,
    rate: Arc<RateLimitState>,
    inspect: bool,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((tcp, peer)) => {
                        let conn = connection.clone();
                        let rate = Arc::clone(&rate);
                        tokio::spawn(async move {
                            if let Err(e) = handle_incoming(tcp, peer, conn, tunnel_id, rate, inspect).await {
                                debug!(?peer, ?tunnel_id, "tunnel connection ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(?tunnel_id, "listener accept failed: {e}");
                        return;
                    }
                }
            }
            () = connection.closed() => {
                debug!(?tunnel_id, "quic connection closed, stopping tunnel");
                return;
            }
        }
    }
}

async fn handle_incoming(
    tcp: TcpStream,
    peer: SocketAddr,
    connection: krot_transport::Connection,
    tunnel_id: TunnelId,
    rate: Arc<RateLimitState>,
    inspect: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    debug!(?peer, ?tunnel_id, "accepted public TCP, opening QUIC bi");
    let (mut send, recv) = connection.open_bi().await?;

    let header = DataHeader {
        kind: StreamKind::DataTcp,
        tunnel_id,
    };
    send.write_all(&header.to_bytes()).await?;

    // §16.2: emit the inspection prelude between the DataHeader and
    // the first payload byte. TCP tunnels carry no HTTP metadata, so
    // `http` is None.
    if inspect {
        let prelude = InspectionPrelude {
            accept_unix_secs: unix_secs_now(),
            peer: peer.to_string(),
            http: None,
        };
        write_frame(&mut send, &prelude).await?;
    }

    let bidi = BidiStream::new(send, recv);
    let _ = run_metered(tcp, bidi, &rate, tunnel_id, DATA_FIRST_BYTE_DEADLINE).await?;
    Ok(())
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
