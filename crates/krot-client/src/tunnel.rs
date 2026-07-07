//! Publish one tunnel (TCP or HTTP): register it with the server, then
//! serve every incoming bi-stream by proxying to a local address until the
//! caller signals shutdown or the QUIC connection dies.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn};

use krot_proto::consts::REGISTRATION_DEADLINE;
use krot_proto::{ClientFrame, ServerFrame, SessionId, TunnelId, TunnelKind};
use krot_transport::{read_frame, write_frame};

use crate::error::ClientError;
use crate::inspector::Inspector;
use crate::local_auth::AuthConfig;
use crate::proxy::handle_bi_inspected;
use crate::session::AuthenticatedSession;

/// Details of the newly registered tunnel that the server assigned.
#[derive(Debug, Clone)]
pub struct PublishedTunnel {
    pub tunnel_id: TunnelId,
    pub public_url: String,
    pub public_port: Option<u16>,
}

/// Type alias for the shutdown / task handle pair returned by every publish call.
pub type TunnelHandle = (
    PublishedTunnel,
    tokio::task::JoinHandle<Result<(), ClientError>>,
    mpsc::Sender<()>,
);

/// Register a TCP tunnel. See [`publish`] for the details.
pub async fn publish_tcp(
    session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
) -> Result<TunnelHandle, ClientError> {
    publish(
        session,
        label,
        TunnelKind::Tcp { remote_port: None },
        local_target,
        None,
        None,
        None,
    )
    .await
}

/// Like [`publish_tcp`], but attempts to resume a previous session's
/// TCP tunnel (§7.3) by presenting its old `session_id`. On resume
/// success the returned [`PublishedTunnel`] carries the same
/// `tunnel_id` and `public_url` as the original.
pub async fn publish_tcp_resume(
    session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
    resume_session_id: SessionId,
) -> Result<TunnelHandle, ClientError> {
    publish(
        session,
        label,
        TunnelKind::Tcp { remote_port: None },
        local_target,
        None,
        Some(resume_session_id),
        None,
    )
    .await
}

/// Register an HTTP tunnel. `inspector`, when present, receives parsed
/// first-line request/response metadata.
pub async fn publish_http(
    session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
    inspector: Option<Arc<Inspector>>,
) -> Result<TunnelHandle, ClientError> {
    publish(
        session,
        label,
        TunnelKind::Http,
        local_target,
        inspector,
        None,
        None,
    )
    .await
}

/// Like [`publish_http`], but attaches a client-side auth policy that
/// gates plain-HTTP traffic before it reaches `local_target`.
///
/// HTTPS-passthrough (TLS ClientHello — first byte `0x16`) traffic
/// bypasses the auth check: the client can't read encrypted headers
/// without terminating TLS. Callers who need auth on the HTTPS path
/// must implement it in the local target itself.
pub async fn publish_http_authed(
    session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
    inspector: Option<Arc<Inspector>>,
    auth: AuthConfig,
) -> Result<TunnelHandle, ClientError> {
    publish(
        session,
        label,
        TunnelKind::Http,
        local_target,
        inspector,
        None,
        Some(auth),
    )
    .await
}

/// Like [`publish_http`], but attempts to resume a previous session's
/// HTTP tunnel by presenting its old `session_id` (§7.3).
pub async fn publish_http_resume(
    session: AuthenticatedSession,
    label: &str,
    local_target: SocketAddr,
    inspector: Option<Arc<Inspector>>,
    resume_session_id: SessionId,
) -> Result<TunnelHandle, ClientError> {
    publish(
        session,
        label,
        TunnelKind::Http,
        local_target,
        inspector,
        Some(resume_session_id),
        None,
    )
    .await
}

async fn publish(
    mut session: AuthenticatedSession,
    label: &str,
    kind: TunnelKind,
    local_target: SocketAddr,
    inspector: Option<Arc<Inspector>>,
    resume_session_id: Option<SessionId>,
    auth: Option<AuthConfig>,
) -> Result<TunnelHandle, ClientError> {
    // §16.2: opt into the server's inspection prelude when — and only
    // when — the caller has attached an Inspector. The two are
    // meaningfully redundant: an inspection prelude with no consumer
    // would just be wasted bytes, and an Inspector without a prelude
    // has to fall back to peeking the plaintext (which doesn't work
    // for HTTPS-passthrough).
    let inspect = inspector.is_some();
    write_frame(
        &mut session.send,
        &ClientFrame::RegisterTunnel {
            label: label.to_string(),
            kind,
            resume_session_id,
            inspect,
        },
    )
    .await?;

    // §10 registration deadline — cap the wait for TunnelRegistered so a
    // silently stuck server doesn't wedge the client forever.
    let reply = tokio::time::timeout(
        REGISTRATION_DEADLINE,
        read_frame::<ServerFrame>(&mut session.recv),
    )
    .await
    .map_err(|_| ClientError::RegistrationTimeout)??;
    let published = match reply {
        ServerFrame::TunnelRegistered {
            tunnel_id,
            public_url,
            public_port,
        } => PublishedTunnel {
            tunnel_id,
            public_url,
            public_port,
        },
        ServerFrame::TunnelRejected { code, detail } => {
            return Err(ClientError::TunnelRejected(code, detail));
        }
        _ => return Err(ClientError::Protocol("expected TunnelRegistered")),
    };
    info!(url = %published.public_url, "tunnel published");

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let tunnel_id = published.tunnel_id;
    let connection = session.connection.clone();

    let handle = tokio::spawn(async move {
        let keep_control = session;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    keep_control.shutdown().await;
                    return Ok(());
                }
                accept = connection.accept_bi() => {
                    match accept {
                        Ok((send, recv)) => {
                            let target = local_target;
                            let insp = inspector.clone();
                            let auth = auth.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_bi_inspected(send, recv, tunnel_id, target, insp, inspect, auth).await {
                                    warn!("proxy stream ended with error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            info!("quic connection ended: {e}");
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    Ok((published, handle, shutdown_tx))
}
