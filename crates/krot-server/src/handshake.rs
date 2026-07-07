//! Control-stream handshake: dispatch between authenticated sessions and
//! bootstrap enrollment (§7.1, §14).

use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{info, warn};

use krot_proto::{
    verify_challenge, ClientFrame, ErrorCode, Nonce, PubKey, ServerFrame, SessionId, StreamKind,
};
use krot_transport::{read_frame, write_frame};

use crate::admin::AdminTokenStore;
use crate::error::ServerError;
use crate::keys::{AuthorizedEntry, KeyRegistry};

/// Data captured from a successful authentication.
#[derive(Debug)]
pub struct HandshakeOk {
    pub pubkey: PubKey,
    pub session_id: SessionId,
    pub entry: AuthorizedEntry,
}

/// Outcome of the very first frame on the Control stream.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// Peer authenticated and is ready for a session loop.
    Auth(HandshakeOk),
    /// A one-shot enrollment ran to completion (either success or
    /// reject). The connection MUST be closed by the caller.
    /// `success` distinguishes the two paths for telemetry.
    EnrollmentDone { success: bool },
    /// Handshake failed. `code` is the QUIC application close code the
    /// caller MUST use — for §7.1 auth failures this is always
    /// `AUTHENTICATION_FAILED`; for §5 stream-kind violations this is
    /// `UNKNOWN_STREAM_KIND` / `UNEXPECTED_STREAM`.
    Failed(ErrorCode),
}

pub async fn perform(
    send: &mut krot_transport::SendStream,
    recv: &mut krot_transport::RecvStream,
    keys: &Arc<KeyRegistry>,
    admin: &Arc<AdminTokenStore>,
) -> Result<HandshakeOutcome, ServerError> {
    let mut kind_byte = [0u8; 1];
    recv.read_exact(&mut kind_byte)
        .await
        .map_err(ServerError::Transport)?;
    let Ok(kind) = StreamKind::try_from(kind_byte[0]) else {
        warn!(
            byte = kind_byte[0],
            "unknown StreamKind on first client stream"
        );
        return Ok(HandshakeOutcome::Failed(ErrorCode::UNKNOWN_STREAM_KIND));
    };
    if !matches!(kind, StreamKind::Control) {
        warn!(?kind, "expected Control stream first");
        return Ok(HandshakeOutcome::Failed(ErrorCode::UNEXPECTED_STREAM));
    }

    let first: ClientFrame = read_frame(recv).await?;
    match first {
        ClientFrame::Enroll {
            admin_token,
            pubkey,
            label_hint,
        } => handle_enroll(send, admin_token, pubkey, label_hint, keys, admin).await,
        ClientFrame::AuthRequest { pubkey } => handle_auth(send, recv, pubkey, keys).await,
        _ => {
            let _ = write_frame(
                send,
                &ServerFrame::AuthReject {
                    code: ErrorCode::PROTOCOL_VIOLATION,
                },
            )
            .await;
            let _ = send.finish();
            let _ = send.stopped().await;
            Ok(HandshakeOutcome::Failed(ErrorCode::AUTHENTICATION_FAILED))
        }
    }
}

async fn handle_enroll(
    send: &mut krot_transport::SendStream,
    token: String,
    pubkey: PubKey,
    label_hint: Option<String>,
    keys: &Arc<KeyRegistry>,
    admin: &Arc<AdminTokenStore>,
) -> Result<HandshakeOutcome, ServerError> {
    if let Err(e) = admin.consume(&token) {
        warn!("enroll rejected: {e}");
        write_frame(
            send,
            &ServerFrame::EnrollRejected {
                code: match e {
                    ServerError::AdminToken("admin token expired") => ErrorCode::TOKEN_EXPIRED,
                    ServerError::AdminToken("no admin token issued") => ErrorCode::ENROLL_DISABLED,
                    _ => ErrorCode::AUTHENTICATION_FAILED,
                },
            },
        )
        .await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        return Ok(HandshakeOutcome::EnrollmentDone { success: false });
    }

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_else(|_| "unknown".into());
    let hint = label_hint.as_deref().unwrap_or("");
    let line = format!(
        "ed25519 {b64} subdomain=* # enrolled {now} {hint}",
        b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(pubkey.0)
        },
    );
    let stored = keys.append_line(&line)?;
    info!(?pubkey, "enrolled new identity");
    write_frame(
        send,
        &ServerFrame::EnrollOk {
            authorized_line: stored,
        },
    )
    .await?;
    let _ = send.finish();
    let _ = send.stopped().await;
    Ok(HandshakeOutcome::EnrollmentDone { success: true })
}

async fn handle_auth(
    send: &mut krot_transport::SendStream,
    recv: &mut krot_transport::RecvStream,
    pubkey: PubKey,
    keys: &Arc<KeyRegistry>,
) -> Result<HandshakeOutcome, ServerError> {
    let Some(entry) = keys.get(&pubkey) else {
        write_frame(
            send,
            &ServerFrame::AuthReject {
                code: ErrorCode::UNKNOWN_IDENTITY,
            },
        )
        .await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        return Ok(HandshakeOutcome::Failed(ErrorCode::AUTHENTICATION_FAILED));
    };

    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce(nonce_bytes);
    write_frame(send, &ServerFrame::AuthChallenge { nonce }).await?;

    let response: ClientFrame = read_frame(recv).await?;
    let ClientFrame::AuthResponse { signature } = response else {
        write_frame(
            send,
            &ServerFrame::AuthReject {
                code: ErrorCode::PROTOCOL_VIOLATION,
            },
        )
        .await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        return Ok(HandshakeOutcome::Failed(ErrorCode::AUTHENTICATION_FAILED));
    };

    if !verify_challenge(&pubkey, &nonce, &signature) {
        write_frame(
            send,
            &ServerFrame::AuthReject {
                code: ErrorCode::AUTHENTICATION_FAILED,
            },
        )
        .await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        return Ok(HandshakeOutcome::Failed(ErrorCode::AUTHENTICATION_FAILED));
    }

    let mut sid = [0u8; 16];
    OsRng.fill_bytes(&mut sid);
    let session_id = SessionId(sid);
    write_frame(send, &ServerFrame::AuthOk { session_id }).await?;

    Ok(HandshakeOutcome::Auth(HandshakeOk {
        pubkey,
        session_id,
        entry,
    }))
}
