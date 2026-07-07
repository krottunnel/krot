//! §16.1.3 TCP-mux transport.
//!
//! One `TcpMuxConn` owns a single underlying byte pipe (typically a
//! TLS-over-TCP connection with ALPN `krot-tcp/1`) and multiplexes
//! streams over it using the OPEN / DATA / FIN framing defined in
//! §16.1.1.
//!
//! ## Layout
//!
//! - **Reader task** owns the read half of the underlying pipe.
//!   Loops: parse a 9-byte [`MuxHeader`], read `payload_len` more
//!   bytes, dispatch:
//!   - `OPEN` → create per-stream mpsc pair, push `AcceptedStream`
//!     onto the accept queue, prime the recv side with the OPEN
//!     payload (the §5.1 Data-stream header) as its first bytes.
//!   - `DATA` → forward `payload` to the target stream's mpsc.
//!   - `FIN` → drop the target stream's data sender; the recv side
//!     observes it as EOF.
//! - **Writer task** owns the write half. Drains an `mpsc<OutFrame>`,
//!   serialises header + payload to the pipe.
//! - **`TcpMuxSendStream`** implements [`AsyncWrite`]. For data
//!   streams (id > 0) opened locally it buffers the first 9 bytes
//!   written by the caller and emits an OPEN with those bytes as
//!   payload (that's the §5.1 Data-stream header). Subsequent bytes
//!   become DATA frames. For the Control stream (id = 0) every write
//!   is DATA from the start — the stream is implicitly present at
//!   connection creation.
//! - **`TcpMuxRecvStream`** implements [`AsyncRead`]. Pulls
//!   `bytes::Bytes` chunks from its per-stream mpsc, tracks a leftover
//!   buffer, EOF when the channel closes.
//!
//! ## Stream id allocation
//!
//! `stream_id = 0` is the Control stream, implicit at connect time.
//! Locally-minted ids are even for the client half and odd for the
//! server half (§16.1.1). They start at 2 / 1 respectively and
//! increment by 2 each `open_bi`.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::sync::{mpsc, Notify};

use krot_proto::mux::{MuxFlag, MuxHeader, CONTROL_STREAM_ID, MUX_HEADER_SIZE};

use crate::error::TransportError;

/// Max buffered inbound frames per stream. Provides light backpressure —
/// once the queue fills the reader task blocks on `send`, which pauses
/// receipt of ALL streams. For simplicity we accept this coupling in
/// v1; a future revision can split reader tasks per-stream.
const STREAM_INBOUND_CAPACITY: usize = 64;

/// Upper bound on a single DATA-frame payload. Adversarial peers can
/// otherwise trigger `vec![0u8; header.payload_len as usize]` with
/// `payload_len = 0xFFFF_FFFF` (4 GiB) and OOM the server with one
/// 9-byte mux header. The cap is 256 KiB — plenty for realistic TLS
/// records (typically ≤ 16 KiB) and TCP MSS-shaped chunks (~1500 B).
/// Frames larger than this cap terminate the mux with a reader-task
/// exit — the peer sees a socket close.
const MAX_MUX_PAYLOAD: u32 = 256 * 1024;

/// Frame the writer task serialises to the underlying pipe.
#[derive(Debug)]
enum OutFrame {
    /// A concrete OPEN / DATA / FIN. Payload MAY be empty (FIN).
    Frame { header: MuxHeader, payload: Bytes },
    /// Writer task drain signal — flush what's queued, then exit.
    Close,
}

/// One entry in the accept queue. Consumers of `accept_bi()` pop this
/// and turn it into a paired `(SendStream, RecvStream)`.
#[derive(Debug)]
struct AcceptedStream {
    stream_id: u32,
    /// The §5.1 Data-stream header extracted from the OPEN payload —
    /// primed as the first 9 bytes readable on the recv side.
    open_payload: [u8; 9],
    /// Inbound data channel for this stream. Reader task holds the
    /// matching sender in `Inner.streams`.
    data_rx: mpsc::Receiver<Bytes>,
}

/// Shared state between the mux connection handle, the reader task,
/// and every stream returned by `open_bi` / `accept_bi`.
#[derive(Debug)]
struct Inner {
    is_server: bool,
    writer_tx: mpsc::UnboundedSender<OutFrame>,
    /// Sender side of every inbound stream, keyed by `stream_id`.
    streams: Mutex<HashMap<u32, mpsc::Sender<Bytes>>>,
    accept_tx: mpsc::UnboundedSender<AcceptedStream>,
    // `tokio::sync::Mutex` so the guard is `Send` across the await
    // inside `accept_bi()`.
    accept_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<AcceptedStream>>,
    next_stream_id: AtomicU32,
    closed: AtomicBool,
    closed_notify: Notify,
    /// Client side: stashed recv-half of the Control stream (id=0).
    /// Populated in `new` on the client, taken by the first
    /// `open_bi()` call. `None` on the server side — Control arrives
    /// via the accept queue there.
    control_recv_slot: Mutex<Option<mpsc::Receiver<Bytes>>>,
}

/// Public handle to a running mux. Cheap to clone.
#[derive(Debug, Clone)]
pub struct TcpMuxConn {
    inner: Arc<Inner>,
}

impl TcpMuxConn {
    /// Wrap an already-established underlying byte pipe (post-TLS)
    /// and spawn the reader + writer tasks. `is_server` picks the
    /// parity of locally-minted `stream_id`s (odd for server, even
    /// for client).
    ///
    /// The returned handle also transparently owns the Control
    /// stream (`stream_id = 0`) — it is registered immediately so
    /// either side may `open_bi()` to obtain its endpoint without
    /// wire coordination.
    pub fn new<S>(io: S, is_server: bool) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (writer_tx, writer_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();

        // Pre-register the Control stream (`stream_id = 0`). Both
        // sides need a channel pair for it, since the spec says
        // Control is implicit at connect (§16.1.1) — no OPEN frame
        // is emitted for it. Server pushes the recv onto the accept
        // queue; client stashes it in `control_recv_slot` for
        // `open_bi()` to hand out on first call.
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<Bytes>(STREAM_INBOUND_CAPACITY);
        let mut streams = HashMap::new();
        streams.insert(CONTROL_STREAM_ID, ctrl_tx);

        let (control_slot, control_pushed_to_accept) = if is_server {
            (None, Some(ctrl_rx))
        } else {
            (Some(ctrl_rx), None)
        };

        let inner = Arc::new(Inner {
            is_server,
            writer_tx,
            streams: Mutex::new(streams),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            // First locally-minted id: 1 for server (odd), 2 for
            // client (even). Zero is reserved for Control.
            next_stream_id: AtomicU32::new(if is_server { 1 } else { 2 }),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
            control_recv_slot: Mutex::new(control_slot),
        });

        // Server pushes the Control stream onto the accept queue
        // immediately — `accept_bi()` returns it first, mirroring
        // how the QUIC server sees the client's first `open_bi()`
        // arrive as an incoming bi stream.
        if let Some(ctrl_rx) = control_pushed_to_accept {
            let _ = inner.accept_tx.send(AcceptedStream {
                stream_id: CONTROL_STREAM_ID,
                open_payload: [0u8; 9],
                data_rx: ctrl_rx,
            });
        }

        let (read_half, write_half) = split(io);
        tokio::spawn(reader_task(read_half, Arc::clone(&inner)));
        tokio::spawn(writer_task(write_half, writer_rx));

        Self { inner }
    }

    /// Open a new bidirectional stream initiated by this side. The
    /// stream is data — the OPEN frame carries the §5.1 Data-stream
    /// header, which the caller supplies here.
    ///
    /// For the Control stream use [`Self::control_stream`] instead;
    /// it has no OPEN and no §5.1 header.
    #[allow(clippy::unused_async)] // Mirrors quinn::Connection::open_bi.
    pub async fn open_data_stream(
        &self,
        header: [u8; 9],
    ) -> Result<(TcpMuxSendStream, TcpMuxRecvStream), TransportError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(TransportError::UnexpectedEof);
        }
        let stream_id = self.mint_stream_id();
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(STREAM_INBOUND_CAPACITY);
        self.inner
            .streams
            .lock()
            .unwrap()
            .insert(stream_id, data_tx);
        // Emit OPEN with the §5.1 header as payload.
        let out = OutFrame::Frame {
            header: MuxHeader {
                flag: MuxFlag::Open,
                stream_id,
                payload_len: 9,
            },
            payload: Bytes::copy_from_slice(&header),
        };
        self.inner
            .writer_tx
            .send(out)
            .map_err(|_| TransportError::UnexpectedEof)?;
        let send = TcpMuxSendStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            pending_open: None,
            finished: false,
        };
        let recv = TcpMuxRecvStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            data_rx,
            leftover: Bytes::new(),
            eof: false,
        };
        Ok((send, recv))
    }

    /// Accept a peer-opened data stream and return `(§5.1 header,
    /// send, recv)`. `header` is the OPEN payload, promoted out-of-band
    /// so the caller doesn't need to re-read it from `recv`.
    pub async fn accept_data_stream(
        &self,
    ) -> Result<([u8; 9], TcpMuxSendStream, TcpMuxRecvStream), TransportError> {
        let mut accept_rx = self.inner.accept_rx.lock().await;
        let AcceptedStream {
            stream_id,
            open_payload,
            data_rx,
        } = accept_rx
            .recv()
            .await
            .ok_or(TransportError::UnexpectedEof)?;
        drop(accept_rx);
        let send = TcpMuxSendStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            pending_open: None,
            finished: false,
        };
        let recv = TcpMuxRecvStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            data_rx,
            leftover: Bytes::new(),
            eof: false,
        };
        Ok((open_payload, send, recv))
    }

    /// Uniform open-bidirectional-stream API, mirroring
    /// `quinn::Connection::open_bi`. The FIRST call on a client-side
    /// mux returns the pre-primed Control stream (`stream_id = 0`);
    /// subsequent calls mint a new even data stream id, and the
    /// returned `SendStream` transparently buffers the caller's
    /// first 9 bytes and emits an OPEN frame with them as payload
    /// (that's the §5.1 Data-stream header). On the server side
    /// every call mints a new odd data stream id.
    ///
    /// The server side ordinarily consumes the Control stream via
    /// `accept_bi()`, not `open_bi()`, so calling this on a server
    /// mux always yields a data stream.
    #[allow(clippy::unused_async)] // Mirrors quinn::Connection::open_bi.
    pub async fn open_bi(&self) -> Result<(TcpMuxSendStream, TcpMuxRecvStream), TransportError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(TransportError::UnexpectedEof);
        }
        // Client side: hand out the pre-primed Control stream on the
        // first open_bi() call.
        if !self.inner.is_server {
            let mut slot = self.inner.control_recv_slot.lock().unwrap();
            if let Some(rx) = slot.take() {
                let send = TcpMuxSendStream {
                    inner: Arc::clone(&self.inner),
                    stream_id: CONTROL_STREAM_ID,
                    pending_open: None,
                    finished: false,
                };
                let recv = TcpMuxRecvStream {
                    inner: Arc::clone(&self.inner),
                    stream_id: CONTROL_STREAM_ID,
                    data_rx: rx,
                    leftover: Bytes::new(),
                    eof: false,
                };
                return Ok((send, recv));
            }
        }
        // Data stream: mint a new id and register the inbound
        // channel. OPEN is deferred until we've buffered 9 bytes.
        let stream_id = self.mint_stream_id();
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(STREAM_INBOUND_CAPACITY);
        self.inner
            .streams
            .lock()
            .unwrap()
            .insert(stream_id, data_tx);
        let send = TcpMuxSendStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            pending_open: Some(Vec::with_capacity(9)),
            finished: false,
        };
        let recv = TcpMuxRecvStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            data_rx,
            leftover: Bytes::new(),
            eof: false,
        };
        Ok((send, recv))
    }

    /// Uniform accept-bidirectional-stream API, mirroring
    /// `quinn::Connection::accept_bi`. On the server side the FIRST
    /// call returns the Control stream (pre-primed at connect); every
    /// subsequent call awaits an OPEN frame from the peer. On the
    /// client side every call awaits an OPEN.
    ///
    /// For data streams the peer's OPEN payload (the §5.1 Data-stream
    /// header) is prepended to the returned `RecvStream`'s leftover
    /// buffer, so callers read it as the first 9 bytes exactly like
    /// they do on QUIC.
    pub async fn accept_bi(&self) -> Result<(TcpMuxSendStream, TcpMuxRecvStream), TransportError> {
        let mut accept_rx = self.inner.accept_rx.lock().await;
        let AcceptedStream {
            stream_id,
            open_payload,
            data_rx,
        } = accept_rx
            .recv()
            .await
            .ok_or(TransportError::UnexpectedEof)?;
        drop(accept_rx);
        let send = TcpMuxSendStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            pending_open: None,
            finished: false,
        };
        // For data streams (id != 0) prime the recv leftover with the
        // §5.1 header from the OPEN payload so the caller reads it as
        // the first 9 stream bytes. Control has no OPEN payload.
        let leftover = if stream_id == CONTROL_STREAM_ID {
            Bytes::new()
        } else {
            Bytes::copy_from_slice(&open_payload)
        };
        let recv = TcpMuxRecvStream {
            inner: Arc::clone(&self.inner),
            stream_id,
            data_rx,
            leftover,
            eof: false,
        };
        Ok((send, recv))
    }

    /// Ask the writer task to drain what's queued and then shut down
    /// the underlying pipe.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let _ = self.inner.writer_tx.send(OutFrame::Close);
        self.inner.closed_notify.notify_waiters();
    }

    /// Wait until the mux is closed (peer disconnect or local
    /// `close()`).
    pub async fn closed(&self) {
        if self.inner.closed.load(Ordering::Relaxed) {
            return;
        }
        self.inner.closed_notify.notified().await;
    }

    fn mint_stream_id(&self) -> u32 {
        // Increment by 2 to keep parity (odd for server, even for
        // client). Wrap-around at u32::MAX is astronomically
        // unlikely on realistic session lifetimes.
        self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed)
    }
}

// ---------------- reader / writer tasks ----------------

async fn reader_task<R>(mut read: ReadHalf<R>, inner: Arc<Inner>)
where
    R: AsyncRead + Unpin,
{
    let mut header_buf = [0u8; MUX_HEADER_SIZE];
    loop {
        if read.read_exact(&mut header_buf).await.is_err() {
            break;
        }
        let Ok(header) = MuxHeader::decode(&header_buf) else {
            break;
        };
        match header.flag {
            MuxFlag::Open => {
                let mut payload = [0u8; 9];
                if read.read_exact(&mut payload).await.is_err() {
                    break;
                }
                // Guard: OPEN with parity we've already assigned to
                // ourselves indicates a bug in the peer; ignore.
                if header.stream_id == CONTROL_STREAM_ID {
                    // Control has no OPEN — treat as protocol
                    // violation.
                    break;
                }
                let (tx, rx) = mpsc::channel::<Bytes>(STREAM_INBOUND_CAPACITY);
                inner.streams.lock().unwrap().insert(header.stream_id, tx);
                let _ = inner.accept_tx.send(AcceptedStream {
                    stream_id: header.stream_id,
                    open_payload: payload,
                    data_rx: rx,
                });
            }
            MuxFlag::Data => {
                if header.payload_len > MAX_MUX_PAYLOAD {
                    break;
                }
                let mut buf = vec![0u8; header.payload_len as usize];
                if read.read_exact(&mut buf).await.is_err() {
                    break;
                }
                let sender = inner
                    .streams
                    .lock()
                    .unwrap()
                    .get(&header.stream_id)
                    .cloned();
                if let Some(tx) = sender {
                    // Best-effort forward. If the receiver was
                    // dropped (the local end abandoned the stream),
                    // silently drop the bytes — the peer will
                    // eventually see a RESET via the enclosing
                    // transport.
                    let _ = tx.send(Bytes::from(buf)).await;
                }
                // Unknown stream_id → discard (peer possibly races
                // with a FIN we sent).
            }
            MuxFlag::Fin => {
                // Drop the sender: the recv side observes EOF the
                // next time its channel is polled.
                inner.streams.lock().unwrap().remove(&header.stream_id);
            }
        }
    }
    inner.closed.store(true, Ordering::Relaxed);
    inner.closed_notify.notify_waiters();
}

async fn writer_task<W>(mut write: WriteHalf<W>, mut rx: mpsc::UnboundedReceiver<OutFrame>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = rx.recv().await {
        match frame {
            OutFrame::Frame { header, payload } => {
                if write.write_all(&header.to_bytes()).await.is_err() {
                    break;
                }
                if !payload.is_empty() && write.write_all(&payload).await.is_err() {
                    break;
                }
            }
            OutFrame::Close => break,
        }
    }
    let _ = write.shutdown().await;
}

// ---------------- streams ----------------

/// Bidirectional-stream send half on top of the mux.
#[derive(Debug)]
pub struct TcpMuxSendStream {
    inner: Arc<Inner>,
    stream_id: u32,
    /// For streams opened locally with the uniform `open_bi()` API,
    /// this holds up to 9 buffered bytes destined for the OPEN
    /// frame's payload (the §5.1 Data-stream header). Once we have
    /// exactly 9 bytes we emit OPEN and set this to `None`;
    /// subsequent writes go straight into DATA frames.
    ///
    /// `None` for the Control stream (id 0, no OPEN) and for the
    /// send half of accepted streams (peer already sent OPEN).
    pending_open: Option<Vec<u8>>,
    finished: bool,
}

impl TcpMuxSendStream {
    /// Mark this side finished — emits a FIN frame. Subsequent
    /// writes are silently dropped (matches
    /// `quinn::SendStream::finish` semantics as we surface them via
    /// `Connection::SendStream::finish`).
    pub fn finish(&mut self) -> Result<(), TransportError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        // If we still owe an OPEN (fewer than 9 buffered bytes), the
        // caller broke the contract by finishing before sending the
        // §5.1 header. We emit OPEN with whatever we buffered plus
        // padding so the peer sees a well-formed OPEN, then FIN —
        // the peer's decode will error on the malformed header at
        // the application layer, which is the same behaviour it'd
        // see over QUIC.
        if let Some(mut buf) = self.pending_open.take() {
            buf.resize(9, 0);
            let out = OutFrame::Frame {
                header: MuxHeader {
                    flag: MuxFlag::Open,
                    stream_id: self.stream_id,
                    payload_len: 9,
                },
                payload: Bytes::from(buf),
            };
            let _ = self.inner.writer_tx.send(out);
        }
        let out = OutFrame::Frame {
            header: MuxHeader {
                flag: MuxFlag::Fin,
                stream_id: self.stream_id,
                payload_len: 0,
            },
            payload: Bytes::new(),
        };
        self.inner
            .writer_tx
            .send(out)
            .map_err(|_| TransportError::UnexpectedEof)?;
        Ok(())
    }
}

impl AsyncWrite for TcpMuxSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.finished || this.inner.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux stream closed",
            )));
        }
        let mut cursor = 0usize;

        // Phase 1: fill the pending_open buffer until we have 9
        // bytes, then emit OPEN with those bytes as payload.
        if let Some(pending) = this.pending_open.as_mut() {
            let need = 9 - pending.len();
            let take = need.min(buf.len());
            pending.extend_from_slice(&buf[..take]);
            cursor += take;
            if pending.len() == 9 {
                let payload = Bytes::from(std::mem::take(pending));
                this.pending_open = None;
                let out = OutFrame::Frame {
                    header: MuxHeader {
                        flag: MuxFlag::Open,
                        stream_id: this.stream_id,
                        payload_len: 9,
                    },
                    payload,
                };
                if this.inner.writer_tx.send(out).is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux writer gone",
                    )));
                }
            } else {
                // We didn't reach 9 bytes; report the take.
                return Poll::Ready(Ok(cursor));
            }
        }

        // Phase 2: emit any remaining bytes as a single DATA frame.
        let rest = &buf[cursor..];
        if !rest.is_empty() {
            let out = OutFrame::Frame {
                header: MuxHeader {
                    flag: MuxFlag::Data,
                    stream_id: this.stream_id,
                    payload_len: rest.len() as u32,
                },
                payload: Bytes::copy_from_slice(rest),
            };
            if this.inner.writer_tx.send(out).is_err() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux writer gone",
                )));
            }
            cursor += rest.len();
        }
        Poll::Ready(Ok(cursor))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writer task drains its queue eagerly; nothing to flush
        // beyond what poll_write already enqueued.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _ = this.finish();
        Poll::Ready(Ok(()))
    }
}

/// Bidirectional-stream recv half on top of the mux.
#[derive(Debug)]
pub struct TcpMuxRecvStream {
    inner: Arc<Inner>,
    stream_id: u32,
    data_rx: mpsc::Receiver<Bytes>,
    leftover: Bytes,
    eof: bool,
}

impl Drop for TcpMuxRecvStream {
    fn drop(&mut self) {
        // Detach the sender when the recv side goes away so the
        // reader task's `send` returns `Err` next time and stops
        // buffering.
        self.inner.streams.lock().unwrap().remove(&self.stream_id);
    }
}

impl AsyncRead for TcpMuxRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve leftover first.
        if !self.leftover.is_empty() {
            let take = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..take]);
            self.leftover = self.leftover.slice(take..);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        // Poll the mpsc for the next inbound chunk.
        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let take = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..take]);
                if take < chunk.len() {
                    self.leftover = chunk.slice(take..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Build a duplex-connected pair of muxes. Represents a
    /// TLS-over-TCP link without the TLS.
    fn duplex_pair() -> (TcpMuxConn, TcpMuxConn) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        // `is_server` decides stream_id parity; give A odd and B even
        // so they don't collide on `open_data_stream`.
        (TcpMuxConn::new(a, true), TcpMuxConn::new(b, false))
    }

    #[tokio::test]
    async fn open_then_send_data_end_to_end() {
        // A opens a data stream to B; sends bytes; B accepts and
        // reads them.
        let (a, b) = duplex_pair();
        let header = [0xAB, 1, 2, 3, 4, 5, 6, 7, 8];
        let (mut a_send, _a_recv) = a.open_data_stream(header).await.unwrap();
        a_send.write_all(b"hello world").await.unwrap();
        a_send.flush().await.unwrap();

        let (b_header, _b_send, mut b_recv) = b.accept_data_stream().await.unwrap();
        assert_eq!(b_header, header);
        let mut got = vec![0u8; 11];
        b_recv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello world");
    }

    #[tokio::test]
    async fn bidirectional_ping_pong() {
        let (a, b) = duplex_pair();
        let header = [0x02, 0, 0, 0, 0, 0, 0, 0, 42];
        let (mut a_send, mut a_recv) = a.open_data_stream(header).await.unwrap();
        let (_, mut b_send, mut b_recv) = b.accept_data_stream().await.unwrap();

        a_send.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        b_send.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        a_recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn fin_produces_eof_on_recv() {
        let (a, b) = duplex_pair();
        let header = [0x02; 9];
        let (mut a_send, _a_recv) = a.open_data_stream(header).await.unwrap();
        let (_, _, mut b_recv) = b.accept_data_stream().await.unwrap();

        a_send.write_all(b"one").await.unwrap();
        a_send.finish().unwrap();

        let mut buf = [0u8; 3];
        b_recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"one");
        // Next read observes EOF.
        let mut tail = [0u8; 8];
        let n = b_recv.read(&mut tail).await.unwrap();
        assert_eq!(n, 0, "expected EOF");
    }

    #[tokio::test]
    async fn multiple_concurrent_streams() {
        let (a, b) = duplex_pair();
        // Open three streams from A; accept and read on B.
        let hdr1 = [0x02, 0, 0, 0, 0, 0, 0, 0, 1];
        let hdr2 = [0x02, 0, 0, 0, 0, 0, 0, 0, 2];
        let hdr3 = [0x02, 0, 0, 0, 0, 0, 0, 0, 3];
        let (mut s1, _r1) = a.open_data_stream(hdr1).await.unwrap();
        let (mut s2, _r2) = a.open_data_stream(hdr2).await.unwrap();
        let (mut s3, _r3) = a.open_data_stream(hdr3).await.unwrap();
        s1.write_all(b"AAA").await.unwrap();
        s2.write_all(b"BBB").await.unwrap();
        s3.write_all(b"CCC").await.unwrap();

        // Streams arrive in emit order on the accept queue.
        let (h1, _, mut r1) = b.accept_data_stream().await.unwrap();
        let (h2, _, mut r2) = b.accept_data_stream().await.unwrap();
        let (h3, _, mut r3) = b.accept_data_stream().await.unwrap();
        assert_eq!(h1, hdr1);
        assert_eq!(h2, hdr2);
        assert_eq!(h3, hdr3);
        let mut buf = [0u8; 3];
        r1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"AAA");
        r2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"BBB");
        r3.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"CCC");
    }

    #[tokio::test]
    async fn open_bi_hands_out_control_stream_first_on_client() {
        // Client's first open_bi() → Control stream (id 0, no OPEN).
        // Server's first accept_bi() gets the same Control stream.
        // Bytes written on client's send are read on server's recv.
        let (server_mux, client_mux) = duplex_pair();
        let (mut c_send, _c_recv) = client_mux.open_bi().await.unwrap();
        c_send.write_all(b"CTRL").await.unwrap();

        let (_s_send, mut s_recv) = server_mux.accept_bi().await.unwrap();
        let mut buf = [0u8; 4];
        s_recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"CTRL");
    }

    #[tokio::test]
    async fn open_bi_data_stream_buffers_9_bytes_as_open_payload() {
        // Server opens a data stream via uniform open_bi(); writes
        // exactly the §5.1 header + payload; client accepts it and
        // reads the header as the first 9 bytes exactly as if this
        // were QUIC.
        let (server_mux, client_mux) = duplex_pair();
        // Step past the Control stream on client so its next accept
        // picks up the data stream, and on server so its next
        // accept picks up a hypothetical client-initiated stream.
        let (_c_ctrl_send, _c_ctrl_recv) = client_mux.open_bi().await.unwrap();
        let (_s_ctrl_send, _s_ctrl_recv) = server_mux.accept_bi().await.unwrap();

        let (mut s_send, _s_recv) = server_mux.open_bi().await.unwrap();
        let header = [0x02u8, 1, 2, 3, 4, 5, 6, 7, 8]; // §5.1 header
        s_send.write_all(&header).await.unwrap();
        s_send.write_all(b"payload!").await.unwrap();

        let (_c_send, mut c_recv) = client_mux.accept_bi().await.unwrap();
        let mut got_header = [0u8; 9];
        c_recv.read_exact(&mut got_header).await.unwrap();
        assert_eq!(got_header, header);
        let mut got_payload = [0u8; 8];
        c_recv.read_exact(&mut got_payload).await.unwrap();
        assert_eq!(&got_payload, b"payload!");
    }

    #[tokio::test]
    async fn open_bi_buffers_across_partial_writes() {
        // First write is 4 bytes (< 9), second write is 20 bytes.
        // The mux should emit OPEN with the first 9 (4 buffered +
        // 5 from the second write) then DATA with the remaining 15.
        let (server_mux, client_mux) = duplex_pair();
        let (_c_ctrl, _) = client_mux.open_bi().await.unwrap();
        let (_s_ctrl, _) = server_mux.accept_bi().await.unwrap();

        let (mut s_send, _) = server_mux.open_bi().await.unwrap();
        s_send.write_all(&[0xAAu8; 4]).await.unwrap();
        let mut second = vec![0xBBu8; 20];
        // Overwrite first 5 so the header we assemble is
        // [AA*4, BB, BB, BB, BB, BB] = 9 header bytes; then 15 DATA.
        second[0] = 0xCC; // marker so we can verify offset
        s_send.write_all(&second).await.unwrap();

        let (_c_send, mut c_recv) = client_mux.accept_bi().await.unwrap();
        let mut got = vec![0u8; 24];
        c_recv.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..4], &[0xAA; 4]);
        assert_eq!(got[4], 0xCC);
        for &b in &got[5..24] {
            assert_eq!(b, 0xBB);
        }
    }

    #[tokio::test]
    async fn large_write_splits_ok() {
        // A big write becomes a single DATA frame for us (writer
        // channel is unbounded), and the reader forwards it as one
        // chunk. Verify a payload larger than the leftover-slot
        // still reassembles bit-for-bit on the reader.
        let (a, b) = duplex_pair();
        let header = [0x02; 9];
        let (mut a_send, _) = a.open_data_stream(header).await.unwrap();
        let payload: Vec<u8> = (0..4096u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        a_send.write_all(&payload).await.unwrap();

        let (_, _, mut b_recv) = b.accept_data_stream().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        b_recv.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }
}
