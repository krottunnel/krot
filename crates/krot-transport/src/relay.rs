//! Adapters that pair a `quinn` bidirectional stream with a local
//! [`tokio::net::TcpStream`] for a full-duplex byte relay.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::conn::{RecvStream, SendStream};

/// Combines a [`SendStream`] and a [`RecvStream`] into a single value
/// that implements both [`AsyncRead`] and [`AsyncWrite`].
///
/// This lets the pair be passed directly to
/// [`tokio::io::copy_bidirectional`], eliminating the need for a manual
/// two-task join.
#[derive(Debug)]
pub struct BidiStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl BidiStream {
    #[inline]
    #[must_use]
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for BidiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BidiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

/// Copy bytes in both directions between `a` and `b` until either side
/// is closed.
///
/// Backpressure is handled by `tokio::io::copy_bidirectional`: it awaits
/// writes before further reads on each direction, which propagates flow
/// control back to the QUIC transport layer via `stream_receive_window`.
///
/// Returns `(a_to_b, b_to_a)` byte counts on graceful shutdown.
pub async fn run_bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}

/// Like [`run_bidirectional`], but enforces a **first-byte deadline**
/// (§10): after `deadline` elapses without any byte
/// flowing in either direction, the operation returns
/// `io::ErrorKind::TimedOut`.
///
/// Once any byte is observed the deadline is dropped; long-lived streams
/// (SSH sessions, database connections) are unaffected. Any bytes read
/// during the race are forwarded to the peer before the unbounded
/// [`tokio::io::copy_bidirectional`] takes over.
pub async fn run_bidirectional_with_first_byte_deadline<A, B>(
    a: &mut A,
    b: &mut B,
    deadline: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Small buffers — we only need enough to catch the arrival of ANY
    // byte; the remainder of the copy is handled unbounded below.
    let mut buf_a = [0u8; 4096];
    let mut buf_b = [0u8; 4096];

    let first = tokio::time::timeout(deadline, async {
        tokio::select! {
            r = a.read(&mut buf_a) => r.map(|n| (Side::A, n)),
            r = b.read(&mut buf_b) => r.map(|n| (Side::B, n)),
        }
    })
    .await;

    let (side, n) = match first {
        Ok(Ok((side, n))) => (side, n),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "data-stream first-byte deadline exceeded",
            ));
        }
    };

    // Forward whatever we peeked (may be zero, meaning the winning side
    // has already half-closed — but the OTHER side may still have data to
    // deliver, so we must not short-circuit here).
    let (mut a_to_b, mut b_to_a) = (0u64, 0u64);
    if n > 0 {
        match side {
            Side::A => {
                b.write_all(&buf_a[..n]).await?;
                a_to_b += n as u64;
            }
            Side::B => {
                a.write_all(&buf_b[..n]).await?;
                b_to_a += n as u64;
            }
        }
    }

    // Unbounded relay from here on. `copy_bidirectional` handles the
    // half-closed case correctly: an EOF on one direction triggers a
    // shutdown of the other, letting any pending response drain.
    let (extra_a_to_b, extra_b_to_a) = tokio::io::copy_bidirectional(a, b).await?;
    a_to_b += extra_a_to_b;
    b_to_a += extra_b_to_a;
    Ok((a_to_b, b_to_a))
}

#[derive(Copy, Clone)]
enum Side {
    A,
    B,
}
