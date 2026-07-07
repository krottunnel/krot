//! §16.1.8 helper: an `AsyncRead + AsyncWrite` wrapper that replays a
//! pre-buffered prefix of bytes before delegating to the underlying
//! stream.
//!
//! Used by the HTTPS dispatcher: it peeks the ClientHello to read
//! SNI + ALPN, then (for `krot-tcp/1` clients) hands the socket to a
//! `TlsAcceptor`. But `TlsAcceptor::accept` reads the ClientHello
//! from byte 0 — so we replay the peeked bytes here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps `S` and drains `replay` bytes into every read until it's
/// exhausted, then delegates to `S`. Writes always go straight to
/// `S`.
#[derive(Debug)]
pub struct ReplayStream<S> {
    replay: Vec<u8>,
    read_pos: usize,
    inner: S,
}

impl<S> ReplayStream<S> {
    #[must_use]
    pub fn new(replay: Vec<u8>, inner: S) -> Self {
        Self {
            replay,
            read_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_pos < this.replay.len() {
            let remaining = &this.replay[this.read_pos..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            this.read_pos += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn read_drains_replay_then_delegates() {
        let (mut a, b) = tokio::io::duplex(1024);
        let mut wrapped = ReplayStream::new(b"prefix-".to_vec(), b);
        // Write "suffix" into `a`; ReplayStream should read
        // "prefix-suffix".
        tokio::spawn(async move {
            a.write_all(b"suffix").await.unwrap();
            a.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        wrapped.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"prefix-suffix");
    }

    #[tokio::test]
    async fn writes_go_to_inner_directly() {
        let (a, b) = tokio::io::duplex(1024);
        let mut wrapped = ReplayStream::new(b"ignored".to_vec(), b);
        // wrapped.write goes to `a` via `b`'s inner.
        wrapped.write_all(b"hello").await.unwrap();
        wrapped.shutdown().await.unwrap();
        drop(wrapped);
        let mut got = Vec::new();
        let mut a = a;
        a.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
    }
}
