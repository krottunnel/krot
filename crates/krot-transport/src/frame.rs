//! Asynchronous length-prefixed frame reader/writer over `quinn` streams.
//!
//! The wire format is defined by [`krot_proto::framing`]. This module
//! provides thin adapters that read the varint prefix incrementally from
//! a [`quinn::RecvStream`] and read the exact payload into a buffer,
//! then hand the bytes to `postcard` for typed decoding.

use tokio::io::AsyncWriteExt;

use serde::de::DeserializeOwned;
use serde::Serialize;

use krot_proto::consts::MAX_FRAME_SIZE;
use krot_proto::{encode_frame, FramingError};

use crate::conn::{RecvStream, SendStream};
use crate::error::TransportError;

const VARINT_MAX_BYTES: usize = 5;

/// Read one frame from `stream`, decode as `T`, and return it.
///
/// Fails with [`TransportError::Framing`] on protocol violation (bad
/// varint, payload larger than [`MAX_FRAME_SIZE`]) and with
/// [`TransportError::UnexpectedEof`] if the stream ends before the frame
/// is complete.
pub async fn read_frame<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T, TransportError> {
    let len = read_varint(stream).await?;
    let len = usize::try_from(len).map_err(|_| FramingError::BadVarint)?;
    if len > MAX_FRAME_SIZE {
        return Err(TransportError::Framing(FramingError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        }));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let value = postcard::from_bytes(&buf).map_err(FramingError::from)?;
    Ok(value)
}

/// Encode `value` as a length-prefixed frame and write it to `stream`.
pub async fn write_frame<T: Serialize>(
    stream: &mut SendStream,
    value: &T,
) -> Result<(), TransportError> {
    let mut buf = Vec::with_capacity(64);
    encode_frame(value, &mut buf)?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Read a LEB128 `u32` varint one byte at a time.
///
/// Uses byte-at-a-time reads because a varint prefix is 1-5 bytes and
/// batching would over-consume into the payload region.
async fn read_varint(stream: &mut RecvStream) -> Result<u32, TransportError> {
    let mut acc: u32 = 0;
    let mut one = [0u8; 1];
    for i in 0..VARINT_MAX_BYTES {
        stream.read_exact(&mut one).await?;
        let byte = one[0];
        let bits = u32::from(byte & 0x7F);
        let shift = (i as u32) * 7;
        if shift >= 32 || (bits << shift) >> shift != bits {
            return Err(TransportError::Framing(FramingError::BadVarint));
        }
        acc |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(acc);
        }
    }
    Err(TransportError::Framing(FramingError::BadVarint))
}
