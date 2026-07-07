//! Length-prefixed `postcard` framing for Control-stream messages
//! (§6).
//!
//! Wire layout of a single frame:
//! ```text
//! +--------------------+---------------------------+
//! | length (varint u32)| postcard-encoded payload  |
//! +--------------------+---------------------------+
//! ```
//!
//! The varint encoding is LEB128: seven payload bits per byte, high bit
//! set on all but the last byte. `u32` therefore occupies 1..=5 bytes.

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::consts::MAX_FRAME_SIZE;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("frame payload too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    #[error("varint length prefix is malformed or truncated")]
    BadVarint,

    #[error("input truncated: needed {needed} bytes, had {had}")]
    Truncated { needed: usize, had: usize },

    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Encode `value` as a length-prefixed frame appended to `out`.
///
/// Returns the number of bytes written.
pub fn encode_frame<T: Serialize>(value: &T, out: &mut Vec<u8>) -> Result<usize, FramingError> {
    let start = out.len();
    let payload = postcard::to_stdvec(value)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }
    write_varint_u32(payload.len() as u32, out);
    out.extend_from_slice(&payload);
    Ok(out.len() - start)
}

/// Decode a length-prefixed frame from the head of `input`.
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode_frame<T: DeserializeOwned>(input: &[u8]) -> Result<(T, usize), FramingError> {
    let (len, prefix_bytes) = read_varint_u32(input)?;
    let len = len as usize;
    if len > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }
    let end = prefix_bytes
        .checked_add(len)
        .ok_or(FramingError::BadVarint)?;
    if input.len() < end {
        return Err(FramingError::Truncated {
            needed: end,
            had: input.len(),
        });
    }
    let value = postcard::from_bytes(&input[prefix_bytes..end])?;
    Ok((value, end))
}

fn write_varint_u32(mut v: u32, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn read_varint_u32(input: &[u8]) -> Result<(u32, usize), FramingError> {
    let mut acc: u32 = 0;
    for (i, &b) in input.iter().enumerate().take(5) {
        let bits = u32::from(b & 0x7F);
        let shift = (i as u32) * 7;
        // Reject shifts that would drop bits.
        if shift >= 32 || (bits << shift) >> shift != bits {
            return Err(FramingError::BadVarint);
        }
        acc |= bits << shift;
        if b & 0x80 == 0 {
            return Ok((acc, i + 1));
        }
    }
    Err(FramingError::BadVarint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_powers_of_two() {
        for shift in 0..32 {
            let v = 1u32 << shift;
            let mut buf = Vec::new();
            write_varint_u32(v, &mut buf);
            let (decoded, used) = read_varint_u32(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn varint_max() {
        let mut buf = Vec::new();
        write_varint_u32(u32::MAX, &mut buf);
        assert_eq!(buf.len(), 5);
        let (decoded, used) = read_varint_u32(&buf).unwrap();
        assert_eq!(decoded, u32::MAX);
        assert_eq!(used, 5);
    }

    #[test]
    fn varint_truncated_rejected() {
        // Continuation bit set on every byte — never terminates.
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(read_varint_u32(&buf).is_err());
    }
}
