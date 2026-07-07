//! Stream discriminator and Data-stream header.
//!
//! Neither type participates in `postcard` framing: they live at the raw
//! QUIC-stream byte level. `StreamKind` is a single byte written as the
//! very first byte of every stream. `DataHeader` is exactly nine bytes
//! written immediately after a `StreamKind::DataHttp` or `DataTcp` byte
//! on a Data stream (see §5.1).

use thiserror::Error;

use crate::consts::DATA_HEADER_SIZE;
use crate::ids::TunnelId;

/// First byte of every stream opened over a KROT connection.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// Bidirectional control stream (auth, register, pings). Client-opened.
    Control = 0x01,
    /// Bidirectional data stream carrying one inbound HTTP connection.
    DataHttp = 0x02,
    /// Bidirectional data stream carrying one inbound raw TCP connection.
    DataTcp = 0x03,
}

impl StreamKind {
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Error)]
#[error("unknown stream kind 0x{0:02X}")]
pub struct StreamKindError(pub u8);

impl TryFrom<u8> for StreamKind {
    type Error = StreamKindError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::DataHttp),
            0x03 => Ok(Self::DataTcp),
            other => Err(StreamKindError(other)),
        }
    }
}

/// Fixed 9-byte header written by the server at the start of every Data stream.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DataHeader {
    pub kind: StreamKind,
    pub tunnel_id: TunnelId,
}

impl DataHeader {
    /// Encode into a caller-provided 9-byte buffer.
    #[inline]
    pub fn encode(self, out: &mut [u8; DATA_HEADER_SIZE]) {
        out[0] = self.kind.as_byte();
        out[1..9].copy_from_slice(&self.tunnel_id.0.to_le_bytes());
    }

    /// Encode into a freshly allocated array.
    #[inline]
    pub fn to_bytes(self) -> [u8; DATA_HEADER_SIZE] {
        let mut buf = [0u8; DATA_HEADER_SIZE];
        self.encode(&mut buf);
        buf
    }

    /// Decode a Data-stream header. Returns an error if the discriminator
    /// is not a valid data-stream kind.
    pub fn decode(bytes: &[u8; DATA_HEADER_SIZE]) -> Result<Self, StreamKindError> {
        let kind = StreamKind::try_from(bytes[0])?;
        // Data-stream headers are only valid for data-carrying kinds.
        if matches!(kind, StreamKind::Control) {
            return Err(StreamKindError(bytes[0]));
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&bytes[1..9]);
        Ok(Self {
            kind,
            tunnel_id: TunnelId(u64::from_le_bytes(id_bytes)),
        })
    }
}
