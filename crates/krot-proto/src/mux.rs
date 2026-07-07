//! `krot-tcp/1` stream-multiplexing header (§16.1.1).
//!
//! Every OPEN / DATA / FIN emitted on a TCP-fallback control connection
//! is prefixed with a fixed 9-byte header:
//!
//! ```text
//! +--------+-----------------+-----------------+
//! | flag   | stream_id (u32) | payload_len (u32) |
//! | 1 byte |     4 bytes     |     4 bytes       |
//! +--------+-----------------+-----------------+
//! ```
//!
//! Integers are little-endian, matching §5.1. `stream_id = 0` is the
//! reserved Control stream; ids ≥ 1 are minted by the opener (even =
//! client, odd = server).

/// Fixed size of the mux frame header. See module docs.
pub const MUX_HEADER_SIZE: usize = 9;

/// Reserved `stream_id` for the Control stream.
pub const CONTROL_STREAM_ID: u32 = 0;

/// Kind of mux frame (§16.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxFlag {
    /// Peer is opening a new stream. Payload is exactly 9 bytes: the
    /// §5.1 Data-stream header (StreamKind + tunnel_id).
    Open = 0x01,
    /// Bytes for an already-open stream. Payload is `payload_len`
    /// bytes long.
    Data = 0x02,
    /// Peer has finished sending on this stream. Payload is empty
    /// (`payload_len = 0`); this half-closes the origin → peer
    /// direction, exactly like `quinn::SendStream::finish`.
    Fin = 0x03,
}

impl MuxFlag {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for MuxFlag {
    type Error = MuxHeaderError;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::Open),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Fin),
            _ => Err(MuxHeaderError::UnknownFlag(byte)),
        }
    }
}

/// Parsed mux frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxHeader {
    pub flag: MuxFlag,
    pub stream_id: u32,
    pub payload_len: u32,
}

impl MuxHeader {
    /// Serialize to a fixed-size byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MUX_HEADER_SIZE] {
        let mut out = [0u8; MUX_HEADER_SIZE];
        out[0] = self.flag.as_byte();
        out[1..5].copy_from_slice(&self.stream_id.to_le_bytes());
        out[5..9].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    /// Parse from a byte slice. Fails if `bytes` is shorter than
    /// [`MUX_HEADER_SIZE`] or the flag byte is unknown.
    pub fn decode(bytes: &[u8]) -> Result<Self, MuxHeaderError> {
        if bytes.len() < MUX_HEADER_SIZE {
            return Err(MuxHeaderError::TooShort);
        }
        let flag = MuxFlag::try_from(bytes[0])?;
        let stream_id = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
        // FIN MUST carry an empty payload (§16.1.1).
        if matches!(flag, MuxFlag::Fin) && payload_len != 0 {
            return Err(MuxHeaderError::FinWithPayload(payload_len));
        }
        // OPEN MUST carry exactly the §5.1 Data-stream header (9 bytes).
        if matches!(flag, MuxFlag::Open) && payload_len != 9 {
            return Err(MuxHeaderError::OpenBadPayload(payload_len));
        }
        Ok(Self {
            flag,
            stream_id,
            payload_len,
        })
    }
}

/// Errors from [`MuxHeader::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxHeaderError {
    TooShort,
    UnknownFlag(u8),
    FinWithPayload(u32),
    OpenBadPayload(u32),
}

impl core::fmt::Display for MuxHeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => f.write_str("mux header too short"),
            Self::UnknownFlag(b) => write!(f, "unknown mux flag byte: {b:#04x}"),
            Self::FinWithPayload(n) => write!(f, "FIN carries {n} bytes, must be 0"),
            Self::OpenBadPayload(n) => write!(f, "OPEN carries {n} bytes, must be 9"),
        }
    }
}

impl std::error::Error for MuxHeaderError {}

/// Whether a `stream_id` was minted by the client half of the mux.
/// Convention: even = client-opened, odd = server-opened, `0` = Control.
#[must_use]
pub const fn is_client_opened(stream_id: u32) -> bool {
    stream_id != CONTROL_STREAM_ID && stream_id % 2 == 0
}

/// Whether a `stream_id` was minted by the server half of the mux.
#[must_use]
pub const fn is_server_opened(stream_id: u32) -> bool {
    stream_id != CONTROL_STREAM_ID && stream_id % 2 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_open() {
        let h = MuxHeader {
            flag: MuxFlag::Open,
            stream_id: 2,
            payload_len: 9,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), MUX_HEADER_SIZE);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(MuxHeader::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn roundtrip_data() {
        let h = MuxHeader {
            flag: MuxFlag::Data,
            stream_id: 5,
            payload_len: 4096,
        };
        assert_eq!(MuxHeader::decode(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn roundtrip_fin() {
        let h = MuxHeader {
            flag: MuxFlag::Fin,
            stream_id: 7,
            payload_len: 0,
        };
        assert_eq!(MuxHeader::decode(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn rejects_unknown_flag() {
        let mut bytes = [0u8; MUX_HEADER_SIZE];
        bytes[0] = 0x9F;
        assert_eq!(
            MuxHeader::decode(&bytes),
            Err(MuxHeaderError::UnknownFlag(0x9F))
        );
    }

    #[test]
    fn rejects_short_buffer() {
        let short = [0u8; MUX_HEADER_SIZE - 1];
        assert_eq!(MuxHeader::decode(&short), Err(MuxHeaderError::TooShort));
    }

    #[test]
    fn rejects_fin_with_payload() {
        let bytes = MuxHeader {
            flag: MuxFlag::Fin,
            stream_id: 3,
            payload_len: 1,
        }
        .to_bytes();
        assert_eq!(
            MuxHeader::decode(&bytes),
            Err(MuxHeaderError::FinWithPayload(1))
        );
    }

    #[test]
    fn rejects_open_with_wrong_payload_len() {
        let bytes = MuxHeader {
            flag: MuxFlag::Open,
            stream_id: 4,
            payload_len: 10,
        }
        .to_bytes();
        assert_eq!(
            MuxHeader::decode(&bytes),
            Err(MuxHeaderError::OpenBadPayload(10))
        );
    }

    #[test]
    fn little_endian_encoding() {
        let h = MuxHeader {
            flag: MuxFlag::Data,
            stream_id: 0x0000_0101,
            payload_len: 0x0000_0203,
        };
        let bytes = h.to_bytes();
        assert_eq!(&bytes[1..5], &[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(&bytes[5..9], &[0x03, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn stream_id_parity() {
        assert!(!is_client_opened(0));
        assert!(!is_server_opened(0));
        assert!(is_client_opened(2));
        assert!(is_server_opened(1));
        assert!(is_client_opened(1024));
        assert!(is_server_opened(1023));
    }
}
