//! Property-based tests for every byte-level parser in `krot-proto`.
//!
//! The invariants under test are all shape-of-parser rather than
//! shape-of-value: given ANY input bytes, the parser MUST either
//! return `Ok(_)` or `Err(_)` — never panic, hang, or over-allocate.
//! Explicit round-trip properties additionally verify that valid
//! values survive an encode→decode cycle unchanged.
//!
//! Run under `cargo test`. For deeper (libfuzzer) runs see
//! `FUZZING.md`.

use proptest::prelude::*;

use krot_proto::{
    decode_frame, encode_frame, ClientFrame, DataHeader, MuxHeader, ServerFrame, StreamKind,
    TunnelKind, MUX_HEADER_SIZE,
};

// ---------- MuxHeader ----------

proptest! {
    /// `MuxHeader::decode` MUST NOT panic on arbitrary input.
    #[test]
    fn mux_header_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = MuxHeader::decode(&bytes);
    }

    /// `MuxHeader::to_bytes(h).decode()` MUST round-trip when `h` is
    /// a well-formed header. Also asserts the encoded size is
    /// exactly `MUX_HEADER_SIZE`.
    #[test]
    fn mux_header_roundtrip_for_open(stream_id in 1u32..=u32::MAX) {
        let h = MuxHeader {
            flag: krot_proto::MuxFlag::Open,
            stream_id,
            payload_len: 9,
        };
        let bytes = h.to_bytes();
        prop_assert_eq!(bytes.len(), MUX_HEADER_SIZE);
        let back = MuxHeader::decode(&bytes).unwrap();
        prop_assert_eq!(back, h);
    }

    #[test]
    fn mux_header_roundtrip_for_data(stream_id in 0u32..=u32::MAX, payload_len in 0u32..=1_000_000) {
        let h = MuxHeader {
            flag: krot_proto::MuxFlag::Data,
            stream_id,
            payload_len,
        };
        let bytes = h.to_bytes();
        let back = MuxHeader::decode(&bytes).unwrap();
        prop_assert_eq!(back, h);
    }
}

// ---------- DataHeader (§5.1) ----------

proptest! {
    /// The header takes exactly `DATA_HEADER_SIZE` bytes. Feed
    /// arbitrary content — decode MUST NOT panic.
    #[test]
    fn data_header_decode_never_panics(bytes in prop::array::uniform9(any::<u8>())) {
        let _ = DataHeader::decode(&bytes);
    }
}

// ---------- Length-prefixed postcard frames ----------

proptest! {
    /// `decode_frame::<ClientFrame>` MUST NOT panic on arbitrary
    /// bytes, no matter how short, how long, or how malformed.
    #[test]
    fn client_frame_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = decode_frame::<ClientFrame>(&bytes);
    }

    #[test]
    fn server_frame_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = decode_frame::<ServerFrame>(&bytes);
    }

    /// A round-trip of a well-formed `ClientFrame::AuthRequest`
    /// yields the same value, and the encoded length matches the
    /// buffer offset returned by `decode_frame`.
    #[test]
    fn client_frame_auth_request_roundtrips(pubkey_bytes in prop::array::uniform32(any::<u8>())) {
        let orig = ClientFrame::AuthRequest {
            pubkey: krot_proto::PubKey(pubkey_bytes),
        };
        let mut buf = Vec::new();
        encode_frame(&orig, &mut buf).unwrap();
        let (back, used) = decode_frame::<ClientFrame>(&buf).unwrap();
        prop_assert_eq!(back, orig);
        prop_assert_eq!(used, buf.len());
    }

    #[test]
    fn client_frame_register_tunnel_roundtrips(
        label in "[a-z0-9-]{0,63}",
        remote_port in prop::option::of(any::<u16>()),
        inspect in any::<bool>(),
    ) {
        let orig = ClientFrame::RegisterTunnel {
            label,
            kind: TunnelKind::Tcp { remote_port },
            resume_session_id: None,
            inspect,
        };
        let mut buf = Vec::new();
        encode_frame(&orig, &mut buf).unwrap();
        let (back, used) = decode_frame::<ClientFrame>(&buf).unwrap();
        prop_assert_eq!(back, orig);
        prop_assert_eq!(used, buf.len());
    }

    /// The frame decoder MUST bounded-allocate even for adversarial
    /// varint prefixes. Encode a valid frame, then flip individual
    /// bytes and re-decode — no panic, no allocation blow-up.
    #[test]
    fn corrupted_frame_never_panics(
        offset in 0usize..64,
        xor_byte in 1u8..=255,
    ) {
        let orig = ClientFrame::Bye;
        let mut buf = Vec::new();
        encode_frame(&orig, &mut buf).unwrap();
        buf.resize(64, 0); // pad so the offset is always in range
        buf[offset] ^= xor_byte;
        let _ = decode_frame::<ClientFrame>(&buf);
    }
}

// ---------- StreamKind ----------

proptest! {
    #[test]
    fn stream_kind_try_from_never_panics(byte in any::<u8>()) {
        let _ = StreamKind::try_from(byte);
    }
}
