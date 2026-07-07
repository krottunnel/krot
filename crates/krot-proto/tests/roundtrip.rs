//! End-to-end round-trip tests for the wire format.
//!
//! These lock the byte-level protocol against unintended changes: adding a
//! new variant in the middle of an enum, reordering fields, or altering a
//! constant will break at least one of these tests.

use krot_proto::{
    decode_frame, encode_frame, ClientFrame, DataHeader, ErrorCode, Nonce, PubKey, ServerFrame,
    SessionId, Signature, StreamKind, TunnelId, TunnelKind, DATA_HEADER_SIZE,
};

fn roundtrip_client(frame: &ClientFrame) {
    let mut buf = Vec::new();
    encode_frame(frame, &mut buf).unwrap();
    let (decoded, used): (ClientFrame, usize) = decode_frame(&buf).unwrap();
    assert_eq!(&decoded, frame);
    assert_eq!(used, buf.len());
}

fn roundtrip_server(frame: &ServerFrame) {
    let mut buf = Vec::new();
    encode_frame(frame, &mut buf).unwrap();
    let (decoded, used): (ServerFrame, usize) = decode_frame(&buf).unwrap();
    assert_eq!(&decoded, frame);
    assert_eq!(used, buf.len());
}

#[test]
fn client_frames_roundtrip() {
    roundtrip_client(&ClientFrame::AuthRequest {
        pubkey: PubKey([0x11; 32]),
    });
    roundtrip_client(&ClientFrame::AuthResponse {
        signature: Signature([0x22; 64]),
    });
    roundtrip_client(&ClientFrame::RegisterTunnel {
        label: "alice".into(),
        kind: TunnelKind::Http,
        resume_session_id: None,
        inspect: false,
    });
    roundtrip_client(&ClientFrame::RegisterTunnel {
        label: "db".into(),
        kind: TunnelKind::Tcp {
            remote_port: Some(5432),
        },
        resume_session_id: Some(SessionId([9u8; 16])),
        inspect: true,
    });
    roundtrip_client(&ClientFrame::UnregisterTunnel {
        tunnel_id: TunnelId(42),
    });
    roundtrip_client(&ClientFrame::Ping { nonce: 0xDEAD_BEEF });
    roundtrip_client(&ClientFrame::Bye);
    roundtrip_client(&ClientFrame::Enroll {
        admin_token: "KROT-TEST-TOKEN".into(),
        pubkey: PubKey([0x33; 32]),
        label_hint: Some("my-laptop".into()),
    });
    roundtrip_client(&ClientFrame::ListPeers);
}

#[test]
fn server_frames_roundtrip() {
    roundtrip_server(&ServerFrame::AuthChallenge {
        nonce: Nonce([0x55; 32]),
    });
    roundtrip_server(&ServerFrame::AuthOk {
        session_id: SessionId([0xAA; 16]),
    });
    roundtrip_server(&ServerFrame::AuthReject {
        code: ErrorCode::UNKNOWN_IDENTITY,
    });
    roundtrip_server(&ServerFrame::TunnelRegistered {
        tunnel_id: TunnelId(1),
        public_url: "https://alice.krot.example".into(),
        public_port: None,
    });
    roundtrip_server(&ServerFrame::TunnelRegistered {
        tunnel_id: TunnelId(2),
        public_url: "tcp://203.0.113.10:24601".into(),
        public_port: Some(24_601),
    });
    roundtrip_server(&ServerFrame::TunnelRejected {
        code: ErrorCode::LABEL_UNAVAILABLE,
        detail: "alice is taken".into(),
    });
    roundtrip_server(&ServerFrame::Pong { nonce: 42 });
    roundtrip_server(&ServerFrame::RateLimit {
        tunnel_id: Some(TunnelId(7)),
        retry_after_ms: 1500,
    });
    roundtrip_server(&ServerFrame::ServerBye {
        code: ErrorCode::SERVER_SHUTDOWN,
    });
    roundtrip_server(&ServerFrame::EnrollOk {
        authorized_line: "ed25519 AAAA... subdomain=*".into(),
    });
    roundtrip_server(&ServerFrame::EnrollRejected {
        code: ErrorCode::TOKEN_EXPIRED,
    });
    roundtrip_server(&ServerFrame::Peers { relays: vec![] });
    roundtrip_server(&ServerFrame::Peers {
        relays: vec![
            "krot.us-east.example".into(),
            "krot.eu-west.example:7854".into(),
        ],
    });
}

#[test]
fn data_header_roundtrip() {
    for kind in [StreamKind::DataHttp, StreamKind::DataTcp] {
        let header = DataHeader {
            kind,
            tunnel_id: TunnelId(0x0123_4567_89AB_CDEF),
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), DATA_HEADER_SIZE);
        // Explicit little-endian check on the tunnel_id encoding.
        assert_eq!(&bytes[1..9], &0x0123_4567_89AB_CDEFu64.to_le_bytes());
        let decoded = DataHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, header);
    }
}

#[test]
fn data_header_rejects_control_kind() {
    let bad = {
        let mut b = [0u8; DATA_HEADER_SIZE];
        b[0] = StreamKind::Control.as_byte();
        b
    };
    assert!(DataHeader::decode(&bad).is_err());
}

#[test]
fn data_header_rejects_unknown_kind() {
    let bad = [0xFFu8; DATA_HEADER_SIZE];
    assert!(DataHeader::decode(&bad).is_err());
}

#[test]
fn multiple_frames_back_to_back() {
    let a = ClientFrame::Ping { nonce: 1 };
    let b = ClientFrame::Ping { nonce: 2 };
    let mut buf = Vec::new();
    encode_frame(&a, &mut buf).unwrap();
    encode_frame(&b, &mut buf).unwrap();

    let (first, used1): (ClientFrame, usize) = decode_frame(&buf).unwrap();
    let (second, used2): (ClientFrame, usize) = decode_frame(&buf[used1..]).unwrap();
    assert_eq!(first, a);
    assert_eq!(second, b);
    assert_eq!(used1 + used2, buf.len());
}
