//! Zero-copy TLS `ClientHello` SNI extractor.
//!
//! Reads bytes from a [`tokio::net::TcpStream`] into a buffer until the
//! ClientHello record is complete, then walks the handshake structure to
//! extract the first `server_name` (host_name) entry from the SNI
//! extension. The buffer is returned unmodified so the caller can replay
//! it into the upstream QUIC stream.

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::error::ServerError;

/// Max size of the buffered ClientHello. The TLS spec caps a single record
/// at 16 KiB, and we only ever need the first record.
const MAX_HELLO: usize = 16 * 1024;

/// Result of a successful SNI extraction: the parsed host name, the
/// list of ALPN identifiers the client offered, and the raw bytes
/// read from the socket up to (and including) the ClientHello record.
#[derive(Debug)]
pub struct SniPeek {
    pub server_name: String,
    /// ALPN identifiers advertised by the client, in order. Used by
    /// §16.1.8 to dispatch `krot-tcp/1` control connections away from
    /// the SNI-passthrough path.
    pub alpn: Vec<Vec<u8>>,
    pub buffered: Vec<u8>,
}

/// Read enough bytes from `stream` to extract the SNI, without consuming
/// them: the returned `buffered` bytes must be forwarded verbatim to the
/// upstream target.
pub async fn peek_sni(stream: &mut TcpStream) -> Result<SniPeek, ServerError> {
    let mut buf = Vec::with_capacity(1024);

    // TLS record header: content_type(1) + version(2) + length(2)
    read_at_least(stream, &mut buf, 5).await?;
    if buf[0] != 0x16 {
        return Err(ServerError::Protocol("not a TLS handshake record"));
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > MAX_HELLO {
        return Err(ServerError::Protocol("implausible TLS record length"));
    }
    let needed = 5 + record_len;
    read_at_least(stream, &mut buf, needed).await?;

    let (server_name, alpn) = parse_client_hello(&buf[5..needed])?;
    Ok(SniPeek {
        server_name,
        alpn,
        buffered: buf,
    })
}

async fn read_at_least(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    needed: usize,
) -> Result<(), ServerError> {
    while buf.len() < needed {
        let before = buf.len();
        buf.resize(needed, 0);
        let read = stream.read(&mut buf[before..needed]).await?;
        buf.truncate(before + read);
        if read == 0 {
            return Err(ServerError::Protocol("eof while reading ClientHello"));
        }
    }
    Ok(())
}

/// Fuzz-friendly entry point over the internal parser. Not a
/// stable API — meant only for property tests and cargo-fuzz
/// targets. See `FUZZING.md`.
#[doc(hidden)]
pub fn parse_client_hello_for_fuzz(fragment: &[u8]) -> Result<(String, Vec<Vec<u8>>), ServerError> {
    parse_client_hello(fragment)
}

fn parse_client_hello(fragment: &[u8]) -> Result<(String, Vec<Vec<u8>>), ServerError> {
    let mut r = Reader::new(fragment);
    // Handshake header
    let msg_type = r.take_u8()?;
    if msg_type != 0x01 {
        return Err(ServerError::Protocol("not a ClientHello"));
    }
    let hs_len = r.take_u24()? as usize;
    let mut body = r.take(hs_len)?;

    // ClientHello body
    body.skip(2)?; // legacy_version
    body.skip(32)?; // random
    let sid_len = body.take_u8()? as usize;
    body.skip(sid_len)?;
    let cs_len = body.take_u16()? as usize;
    body.skip(cs_len)?;
    let cm_len = body.take_u8()? as usize;
    body.skip(cm_len)?;

    let ext_len = body.take_u16()? as usize;
    let mut exts = body.take(ext_len)?;
    let mut server_name: Option<String> = None;
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    while !exts.is_empty() {
        let ext_type = exts.take_u16()?;
        let ext_data_len = exts.take_u16()? as usize;
        let ext_data = exts.take(ext_data_len)?;
        match ext_type {
            0x0000 => server_name = Some(parse_sni_extension(ext_data.remaining())?),
            // §16.1.8: ALPN extension. TLS 1.3 RFC 8446 §4.2.7 —
            // ProtocolNameList: uint16 list_len, then a series of
            // ProtocolName { uint8 len, opaque data[len] }.
            0x0010 => {
                alpn = parse_alpn_extension(ext_data.remaining())?;
            }
            _ => {}
        }
    }
    let server_name =
        server_name.ok_or(ServerError::Protocol("no SNI extension in ClientHello"))?;
    Ok((server_name, alpn))
}

fn parse_alpn_extension(data: &[u8]) -> Result<Vec<Vec<u8>>, ServerError> {
    let mut r = Reader::new(data);
    let list_len = r.take_u16()? as usize;
    let mut list = r.take(list_len)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let name_len = list.take_u8()? as usize;
        let name = list.take(name_len)?;
        out.push(name.remaining().to_vec());
    }
    Ok(out)
}

fn parse_sni_extension(data: &[u8]) -> Result<String, ServerError> {
    let mut r = Reader::new(data);
    let list_len = r.take_u16()? as usize;
    let mut list = r.take(list_len)?;
    while !list.is_empty() {
        let name_type = list.take_u8()?;
        let name_len = list.take_u16()? as usize;
        let name_bytes = list.take(name_len)?;
        if name_type == 0 {
            return std::str::from_utf8(name_bytes.remaining())
                .map(str::to_lowercase)
                .map_err(|_| ServerError::Protocol("non-utf8 SNI"));
        }
    }
    Err(ServerError::Protocol("no host_name in SNI extension"))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn take_u8(&mut self) -> Result<u8, ServerError> {
        self.ensure(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn take_u16(&mut self) -> Result<u16, ServerError> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn take_u24(&mut self) -> Result<u32, ServerError> {
        self.ensure(3)?;
        let v = (u32::from(self.buf[self.pos]) << 16)
            | (u32::from(self.buf[self.pos + 1]) << 8)
            | u32::from(self.buf[self.pos + 2]);
        self.pos += 3;
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), ServerError> {
        self.ensure(n)?;
        self.pos += n;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<Reader<'a>, ServerError> {
        self.ensure(n)?;
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(Reader::new(slice))
    }

    fn ensure(&self, n: usize) -> Result<(), ServerError> {
        if self.buf.len() - self.pos < n {
            return Err(ServerError::Protocol("truncated ClientHello field"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A hand-crafted minimal ClientHello with SNI = "alice.krot.test".
    // Constructed by concatenating the record + handshake headers around a
    // valid ClientHello body.
    fn build_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        // SNI extension body: list_len(u16) name_type(u8) name_len(u16) name
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + sni_bytes.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);
        // Extension: type(u16=0) length(u16) data
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // sid_len
        body.extend_from_slice(&[0u8, 2, 0x13, 0x01]); // 2 bytes cipher suite
        body.push(1); // cm_len
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01); // client_hello
        let body_len = body.len();
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x03]); // version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_hand_crafted_hello() {
        let hello = build_hello("alice.krot.test");
        // parse_client_hello sees the record body (skip 5-byte header).
        let (sni, alpn) = parse_client_hello(&hello[5..]).unwrap();
        assert_eq!(sni, "alice.krot.test");
        assert!(alpn.is_empty(), "hand-crafted hello has no ALPN extension");
    }

    /// Same as `build_hello` but with an ALPN extension carrying the
    /// given identifiers.
    fn build_hello_with_alpn(sni: &str, alpns: &[&[u8]]) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = (1 + 2 + sni_bytes.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // SNI ext type
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        // ALPN extension: type 0x0010, then u16 length, then
        // ProtocolNameList {u16 list_len, N x {u8 name_len, name}}.
        let mut names_body = Vec::new();
        for name in alpns {
            names_body.push(name.len() as u8);
            names_body.extend_from_slice(name);
        }
        let mut alpn_ext = Vec::new();
        alpn_ext.extend_from_slice(&(names_body.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&names_body);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&alpn_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0u8, 2, 0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = body.len();
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_alpn_extension() {
        let hello = build_hello_with_alpn("alice.krot.test", &[b"krot-tcp/1", b"h2", b"http/1.1"]);
        let (sni, alpn) = parse_client_hello(&hello[5..]).unwrap();
        assert_eq!(sni, "alice.krot.test");
        assert_eq!(
            alpn,
            vec![b"krot-tcp/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec(),]
        );
    }

    #[test]
    fn alpn_absent_yields_empty_list() {
        let hello = build_hello("alice.krot.test");
        let (_, alpn) = parse_client_hello(&hello[5..]).unwrap();
        assert!(alpn.is_empty());
    }

    // -------- Property tests: parser MUST NOT panic on any input --------
    // See `FUZZING.md` for deeper libfuzzer coverage.

    proptest::proptest! {
        /// Feed arbitrary bytes to `parse_client_hello` — Err is
        /// fine, panic is not.
        #[test]
        fn parse_client_hello_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
        ) {
            let _ = parse_client_hello(&bytes);
        }

        /// Feed arbitrary bytes to the ALPN sub-parser.
        #[test]
        fn parse_alpn_extension_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)
        ) {
            let _ = parse_alpn_extension(&bytes);
        }

        /// Feed arbitrary bytes to the SNI sub-parser.
        #[test]
        fn parse_sni_extension_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)
        ) {
            let _ = parse_sni_extension(&bytes);
        }

        /// A ClientHello with a valid SNI + arbitrary bytes appended
        /// after the record MUST still yield the SNI (defence
        /// against a peer that reuses the socket after the
        /// handshake).
        #[test]
        fn valid_hello_survives_trailing_garbage(
            trailing in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)
        ) {
            let hello = build_hello("alice.krot.test");
            let mut full = hello.clone();
            full.extend_from_slice(&trailing);
            // Only the first `record_len` bytes matter.
            let (sni, _) = parse_client_hello(&hello[5..]).unwrap();
            proptest::prop_assert_eq!(sni, "alice.krot.test");
        }
    }
}
