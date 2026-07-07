//! Typed identifiers used across the wire protocol.
//!
//! Every identifier is a thin newtype so that a `TunnelId` cannot be
//! accidentally passed where a `SessionId` is expected. On the wire each
//! type is a fixed-size byte array; there is no length prefix.

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::consts::{AUTH_NONCE_LEN, SESSION_ID_LEN};

/// Server-assigned identifier for a registered tunnel.
///
/// Written as a little-endian `u64` in the Data-stream header (see §5.1).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TunnelId(pub u64);

impl TunnelId {
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for TunnelId {
    #[inline]
    fn from(v: u64) -> Self {
        Self(v)
    }
}

/// Server-issued session identifier used for lease resumption (§7.3).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

/// Random challenge sent by the server during authentication (§7.1).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(pub [u8; AUTH_NONCE_LEN]);

/// Ed25519 public key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PubKey(pub [u8; 32]);

/// Ed25519 signature over the domain-separated challenge (§7.1).
///
/// `serde` derives array impls only up to length 32, so this type
/// implements `Serialize`/`Deserialize` manually as a fixed-length tuple
/// of 64 bytes — which `postcard` encodes as 64 raw bytes with no prefix.
#[derive(Copy, Clone)]
pub struct Signature(pub [u8; 64]);

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Signature").field(&"..").finish()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        // Non-constant-time; fine — signatures are public.
        self.0 == other.0
    }
}

impl Eq for Signature {}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut t = ser.serialize_tuple(64)?;
        for byte in &self.0 {
            t.serialize_element(byte)?;
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> Visitor<'de> for SigVisitor {
            type Value = Signature;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("64-byte Ed25519 signature")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Signature, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(Signature(out))
            }
        }
        de.deserialize_tuple(64, SigVisitor)
    }
}
