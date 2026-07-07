//! Ed25519 challenge-response helpers (§7.1).
//!
//! The domain separator [`AUTH_DOMAIN_SEPARATOR`] is prefixed to the
//! server-provided nonce before signing. Both sides MUST include it or
//! the verification will fail; this prevents a signature produced for a
//! different KROT-version challenge from being reused here.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::ids::{Nonce, PubKey, Signature};

/// Domain-separation prefix hashed into every authentication signature.
///
/// The trailing NUL byte is significant: it terminates the version tag and
/// prevents ambiguity if future revisions extend the label.
pub const AUTH_DOMAIN_SEPARATOR: &[u8] = b"krot-auth-v1\0";

fn signing_payload(nonce: &Nonce) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AUTH_DOMAIN_SEPARATOR.len() + nonce.0.len());
    buf.extend_from_slice(AUTH_DOMAIN_SEPARATOR);
    buf.extend_from_slice(&nonce.0);
    buf
}

/// Sign an authentication challenge using the client's private key.
pub fn sign_challenge(key: &SigningKey, nonce: &Nonce) -> Signature {
    let sig = key.sign(&signing_payload(nonce));
    Signature(sig.to_bytes())
}

/// Verify an authentication challenge signature.
///
/// Returns `true` iff `signature` was produced by the private key matching
/// `pubkey` over the domain-separated `nonce`.
pub fn verify_challenge(pubkey: &PubKey, nonce: &Nonce, signature: &Signature) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&pubkey.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
    vk.verify(&signing_payload(nonce), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn sign_then_verify_ok() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let pk = PubKey(sk.verifying_key().to_bytes());
        let nonce = Nonce([7u8; 32]);
        let sig = sign_challenge(&sk, &nonce);
        assert!(verify_challenge(&pk, &nonce, &sig));
    }

    #[test]
    fn tampered_nonce_rejected() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let pk = PubKey(sk.verifying_key().to_bytes());
        let sig = sign_challenge(&sk, &Nonce([1u8; 32]));
        assert!(!verify_challenge(&pk, &Nonce([2u8; 32]), &sig));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let mut rng = OsRng;
        let sk_a = SigningKey::generate(&mut rng);
        let sk_b = SigningKey::generate(&mut rng);
        let nonce = Nonce([0xABu8; 32]);
        let sig = sign_challenge(&sk_a, &nonce);
        let pk_b = PubKey(sk_b.verifying_key().to_bytes());
        assert!(!verify_challenge(&pk_b, &nonce, &sig));
    }
}
