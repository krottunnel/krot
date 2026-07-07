//! §16.3.4 cross-relay collision detection.
//!
//! When `register_http` runs, the server consults a
//! [`PeerLabelLookup`] to see whether the requested label is already
//! live on any federated peer relay. Two outcomes matter:
//!
//! - **Same identity** on the peer — treat as an "additional
//!   destination" of the same logical tunnel; the local registration
//!   proceeds. The client will surface multiple URLs (§16.3.5).
//! - **Different identity** — reject with `LABEL_UNAVAILABLE`.
//!
//! The lookup itself is pluggable: this trait defines the contract,
//! and the default in-tree implementation is a no-op that always
//! reports "no collision". Real deployments plug in an implementation
//! that queries the peer's §16.4 admin API (`GET /admin/v1/tunnels`)
//! with a pre-provisioned bearer token; that plumbing is operator
//! configuration outside the wire protocol.

use std::sync::Arc;

use async_trait::async_trait;

use krot_proto::PubKey;

/// Outcome of a single-peer lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLookupOutcome {
    /// The peer relay does not have the label registered (or the
    /// lookup implementation gave up — see `Unavailable`).
    NotFound,
    /// The peer has the label, owned by the returned pubkey.
    Found(PubKey),
    /// The peer could not be reached / the lookup timed out. Callers
    /// SHOULD treat this as fail-open (proceed with registration) to
    /// avoid coupling local availability to peer availability.
    Unavailable,
}

/// Contract for the peer-label lookup that `register_http` calls
/// against every peer this identity is federated with.
///
/// Implementations MUST be cheap to `Arc::clone` and safe to call
/// concurrently.
#[async_trait]
pub trait PeerLabelLookup: Send + Sync + std::fmt::Debug {
    /// Ask peer `peer_apex` whether it has `label` registered. Returns
    /// per-peer outcome; the caller aggregates across all peers this
    /// identity is authorized on.
    async fn find_owner(&self, peer_apex: &str, label: &str) -> PeerLookupOutcome;
}

/// Default no-op implementation. Every lookup returns `NotFound`, so
/// no relay ever collides with a peer. Suitable for single-relay
/// deployments and for tests that don't want to mock a peer.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpPeerLookup;

#[async_trait]
impl PeerLabelLookup for NoOpPeerLookup {
    async fn find_owner(&self, _peer_apex: &str, _label: &str) -> PeerLookupOutcome {
        PeerLookupOutcome::NotFound
    }
}

/// Aggregated result of consulting every peer in the caller's
/// federation set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollisionCheck {
    /// No peer reports a collision (or every peer that does reports
    /// the SAME owner as `self_pubkey`). Registration MAY proceed.
    /// `matched_peers` is the list of peers where the same identity
    /// already holds the label — the local relay logs these as
    /// additional destinations.
    Clear { matched_peers: Vec<String> },
    /// At least one peer has the label registered to a different
    /// identity. Reject with `LABEL_UNAVAILABLE`; `first_conflict`
    /// carries the offending peer for the error `detail`.
    Conflict { first_conflict: String },
}

/// Walk every peer in `peers` (intersection of the identity's
/// `federation=` and the server's static peer list) and aggregate the
/// per-peer outcomes into a single [`CollisionCheck`].
pub async fn check_collision(
    lookup: &Arc<dyn PeerLabelLookup>,
    peers: &[String],
    label: &str,
    self_pubkey: &PubKey,
) -> CollisionCheck {
    let mut matched_peers = Vec::new();
    for peer in peers {
        match lookup.find_owner(peer, label).await {
            PeerLookupOutcome::NotFound | PeerLookupOutcome::Unavailable => {}
            PeerLookupOutcome::Found(owner) => {
                if owner == *self_pubkey {
                    matched_peers.push(peer.clone());
                } else {
                    return CollisionCheck::Conflict {
                        first_conflict: peer.clone(),
                    };
                }
            }
        }
    }
    CollisionCheck::Clear { matched_peers }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test fixture: mock lookup driven by a fixed table.
    #[derive(Debug, Default)]
    struct MockLookup {
        by_peer_label: Mutex<HashMap<(String, String), PeerLookupOutcome>>,
    }

    impl MockLookup {
        fn insert(&self, peer: &str, label: &str, outcome: PeerLookupOutcome) {
            self.by_peer_label
                .lock()
                .unwrap()
                .insert((peer.into(), label.into()), outcome);
        }
    }

    #[async_trait]
    impl PeerLabelLookup for MockLookup {
        async fn find_owner(&self, peer: &str, label: &str) -> PeerLookupOutcome {
            self.by_peer_label
                .lock()
                .unwrap()
                .get(&(peer.into(), label.into()))
                .copied()
                .unwrap_or(PeerLookupOutcome::NotFound)
        }
    }

    #[tokio::test]
    async fn no_op_always_clear() {
        let lookup: Arc<dyn PeerLabelLookup> = Arc::new(NoOpPeerLookup);
        let peers = vec!["a".into(), "b".into()];
        let out = check_collision(&lookup, &peers, "svc", &PubKey([1; 32])).await;
        assert_eq!(
            out,
            CollisionCheck::Clear {
                matched_peers: vec![]
            }
        );
    }

    #[tokio::test]
    async fn conflict_on_different_owner() {
        let mock = Arc::new(MockLookup::default());
        mock.insert(
            "a.example",
            "svc",
            PeerLookupOutcome::Found(PubKey([9; 32])),
        );
        let lookup: Arc<dyn PeerLabelLookup> = mock;
        let peers = vec!["a.example".into()];
        let out = check_collision(&lookup, &peers, "svc", &PubKey([1; 32])).await;
        assert_eq!(
            out,
            CollisionCheck::Conflict {
                first_conflict: "a.example".into()
            }
        );
    }

    #[tokio::test]
    async fn same_owner_is_additional_destination() {
        let self_pk = PubKey([1; 32]);
        let mock = Arc::new(MockLookup::default());
        mock.insert("a.example", "svc", PeerLookupOutcome::Found(self_pk));
        mock.insert("b.example", "svc", PeerLookupOutcome::Found(self_pk));
        let lookup: Arc<dyn PeerLabelLookup> = mock;
        let peers = vec!["a.example".into(), "b.example".into()];
        let out = check_collision(&lookup, &peers, "svc", &self_pk).await;
        assert_eq!(
            out,
            CollisionCheck::Clear {
                matched_peers: vec!["a.example".into(), "b.example".into()]
            }
        );
    }

    #[tokio::test]
    async fn unavailable_is_fail_open() {
        let mock = Arc::new(MockLookup::default());
        mock.insert("a.example", "svc", PeerLookupOutcome::Unavailable);
        let lookup: Arc<dyn PeerLabelLookup> = mock;
        let peers = vec!["a.example".into()];
        let out = check_collision(&lookup, &peers, "svc", &PubKey([1; 32])).await;
        assert_eq!(
            out,
            CollisionCheck::Clear {
                matched_peers: vec![]
            }
        );
    }

    #[tokio::test]
    async fn any_conflict_short_circuits() {
        let self_pk = PubKey([1; 32]);
        let other = PubKey([9; 32]);
        let mock = Arc::new(MockLookup::default());
        mock.insert("a.example", "svc", PeerLookupOutcome::Found(self_pk));
        mock.insert("b.example", "svc", PeerLookupOutcome::Found(other));
        // A peer we'd never even reach — `check_collision` must
        // short-circuit on b's conflict.
        mock.insert("c.example", "svc", PeerLookupOutcome::Found(other));
        let lookup: Arc<dyn PeerLabelLookup> = mock;
        let peers = vec!["a.example".into(), "b.example".into(), "c.example".into()];
        let out = check_collision(&lookup, &peers, "svc", &self_pk).await;
        assert_eq!(
            out,
            CollisionCheck::Conflict {
                first_conflict: "b.example".into()
            }
        );
    }
}
