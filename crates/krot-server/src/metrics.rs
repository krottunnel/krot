//! Process-wide counters and gauges exposed on `/admin/v1/metrics`
//! in Prometheus text-exposition format (§16.4).
//!
//! Hand-rolled `AtomicU64`/`AtomicUsize` bags — no `prometheus`
//! crate dep. Matches the codebase's "hand-rolled where reasonable"
//! philosophy and keeps the binary lean.
//!
//! ## Semantics
//!
//! All counters are monotonically-increasing `u64`s that never reset
//! at runtime. Rate calculations are the scrape client's job.
//! Gauges (`tunnels_live`, `tunnels_dangling`) are computed on each
//! scrape from [`crate::registry::TunnelRegistry::snapshot`] and
//! per-identity `RateLimitState`s — the metrics module doesn't
//! duplicate that state.

use std::sync::atomic::{AtomicU64, Ordering};

/// Every process-lifetime counter exposed to Prometheus.
#[derive(Debug, Default)]
pub struct ServerMetrics {
    // ---- Handshake outcomes (§7.1) ----
    pub handshake_auth_ok: AtomicU64,
    /// Unknown pubkey — not in `authorized_keys`.
    pub handshake_unknown_identity: AtomicU64,
    /// Signature verification failed.
    pub handshake_signature_invalid: AtomicU64,
    /// Handshake exceeded §10 auth deadline (10 s).
    pub handshake_timed_out: AtomicU64,
    /// Protocol violation on the initial stream (unknown StreamKind,
    /// non-Control first frame, etc.).
    pub handshake_protocol_violation: AtomicU64,

    // ---- Enrollment (§14) ----
    pub enrollment_ok: AtomicU64,
    /// Admin token was wrong / expired / already consumed.
    pub enrollment_rejected: AtomicU64,

    // ---- Session outcomes (§7.5, §7.3) ----
    /// Session ended with an explicit client `Bye`.
    pub session_bye: AtomicU64,
    /// Session ended without a `Bye` — abrupt drop, tunnels marked
    /// Dangling for §7.3 grace window.
    pub session_dropped: AtomicU64,
    /// Session terminated by shutdown / revocation / protocol
    /// violation — tunnels removed immediately.
    pub session_terminal: AtomicU64,

    // ---- Session resume (§7.3) ----
    pub resume_reattached: AtomicU64,
    pub resume_identity_mismatch: AtomicU64,
    pub resume_unknown: AtomicU64,

    // ---- Tunnel registration ----
    pub tunnel_registered_http: AtomicU64,
    pub tunnel_registered_tcp: AtomicU64,
    pub tunnel_rejected_label: AtomicU64,
    pub tunnel_rejected_conns: AtomicU64,
    pub tunnel_rejected_ports: AtomicU64,
    pub tunnel_rejected_pool: AtomicU64,
    pub tunnel_rejected_peer_collision: AtomicU64,

    // ---- Rate limits (§9) ----
    /// Number of times a data-path chunk tripped the period-quota
    /// counter and got a `RateLimit` frame sent to the identity.
    pub rate_limit_quota_exceeded: AtomicU64,

    // ---- Transport split (§16.1) ----
    /// QUIC (`krot/1`) connections handed to `handle_connection`.
    pub transport_quic_accepted: AtomicU64,
    /// `krot-tcp/1` connections handed to `handle_connection`
    /// (either via the dedicated fallback listener or the HTTPS
    /// ALPN dispatcher).
    pub transport_tcp_fallback_accepted: AtomicU64,

    // ---- Admin API (§16.4) ----
    pub admin_api_session_minted: AtomicU64,
    pub admin_api_session_rejected: AtomicU64,
    pub admin_api_key_appended: AtomicU64,
    pub admin_api_key_removed: AtomicU64,
    pub admin_api_key_remove_not_found: AtomicU64,
    /// Unauthenticated hits (missing header, bad token, expired session).
    pub admin_api_auth_failed: AtomicU64,

    /// UNIX epoch second the server started. Emitted as a gauge so
    /// dashboards can plot uptime.
    pub process_start_unix_secs: AtomicU64,
}

impl ServerMetrics {
    /// Build the metrics bag. Records the current wall-clock time so
    /// `krot_uptime_seconds` on scrape can compute an elapsed value.
    #[must_use]
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let m = Self::default();
        m.process_start_unix_secs.store(now, Ordering::Relaxed);
        m
    }

    /// Read one atomic. Wrapper for ergonomics.
    #[inline]
    fn get(a: &AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }

    /// Prometheus text exposition of every field on `self`, plus the
    /// two callsite-provided gauges (`tunnels_live`, `tunnels_dangling`)
    /// and the aggregate `bytes_period_used` per-identity map.
    #[must_use]
    pub fn to_prometheus_text(
        &self,
        tunnels_live: usize,
        tunnels_dangling: usize,
        per_identity_bytes: &[(String, u64)],
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let uptime = now.saturating_sub(Self::get(&self.process_start_unix_secs));

        let mut out = String::new();

        // ---- Uptime / build info ----
        out.push_str("# HELP krot_uptime_seconds Seconds since the server process started.\n");
        out.push_str("# TYPE krot_uptime_seconds gauge\n");
        out.push_str(&format!("krot_uptime_seconds {uptime}\n"));

        out.push_str(
            "# HELP krot_build_info Static build metadata as labels; value is always 1.\n",
        );
        out.push_str("# TYPE krot_build_info gauge\n");
        out.push_str(&format!(
            "krot_build_info{{version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION"),
        ));

        // ---- Tunnels (live / dangling) ----
        out.push_str(
            "# HELP krot_tunnels_total Tunnels currently in the registry (live + dangling).\n",
        );
        out.push_str("# TYPE krot_tunnels_total gauge\n");
        out.push_str(&format!(
            "krot_tunnels_total {}\n",
            tunnels_live + tunnels_dangling
        ));
        out.push_str(
            "# HELP krot_tunnels_dangling_total Dangling tunnels in the §7.3 grace window.\n",
        );
        out.push_str("# TYPE krot_tunnels_dangling_total gauge\n");
        out.push_str(&format!("krot_tunnels_dangling_total {tunnels_dangling}\n"));

        // ---- Handshake outcomes ----
        counter(
            &mut out,
            "krot_handshake_auth_ok_total",
            "Successful `AuthOk` responses (§7.1).",
            Self::get(&self.handshake_auth_ok),
        );
        counter(
            &mut out,
            "krot_handshake_unknown_identity_total",
            "Handshakes rejected because the presented pubkey is not in authorized_keys.",
            Self::get(&self.handshake_unknown_identity),
        );
        counter(
            &mut out,
            "krot_handshake_signature_invalid_total",
            "Handshakes rejected due to bad Ed25519 signature.",
            Self::get(&self.handshake_signature_invalid),
        );
        counter(
            &mut out,
            "krot_handshake_timed_out_total",
            "Handshakes that exceeded the §10 auth deadline.",
            Self::get(&self.handshake_timed_out),
        );
        counter(
            &mut out,
            "krot_handshake_protocol_violation_total",
            "First-stream protocol violations (unknown StreamKind, etc.).",
            Self::get(&self.handshake_protocol_violation),
        );

        // ---- Enrollment ----
        counter(
            &mut out,
            "krot_enrollment_ok_total",
            "Successful enrollments (§14).",
            Self::get(&self.enrollment_ok),
        );
        counter(
            &mut out,
            "krot_enrollment_rejected_total",
            "Enrollments rejected (bad / expired / consumed admin token).",
            Self::get(&self.enrollment_rejected),
        );

        // ---- Session outcomes ----
        counter(
            &mut out,
            "krot_session_bye_total",
            "Sessions that ended with an explicit client `Bye` (§7.5).",
            Self::get(&self.session_bye),
        );
        counter(
            &mut out,
            "krot_session_dropped_total",
            "Sessions that ended without a `Bye` — tunnels marked Dangling.",
            Self::get(&self.session_dropped),
        );
        counter(
            &mut out,
            "krot_session_terminal_total",
            "Sessions terminated by shutdown / revocation / protocol violation.",
            Self::get(&self.session_terminal),
        );

        // ---- Resume ----
        counter(
            &mut out,
            "krot_resume_reattached_total",
            "Successful §7.3 resume — same tunnel_id reused.",
            Self::get(&self.resume_reattached),
        );
        counter(
            &mut out,
            "krot_resume_identity_mismatch_total",
            "Resume attempts rejected because the presenting pubkey does not own the lease.",
            Self::get(&self.resume_identity_mismatch),
        );
        counter(
            &mut out,
            "krot_resume_unknown_total",
            "Resume attempts against expired / never-registered leases.",
            Self::get(&self.resume_unknown),
        );

        // ---- Tunnel registration ----
        counter(
            &mut out,
            "krot_tunnel_registered_http_total",
            "HTTP tunnels successfully registered.",
            Self::get(&self.tunnel_registered_http),
        );
        counter(
            &mut out,
            "krot_tunnel_registered_tcp_total",
            "TCP tunnels successfully registered.",
            Self::get(&self.tunnel_registered_tcp),
        );
        counter(
            &mut out,
            "krot_tunnel_rejected_label_total",
            "Tunnels rejected because the requested label is forbidden or already taken.",
            Self::get(&self.tunnel_rejected_label),
        );
        counter(
            &mut out,
            "krot_tunnel_rejected_conns_total",
            "Tunnels rejected by the §13 `conns=` cap.",
            Self::get(&self.tunnel_rejected_conns),
        );
        counter(
            &mut out,
            "krot_tunnel_rejected_ports_total",
            "Tunnels rejected by the §13 `ports=` allowlist.",
            Self::get(&self.tunnel_rejected_ports),
        );
        counter(
            &mut out,
            "krot_tunnel_rejected_pool_total",
            "Tunnels rejected because the TCP port pool was exhausted.",
            Self::get(&self.tunnel_rejected_pool),
        );
        counter(
            &mut out,
            "krot_tunnel_rejected_peer_collision_total",
            "Tunnels rejected by §16.3.4 cross-relay collision detection.",
            Self::get(&self.tunnel_rejected_peer_collision),
        );

        // ---- Rate limits ----
        counter(
            &mut out,
            "krot_rate_limit_quota_exceeded_total",
            "Data-path chunks that tripped the §9 period quota.",
            Self::get(&self.rate_limit_quota_exceeded),
        );

        // ---- Transport split ----
        counter(
            &mut out,
            "krot_transport_quic_accepted_total",
            "QUIC (`krot/1`) connections that reached handle_connection.",
            Self::get(&self.transport_quic_accepted),
        );
        counter(
            &mut out,
            "krot_transport_tcp_fallback_accepted_total",
            "`krot-tcp/1` connections that reached handle_connection.",
            Self::get(&self.transport_tcp_fallback_accepted),
        );

        // ---- Admin API ----
        counter(
            &mut out,
            "krot_admin_api_session_minted_total",
            "Sessions minted via POST /admin/v1/session.",
            Self::get(&self.admin_api_session_minted),
        );
        counter(
            &mut out,
            "krot_admin_api_session_rejected_total",
            "POST /session calls rejected — bad admin token.",
            Self::get(&self.admin_api_session_rejected),
        );
        counter(
            &mut out,
            "krot_admin_api_key_appended_total",
            "authorized_keys entries appended via POST /admin/v1/keys.",
            Self::get(&self.admin_api_key_appended),
        );
        counter(
            &mut out,
            "krot_admin_api_key_removed_total",
            "authorized_keys entries removed via DELETE /admin/v1/keys/*.",
            Self::get(&self.admin_api_key_removed),
        );
        counter(
            &mut out,
            "krot_admin_api_key_remove_not_found_total",
            "DELETE /admin/v1/keys/* against a pubkey that isn't present.",
            Self::get(&self.admin_api_key_remove_not_found),
        );
        counter(
            &mut out,
            "krot_admin_api_auth_failed_total",
            "Unauthenticated hits to the admin API.",
            Self::get(&self.admin_api_auth_failed),
        );

        // ---- Per-identity bytes ----
        out.push_str(
            "# HELP krot_bytes_period_used Bytes counted against the identity's period quota.\n",
        );
        out.push_str("# TYPE krot_bytes_period_used counter\n");
        for (pubkey_b64, used) in per_identity_bytes {
            out.push_str(&format!(
                "krot_bytes_period_used{{pubkey=\"{pubkey_b64}\"}} {used}\n"
            ));
        }

        out
    }
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    out.push_str(&format!("{name} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_atomic_counter_is_serialised() {
        // Bump every field so a scrape reflects real activity.
        let m = ServerMetrics::new();
        m.handshake_auth_ok.fetch_add(1, Ordering::Relaxed);
        m.handshake_unknown_identity.fetch_add(2, Ordering::Relaxed);
        m.handshake_signature_invalid
            .fetch_add(3, Ordering::Relaxed);
        m.handshake_timed_out.fetch_add(4, Ordering::Relaxed);
        m.handshake_protocol_violation
            .fetch_add(5, Ordering::Relaxed);
        m.enrollment_ok.fetch_add(6, Ordering::Relaxed);
        m.enrollment_rejected.fetch_add(7, Ordering::Relaxed);
        m.session_bye.fetch_add(8, Ordering::Relaxed);
        m.session_dropped.fetch_add(9, Ordering::Relaxed);
        m.session_terminal.fetch_add(10, Ordering::Relaxed);
        m.resume_reattached.fetch_add(11, Ordering::Relaxed);
        m.resume_identity_mismatch.fetch_add(12, Ordering::Relaxed);
        m.resume_unknown.fetch_add(13, Ordering::Relaxed);
        m.tunnel_registered_http.fetch_add(14, Ordering::Relaxed);
        m.tunnel_registered_tcp.fetch_add(15, Ordering::Relaxed);
        m.tunnel_rejected_label.fetch_add(16, Ordering::Relaxed);
        m.tunnel_rejected_conns.fetch_add(17, Ordering::Relaxed);
        m.tunnel_rejected_ports.fetch_add(18, Ordering::Relaxed);
        m.tunnel_rejected_pool.fetch_add(19, Ordering::Relaxed);
        m.tunnel_rejected_peer_collision
            .fetch_add(20, Ordering::Relaxed);
        m.rate_limit_quota_exceeded.fetch_add(21, Ordering::Relaxed);
        m.transport_quic_accepted.fetch_add(22, Ordering::Relaxed);
        m.transport_tcp_fallback_accepted
            .fetch_add(23, Ordering::Relaxed);
        m.admin_api_session_minted.fetch_add(24, Ordering::Relaxed);
        m.admin_api_session_rejected
            .fetch_add(25, Ordering::Relaxed);
        m.admin_api_key_appended.fetch_add(26, Ordering::Relaxed);
        m.admin_api_key_removed.fetch_add(27, Ordering::Relaxed);
        m.admin_api_key_remove_not_found
            .fetch_add(28, Ordering::Relaxed);
        m.admin_api_auth_failed.fetch_add(29, Ordering::Relaxed);

        let text = m.to_prometheus_text(3, 1, &[("AAAA==".into(), 999)]);

        // Every value we set should show up on its own line. Grep by
        // suffix so a rename catches this test at the same time as
        // the metric name changes.
        for (name, val) in [
            ("krot_handshake_auth_ok_total", 1),
            ("krot_handshake_unknown_identity_total", 2),
            ("krot_handshake_signature_invalid_total", 3),
            ("krot_handshake_timed_out_total", 4),
            ("krot_handshake_protocol_violation_total", 5),
            ("krot_enrollment_ok_total", 6),
            ("krot_enrollment_rejected_total", 7),
            ("krot_session_bye_total", 8),
            ("krot_session_dropped_total", 9),
            ("krot_session_terminal_total", 10),
            ("krot_resume_reattached_total", 11),
            ("krot_resume_identity_mismatch_total", 12),
            ("krot_resume_unknown_total", 13),
            ("krot_tunnel_registered_http_total", 14),
            ("krot_tunnel_registered_tcp_total", 15),
            ("krot_tunnel_rejected_label_total", 16),
            ("krot_tunnel_rejected_conns_total", 17),
            ("krot_tunnel_rejected_ports_total", 18),
            ("krot_tunnel_rejected_pool_total", 19),
            ("krot_tunnel_rejected_peer_collision_total", 20),
            ("krot_rate_limit_quota_exceeded_total", 21),
            ("krot_transport_quic_accepted_total", 22),
            ("krot_transport_tcp_fallback_accepted_total", 23),
            ("krot_admin_api_session_minted_total", 24),
            ("krot_admin_api_session_rejected_total", 25),
            ("krot_admin_api_key_appended_total", 26),
            ("krot_admin_api_key_removed_total", 27),
            ("krot_admin_api_key_remove_not_found_total", 28),
            ("krot_admin_api_auth_failed_total", 29),
        ] {
            let expected = format!("\n{name} {val}\n");
            assert!(
                text.contains(&expected),
                "missing `{expected}` in scrape:\n{text}"
            );
        }

        // Gauges + per-identity map.
        assert!(text.contains("krot_tunnels_total 4"));
        assert!(text.contains("krot_tunnels_dangling_total 1"));
        assert!(text.contains("krot_bytes_period_used{pubkey=\"AAAA==\"} 999"));
        assert!(text.contains("krot_build_info{version="));
    }
}
