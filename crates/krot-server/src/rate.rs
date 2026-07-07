//! Per-identity rate limiting (§9).
//!
//! Three orthogonal limits:
//!
//! - **Bandwidth** (bytes/s): a `governor` direct rate-limiter. Data-path
//!   copiers call [`RateLimitState::throttle`] before each read chunk;
//!   `governor` sleeps until the requested number of tokens is
//!   available, which pauses reads and (transitively) engages QUIC
//!   flow-control.
//! - **Period quota** (bytes/period): an [`AtomicU64`] plus a rolling
//!   reset deadline. Every chunk calls [`RateLimitState::charge`], which
//!   increments the counter and, on cap breach, emits a `RateLimit`
//!   frame on the identity's control stream and asks the caller to
//!   close the data stream.
//! - **Concurrent tunnels** — enforced elsewhere (in `session::register`
//!   via `TunnelRegistry::count_owned_by`).
//!
//! Cross-core semantics (§9.2): the bandwidth bucket is per-`SharedState`
//! (which is `Arc`'d across cores) and therefore already shared. The
//! quota counter is a plain `AtomicU64` behind the same `Arc`, so
//! reservation is naturally atomic across worker threads.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use krot_proto::{ServerFrame, TunnelId};

/// The concrete governor type we hold — bytes/s direct limiter.
type BandwidthBucket = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// One time period. Used both for `bw=` (per-second is by far the most
/// common but the grammar accepts anything) and `quota=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Second,
    Minute,
    Hour,
    Day,
    Week,
    /// 30-day accounting period. Matches how most operators think about
    /// monthly bandwidth caps ("500GB/month" ≈ 500 GB per 30 days).
    Month,
}

impl Period {
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        match self {
            Self::Second => Duration::from_secs(1),
            Self::Minute => Duration::from_secs(60),
            Self::Hour => Duration::from_secs(60 * 60),
            Self::Day => Duration::from_secs(24 * 60 * 60),
            Self::Week => Duration::from_secs(7 * 24 * 60 * 60),
            Self::Month => Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

/// Parsed `<n><unit>/<period>` value from `authorized_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatePer {
    pub bytes: u64,
    pub period: Period,
}

impl RatePer {
    /// Convert to bytes-per-second. Fractional seconds round *up* so a
    /// declared cap is never silently exceeded by rounding.
    #[must_use]
    pub fn as_bytes_per_second(self) -> u64 {
        let secs = self.period.as_duration().as_secs().max(1);
        self.bytes.div_ceil(secs)
    }
}

/// Parse `<n><unit>/<period>`, e.g. `50MB/s`, `10GB/day`, `500GB/month`.
///
/// Units are SI base-10 (`KB=1_000`, `MB=1_000_000`, etc.). Base-2
/// (`KiB`, `MiB`, ...) are accepted as an operator convenience.
#[must_use]
pub fn parse_rate_per(s: &str) -> Option<RatePer> {
    let (amount, period) = s.rsplit_once('/')?;
    let period = match period.trim() {
        "s" | "sec" | "second" => Period::Second,
        "m" | "min" | "minute" => Period::Minute,
        "h" | "hr" | "hour" => Period::Hour,
        "d" | "day" => Period::Day,
        "w" | "week" => Period::Week,
        "mo" | "month" => Period::Month,
        _ => return None,
    };
    let bytes = parse_bytes(amount.trim())?;
    Some(RatePer { bytes, period })
}

fn parse_bytes(s: &str) -> Option<u64> {
    // Split off the numeric prefix.
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().ok()?;
    let mul: u64 = match unit.trim() {
        "" | "B" => 1,
        "KB" | "kB" => 1_000,
        "KiB" => 1_024,
        "MB" => 1_000_000,
        "MiB" => 1_024 * 1_024,
        "GB" => 1_000_000_000,
        "GiB" => 1_024 * 1_024 * 1_024,
        "TB" => 1_000_000_000_000,
        "TiB" => 1_024_u64.pow(4),
        _ => return None,
    };
    n.checked_mul(mul)
}

/// A charge outcome from [`RateLimitState::charge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// The bytes were counted and the caller may proceed.
    Ok,
    /// The period quota is exhausted; the caller MUST close the stream
    /// and stop reading. A `RateLimit` frame has been scheduled for
    /// delivery on the control stream (if a sender is attached).
    QuotaExceeded { retry_after_ms: u32 },
}

std::thread_local! {
    /// §9.2 per-core rate-limit partition index. Set once at each
    /// worker thread's startup by [`set_worker_id`]. Single-core
    /// deployments leave it at the default `0`.
    static WORKER_ID: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Called by each worker thread at startup so [`RateLimitState::throttle`]
/// picks the right per-core bucket.
pub fn set_worker_id(id: usize) {
    WORKER_ID.with(|w| w.set(id));
}

/// Current worker index. Zero on threads that never called
/// [`set_worker_id`] — safe default.
#[must_use]
pub fn current_worker_id() -> usize {
    WORKER_ID.with(std::cell::Cell::get)
}

/// Per-identity limits. Cheap to clone (all fields are shared / atomic).
#[derive(Debug)]
pub struct RateLimitState {
    /// §9.2: N bandwidth buckets, one per worker thread. Total
    /// aggregate rate = declared `bw=` cap, with each worker limited
    /// to `bw / N` bytes/s. Under-utilised buckets do NOT lend
    /// tokens to busier peers (spec allows periodic reconciliation
    /// but we take the simpler "static partition" path). `None` when
    /// no `bw=` cap is set.
    ///
    /// A single-core deployment (`n_cores = 1`) collapses to the
    /// pre-§9.2 behaviour: one bucket at the full declared rate.
    bw: Option<Vec<BandwidthBucket>>,
    quota_cap: Option<u64>,
    quota_period: Period,
    quota_used: AtomicU64,
    quota_reset_at: Mutex<Instant>,
    /// mpsc sender back to the identity's live session control loop. On
    /// quota breach a [`ServerFrame::RateLimit`] is queued here; the
    /// session's `select!` forwards it. If no session is currently
    /// live (dangling / not yet resumed) the send is a no-op.
    ctrl_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ServerFrame>>>,
    /// Optional link to the process-wide metrics bag. Bumped on
    /// every [`Charge::QuotaExceeded`]. When `None` (tests) it's a
    /// no-op — the state still works, just doesn't publish counters.
    metrics: Option<Arc<crate::metrics::ServerMetrics>>,
}

impl RateLimitState {
    /// Build a fresh state from an identity's `authorized_keys`
    /// entry. `bw_partitions` is the number of worker threads the
    /// server is running (§9.2 per-core split); passing `1`
    /// preserves the pre-§9.2 single-bucket behaviour.
    #[must_use]
    pub fn from_entry(bw: Option<RatePer>, quota: Option<RatePer>, bw_partitions: usize) -> Self {
        Self::from_entry_with_metrics(bw, quota, bw_partitions, None)
    }

    /// Same as [`Self::from_entry`] but plumbs the process-wide
    /// metrics bag so quota breaches show up on `/admin/v1/metrics`.
    #[must_use]
    pub fn from_entry_with_metrics(
        bw: Option<RatePer>,
        quota: Option<RatePer>,
        bw_partitions: usize,
        metrics: Option<Arc<crate::metrics::ServerMetrics>>,
    ) -> Self {
        let partitions = bw_partitions.max(1);
        let bw = bw.and_then(|r| {
            let total_bps = r.as_bytes_per_second().min(u64::from(u32::MAX));
            // Split the total rate evenly across workers. Aggregate
            // ceiling stays at `total_bps` (partitions * per_core_bps),
            // matching the declared cap.
            let per_core_bps = (total_bps / partitions as u64).max(1);
            let bps = NonZeroU32::new(per_core_bps as u32)?;
            let mut buckets = Vec::with_capacity(partitions);
            for _ in 0..partitions {
                buckets.push(RateLimiter::direct(Quota::per_second(bps)));
            }
            Some(buckets)
        });
        let (quota_cap, quota_period) = match quota {
            Some(q) => (Some(q.bytes), q.period),
            None => (None, Period::Month),
        };
        Self {
            bw,
            quota_cap,
            quota_period,
            quota_used: AtomicU64::new(0),
            quota_reset_at: Mutex::new(Instant::now() + quota_period.as_duration()),
            ctrl_tx: Mutex::new(None),
            metrics,
        }
    }

    /// Install a fresh control-stream sender. Called at session start,
    /// replacing any leftover sender from a prior session for the same
    /// identity.
    pub fn attach_ctrl(&self, tx: tokio::sync::mpsc::UnboundedSender<ServerFrame>) {
        *self.ctrl_tx.lock().unwrap() = Some(tx);
    }

    /// Detach the current control-stream sender. Called at session end.
    pub fn detach_ctrl(&self) {
        *self.ctrl_tx.lock().unwrap() = None;
    }

    /// Await bandwidth-bucket tokens for `n` bytes, blocking as needed.
    ///
    /// If no `bw=` cap is set this is a no-op. On a multi-worker
    /// runtime the current thread's [`current_worker_id`] picks
    /// which per-core partition to spend tokens against (§9.2).
    pub async fn throttle(&self, n: u32) {
        let Some(buckets) = &self.bw else { return };
        let Some(n) = NonZeroU32::new(n) else { return };
        let idx = current_worker_id() % buckets.len();
        let bw = &buckets[idx];
        // until_n_ready cannot fail when n <= burst; governor sizes the
        // burst to the per-second quota. Larger single-shot reads simply
        // wait as many intervals as needed.
        if let Err(_e) = bw.until_n_ready(n).await {
            // Insufficient burst capacity: fall back to per-token wait
            // by looping. Practically unreachable with our default
            // Quota::per_second which has burst == quota.
            for _ in 0..n.get() {
                bw.until_ready().await;
            }
        }
    }

    /// Account `n` bytes against the period quota. Rolls the counter
    /// over automatically at the reset deadline. On breach a
    /// `RateLimit` frame is queued for the control stream and
    /// [`Charge::QuotaExceeded`] is returned.
    pub fn charge(&self, tunnel_id: TunnelId, n: u64) -> Charge {
        let Some(cap) = self.quota_cap else {
            return Charge::Ok;
        };
        // Roll the counter if the reset instant has passed.
        {
            let mut deadline = self.quota_reset_at.lock().unwrap();
            let now = Instant::now();
            if now >= *deadline {
                self.quota_used.store(0, Ordering::Relaxed);
                *deadline = now + self.quota_period.as_duration();
            }
        }
        let prev = self.quota_used.fetch_add(n, Ordering::Relaxed);
        if prev + n > cap {
            let retry_after_ms = self.retry_after_ms();
            // Notify the session loop. Failure to send (no live
            // session) is fine — nothing observes the queued frame
            // and the data stream is closed anyway.
            if let Some(tx) = self.ctrl_tx.lock().unwrap().as_ref() {
                let _ = tx.send(ServerFrame::RateLimit {
                    tunnel_id: Some(tunnel_id),
                    retry_after_ms,
                });
            }
            if let Some(m) = &self.metrics {
                m.rate_limit_quota_exceeded.fetch_add(1, Ordering::Relaxed);
            }
            return Charge::QuotaExceeded { retry_after_ms };
        }
        Charge::Ok
    }

    /// Bytes currently counted against the period quota. Used by the
    /// §16.4 admin API's `/metrics` endpoint.
    #[must_use]
    pub fn quota_used_snapshot(&self) -> u64 {
        self.quota_used.load(Ordering::Relaxed)
    }

    /// Millis until the current quota period resets. Clamped to
    /// `u32::MAX` to fit `RateLimit.retry_after_ms`.
    #[must_use]
    pub fn retry_after_ms(&self) -> u32 {
        let now = Instant::now();
        let deadline = *self.quota_reset_at.lock().unwrap();
        let d = deadline.saturating_duration_since(now);
        u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
    }
}

/// Bidirectional byte-shovel that meters both directions against a
/// shared [`RateLimitState`]. Each chunk read on either side is
/// (1) throttled against the bandwidth bucket, then (2) charged
/// against the period quota, then (3) forwarded to the peer.
///
/// `first_byte_deadline` enforces §10: if NO byte flows in either
/// direction within the deadline, the streams are dropped and
/// `io::ErrorKind::TimedOut` is returned. Once at least one byte has
/// flowed (in either direction) the deadline no longer applies.
///
/// Returns `(a_to_b, b_to_a)` byte counts. Terminates cleanly on EOF,
/// or with `io::ErrorKind::Other` on quota exhaustion (the peer has
/// already been half-closed).
pub async fn run_metered<A, B>(
    a: A,
    b: B,
    rate: &RateLimitState,
    tunnel_id: TunnelId,
    first_byte_deadline: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use std::sync::atomic::AtomicBool;
    let seen_any = Arc::new(AtomicBool::new(false));
    let (a_r, a_w) = tokio::io::split(a);
    let (b_r, b_w) = tokio::io::split(b);
    let (n_ab, n_ba) = tokio::try_join!(
        shovel(
            a_r,
            b_w,
            rate,
            tunnel_id,
            first_byte_deadline,
            Arc::clone(&seen_any)
        ),
        shovel(
            b_r,
            a_w,
            rate,
            tunnel_id,
            first_byte_deadline,
            Arc::clone(&seen_any)
        ),
    )?;
    Ok((n_ab, n_ba))
}

async fn shovel<R, W>(
    mut r: R,
    mut w: W,
    rate: &RateLimitState,
    tunnel_id: TunnelId,
    first_byte_deadline: Duration,
    seen_any: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering as AtomicOrdering;
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    let mut first = true;
    loop {
        let n = if first && !seen_any.load(AtomicOrdering::Relaxed) {
            // §10 first-byte deadline — applies only until either
            // direction has moved bytes.
            if let Ok(res) = tokio::time::timeout(first_byte_deadline, r.read(&mut buf)).await {
                res?
            } else if seen_any.load(AtomicOrdering::Relaxed) {
                // Peer direction already saw bytes; retry without
                // deadline.
                r.read(&mut buf).await?
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "data-stream first-byte deadline exceeded",
                ));
            }
        } else {
            r.read(&mut buf).await?
        };
        first = false;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(total);
        }
        seen_any.store(true, AtomicOrdering::Relaxed);
        // Bandwidth throttle first — this awaits token availability.
        rate.throttle(u32::try_from(n).unwrap_or(u32::MAX)).await;
        // Quota check.
        match rate.charge(tunnel_id, n as u64) {
            Charge::Ok => {}
            Charge::QuotaExceeded { retry_after_ms } => {
                debug!(?tunnel_id, retry_after_ms, "quota exceeded, closing stream");
                let _ = w.shutdown().await;
                return Err(io::Error::other("period quota exceeded"));
            }
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krot_proto::TunnelId;

    #[test]
    fn parses_bw() {
        let r = parse_rate_per("50MB/s").unwrap();
        assert_eq!(r.bytes, 50_000_000);
        assert_eq!(r.period, Period::Second);
        assert_eq!(r.as_bytes_per_second(), 50_000_000);
    }

    #[test]
    fn parses_quota() {
        let r = parse_rate_per("500GB/month").unwrap();
        assert_eq!(r.bytes, 500_000_000_000);
        assert_eq!(r.period, Period::Month);
    }

    #[test]
    fn parses_units() {
        assert_eq!(parse_rate_per("1KiB/s").unwrap().bytes, 1024);
        assert_eq!(parse_rate_per("1MiB/s").unwrap().bytes, 1024 * 1024);
        assert_eq!(parse_rate_per("2GB/day").unwrap().bytes, 2_000_000_000);
    }

    #[test]
    fn rejects_bogus() {
        assert!(parse_rate_per("garbage").is_none());
        assert!(parse_rate_per("50MB").is_none());
        assert!(parse_rate_per("50MB/yr").is_none());
    }

    #[test]
    fn quota_exhausts_and_reports_retry() {
        let state = RateLimitState::from_entry(
            None,
            Some(RatePer {
                bytes: 100,
                period: Period::Second,
            }),
            1,
        );
        assert!(matches!(state.charge(TunnelId(1), 60), Charge::Ok));
        // 60 + 60 > 100 — should trip.
        let c = state.charge(TunnelId(1), 60);
        assert!(matches!(c, Charge::QuotaExceeded { .. }), "got {c:?}");
    }

    #[test]
    fn no_quota_is_always_ok() {
        let state = RateLimitState::from_entry(None, None, 1);
        for _ in 0..1000 {
            assert!(matches!(state.charge(TunnelId(1), 1_000_000), Charge::Ok));
        }
    }

    #[test]
    fn bw_partitions_split_evenly() {
        // 4 workers, 400 B/s cap → each worker gets 100 B/s bucket.
        let state = RateLimitState::from_entry(
            Some(RatePer {
                bytes: 400,
                period: Period::Second,
            }),
            None,
            4,
        );
        let Some(buckets) = state.bw.as_ref() else {
            panic!("expected bw buckets");
        };
        assert_eq!(buckets.len(), 4);
    }

    #[test]
    fn bw_partitions_zero_treated_as_one() {
        // Defensive: 0 workers should still produce 1 bucket at full
        // rate rather than divide-by-zero panic.
        let state = RateLimitState::from_entry(
            Some(RatePer {
                bytes: 100,
                period: Period::Second,
            }),
            None,
            0,
        );
        let buckets = state.bw.as_ref().unwrap();
        assert_eq!(buckets.len(), 1);
    }

    #[test]
    fn worker_id_thread_local_isolates() {
        set_worker_id(7);
        assert_eq!(current_worker_id(), 7);
        // A fresh thread starts at 0 (default).
        std::thread::spawn(|| {
            assert_eq!(current_worker_id(), 0);
        })
        .join()
        .unwrap();
        // The setter is scoped to this thread.
        assert_eq!(current_worker_id(), 7);
    }
}
