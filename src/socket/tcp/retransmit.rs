//! Retransmission Timeout (RTO) estimation and retransmit queue.
//!
//! Implements RFC 6298 (Jacobson/Karels algorithm) for RTT-based RTO
//! calculation, plus a retransmit queue that tracks in-flight segments
//! and supports exponential backoff on timeout.

use crate::time::{Duration, Instant};
use super::connection::TcpSegmentOut;

/// Minimum RTO value (200 ms per RFC 6298 §2.4).
const MIN_RTO: Duration = Duration::from_millis(200);

/// Maximum RTO value (60 seconds).
const MAX_RTO: Duration = Duration::from_secs(60);

/// Initial RTO before any RTT samples (1 second per RFC 6298 §2.1).
const INITIAL_RTO: Duration = Duration::from_secs(1);

/// Maximum number of retransmission attempts before giving up.
const MAX_RETRIES: u32 = 12;

/// Alpha factor for SRTT (1/8), represented as a shift count.
const ALPHA_SHIFT: i64 = 3; // 1/8

/// Beta factor for RTTVAR (1/4), represented as a shift count.
const BETA_SHIFT: i64 = 2; // 1/4

// ── RTO Estimator ────────────────────────────────────────────────

/// Computes the retransmission timeout using the Jacobson/Karels algorithm
/// described in RFC 6298.
///
/// # Algorithm
///
/// On first RTT sample *R*:
///   - SRTT  ← R
///   - RTTVAR ← R / 2
///
/// On subsequent samples:
///   - RTTVAR ← (1 − β) × RTTVAR + β × |SRTT − R|    (β = 1/4)
///   - SRTT  ← (1 − α) × SRTT   + α × R              (α = 1/8)
///
/// RTO = SRTT + max(G, 4 × RTTVAR), clamped to [MIN_RTO, MAX_RTO].
#[derive(Debug)]
pub struct RtoEstimator {
    /// Smoothed round-trip time (milliseconds).
    srtt: Option<i64>,
    /// RTT variance (milliseconds).
    rttvar: i64,
    /// Current computed RTO.
    rto: Duration,
    /// Backed-off RTO used for retransmissions (doubles each time).
    backed_off_rto: Duration,
}

impl RtoEstimator {
    /// Create a new estimator with RFC 6298 defaults.
    pub fn new() -> Self {
        RtoEstimator {
            srtt: None,
            rttvar: 0,
            rto: INITIAL_RTO,
            backed_off_rto: INITIAL_RTO,
        }
    }

    /// Returns the current RTO (the base value, not backed-off).
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns the backed-off RTO (used for retransmit scheduling).
    pub fn backed_off_rto(&self) -> Duration {
        self.backed_off_rto
    }

    /// Feed a new RTT sample into the estimator (RFC 6298 §2).
    ///
    /// Call this only for segments that have **not** been retransmitted
    /// (Karn's algorithm).
    pub fn on_rtt_sample(&mut self, rtt: Duration) {
        let r = rtt.millis();

        match self.srtt {
            None => {
                // First measurement (§2.2)
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                // Subsequent measurements (§2.3)
                let diff = (srtt - r).abs();
                self.rttvar = self.rttvar
                    - (self.rttvar >> BETA_SHIFT)
                    + (diff >> BETA_SHIFT);
                let new_srtt = srtt
                    - (srtt >> ALPHA_SHIFT)
                    + (r >> ALPHA_SHIFT);
                self.srtt = Some(new_srtt);
            }
        }

        self.recompute_rto();
        // Reset backoff on new valid RTT sample
        self.backed_off_rto = self.rto;
    }

    /// Apply exponential backoff: double the backed-off RTO (RFC 6298 §5.5).
    pub fn backoff(&mut self) {
        let doubled = Duration::from_millis(self.backed_off_rto.millis() * 2);
        self.backed_off_rto = clamp_rto(doubled);
    }

    /// Recompute RTO from SRTT and RTTVAR.
    fn recompute_rto(&mut self) {
        if let Some(srtt) = self.srtt {
            // RTO = SRTT + max(G, 4 * RTTVAR)
            // G (clock granularity) is 1 ms in our stack.
            let k_rttvar = self.rttvar * 4;
            let rto_ms = srtt + k_rttvar.max(1);
            self.rto = clamp_rto(Duration::from_millis(rto_ms));
        }
    }
}

/// Clamp an RTO value to [MIN_RTO, MAX_RTO].
fn clamp_rto(d: Duration) -> Duration {
    if d.millis() < MIN_RTO.millis() {
        MIN_RTO
    } else if d.millis() > MAX_RTO.millis() {
        MAX_RTO
    } else {
        d
    }
}

// ── Retransmit Queue ─────────────────────────────────────────────

/// A segment stored in the retransmit queue for potential retransmission.
#[derive(Debug, Clone)]
pub struct RetransmitEntry {
    /// Starting sequence number of the segment payload.
    pub seq_start: u32,
    /// Ending sequence number (exclusive): seq_start + payload_len.
    /// For SYN/FIN, this is seq_start + 1 (they consume one sequence number).
    pub seq_end: u32,
    /// The segment to retransmit.
    pub segment: TcpSegmentOut,
    /// When this entry was first sent (for RTT measurement).
    pub first_sent_at: Instant,
    /// When the retransmit timer was last (re)started.
    pub last_sent_at: Instant,
    /// Number of times this segment has been retransmitted.
    pub retransmit_count: u32,
}

/// Manages in-flight segments awaiting acknowledgement.
///
/// Segments are pushed when sent and removed when acknowledged.
/// The queue supports timeout detection and retransmission with
/// exponential backoff.
#[derive(Debug)]
pub struct RetransmitQueue {
    entries: Vec<RetransmitEntry>,
}

impl RetransmitQueue {
    /// Create an empty retransmit queue.
    pub fn new() -> Self {
        RetransmitQueue {
            entries: Vec::new(),
        }
    }

    /// Push a newly-sent segment into the queue.
    pub fn push(&mut self, entry: RetransmitEntry) {
        self.entries.push(entry);
    }

    /// Returns `true` if there are no in-flight segments.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Acknowledge all data up to `ack_num`.
    ///
    /// Removes fully-acknowledged entries and returns an RTT sample
    /// from the first acknowledged entry that has **not** been
    /// retransmitted (Karn's algorithm: retransmitted segments are
    /// ambiguous and must not be used for RTT measurement).
    pub fn ack_up_to(&mut self, ack_num: u32, now: Instant) -> Option<Duration> {
        let mut rtt_sample = None;

        self.entries.retain(|entry| {
            if wrapping_lte(entry.seq_end, ack_num) {
                // This entry is fully acknowledged.
                // Use it for RTT only if it was never retransmitted.
                if entry.retransmit_count == 0 && rtt_sample.is_none() {
                    rtt_sample = Some(now.duration_since(entry.first_sent_at));
                }
                false // remove
            } else {
                true // keep
            }
        });

        rtt_sample
    }

    /// Returns the `Instant` at which the next retransmission timer fires,
    /// or `None` if the queue is empty.
    pub fn next_timeout(&self, rto: Duration) -> Option<Instant> {
        self.entries
            .first()
            .map(|entry| entry.last_sent_at + rto)
    }

    /// Collect all segments whose retransmission timer has expired.
    ///
    /// For each timed-out entry, the `retransmit_count` is incremented
    /// and `last_sent_at` is reset to `now`.
    ///
    /// Returns `Err(max_retransmit_count)` for entries that exceed
    /// `MAX_RETRIES`, along with any segments that are still retryable.
    pub fn collect_expired(
        &mut self,
        now: Instant,
        rto: Duration,
    ) -> RetransmitResult {
        let mut segments = Vec::new();
        let mut exhausted = false;

        for entry in self.entries.iter_mut() {
            let deadline = entry.last_sent_at + rto;
            if now >= deadline {
                if entry.retransmit_count >= MAX_RETRIES {
                    exhausted = true;
                    break;
                }
                entry.retransmit_count += 1;
                entry.last_sent_at = now;
                segments.push(entry.segment.clone());
            }
        }

        if exhausted {
            RetransmitResult::Exhausted
        } else if segments.is_empty() {
            RetransmitResult::NothingToDo
        } else {
            RetransmitResult::Segments(segments)
        }
    }
}

/// Result of checking the retransmit queue for timed-out segments.
#[derive(Debug)]
pub enum RetransmitResult {
    /// No timers have expired.
    NothingToDo,
    /// One or more segments need retransmission.
    Segments(Vec<TcpSegmentOut>),
    /// A segment has exceeded `MAX_RETRIES` — the connection should be aborted.
    Exhausted,
}

/// Wrapping comparison: `a <= b` in 32-bit sequence-number space.
fn wrapping_lte(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::tcp::flags;

    fn make_segment(seq: u32, payload_len: usize) -> TcpSegmentOut {
        TcpSegmentOut {
            src_port: 50000,
            dst_port: 80,
            seq,
            ack: 0,
            flags: flags::ACK | flags::PSH,
            window: 65535,
            payload: vec![0u8; payload_len],
        }
    }

    fn make_entry(seq: u32, payload_len: usize, sent_at: Instant) -> RetransmitEntry {
        let seg = make_segment(seq, payload_len);
        RetransmitEntry {
            seq_start: seq,
            seq_end: seq.wrapping_add(payload_len as u32),
            segment: seg,
            first_sent_at: sent_at,
            last_sent_at: sent_at,
            retransmit_count: 0,
        }
    }

    // ── RtoEstimator tests ───────────────────────────────────────

    #[test]
    fn test_rto_initial_value() {
        let est = RtoEstimator::new();
        assert_eq!(est.rto().millis(), 1000);
    }

    #[test]
    fn test_rto_first_sample() {
        let mut est = RtoEstimator::new();
        est.on_rtt_sample(Duration::from_millis(100));

        // SRTT = 100, RTTVAR = 50
        // RTO = 100 + max(1, 4*50) = 100 + 200 = 300
        assert_eq!(est.rto().millis(), 300);
    }

    #[test]
    fn test_rto_converges() {
        let mut est = RtoEstimator::new();

        // Feed several roughly equal RTT samples
        for _ in 0..20 {
            est.on_rtt_sample(Duration::from_millis(50));
        }

        // RTO should converge close to 50 + small variance
        let rto = est.rto().millis();
        // With very stable RTTs, RTTVAR approaches 0, so RTO → SRTT + 1
        // But it gets clamped to MIN_RTO (200 ms)
        assert_eq!(rto, 200); // clamped to MIN_RTO
    }

    #[test]
    fn test_rto_min_clamp() {
        let mut est = RtoEstimator::new();
        est.on_rtt_sample(Duration::from_millis(10));
        // Very small RTT → RTO would be small, clamped to MIN_RTO
        assert!(est.rto().millis() >= MIN_RTO.millis());
    }

    #[test]
    fn test_rto_max_clamp() {
        let mut est = RtoEstimator::new();
        // Extremely large RTT
        est.on_rtt_sample(Duration::from_secs(100));
        assert!(est.rto().millis() <= MAX_RTO.millis());
    }

    #[test]
    fn test_backoff() {
        let mut est = RtoEstimator::new();
        assert_eq!(est.backed_off_rto().millis(), 1000);
        est.backoff();
        assert_eq!(est.backed_off_rto().millis(), 2000);
        est.backoff();
        assert_eq!(est.backed_off_rto().millis(), 4000);
    }

    #[test]
    fn test_backoff_clamped_at_max() {
        let mut est = RtoEstimator::new();
        for _ in 0..20 {
            est.backoff();
        }
        assert!(est.backed_off_rto().millis() <= MAX_RTO.millis());
    }

    #[test]
    fn test_rtt_sample_resets_backoff() {
        let mut est = RtoEstimator::new();
        est.backoff();
        est.backoff();
        assert_eq!(est.backed_off_rto().millis(), 4000);

        est.on_rtt_sample(Duration::from_millis(100));
        // After a new RTT sample, backed_off_rto should reset to base RTO
        assert_eq!(est.backed_off_rto().millis(), est.rto().millis());
    }

    // ── RetransmitQueue tests ────────────────────────────────────

    #[test]
    fn test_queue_push_and_empty() {
        let mut q = RetransmitQueue::new();
        assert!(q.is_empty());

        let t0 = Instant::from_millis(0);
        q.push(make_entry(100, 50, t0));
        assert!(!q.is_empty());
    }

    #[test]
    fn test_ack_removes_entries() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(0);

        q.push(make_entry(100, 50, t0)); // seq 100..150
        q.push(make_entry(150, 50, t0)); // seq 150..200

        let now = Instant::from_millis(100);
        // ACK 150 → first entry removed, second kept
        q.ack_up_to(150, now);
        assert!(!q.is_empty());

        // ACK 200 → second entry removed
        q.ack_up_to(200, now);
        assert!(q.is_empty());
    }

    #[test]
    fn test_ack_returns_rtt_sample() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(1000);
        q.push(make_entry(100, 50, t0));

        let now = Instant::from_millis(1080);
        let sample = q.ack_up_to(150, now);
        assert_eq!(sample, Some(Duration::from_millis(80)));
    }

    #[test]
    fn test_karns_algorithm() {
        // Retransmitted segments should not produce RTT samples.
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(1000);
        let mut entry = make_entry(100, 50, t0);
        entry.retransmit_count = 1; // mark as retransmitted
        q.push(entry);

        let now = Instant::from_millis(2000);
        let sample = q.ack_up_to(150, now);
        assert_eq!(sample, None); // no sample due to Karn's algorithm
    }

    #[test]
    fn test_next_timeout() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(5000);
        q.push(make_entry(100, 50, t0));

        let rto = Duration::from_secs(1);
        let deadline = q.next_timeout(rto);
        assert_eq!(deadline, Some(Instant::from_millis(6000)));
    }

    #[test]
    fn test_collect_expired_nothing() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(1000);
        q.push(make_entry(100, 50, t0));

        let rto = Duration::from_secs(1);
        // Check at t=1500 (before deadline)
        let result = q.collect_expired(Instant::from_millis(1500), rto);
        assert!(matches!(result, RetransmitResult::NothingToDo));
    }

    #[test]
    fn test_collect_expired_retransmit() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(1000);
        q.push(make_entry(100, 50, t0));

        let rto = Duration::from_secs(1);
        // Check at t=2000 (at deadline)
        let result = q.collect_expired(Instant::from_millis(2000), rto);
        match result {
            RetransmitResult::Segments(segs) => {
                assert_eq!(segs.len(), 1);
                assert_eq!(segs[0].seq, 100);
            }
            _ => panic!("expected Segments"),
        }
        // retransmit_count should now be 1
        assert_eq!(q.entries[0].retransmit_count, 1);
    }

    #[test]
    fn test_collect_expired_exhausted() {
        let mut q = RetransmitQueue::new();
        let t0 = Instant::from_millis(0);
        let mut entry = make_entry(100, 50, t0);
        entry.retransmit_count = MAX_RETRIES; // already at max
        q.push(entry);

        let rto = Duration::from_secs(1);
        let result = q.collect_expired(Instant::from_millis(1000), rto);
        assert!(matches!(result, RetransmitResult::Exhausted));
    }
}
