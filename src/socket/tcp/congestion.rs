//! RFC 5681 — TCP Congestion Control Algorithms.
//!
//! Implements:
//! - Slow Start: exponential cwnd growth
//! - Congestion Avoidance: linear cwnd growth
//! - Fast Retransmit: retransmit on 3 duplicate ACKs
//! - Fast Recovery: congestion window adjustment on loss

/// Default Maximum Segment Size in bytes.
pub const DEFAULT_MSS: u32 = 1460;

/// Initial congestion window (2 MSS per RFC 5681 §3.1).
pub const INITIAL_CWND: u32 = DEFAULT_MSS * 2;

/// Slow start threshold initialization (65535 bytes).
pub const INITIAL_SSTHRESH: u32 = 65535;

/// Number of duplicate ACKs before triggering fast retransmit.
pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;

/// TCP congestion control states (RFC 5681).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Connection is starting; cwnd grows exponentially.
    SlowStart,
    /// Normal operating state; cwnd grows linearly.
    CongestionAvoidance,
    /// Recovery phase after loss detection via fast retransmit.
    FastRecovery,
}

/// Manages TCP congestion control per RFC 5681.
///
/// Tracks:
/// - Congestion window (cwnd): bytes we can send without ACK
/// - Slow start threshold (ssthresh): transition point between slow start and congestion avoidance
/// - Bytes in flight (bytes sent but not yet ACKed)
/// - Duplicate ACK counter for fast retransmit detection
/// - Current congestion state
#[derive(Debug)]
pub struct CongestionControl {
    /// Congestion window in bytes.
    cwnd: u32,
    /// Slow start threshold in bytes.
    ssthresh: u32,
    /// Number of bytes sent but not yet acknowledged.
    bytes_in_flight: u32,
    /// Number of duplicate ACKs seen for the current `ack_num`.
    duplicate_ack_count: u32,
    /// Last acknowledged sequence number (for duplicate detection).
    last_acked_seq: u32,
    /// Current congestion control state.
    state: CongestionState,
    /// Maximum Segment Size in bytes.
    mss: u32,
    /// Bytes acknowledged in current RTT (for congestion avoidance).
    ack_bytes_in_cwnd: u32,
}

impl CongestionControl {
    /// Create a new congestion control state with default parameters.
    pub fn new() -> Self {
        CongestionControl {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            bytes_in_flight: 0,
            duplicate_ack_count: 0,
            last_acked_seq: 0,
            state: CongestionState::SlowStart,
            mss: DEFAULT_MSS,
            ack_bytes_in_cwnd: 0,
        }
    }

    /// Create a new congestion control state with custom MSS.
    pub fn with_mss(mss: u32) -> Self {
        CongestionControl {
            cwnd: (mss * 2).max(INITIAL_CWND),
            ssthresh: INITIAL_SSTHRESH,
            bytes_in_flight: 0,
            duplicate_ack_count: 0,
            last_acked_seq: 0,
            state: CongestionState::SlowStart,
            mss,
            ack_bytes_in_cwnd: 0,
        }
    }

    /// Returns the current congestion window in bytes.
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Returns the current slow start threshold.
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Returns the number of bytes currently in flight.
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    /// Returns the current congestion control state.
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Returns the number of bytes available to send (cwnd - bytes_in_flight).
    pub fn available_window(&self) -> u32 {
        if self.bytes_in_flight >= self.cwnd {
            0
        } else {
            self.cwnd - self.bytes_in_flight
        }
    }

    /// Record that `num_bytes` have been transmitted.
    ///
    /// This increases the bytes-in-flight counter. The caller is responsible
    /// for tracking when segments are sent.
    pub fn on_send(&mut self, num_bytes: u32) {
        self.bytes_in_flight = self.bytes_in_flight.wrapping_add(num_bytes);
    }

    /// Process an incoming ACK that acknowledges new data.
    ///
    /// Updates congestion window according to the current state.
    /// Returns `true` if this is a duplicate ACK (for fast retransmit detection).
    pub fn on_ack(&mut self, ack_number: u32, bytes_acked: u32) -> bool {
        // Detect duplicate ACK: same ack_number as before
        if ack_number == self.last_acked_seq {
            self.duplicate_ack_count += 1;
            return true; // This is a duplicate ACK
        }

        // New ACK: reset duplicate counter and advance tracking
        self.last_acked_seq = ack_number;
        self.duplicate_ack_count = 0;

        // Update bytes in flight
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        // Update cwnd based on congestion state
        match self.state {
            CongestionState::SlowStart => self.on_ack_slow_start(bytes_acked),
            CongestionState::CongestionAvoidance => self.on_ack_congestion_avoidance(bytes_acked),
            CongestionState::FastRecovery => self.on_ack_fast_recovery(bytes_acked),
        }

        false // Not a duplicate ACK
    }

    /// Slow Start: increase cwnd by 1 MSS per ACK (exponential growth).
    fn on_ack_slow_start(&mut self, bytes_acked: u32) {
        self.cwnd = self.cwnd.saturating_add(bytes_acked);

        // Transition to Congestion Avoidance when cwnd >= ssthresh
        if self.cwnd >= self.ssthresh {
            self.state = CongestionState::CongestionAvoidance;
            self.ack_bytes_in_cwnd = 0;
        }
    }

    /// Congestion Avoidance: increase cwnd by 1 MSS per RTT (linear growth).
    fn on_ack_congestion_avoidance(&mut self, bytes_acked: u32) {
        // Approximately 1 MSS per RTT: accumulate bytes and grant 1 MSS per cwnd bytes.
        self.ack_bytes_in_cwnd += bytes_acked;
        if self.ack_bytes_in_cwnd >= self.cwnd {
            self.cwnd = self.cwnd.saturating_add(self.mss);
            self.ack_bytes_in_cwnd = 0;
        }
    }

    /// Fast Recovery: increase cwnd by the ACK'd amount (additive).
    ///
    /// This is the "new Reno" behavior: inflate cwnd cautiously during recovery.
    fn on_ack_fast_recovery(&mut self, _bytes_acked: u32) {
        // Increase cwnd slightly to keep data flowing
        self.cwnd = self.cwnd.saturating_add(self.mss);
    }

    /// Detect if we should enter Fast Retransmit.
    ///
    /// Returns `true` if duplicate ACK count has reached the threshold (3).
    pub fn should_fast_retransmit(&self) -> bool {
        self.duplicate_ack_count >= FAST_RETRANSMIT_THRESHOLD
    }

    /// Enter Fast Recovery phase after packet loss is detected.
    ///
    /// Sets ssthresh = cwnd/2 and cwnd = ssthresh + 3*MSS (per RFC 5681 §3.2).
    pub fn on_loss_detected(&mut self) {
        // ssthresh = max(cwnd/2, 2*MSS)
        self.ssthresh = (self.cwnd / 2).max(self.mss * 2);

        // cwnd = ssthresh + 3*MSS (account for the 3 duplicate ACKs)
        self.cwnd = self.ssthresh + self.mss * 3;

        // Enter Fast Recovery
        self.state = CongestionState::FastRecovery;

        // Reset duplicate ACK counter
        self.duplicate_ack_count = 0;
    }

    /// Exit Fast Recovery (called when new ACK advances past recovery point).
    pub fn exit_fast_recovery(&mut self) {
        self.state = CongestionState::CongestionAvoidance;
        self.cwnd = self.ssthresh;
        self.ack_bytes_in_cwnd = 0;
    }

    /// Timeout-based loss: reduce cwnd aggressively (Reno algorithm).
    ///
    /// Sets ssthresh = cwnd/2 and cwnd = 1*MSS, then enters Slow Start.
    pub fn on_retransmit_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mss * 2);
        self.cwnd = self.mss;
        self.state = CongestionState::SlowStart;

        // Half the in-flight count (conservative estimate)
        self.bytes_in_flight = self.bytes_in_flight / 2;
        self.duplicate_ack_count = 0;
    }

    /// Reset congestion control state (for connection close/reset).
    pub fn reset(&mut self) {
        self.cwnd = INITIAL_CWND;
        self.ssthresh = INITIAL_SSTHRESH;
        self.bytes_in_flight = 0;
        self.duplicate_ack_count = 0;
        self.state = CongestionState::SlowStart;
        self.ack_bytes_in_cwnd = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionControl::new();
        assert_eq!(cc.cwnd, INITIAL_CWND);
        assert_eq!(cc.state, CongestionState::SlowStart);
        assert_eq!(cc.bytes_in_flight, 0);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionControl::new();
        assert_eq!(cc.cwnd, INITIAL_CWND);

        // Simulate sending 1 MSS
        cc.on_send(DEFAULT_MSS);
        assert_eq!(cc.bytes_in_flight, DEFAULT_MSS);

        // ACK for that segment: cwnd should increase by 1 MSS
        let was_dup = cc.on_ack(100, DEFAULT_MSS);
        assert!(!was_dup);
        assert_eq!(cc.cwnd, INITIAL_CWND + DEFAULT_MSS);
        assert_eq!(cc.bytes_in_flight, 0);
    }

    #[test]
    fn test_duplicate_ack_detection() {
        let mut cc = CongestionControl::new();
        assert_eq!(cc.duplicate_ack_count, 0);

        // First ACK
        let was_dup = cc.on_ack(100, 0);
        assert!(!was_dup);
        assert_eq!(cc.duplicate_ack_count, 0);

        // Second ACK for same ack_number (duplicate)
        let was_dup = cc.on_ack(100, 0);
        assert!(was_dup);
        assert_eq!(cc.duplicate_ack_count, 1);

        // Third duplicate
        let was_dup = cc.on_ack(100, 0);
        assert!(was_dup);
        assert_eq!(cc.duplicate_ack_count, 2);

        // Fourth duplicate (should trigger fast retransmit at 3)
        let was_dup = cc.on_ack(100, 0);
        assert!(was_dup);
        assert_eq!(cc.duplicate_ack_count, 3);
    }

    #[test]
    fn test_fast_retransmit_threshold() {
        let mut cc = CongestionControl::new();

        // Trigger 3 duplicate ACKs
        cc.on_ack(100, 0);
        cc.on_ack(100, 0);
        cc.on_ack(100, 0);
        cc.on_ack(100, 0); // 4th one; duplicate_ack_count = 3

        assert!(cc.should_fast_retransmit());
    }

    #[test]
    fn test_loss_detection_and_fast_recovery() {
        let mut cc = CongestionControl::new();
        let initial_cwnd = cc.cwnd;

        // Simulate Slow Start: reach some cwnd value
        for _ in 0..5 {
            cc.on_send(DEFAULT_MSS);
            cc.on_ack(100 + DEFAULT_MSS as u32, DEFAULT_MSS);
        }
        let cwnd_before = cc.cwnd;
        assert!(cwnd_before > initial_cwnd);

        // Detect loss
        cc.on_loss_detected();

        // ssthresh should be cwnd/2
        assert_eq!(cc.ssthresh, (cwnd_before / 2).max(DEFAULT_MSS * 2));
        // cwnd should be ssthresh + 3*MSS
        assert_eq!(cc.cwnd, cc.ssthresh + DEFAULT_MSS * 3);
        // Should be in Fast Recovery
        assert_eq!(cc.state, CongestionState::FastRecovery);
    }

    #[test]
    fn test_retransmit_timeout() {
        let mut cc = CongestionControl::new();

        // Send some data and grow cwnd
        let mut ack_num = 1000u32;
        for _ in 0..10 {
            cc.on_send(DEFAULT_MSS);
            cc.on_ack(ack_num, DEFAULT_MSS);
            ack_num = ack_num.wrapping_add(DEFAULT_MSS);
        }

        let cwnd_before = cc.cwnd;
        cc.on_send(DEFAULT_MSS);
        let _bif_before = cc.bytes_in_flight;

        // RTO: aggressive reduction
        cc.on_retransmit_timeout();

        assert_eq!(cc.cwnd, DEFAULT_MSS);
        assert_eq!(cc.state, CongestionState::SlowStart);
        assert!(cc.ssthresh <= cwnd_before / 2 + 1); // Allow for rounding
    }

    #[test]
    fn test_congestion_avoidance() {
        let mut cc = CongestionControl::with_mss(1000);

        // Manually transition to Congestion Avoidance
        cc.state = CongestionState::CongestionAvoidance;
        cc.cwnd = 10000;

        let initial_cwnd = cc.cwnd;

        // ACK half the cwnd: should not increase yet
        cc.on_ack(100, 5000);
        assert_eq!(cc.cwnd, initial_cwnd);

        // ACK another half: should increase by 1 MSS
        cc.on_ack(200, 5000);
        assert_eq!(cc.cwnd, initial_cwnd + 1000);
    }
}
