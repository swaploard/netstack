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
/// - Recovery sequence number: highest sequence sent when entering fast recovery
/// - Receiver window (rwnd): advertised window from peer (bytes we can send)
/// - RTT tracking for pacing calculations
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
    /// Recovery sequence number (highest seq sent at recovery start, RFC 3782).
    /// Used to detect when recovery ends (partial ACK vs full recovery).
    recovery_seq: u32,
    /// Receiver's advertised window in bytes (from TCP header).
    /// Actual sending window = min(cwnd, rwnd).
    rwnd: u32,
    /// Estimated RTT in milliseconds (for pacing calculations).
    rtt_ms: u32,
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
            recovery_seq: 0,
            rwnd: 65535, // Default initial receiver window
            rtt_ms: 50,  // Default estimated RTT: 50ms
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
            recovery_seq: 0,
            rwnd: 65535, // Default initial receiver window
            rtt_ms: 50,  // Default estimated RTT: 50ms
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

    /// Returns the receiver's advertised window (rwnd).
    pub fn rwnd(&self) -> u32 {
        self.rwnd
    }

    /// Updates the receiver's advertised window from TCP header.
    ///
    /// This represents the bytes the peer is willing to receive.
    pub fn set_rwnd(&mut self, rwnd: u32) {
        self.rwnd = rwnd;
    }

    /// Returns the real sending window: min(cwnd, rwnd).
    ///
    /// This is the actual data we can send considering both congestion control
    /// and the receiver's advertised window (RFC 793 §3.7).
    pub fn sending_window(&self) -> u32 {
        self.cwnd.min(self.rwnd)
    }

    /// Returns the available bytes considering both cwnd and rwnd.
    pub fn available_sending_window(&self) -> u32 {
        let send_window = self.sending_window();
        if self.bytes_in_flight >= send_window {
            0
        } else {
            send_window - self.bytes_in_flight
        }
    }

    /// Returns the estimated RTT in milliseconds.
    pub fn rtt_ms(&self) -> u32 {
        self.rtt_ms
    }

    /// Updates the estimated RTT (typically from RTT samples).
    pub fn set_rtt_ms(&mut self, rtt_ms: u32) {
        // Smooth RTT updates: avoid extreme values
        self.rtt_ms = self.rtt_ms.saturating_mul(3) / 4 + rtt_ms / 4;
        if self.rtt_ms == 0 {
            self.rtt_ms = 1; // Prevent division by zero
        }
    }

    /// Returns the pacing rate in bytes per millisecond.
    ///
    /// Modern TCP uses pacing: send_rate = cwnd / RTT.
    /// This smooths packet transmission to avoid burstiness.
    pub fn pacing_rate(&self) -> u32 {
        // Rate = cwnd / RTT (in bytes/ms, rounded up)
        (self.cwnd + self.rtt_ms - 1) / self.rtt_ms
    }

    /// Returns the recovery sequence number (used in fast recovery).
    pub fn recovery_seq(&self) -> u32 {
        self.recovery_seq
    }

    /// Checks if we're still in recovery (ACK has not yet acknowledged past recovery_seq).
    pub fn is_in_recovery(&self) -> bool {
        self.state == CongestionState::FastRecovery
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
    /// Handles partial ACKs during fast recovery (RFC 3782 — New Reno).
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

        // Handle partial ACKs during fast recovery (RFC 3782 — New Reno)
        if self.state == CongestionState::FastRecovery {
            if ack_number > self.recovery_seq {
                // Full recovery: ACK advanced past recovery point
                self.exit_fast_recovery();
            } else {
                // Partial ACK: new data acknowledged but not past recovery point
                // Retransmit the next segment (implicit in returning, caller handles retransmit)
                // In New Reno, deflate cwnd by bytes acked, then add back 1 MSS
                self.cwnd = self.cwnd.saturating_sub(bytes_acked).saturating_add(self.mss);
                return false;
            }
        }

        // Update cwnd based on congestion state
        match self.state {
            CongestionState::SlowStart => self.on_ack_slow_start(bytes_acked),
            CongestionState::CongestionAvoidance => self.on_ack_congestion_avoidance(bytes_acked),
            CongestionState::FastRecovery => {
                // Fast recovery cwnd update (already handled above for partial ACKs)
                self.on_ack_fast_recovery(bytes_acked)
            }
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
    /// Tracks the recovery sequence number (RFC 3782 — New Reno) for partial ACK detection.
    ///
    /// # Arguments
    /// * `next_seq` - The next sequence number to send (used to mark recovery boundary)
    pub fn on_loss_detected(&mut self, next_seq: u32) {
        // ssthresh = max(cwnd/2, 2*MSS)
        self.ssthresh = (self.cwnd / 2).max(self.mss * 2);

        // cwnd = ssthresh + 3*MSS (account for the 3 duplicate ACKs)
        self.cwnd = self.ssthresh + self.mss * 3;

        // Track recovery boundary (RFC 3782): mark last outstanding sequence
        self.recovery_seq = next_seq.saturating_sub(1);

        // Enter Fast Recovery
        self.state = CongestionState::FastRecovery;

        // Reset duplicate ACK counter
        self.duplicate_ack_count = 0;
    }

    /// Enter Fast Recovery with the current last_acked_seq as recovery reference.
    ///
    /// Use this variant when you don't have the next sequence number available.
    pub fn on_loss_detected_from_ack(&mut self) {
        // Use last_acked_seq as the recovery boundary
        self.on_loss_detected(self.last_acked_seq.wrapping_add(1));
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
        self.recovery_seq = 0;
        self.rwnd = 65535;
        self.rtt_ms = 50;
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
        for i in 0..5 {
            cc.on_send(DEFAULT_MSS);
            cc.on_ack(100 + (i + 1) as u32 * DEFAULT_MSS, DEFAULT_MSS);
        }
        let cwnd_before = cc.cwnd;
        assert!(cwnd_before > initial_cwnd);

        // Detect loss with recovery sequence number
        let next_seq = 1000u32;
        cc.on_loss_detected(next_seq);

        // ssthresh should be cwnd/2
        assert_eq!(cc.ssthresh, (cwnd_before / 2).max(DEFAULT_MSS * 2));
        // cwnd should be ssthresh + 3*MSS
        assert_eq!(cc.cwnd, cc.ssthresh + DEFAULT_MSS * 3);
        // Should be in Fast Recovery
        assert_eq!(cc.state, CongestionState::FastRecovery);
        // Recovery seq should be set
        assert_eq!(cc.recovery_seq, next_seq - 1);
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

    #[test]
    fn test_partial_ack_during_fast_recovery() {
        // RFC 3782 — New Reno: partial ACK detection and handling
        let mut cc = CongestionControl::new();

        // Set up initial state
        cc.state = CongestionState::FastRecovery;
        cc.recovery_seq = 2000; // Recovery boundary
        cc.last_acked_seq = 1500; // Current ACK position
        cc.cwnd = 4000;
        cc.bytes_in_flight = 2000;

        let cwnd_before = cc.cwnd;

        // Partial ACK: advances ack_number but doesn't go past recovery_seq
        let ack_number = 1600; // New ACK < recovery_seq (2000)
        let bytes_acked = 100;
        let was_dup = cc.on_ack(ack_number, bytes_acked);

        assert!(!was_dup);
        assert_eq!(cc.state, CongestionState::FastRecovery); // Still in recovery
        assert_eq!(cc.last_acked_seq, ack_number);
        // Cwnd deflates by bytes_acked and inflates by 1 MSS
        assert_eq!(
            cc.cwnd,
            cwnd_before.saturating_sub(bytes_acked).saturating_add(cc.mss)
        );
    }

    #[test]
    fn test_full_recovery_exit() {
        // When ACK passes recovery_seq, we exit fast recovery
        let mut cc = CongestionControl::new();

        cc.state = CongestionState::FastRecovery;
        cc.recovery_seq = 2000;
        cc.last_acked_seq = 1500;
        cc.cwnd = 4000;
        cc.ssthresh = 2000;
        cc.bytes_in_flight = 500;

        // ACK that goes past recovery_seq
        let ack_number = 2100; // > recovery_seq
        let was_dup = cc.on_ack(ack_number, 600);

        assert!(!was_dup);
        assert_eq!(cc.state, CongestionState::CongestionAvoidance); // Exited recovery
        assert_eq!(cc.cwnd, cc.ssthresh); // cwnd set to ssthresh
    }

    #[test]
    fn test_receiver_window_limiting() {
        let mut cc = CongestionControl::new();

        // Cwnd grows larger than rwnd
        cc.cwnd = 8000;
        cc.set_rwnd(5000); // Peer only wants 5000 bytes

        // sending_window should be the minimum
        assert_eq!(cc.sending_window(), 5000);
        assert_eq!(cc.rwnd(), 5000);

        // available_sending_window accounts for bytes_in_flight
        cc.bytes_in_flight = 2000;
        assert_eq!(cc.available_sending_window(), 3000); // min(8000, 5000) - 2000
    }

    #[test]
    fn test_pacing_rate_calculation() {
        let mut cc = CongestionControl::new();

        // Initial RTT is 50ms
        let initial_rtt = cc.rtt_ms;
        cc.cwnd = 5000;

        // Pacing rate = cwnd / RTT
        let initial_rate = cc.pacing_rate();
        assert!(initial_rate > 0);

        // Set a higher RTT
        cc.set_rtt_ms(100); // 100ms RTT (but smoothed)
        let higher_rtt = cc.rtt_ms;

        // RTT should be smoothed (not directly 100)
        assert!(higher_rtt > initial_rtt);
        assert!(higher_rtt < 100);

        // Higher RTT → lower pacing rate
        let lower_rate = cc.pacing_rate();
        assert!(lower_rate < initial_rate);

        // Larger cwnd → higher pacing rate
        cc.cwnd = 10000;
        let higher_rate = cc.pacing_rate();
        assert!(higher_rate > lower_rate);
    }

    #[test]
    fn test_rtt_smoothing() {
        let mut cc = CongestionControl::new();
        let initial_rtt = cc.rtt_ms;

        // Add a high RTT sample
        cc.set_rtt_ms(200); // 200ms
        let after_high = cc.rtt_ms;

        // Should be smoothed, not directly 200
        // Formula: rtt = rtt * 3/4 + new_rtt / 4
        // Expected: 50 * 3/4 + 200/4 = 37 + 50 = 87
        let expected_high = (initial_rtt * 3) / 4 + 200 / 4;
        assert_eq!(after_high, expected_high);
        assert!(after_high < 200);

        // Add a lower sample to see it decrease
        cc.set_rtt_ms(50);
        let after_low = cc.rtt_ms;

        // With lower sample, weighted average should decrease
        // Expected: 87 * 3/4 + 50/4 = 65 + 12 = 77
        let expected_low = (after_high * 3) / 4 + 50 / 4;
        assert_eq!(after_low, expected_low);
        assert!(after_low < after_high);
    }

    #[test]
    fn test_recovery_sequence_number() {
        let mut cc = CongestionControl::new();

        // Initially, recovery_seq should be 0
        assert_eq!(cc.recovery_seq(), 0);

        // Trigger fast recovery
        let next_seq = 5000u32;
        cc.on_loss_detected(next_seq);

        // recovery_seq should be set to next_seq - 1
        assert_eq!(cc.recovery_seq(), next_seq - 1);
        assert!(cc.is_in_recovery());
    }

    #[test]
    fn test_loss_detected_from_ack() {
        let mut cc = CongestionControl::new();

        // Advance ack to some value
        cc.on_ack(1000, 0);

        // Enter fast recovery using the ack-based method
        cc.on_loss_detected_from_ack();

        assert_eq!(cc.state, CongestionState::FastRecovery);
        // recovery_seq should be approximately 1000 (based on last_acked_seq)
        assert!(cc.recovery_seq >= 999 && cc.recovery_seq <= 1001);
    }
}
