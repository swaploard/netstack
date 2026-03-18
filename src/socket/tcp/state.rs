//! TCP state machine per RFC 793.
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   V
//!                              +---------+            +---------+
//!                              |  LISTEN |            | SYN     |
//!                              +---------+            | SENT    |
//!                    rcv SYN   |     |                +---------+
//!                   ---------- |     |     rcv SYN,ACK  |     |
//!                   snd SYN,ACK/     \     ----------   |     |
//!                              |       \   snd ACK      |     V
//!                              V        \               |  +--------+
//!                          +---------+   \              |  |  ESTAB |
//!                          | SYN     |    \             |  |  LISHED|
//!                          | RCVD    |     \            |  +--------+
//!                          +---------+      \           |
//!                                            \          |
//! ```

use core::fmt;
use crate::error::{NetError, Result};

/// TCP connection states as defined in RFC 793, Section 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// No connection exists.
    Closed,
    /// Waiting for a connection request (passive open).
    Listen,
    /// SYN sent, waiting for SYN-ACK (active open).
    SynSent,
    /// SYN received, SYN-ACK sent, waiting for ACK.
    SynReceived,
    /// Connection is open — data can flow.
    Established,
    /// Local side has sent FIN; waiting for ACK.
    FinWait1,
    /// Local FIN acknowledged; waiting for remote FIN.
    FinWait2,
    /// Remote side has sent FIN; waiting for local close.
    CloseWait,
    /// Both sides have sent FIN; waiting for final ACK.
    Closing,
    /// Waiting for ACK of our FIN (initiated from CloseWait).
    LastAck,
    /// Waiting 2*MSL before fully closing.
    TimeWait,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::Closed       => write!(f, "CLOSED"),
            TcpState::Listen       => write!(f, "LISTEN"),
            TcpState::SynSent      => write!(f, "SYN-SENT"),
            TcpState::SynReceived  => write!(f, "SYN-RECEIVED"),
            TcpState::Established  => write!(f, "ESTABLISHED"),
            TcpState::FinWait1     => write!(f, "FIN-WAIT-1"),
            TcpState::FinWait2     => write!(f, "FIN-WAIT-2"),
            TcpState::CloseWait    => write!(f, "CLOSE-WAIT"),
            TcpState::Closing      => write!(f, "CLOSING"),
            TcpState::LastAck      => write!(f, "LAST-ACK"),
            TcpState::TimeWait     => write!(f, "TIME-WAIT"),
        }
    }
}

impl TcpState {
    /// Returns `true` if data can be sent in this state.
    pub fn can_send(&self) -> bool {
        matches!(self, TcpState::Established | TcpState::CloseWait)
    }

    /// Returns `true` if data can be received in this state.
    pub fn can_recv(&self) -> bool {
        matches!(
            self,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        )
    }

    /// Returns `true` if the connection is in a synchronized state
    /// (i.e., past the three-way handshake).
    pub fn is_synchronized(&self) -> bool {
        !matches!(
            self,
            TcpState::Closed | TcpState::Listen | TcpState::SynSent | TcpState::SynReceived
        )
    }

    /// Returns `true` if the connection is fully closed.
    pub fn is_closed(&self) -> bool {
        *self == TcpState::Closed
    }

    /// Validate that a transition from the current state to `next` is legal.
    ///
    /// This enforces the RFC 793 state diagram.
    pub fn validate_transition(&self, next: TcpState) -> Result<()> {
        let valid = match self {
            TcpState::Closed => matches!(next, TcpState::Listen | TcpState::SynSent),
            TcpState::Listen => matches!(next, TcpState::SynReceived | TcpState::SynSent | TcpState::Closed),
            TcpState::SynSent => matches!(next, TcpState::Established | TcpState::SynReceived | TcpState::Closed),
            TcpState::SynReceived => matches!(next, TcpState::Established | TcpState::FinWait1 | TcpState::Closed),
            TcpState::Established => matches!(next, TcpState::FinWait1 | TcpState::CloseWait | TcpState::Closed),
            TcpState::FinWait1 => matches!(next, TcpState::FinWait2 | TcpState::Closing | TcpState::TimeWait | TcpState::Closed),
            TcpState::FinWait2 => matches!(next, TcpState::TimeWait | TcpState::Closed),
            TcpState::CloseWait => matches!(next, TcpState::LastAck | TcpState::Closed),
            TcpState::Closing => matches!(next, TcpState::TimeWait | TcpState::Closed),
            TcpState::LastAck => matches!(next, TcpState::Closed),
            TcpState::TimeWait => matches!(next, TcpState::Closed),
        };

        if valid {
            Ok(())
        } else {
            Err(NetError::InvalidState)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_open_handshake() {
        let s = TcpState::Closed;
        s.validate_transition(TcpState::SynSent).unwrap();

        let s = TcpState::SynSent;
        s.validate_transition(TcpState::Established).unwrap();
    }

    #[test]
    fn test_passive_open_handshake() {
        let s = TcpState::Closed;
        s.validate_transition(TcpState::Listen).unwrap();

        let s = TcpState::Listen;
        s.validate_transition(TcpState::SynReceived).unwrap();

        let s = TcpState::SynReceived;
        s.validate_transition(TcpState::Established).unwrap();
    }

    #[test]
    fn test_active_close() {
        let s = TcpState::Established;
        s.validate_transition(TcpState::FinWait1).unwrap();

        let s = TcpState::FinWait1;
        s.validate_transition(TcpState::FinWait2).unwrap();

        let s = TcpState::FinWait2;
        s.validate_transition(TcpState::TimeWait).unwrap();

        let s = TcpState::TimeWait;
        s.validate_transition(TcpState::Closed).unwrap();
    }

    #[test]
    fn test_passive_close() {
        let s = TcpState::Established;
        s.validate_transition(TcpState::CloseWait).unwrap();

        let s = TcpState::CloseWait;
        s.validate_transition(TcpState::LastAck).unwrap();

        let s = TcpState::LastAck;
        s.validate_transition(TcpState::Closed).unwrap();
    }

    #[test]
    fn test_simultaneous_close() {
        let s = TcpState::FinWait1;
        s.validate_transition(TcpState::Closing).unwrap();

        let s = TcpState::Closing;
        s.validate_transition(TcpState::TimeWait).unwrap();
    }

    #[test]
    fn test_invalid_transitions() {
        assert_eq!(
            TcpState::Closed.validate_transition(TcpState::Established),
            Err(NetError::InvalidState)
        );
        assert_eq!(
            TcpState::Listen.validate_transition(TcpState::Established),
            Err(NetError::InvalidState)
        );
        assert_eq!(
            TcpState::Established.validate_transition(TcpState::Listen),
            Err(NetError::InvalidState)
        );
    }

    #[test]
    fn test_can_send_recv() {
        assert!(TcpState::Established.can_send());
        assert!(TcpState::Established.can_recv());
        assert!(TcpState::CloseWait.can_send());
        assert!(!TcpState::CloseWait.can_recv());
        assert!(!TcpState::SynSent.can_send());
        assert!(!TcpState::Closed.can_send());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", TcpState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", TcpState::SynSent), "SYN-SENT");
    }
}
