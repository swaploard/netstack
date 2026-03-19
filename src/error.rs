//! Unified error types for the networking stack.

use core::fmt;

/// All errors that can occur within the networking stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// The buffer or packet was shorter than the minimum required length.
    Truncated,
    /// A checksum validation failed.
    BadChecksum,
    /// A header field contained an invalid or unsupported value.
    InvalidHeader,
    /// The protocol is not supported by this stack.
    UnsupportedProtocol,
    /// An internal buffer is full and cannot accept more data.
    BufferFull,
    /// An internal buffer is empty.
    BufferEmpty,
    /// The operation is not valid in the current state.
    InvalidState,
    /// The connection was refused by the remote peer.
    ConnectionRefused,
    /// The connection was reset by the remote peer.
    ConnectionReset,
    /// The requested address is already in use.
    AddressInUse,
    /// No route to the destination address.
    NoRoute,
    /// An ARP resolution is pending for the destination.
    ArpPending,
    /// The operation would block.
    WouldBlock,
    /// The connection timed out (retransmission attempts exhausted).
    TimedOut,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Truncated => write!(f, "packet truncated"),
            NetError::BadChecksum => write!(f, "bad checksum"),
            NetError::InvalidHeader => write!(f, "invalid header"),
            NetError::UnsupportedProtocol => write!(f, "unsupported protocol"),
            NetError::BufferFull => write!(f, "buffer full"),
            NetError::BufferEmpty => write!(f, "buffer empty"),
            NetError::InvalidState => write!(f, "invalid state for operation"),
            NetError::ConnectionRefused => write!(f, "connection refused"),
            NetError::ConnectionReset => write!(f, "connection reset"),
            NetError::AddressInUse => write!(f, "address in use"),
            NetError::NoRoute => write!(f, "no route to host"),
            NetError::ArpPending => write!(f, "ARP resolution pending"),
            NetError::WouldBlock => write!(f, "operation would block"),
            NetError::TimedOut => write!(f, "connection timed out"),
        }
    }
}

impl std::error::Error for NetError {}

/// Convenience type alias used throughout the crate.
pub type Result<T> = core::result::Result<T, NetError>;
