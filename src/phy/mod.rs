//! Physical device abstraction layer.
//!
//! Provides the [`Device`] trait that all network interfaces must implement,
//! plus built-in device implementations for testing.

pub mod loopback;

use crate::error::Result;

/// A network device capable of sending and receiving raw frames.
///
/// This is the lowest layer of the stack. Implementations may wrap:
/// - Linux TAP/TUN devices
/// - Raw sockets
/// - Hardware NIC drivers
/// - The built-in [`loopback::LoopbackDevice`]
pub trait Device {
    /// Transmit a raw frame.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Receive a raw frame into `buffer`.
    ///
    /// Returns the number of bytes written to `buffer`, or
    /// [`NetError::WouldBlock`] if no frame is available.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize>;

    /// The maximum transmission unit (MTU) of this device.
    ///
    /// This is the maximum payload size (excluding the link-layer header).
    fn mtu(&self) -> usize;
}
