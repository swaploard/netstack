//! Loopback device — all transmitted frames are received back.
//!
//! Used for testing the stack without real hardware.

use std::collections::VecDeque;

use crate::error::{NetError, Result};
use super::Device;

/// A loopback network device.
///
/// Every frame sent via [`Device::send`] is queued internally and
/// returned by the next call to [`Device::recv`]. This allows the full
/// protocol stack to be exercised without any external network.
pub struct LoopbackDevice {
    queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl LoopbackDevice {
    /// Create a new loopback device with the given MTU.
    pub fn new(mtu: usize) -> Self {
        LoopbackDevice {
            queue: VecDeque::new(),
            mtu,
        }
    }

    /// Returns the number of frames currently queued.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

impl Device for LoopbackDevice {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.queue.push_back(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        match self.queue.pop_front() {
            Some(frame) => {
                let len = frame.len().min(buffer.len());
                buffer[..len].copy_from_slice(&frame[..len]);
                Ok(len)
            }
            None => Err(NetError::WouldBlock),
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_send_recv() {
        let mut dev = LoopbackDevice::new(1500);
        let frame = b"hello loopback";
        dev.send(frame).unwrap();
        assert_eq!(dev.pending(), 1);

        let mut buf = [0u8; 64];
        let n = dev.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], frame);
        assert_eq!(dev.pending(), 0);
    }

    #[test]
    fn test_loopback_empty_recv() {
        let mut dev = LoopbackDevice::new(1500);
        let mut buf = [0u8; 64];
        assert_eq!(dev.recv(&mut buf), Err(NetError::WouldBlock));
    }

    #[test]
    fn test_loopback_fifo_order() {
        let mut dev = LoopbackDevice::new(1500);
        dev.send(b"first").unwrap();
        dev.send(b"second").unwrap();

        let mut buf = [0u8; 64];
        let n = dev.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = dev.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"second");
    }
}
