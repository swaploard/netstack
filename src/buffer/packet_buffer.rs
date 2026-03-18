//! A packet buffer with headroom for zero-copy header prepending.
//!
//! Network stacks build packets inside-out: the payload is written first,
//! then transport, network, and link headers are prepended. This buffer
//! reserves headroom at the front so that headers can be prepended without
//! any memmove or reallocation.

use crate::error::{NetError, Result};

/// A byte buffer that supports efficient prepending of protocol headers.
///
/// The buffer is split into three logical regions:
///
/// ```text
///  [ headroom (unused) | header region | payload region ]
///  0               head             tail              cap
/// ```
///
/// - **Prepend** writes into the headroom region (grows `head` leftward).
/// - **Append** writes into the payload region (grows `tail` rightward).
pub struct PacketBuffer {
    storage: Vec<u8>,
    /// Points to the first byte of data.
    head: usize,
    /// Points to one past the last byte of data.
    tail: usize,
}

impl PacketBuffer {
    /// Create a new packet buffer.
    ///
    /// * `headroom` — bytes reserved at the front for header prepending.
    /// * `capacity` — total byte capacity (including headroom).
    ///
    /// # Panics
    ///
    /// Panics if `headroom >= capacity`.
    pub fn new(headroom: usize, capacity: usize) -> Self {
        assert!(headroom < capacity, "headroom must be less than capacity");
        PacketBuffer {
            storage: vec![0u8; capacity],
            head: headroom,
            tail: headroom,
        }
    }

    /// Create a packet buffer from existing payload data.
    ///
    /// Reserves `headroom` bytes before the payload for header prepending.
    pub fn from_payload(headroom: usize, payload: &[u8]) -> Self {
        let capacity = headroom + payload.len();
        let mut storage = vec![0u8; capacity];
        storage[headroom..].copy_from_slice(payload);
        PacketBuffer {
            storage,
            head: headroom,
            tail: capacity,
        }
    }

    /// Prepend `data` into the headroom region.
    ///
    /// This is used to prepend protocol headers (e.g. TCP → IP → Ethernet)
    /// without copying the payload.
    pub fn prepend(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.head {
            return Err(NetError::BufferFull);
        }
        self.head -= data.len();
        self.storage[self.head..self.head + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Append `data` to the end of the buffer.
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        if self.tail + data.len() > self.storage.len() {
            return Err(NetError::BufferFull);
        }
        self.storage[self.tail..self.tail + data.len()].copy_from_slice(data);
        self.tail += data.len();
        Ok(())
    }

    /// Returns a slice over the current data (headers + payload).
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.head..self.tail]
    }

    /// Returns a mutable slice over the current data.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.head..self.tail]
    }

    /// The number of data bytes currently in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    /// Returns `true` if the buffer contains no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Remaining headroom available for prepending.
    #[inline]
    pub fn headroom(&self) -> usize {
        self.head
    }

    /// Remaining space available for appending.
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.storage.len() - self.tail
    }

    /// Reset the buffer, restoring headroom to a given value.
    pub fn reset(&mut self, headroom: usize) {
        assert!(headroom < self.storage.len());
        self.head = headroom;
        self.tail = headroom;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_read() {
        let mut buf = PacketBuffer::new(14, 100); // 14 bytes headroom for Ethernet
        buf.append(b"Hello, TCP!").unwrap();
        assert_eq!(buf.as_slice(), b"Hello, TCP!");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn test_prepend_header() {
        let mut buf = PacketBuffer::new(34, 100); // headroom for ETH(14)+IP(20)
        buf.append(b"payload").unwrap();

        // Simulate prepending an IP header (20 bytes)
        let ip_header = [0u8; 20];
        buf.prepend(&ip_header).unwrap();
        assert_eq!(buf.len(), 20 + 7);

        // Simulate prepending an Ethernet header (14 bytes)
        let eth_header = [0u8; 14];
        buf.prepend(&eth_header).unwrap();
        assert_eq!(buf.len(), 14 + 20 + 7);
        assert_eq!(buf.headroom(), 0);
    }

    #[test]
    fn test_prepend_overflow() {
        let mut buf = PacketBuffer::new(2, 10);
        assert_eq!(buf.prepend(&[1, 2, 3]), Err(NetError::BufferFull));
    }

    #[test]
    fn test_from_payload() {
        let buf = PacketBuffer::from_payload(20, b"data");
        assert_eq!(buf.as_slice(), b"data");
        assert_eq!(buf.headroom(), 20);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn test_reset() {
        let mut buf = PacketBuffer::new(10, 50);
        buf.append(b"some data").unwrap();
        buf.reset(10);
        assert!(buf.is_empty());
        assert_eq!(buf.headroom(), 10);
    }

    #[test]
    #[should_panic]
    fn test_invalid_headroom() {
        let _buf = PacketBuffer::new(100, 100);
    }
}
