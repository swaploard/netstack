//! A generic fixed-capacity ring buffer.
//!
//! Used internally by TCP for send and receive windows. Supports push,
//! pop, and peek operations. Does not allocate beyond initial capacity.

use crate::error::{NetError, Result};

/// A fixed-capacity circular (ring) buffer.
///
/// Stores elements in a contiguous `Vec<T>` and wraps indices around
/// the capacity boundary. This avoids repeated allocation and is
/// cache-friendly for sequential access patterns.
pub struct RingBuffer<T> {
    storage: Vec<Option<T>>,
    head: usize,
    tail: usize,
    len: usize,
}

impl<T> RingBuffer<T> {
    /// Create a new ring buffer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBuffer capacity must be > 0");
        let mut storage = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            storage.push(None);
        }
        RingBuffer {
            storage,
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Push an element to the back of the buffer.
    pub fn push(&mut self, value: T) -> Result<()> {
        if self.is_full() {
            return Err(NetError::BufferFull);
        }
        self.storage[self.tail] = Some(value);
        self.tail = (self.tail + 1) % self.capacity();
        self.len += 1;
        Ok(())
    }

    /// Pop an element from the front of the buffer.
    pub fn pop(&mut self) -> Result<T> {
        if self.is_empty() {
            return Err(NetError::BufferEmpty);
        }
        let value = self.storage[self.head].take().unwrap();
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
        Ok(value)
    }

    /// Peek at the front element without removing it.
    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            self.storage[self.head].as_ref()
        }
    }

    /// Returns the number of elements currently in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the total capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Returns `true` if the buffer has no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the buffer is at capacity.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.capacity()
    }

    /// Returns the number of free slots remaining.
    #[inline]
    pub fn available(&self) -> usize {
        self.capacity() - self.len
    }

    /// Clear all elements from the buffer.
    pub fn clear(&mut self) {
        while self.pop().is_ok() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_pop() {
        let mut rb = RingBuffer::new(4);
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        rb.push(3).unwrap();
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.pop().unwrap(), 1);
        assert_eq!(rb.pop().unwrap(), 2);
        assert_eq!(rb.pop().unwrap(), 3);
        assert!(rb.is_empty());
    }

    #[test]
    fn test_full_buffer() {
        let mut rb = RingBuffer::new(2);
        rb.push(10).unwrap();
        rb.push(20).unwrap();
        assert!(rb.is_full());
        assert_eq!(rb.push(30), Err(NetError::BufferFull));
    }

    #[test]
    fn test_empty_pop() {
        let mut rb: RingBuffer<u8> = RingBuffer::new(2);
        assert_eq!(rb.pop(), Err(NetError::BufferEmpty));
    }

    #[test]
    fn test_wraparound() {
        let mut rb = RingBuffer::new(3);
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        rb.push(3).unwrap();
        assert_eq!(rb.pop().unwrap(), 1);
        rb.push(4).unwrap(); // wraps around
        assert_eq!(rb.pop().unwrap(), 2);
        assert_eq!(rb.pop().unwrap(), 3);
        assert_eq!(rb.pop().unwrap(), 4);
        assert!(rb.is_empty());
    }

    #[test]
    fn test_peek() {
        let mut rb = RingBuffer::new(4);
        assert!(rb.peek().is_none());
        rb.push(42).unwrap();
        assert_eq!(rb.peek(), Some(&42));
        assert_eq!(rb.len(), 1); // peek should not remove
    }

    #[test]
    fn test_clear() {
        let mut rb = RingBuffer::new(4);
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        rb.clear();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_zero_capacity_panics() {
        let _rb: RingBuffer<u8> = RingBuffer::new(0);
    }
}
