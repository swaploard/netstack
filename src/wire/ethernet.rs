//! Zero-copy Ethernet II frame parser and builder.
//!
//! Ethernet II frame layout (14-byte header):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Destination MAC (6 bytes)                  |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Source MAC (6 bytes)        |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         EtherType             |          Payload ...           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! ```

use crate::error::{NetError, Result};
use super::mac::MacAddress;
use super::EtherType;

/// Minimum Ethernet frame header size in bytes.
pub const HEADER_LEN: usize = 14;

/// Zero-copy view over an Ethernet II frame.
///
/// The type parameter `T` borrows the underlying buffer, allowing
/// both `&[u8]` (read-only) and `&mut [u8]` (read-write) views.
pub struct EthernetFrame<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> EthernetFrame<T> {
    /// Wrap an existing buffer as an Ethernet frame.
    ///
    /// Returns `Err(Truncated)` if the buffer is shorter than 14 bytes.
    pub fn new(buffer: T) -> Result<Self> {
        if buffer.as_ref().len() < HEADER_LEN {
            return Err(NetError::Truncated);
        }
        Ok(EthernetFrame { buffer })
    }

    /// Returns the destination MAC address.
    pub fn dst_addr(&self) -> MacAddress {
        let b = self.buffer.as_ref();
        MacAddress::new([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    /// Returns the source MAC address.
    pub fn src_addr(&self) -> MacAddress {
        let b = self.buffer.as_ref();
        MacAddress::new([b[6], b[7], b[8], b[9], b[10], b[11]])
    }

    /// Returns the raw EtherType field.
    pub fn ethertype_raw(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[12], b[13]])
    }

    /// Returns the parsed EtherType, if recognized.
    pub fn ethertype(&self) -> Option<EtherType> {
        EtherType::from_u16(self.ethertype_raw())
    }

    /// Returns the frame payload (everything after the 14-byte header).
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[HEADER_LEN..]
    }

    /// Returns the total frame length.
    pub fn total_len(&self) -> usize {
        self.buffer.as_ref().len()
    }

    /// Consume the wrapper and return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EthernetFrame<T> {
    /// Set the destination MAC address.
    pub fn set_dst_addr(&mut self, addr: MacAddress) {
        self.buffer.as_mut()[0..6].copy_from_slice(addr.as_bytes());
    }

    /// Set the source MAC address.
    pub fn set_src_addr(&mut self, addr: MacAddress) {
        self.buffer.as_mut()[6..12].copy_from_slice(addr.as_bytes());
    }

    /// Set the EtherType field.
    pub fn set_ethertype(&mut self, ethertype: EtherType) {
        let bytes = (ethertype as u16).to_be_bytes();
        self.buffer.as_mut()[12..14].copy_from_slice(&bytes);
    }

    /// Returns a mutable slice over the payload region.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[HEADER_LEN..]
    }
}

/// Build an Ethernet frame into a provided buffer.
///
/// Returns the total number of bytes written (header + payload).
pub fn build_frame(
    buffer: &mut [u8],
    dst: MacAddress,
    src: MacAddress,
    ethertype: EtherType,
    payload: &[u8],
) -> Result<usize> {
    let total = HEADER_LEN + payload.len();
    if buffer.len() < total {
        return Err(NetError::Truncated);
    }
    buffer[0..6].copy_from_slice(dst.as_bytes());
    buffer[6..12].copy_from_slice(src.as_bytes());
    buffer[12..14].copy_from_slice(&(ethertype as u16).to_be_bytes());
    buffer[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        let dst = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let src = MacAddress::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        build_frame(&mut buf, dst, src, EtherType::Ipv4, &[0xde, 0xad]).unwrap();
        buf.truncate(HEADER_LEN + 2);
        buf
    }

    #[test]
    fn test_parse_frame() {
        let data = sample_frame();
        let frame = EthernetFrame::new(&data[..]).unwrap();
        assert_eq!(
            frame.dst_addr(),
            MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            frame.src_addr(),
            MacAddress::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        );
        assert_eq!(frame.ethertype(), Some(EtherType::Ipv4));
        assert_eq!(frame.payload(), &[0xde, 0xad]);
    }

    #[test]
    fn test_truncated_frame() {
        let data = [0u8; 10]; // too short
        assert_eq!(EthernetFrame::new(&data[..]).err(), Some(NetError::Truncated));
    }

    #[test]
    fn test_build_roundtrip() {
        let dst = MacAddress::BROADCAST;
        let src = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let payload = b"test payload";
        let mut buf = vec![0u8; 128];
        let n = build_frame(&mut buf, dst, src, EtherType::Arp, payload).unwrap();

        let frame = EthernetFrame::new(&buf[..n]).unwrap();
        assert_eq!(frame.dst_addr(), MacAddress::BROADCAST);
        assert_eq!(frame.ethertype(), Some(EtherType::Arp));
        assert_eq!(frame.payload(), payload);
    }

    #[test]
    fn test_mutable_frame() {
        let mut data = sample_frame();
        let mut frame = EthernetFrame::new(&mut data[..]).unwrap();
        frame.set_ethertype(EtherType::Arp);
        assert_eq!(frame.ethertype(), Some(EtherType::Arp));
    }
}
