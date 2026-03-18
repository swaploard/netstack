//! UDP datagram parser and builder (RFC 768).
//!
//! UDP header layout (8 bytes):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Length             |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{NetError, Result};
use crate::util::checksum;

/// UDP header length.
pub const HEADER_LEN: usize = 8;

/// Zero-copy view over a UDP datagram.
pub struct UdpPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> UdpPacket<T> {
    /// Wrap an existing buffer as a UDP datagram.
    pub fn new(buffer: T) -> Result<Self> {
        if buffer.as_ref().len() < HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let pkt = UdpPacket { buffer };
        if (pkt.length() as usize) < HEADER_LEN {
            return Err(NetError::InvalidHeader);
        }
        Ok(pkt)
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[2], b[3]])
    }

    /// Total datagram length (header + data), in bytes.
    pub fn length(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[4], b[5]])
    }

    /// Checksum field.
    pub fn checksum(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[6], b[7]])
    }

    /// Returns the payload (data after the 8-byte header).
    pub fn payload(&self) -> &[u8] {
        let len = self.length() as usize;
        let end = len.min(self.buffer.as_ref().len());
        &self.buffer.as_ref()[HEADER_LEN..end]
    }

    /// Verify the UDP checksum using the IPv4 pseudo-header.
    pub fn verify_checksum(&self, src_addr: &[u8; 4], dst_addr: &[u8; 4]) -> bool {
        let len = self.length();
        let pseudo = checksum::pseudo_header_checksum(src_addr, dst_addr, 17, len);
        let data = &self.buffer.as_ref()[..len as usize];
        let raw = data.iter().enumerate().fold(0u32, |acc, (i, _)| {
            if i + 1 < data.len() {
                if i % 2 == 0 {
                    acc + u16::from_be_bytes([data[i], data[i + 1]]) as u32
                } else {
                    acc
                }
            } else if i % 2 == 0 {
                acc + ((data[i] as u32) << 8)
            } else {
                acc
            }
        });
        let combined = checksum::combine_checksums(raw, pseudo);
        // A zero result (after complement) means valid
        combined == 0 || self.checksum() == 0 // checksum 0 means not computed
    }

    /// Consume the wrapper and return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<T> {
    pub fn set_src_port(&mut self, port: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_length(&mut self, length: u16) {
        self.buffer.as_mut()[4..6].copy_from_slice(&length.to_be_bytes());
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[6..8].copy_from_slice(&checksum.to_be_bytes());
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = self.length() as usize;
        let buf_len = self.buffer.as_ref().len();
        let end = len.min(buf_len);
        &mut self.buffer.as_mut()[HEADER_LEN..end]
    }

    /// Compute and set the UDP checksum using the IPv4 pseudo-header.
    pub fn fill_checksum(&mut self, src_addr: &[u8; 4], dst_addr: &[u8; 4]) {
        self.set_checksum(0);
        let len = self.length();
        let pseudo = checksum::pseudo_header_checksum(src_addr, dst_addr, 17, len);
        let data = &self.buffer.as_ref()[..len as usize];
        let csum = checksum::combine_checksums(
            {
                let mut sum = 0u32;
                let mut i = 0;
                while i + 1 < data.len() {
                    sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
                    i += 2;
                }
                if i < data.len() {
                    sum += (data[i] as u32) << 8;
                }
                sum
            },
            pseudo,
        );
        self.set_checksum(if csum == 0 { 0xffff } else { csum });
    }
}

/// Build a UDP datagram into the given buffer.
///
/// Returns the total number of bytes written.
pub fn build_udp(
    buffer: &mut [u8],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
) -> Result<usize> {
    let total = HEADER_LEN + payload.len();
    if buffer.len() < total {
        return Err(NetError::Truncated);
    }

    buffer[0..2].copy_from_slice(&src_port.to_be_bytes());
    buffer[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buffer[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    buffer[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buffer[HEADER_LEN..total].copy_from_slice(payload);

    // Compute checksum
    let mut pkt = UdpPacket::new(&mut buffer[..total])?;
    pkt.fill_checksum(src_addr, dst_addr);

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse() {
        let mut buf = [0u8; 128];
        let payload = b"UDP data";
        let n = build_udp(
            &mut buf,
            12345,
            80,
            payload,
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )
        .unwrap();

        let pkt = UdpPacket::new(&buf[..n]).unwrap();
        assert_eq!(pkt.src_port(), 12345);
        assert_eq!(pkt.dst_port(), 80);
        assert_eq!(pkt.length(), n as u16);
        assert_eq!(pkt.payload(), payload);
        assert_ne!(pkt.checksum(), 0);
    }

    #[test]
    fn test_truncated() {
        let buf = [0u8; 4];
        assert_eq!(UdpPacket::new(&buf[..]).err(), Some(NetError::Truncated));
    }

    #[test]
    fn test_roundtrip_mutable() {
        let mut buf = [0u8; 32];
        let n = build_udp(&mut buf, 1000, 2000, b"test", &[1, 2, 3, 4], &[5, 6, 7, 8]).unwrap();
        let mut pkt = UdpPacket::new(&mut buf[..n]).unwrap();
        pkt.set_src_port(9999);
        assert_eq!(pkt.src_port(), 9999);
    }
}
