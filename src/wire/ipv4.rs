//! IPv4 packet parser and builder (RFC 791).
//!
//! IPv4 header layout (20 bytes minimum, no options):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version|  IHL  |    DSCP/ECN   |         Total Length          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Identification        |Flags|    Fragment Offset      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Time to Live |    Protocol   |       Header Checksum         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Source Address                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Destination Address                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{NetError, Result};
use crate::util::checksum;

/// Minimum IPv4 header length (no options).
pub const MIN_HEADER_LEN: usize = 20;

/// Zero-copy view over an IPv4 packet.
pub struct Ipv4Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Ipv4Packet<T> {
    /// Wrap an existing buffer as an IPv4 packet.
    ///
    /// Validates minimum length and IP version.
    pub fn new(buffer: T) -> Result<Self> {
        {
            let b = buffer.as_ref();
            if b.len() < MIN_HEADER_LEN {
                return Err(NetError::Truncated);
            }
            // Pre-validate version and IHL before moving buffer
            let version = b[0] >> 4;
            if version != 4 {
                return Err(NetError::InvalidHeader);
            }
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if ihl < MIN_HEADER_LEN {
                return Err(NetError::InvalidHeader);
            }
            let total_len = u16::from_be_bytes([b[2], b[3]]) as usize;
            if b.len() < total_len {
                return Err(NetError::Truncated);
            }
        }
        Ok(Ipv4Packet { buffer })
    }

    /// IP version (always 4).
    #[inline]
    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }

    /// Internet Header Length, in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ((self.buffer.as_ref()[0] & 0x0f) as usize) * 4
    }

    /// Type of Service / DSCP + ECN byte.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    /// Total length of the IP packet (header + payload), in bytes.
    #[inline]
    pub fn total_len(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[2], b[3]])
    }

    /// Identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[4], b[5]])
    }

    /// Don't Fragment flag.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.buffer.as_ref()[6] & 0x40 != 0
    }

    /// More Fragments flag.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.buffer.as_ref()[6] & 0x20 != 0
    }

    /// Fragment offset (in 8-byte units).
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[6] & 0x1f, b[7]])
    }

    /// Time To Live.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buffer.as_ref()[8]
    }

    /// Protocol number (6 = TCP, 17 = UDP, 1 = ICMP).
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.buffer.as_ref()[9]
    }

    /// Header checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[10], b[11]])
    }

    /// Source IPv4 address.
    pub fn src_addr(&self) -> [u8; 4] {
        let b = self.buffer.as_ref();
        [b[12], b[13], b[14], b[15]]
    }

    /// Destination IPv4 address.
    pub fn dst_addr(&self) -> [u8; 4] {
        let b = self.buffer.as_ref();
        [b[16], b[17], b[18], b[19]]
    }

    /// Returns the payload (data after the IP header).
    pub fn payload(&self) -> &[u8] {
        let hdr_len = self.header_len();
        let total = self.total_len() as usize;
        &self.buffer.as_ref()[hdr_len..total]
    }

    /// Verify the header checksum.
    pub fn verify_checksum(&self) -> bool {
        let hdr = &self.buffer.as_ref()[..self.header_len()];
        checksum::verify_checksum(hdr)
    }

    /// Consume the wrapper and return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv4Packet<T> {
    /// Set the Time To Live field.
    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer.as_mut()[8] = ttl;
    }

    /// Set the protocol field.
    pub fn set_protocol(&mut self, protocol: u8) {
        self.buffer.as_mut()[9] = protocol;
    }

    /// Set the source address.
    pub fn set_src_addr(&mut self, addr: [u8; 4]) {
        self.buffer.as_mut()[12..16].copy_from_slice(&addr);
    }

    /// Set the destination address.
    pub fn set_dst_addr(&mut self, addr: [u8; 4]) {
        self.buffer.as_mut()[16..20].copy_from_slice(&addr);
    }

    /// Returns a mutable slice over the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let hdr_len = self.header_len();
        let total = self.total_len() as usize;
        &mut self.buffer.as_mut()[hdr_len..total]
    }

    /// Recompute and set the header checksum.
    pub fn fill_checksum(&mut self) {
        // Clear checksum field first
        self.buffer.as_mut()[10] = 0;
        self.buffer.as_mut()[11] = 0;
        let hdr_len = self.header_len();
        let csum = checksum::internet_checksum(&self.buffer.as_ref()[..hdr_len]);
        self.buffer.as_mut()[10] = (csum >> 8) as u8;
        self.buffer.as_mut()[11] = csum as u8;
    }
}

/// Build an IPv4 packet into the given buffer.
///
/// Writes a minimal 20-byte header with the given parameters and copies
/// the payload. Computes and embeds the header checksum.
///
/// Returns the total number of bytes written.
pub fn build_ipv4(
    buffer: &mut [u8],
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    ttl: u8,
    identification: u16,
    payload: &[u8],
) -> Result<usize> {
    let total_len = MIN_HEADER_LEN + payload.len();
    if buffer.len() < total_len {
        return Err(NetError::Truncated);
    }

    // Version (4) + IHL (5) = 0x45
    buffer[0] = 0x45;
    // DSCP/ECN
    buffer[1] = 0;
    // Total length
    buffer[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    // Identification
    buffer[4..6].copy_from_slice(&identification.to_be_bytes());
    // Flags + Fragment offset (Don't Fragment set)
    buffer[6] = 0x40;
    buffer[7] = 0x00;
    // TTL
    buffer[8] = ttl;
    // Protocol
    buffer[9] = protocol;
    // Checksum (initially zero, computed below)
    buffer[10] = 0;
    buffer[11] = 0;
    // Source
    buffer[12..16].copy_from_slice(&src);
    // Destination
    buffer[16..20].copy_from_slice(&dst);
    // Payload
    buffer[MIN_HEADER_LEN..total_len].copy_from_slice(payload);

    // Compute header checksum
    let csum = checksum::internet_checksum(&buffer[..MIN_HEADER_LEN]);
    buffer[10] = (csum >> 8) as u8;
    buffer[11] = csum as u8;

    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse() {
        let mut buf = [0u8; 128];
        let payload = b"Hello, IPv4!";
        let n = build_ipv4(
            &mut buf,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            6,  // TCP
            64,
            0x1234,
            payload,
        )
        .unwrap();

        let pkt = Ipv4Packet::new(&buf[..n]).unwrap();
        assert_eq!(pkt.version(), 4);
        assert_eq!(pkt.header_len(), 20);
        assert_eq!(pkt.total_len(), n as u16);
        assert_eq!(pkt.ttl(), 64);
        assert_eq!(pkt.protocol(), 6);
        assert_eq!(pkt.src_addr(), [10, 0, 0, 1]);
        assert_eq!(pkt.dst_addr(), [10, 0, 0, 2]);
        assert_eq!(pkt.identification(), 0x1234);
        assert!(pkt.dont_fragment());
        assert!(!pkt.more_fragments());
        assert_eq!(pkt.payload(), payload);
        assert!(pkt.verify_checksum());
    }

    #[test]
    fn test_truncated_packet() {
        let buf = [0x45, 0, 0, 40]; // claims 40 bytes but only 4 provided
        assert_eq!(Ipv4Packet::new(&buf[..]).err(), Some(NetError::Truncated));
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = [0u8; 20];
        buf[0] = 0x65; // Version 6
        buf[2] = 0;
        buf[3] = 20;
        assert_eq!(Ipv4Packet::new(&buf[..]).err(), Some(NetError::InvalidHeader));
    }

    #[test]
    fn test_checksum_recompute() {
        let mut buf = [0u8; 64];
        let n = build_ipv4(&mut buf, [192, 168, 1, 1], [192, 168, 1, 2], 17, 128, 1, b"data").unwrap();
        let mut pkt = Ipv4Packet::new(&mut buf[..n]).unwrap();
        pkt.set_ttl(32);
        pkt.fill_checksum();
        assert!(pkt.verify_checksum());
    }
}
