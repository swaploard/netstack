//! TCP segment parser and builder (RFC 793).
//!
//! TCP header layout (20 bytes minimum, no options):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Data  |       |U|A|P|R|S|F|                                  |
//! |Offset |  Rsv  |R|C|S|S|Y|I|          Window Size             |
//! |       |       |G|K|H|T|N|N|                                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |        Urgent Pointer         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{NetError, Result};
use crate::util::checksum;

/// Minimum TCP header length (no options).
pub const MIN_HEADER_LEN: usize = 20;

/// TCP flag bitmask constants.
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// Zero-copy view over a TCP segment.
pub struct TcpPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> TcpPacket<T> {
    /// Wrap an existing buffer as a TCP segment.
    pub fn new(buffer: T) -> Result<Self> {
        if buffer.as_ref().len() < MIN_HEADER_LEN {
            return Err(NetError::Truncated);
        }
        let pkt = TcpPacket { buffer };
        if pkt.header_len() < MIN_HEADER_LEN {
            return Err(NetError::InvalidHeader);
        }
        if pkt.buffer.as_ref().len() < pkt.header_len() {
            return Err(NetError::Truncated);
        }
        Ok(pkt)
    }

    /// Source port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// Destination port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[2], b[3]])
    }

    /// Sequence number.
    #[inline]
    pub fn seq_number(&self) -> u32 {
        let b = self.buffer.as_ref();
        u32::from_be_bytes([b[4], b[5], b[6], b[7]])
    }

    /// Acknowledgment number.
    #[inline]
    pub fn ack_number(&self) -> u32 {
        let b = self.buffer.as_ref();
        u32::from_be_bytes([b[8], b[9], b[10], b[11]])
    }

    /// Data offset (header length), in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        ((self.buffer.as_ref()[12] >> 4) as usize) * 4
    }

    /// Raw flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buffer.as_ref()[13]
    }

    /// Returns `true` if the SYN flag is set.
    #[inline]
    pub fn syn(&self) -> bool {
        self.flags() & flags::SYN != 0
    }

    /// Returns `true` if the ACK flag is set.
    #[inline]
    pub fn ack(&self) -> bool {
        self.flags() & flags::ACK != 0
    }

    /// Returns `true` if the FIN flag is set.
    #[inline]
    pub fn fin(&self) -> bool {
        self.flags() & flags::FIN != 0
    }

    /// Returns `true` if the RST flag is set.
    #[inline]
    pub fn rst(&self) -> bool {
        self.flags() & flags::RST != 0
    }

    /// Returns `true` if the PSH flag is set.
    #[inline]
    pub fn psh(&self) -> bool {
        self.flags() & flags::PSH != 0
    }

    /// Window size.
    #[inline]
    pub fn window(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[14], b[15]])
    }

    /// Checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[16], b[17]])
    }

    /// Urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[18], b[19]])
    }

    /// Returns the segment payload (data after the TCP header).
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[self.header_len()..]
    }

    /// Consume the wrapper and return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TcpPacket<T> {
    pub fn set_src_port(&mut self, port: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&port.to_be_bytes());
    }

    pub fn set_seq_number(&mut self, seq: u32) {
        self.buffer.as_mut()[4..8].copy_from_slice(&seq.to_be_bytes());
    }

    pub fn set_ack_number(&mut self, ack: u32) {
        self.buffer.as_mut()[8..12].copy_from_slice(&ack.to_be_bytes());
    }

    /// Set the data offset (header length in 4-byte units) and reserved bits.
    pub fn set_data_offset(&mut self, words: u8) {
        self.buffer.as_mut()[12] = words << 4;
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.buffer.as_mut()[13] = flags;
    }

    pub fn set_window(&mut self, window: u16) {
        self.buffer.as_mut()[14..16].copy_from_slice(&window.to_be_bytes());
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    pub fn set_urgent_pointer(&mut self, urgent: u16) {
        self.buffer.as_mut()[18..20].copy_from_slice(&urgent.to_be_bytes());
    }

    /// Returns a mutable slice over the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let hdr_len = self.header_len();
        &mut self.buffer.as_mut()[hdr_len..]
    }

    /// Compute and fill the TCP checksum using the IPv4 pseudo-header.
    pub fn fill_checksum(&mut self, src_addr: &[u8; 4], dst_addr: &[u8; 4]) {
        self.set_checksum(0);
        let len = self.buffer.as_ref().len() as u16;
        let pseudo = checksum::pseudo_header_checksum(src_addr, dst_addr, 6, len);
        let data = self.buffer.as_ref();
        let mut raw = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            raw += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            raw += (data[i] as u32) << 8;
        }
        let csum = checksum::combine_checksums(raw, pseudo);
        self.set_checksum(if csum == 0 { 0xffff } else { csum });
    }
}

/// Build a TCP segment into the given buffer.
///
/// Returns the total number of bytes written (header + payload).
pub fn build_tcp(
    buffer: &mut [u8],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
) -> Result<usize> {
    let total = MIN_HEADER_LEN + payload.len();
    if buffer.len() < total {
        return Err(NetError::Truncated);
    }

    // Zero-init the header region
    buffer[..MIN_HEADER_LEN].fill(0);

    // Set the data offset field (byte 12) before creating TcpPacket to pass validation
    buffer[12] = 5 << 4; // 20 bytes / 4 = 5

    let mut pkt = TcpPacket::new(&mut buffer[..total])?;
    pkt.set_src_port(src_port);
    pkt.set_dst_port(dst_port);
    pkt.set_seq_number(seq);
    pkt.set_ack_number(ack);
    pkt.set_flags(tcp_flags);
    pkt.set_window(window);
    pkt.set_urgent_pointer(0);

    // Copy payload
    if !payload.is_empty() {
        pkt.payload_mut().copy_from_slice(payload);
    }

    // Compute checksum
    pkt.fill_checksum(src_addr, dst_addr);

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_syn() {
        let mut buf = [0u8; 64];
        let n = build_tcp(
            &mut buf,
            50000,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )
        .unwrap();

        assert_eq!(n, 20);
        let pkt = TcpPacket::new(&buf[..n]).unwrap();
        assert_eq!(pkt.src_port(), 50000);
        assert_eq!(pkt.dst_port(), 80);
        assert_eq!(pkt.seq_number(), 1000);
        assert_eq!(pkt.ack_number(), 0);
        assert!(pkt.syn());
        assert!(!pkt.ack());
        assert!(!pkt.fin());
        assert!(!pkt.rst());
        assert_eq!(pkt.window(), 65535);
        assert_eq!(pkt.header_len(), 20);
        assert!(pkt.payload().is_empty());
    }

    #[test]
    fn test_build_syn_ack() {
        let mut buf = [0u8; 64];
        let n = build_tcp(
            &mut buf,
            80,
            50000,
            2000,
            1001,
            flags::SYN | flags::ACK,
            32768,
            &[],
            &[10, 0, 0, 2],
            &[10, 0, 0, 1],
        )
        .unwrap();

        let pkt = TcpPacket::new(&buf[..n]).unwrap();
        assert!(pkt.syn());
        assert!(pkt.ack());
        assert_eq!(pkt.seq_number(), 2000);
        assert_eq!(pkt.ack_number(), 1001);
    }

    #[test]
    fn test_build_with_payload() {
        let mut buf = [0u8; 128];
        let payload = b"GET / HTTP/1.1\r\n";
        let n = build_tcp(
            &mut buf,
            50000,
            80,
            1001,
            2001,
            flags::ACK | flags::PSH,
            65535,
            payload,
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )
        .unwrap();

        let pkt = TcpPacket::new(&buf[..n]).unwrap();
        assert_eq!(pkt.payload(), payload);
        assert!(pkt.psh());
        assert!(pkt.ack());
    }

    #[test]
    fn test_truncated() {
        let buf = [0u8; 10];
        assert_eq!(TcpPacket::new(&buf[..]).err(), Some(NetError::Truncated));
    }

    #[test]
    fn test_flags_constants() {
        let combined = flags::SYN | flags::ACK;
        assert_eq!(combined & flags::SYN, flags::SYN);
        assert_eq!(combined & flags::ACK, flags::ACK);
        assert_eq!(combined & flags::FIN, 0);
    }
}
