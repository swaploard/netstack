//! ARP (Address Resolution Protocol) packet parser and builder.
//!
//! ARP packet layout (28 bytes for IPv4-over-Ethernet):
//!
//! ```text
//!  0       7       15      23      31
//! +-------+-------+-------+-------+
//! |  HW Type      | Proto Type    |  0-3
//! +-------+-------+-------+-------+
//! |HW Len |PR Len |   Operation   |  4-7
//! +-------+-------+-------+-------+
//! |     Sender Hardware Address   |  8-13
//! |               +-------+-------+
//! |               | Sender Proto  | 14-17
//! +-------+-------+ Address       |
//! |               +-------+-------+
//! |     Target Hardware Address   | 18-23
//! |               +-------+-------+
//! |               | Target Proto  | 24-27
//! +-------+-------+ Address       |
//! +-------+-------+-------+-------+
//! ```

use crate::error::{NetError, Result};
use super::mac::MacAddress;

/// ARP header length for IPv4-over-Ethernet.
pub const HEADER_LEN: usize = 28;

/// ARP operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
}

impl ArpOperation {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(ArpOperation::Request),
            2 => Some(ArpOperation::Reply),
            _ => None,
        }
    }
}

/// Zero-copy view over an ARP packet.
pub struct ArpPacket<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ArpPacket<T> {
    /// Wrap an existing buffer as an ARP packet.
    pub fn new(buffer: T) -> Result<Self> {
        if buffer.as_ref().len() < HEADER_LEN {
            return Err(NetError::Truncated);
        }
        Ok(ArpPacket { buffer })
    }

    /// Hardware type (1 = Ethernet).
    pub fn hardware_type(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// Protocol type (0x0800 = IPv4).
    pub fn protocol_type(&self) -> u16 {
        let b = self.buffer.as_ref();
        u16::from_be_bytes([b[2], b[3]])
    }

    /// Hardware address length.
    pub fn hw_addr_len(&self) -> u8 {
        self.buffer.as_ref()[4]
    }

    /// Protocol address length.
    pub fn proto_addr_len(&self) -> u8 {
        self.buffer.as_ref()[5]
    }

    /// ARP operation (request / reply).
    pub fn operation(&self) -> Option<ArpOperation> {
        let b = self.buffer.as_ref();
        ArpOperation::from_u16(u16::from_be_bytes([b[6], b[7]]))
    }

    /// Sender hardware (MAC) address.
    pub fn sender_hw_addr(&self) -> MacAddress {
        let b = self.buffer.as_ref();
        MacAddress::new([b[8], b[9], b[10], b[11], b[12], b[13]])
    }

    /// Sender protocol (IPv4) address.
    pub fn sender_proto_addr(&self) -> [u8; 4] {
        let b = self.buffer.as_ref();
        [b[14], b[15], b[16], b[17]]
    }

    /// Target hardware (MAC) address.
    pub fn target_hw_addr(&self) -> MacAddress {
        let b = self.buffer.as_ref();
        MacAddress::new([b[18], b[19], b[20], b[21], b[22], b[23]])
    }

    /// Target protocol (IPv4) address.
    pub fn target_proto_addr(&self) -> [u8; 4] {
        let b = self.buffer.as_ref();
        [b[24], b[25], b[26], b[27]]
    }

    /// Consume the wrapper and return the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ArpPacket<T> {
    pub fn set_hardware_type(&mut self, value: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_protocol_type(&mut self, value: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn set_hw_addr_len(&mut self, value: u8) {
        self.buffer.as_mut()[4] = value;
    }

    pub fn set_proto_addr_len(&mut self, value: u8) {
        self.buffer.as_mut()[5] = value;
    }

    pub fn set_operation(&mut self, op: ArpOperation) {
        self.buffer.as_mut()[6..8].copy_from_slice(&(op as u16).to_be_bytes());
    }

    pub fn set_sender_hw_addr(&mut self, addr: MacAddress) {
        self.buffer.as_mut()[8..14].copy_from_slice(addr.as_bytes());
    }

    pub fn set_sender_proto_addr(&mut self, addr: [u8; 4]) {
        self.buffer.as_mut()[14..18].copy_from_slice(&addr);
    }

    pub fn set_target_hw_addr(&mut self, addr: MacAddress) {
        self.buffer.as_mut()[18..24].copy_from_slice(addr.as_bytes());
    }

    pub fn set_target_proto_addr(&mut self, addr: [u8; 4]) {
        self.buffer.as_mut()[24..28].copy_from_slice(&addr);
    }
}

/// Build an ARP packet for IPv4-over-Ethernet into the given buffer.
pub fn build_arp_ipv4(
    buffer: &mut [u8],
    operation: ArpOperation,
    sender_mac: MacAddress,
    sender_ip: [u8; 4],
    target_mac: MacAddress,
    target_ip: [u8; 4],
) -> Result<usize> {
    if buffer.len() < HEADER_LEN {
        return Err(NetError::Truncated);
    }
    let mut pkt = ArpPacket::new(&mut buffer[..HEADER_LEN])?;
    pkt.set_hardware_type(1);       // Ethernet
    pkt.set_protocol_type(0x0800);  // IPv4
    pkt.set_hw_addr_len(6);
    pkt.set_proto_addr_len(4);
    pkt.set_operation(operation);
    pkt.set_sender_hw_addr(sender_mac);
    pkt.set_sender_proto_addr(sender_ip);
    pkt.set_target_hw_addr(target_mac);
    pkt.set_target_proto_addr(target_ip);
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_roundtrip() {
        let mut buf = [0u8; 28];
        let sender_mac = MacAddress::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let target_mac = MacAddress::UNSPECIFIED;
        let sender_ip = [10, 0, 0, 1];
        let target_ip = [10, 0, 0, 2];

        build_arp_ipv4(
            &mut buf,
            ArpOperation::Request,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        )
        .unwrap();

        let pkt = ArpPacket::new(&buf[..]).unwrap();
        assert_eq!(pkt.hardware_type(), 1);
        assert_eq!(pkt.protocol_type(), 0x0800);
        assert_eq!(pkt.operation(), Some(ArpOperation::Request));
        assert_eq!(pkt.sender_hw_addr(), sender_mac);
        assert_eq!(pkt.sender_proto_addr(), sender_ip);
        assert_eq!(pkt.target_hw_addr(), target_mac);
        assert_eq!(pkt.target_proto_addr(), target_ip);
    }

    #[test]
    fn test_arp_truncated() {
        let buf = [0u8; 10];
        assert_eq!(ArpPacket::new(&buf[..]).err(), Some(NetError::Truncated));
    }
}
