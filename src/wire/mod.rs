//! Wire-format protocol parsers and builders.
//!
//! Each protocol provides a zero-copy view type `Protocol<T: AsRef<[u8]>>`
//! that borrows the underlying buffer and exposes typed accessor methods.
//! Builders create frames/packets into caller-provided buffers.

pub mod mac;
pub mod ethernet;
pub mod arp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

/// Well-known EtherType values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp  = 0x0806,
    Ipv6 = 0x86DD,
}

impl EtherType {
    /// Try to convert a raw `u16` into a known EtherType.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0800 => Some(EtherType::Ipv4),
            0x0806 => Some(EtherType::Arp),
            0x86DD => Some(EtherType::Ipv6),
            _ => None,
        }
    }
}

/// Well-known IP protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp  = 6,
    Udp  = 17,
}

impl IpProtocol {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1  => Some(IpProtocol::Icmp),
            6  => Some(IpProtocol::Tcp),
            17 => Some(IpProtocol::Udp),
            _ => None,
        }
    }
}
