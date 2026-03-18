//! MAC (Media Access Control) address type.

use core::fmt;

/// A 6-byte IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The broadcast MAC address (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    /// The zero / unspecified MAC address.
    pub const UNSPECIFIED: MacAddress = MacAddress([0x00; 6]);

    /// Create a MAC address from raw bytes.
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Returns `true` if this is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Returns `true` if the multicast bit is set.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Returns `true` if this is the unspecified (all-zeros) address.
    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl core::str::FromStr for MacAddress {
    type Err = ();

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(());
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| ())?;
        }
        Ok(MacAddress(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_display() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_from_str() {
        let mac = MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_broadcast() {
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_multicast());
    }

    #[test]
    fn test_unspecified() {
        assert!(MacAddress::UNSPECIFIED.is_unspecified());
    }
}
