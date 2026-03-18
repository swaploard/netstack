//! ARP cache — maps IPv4 addresses to MAC addresses.

use std::collections::HashMap;
use crate::wire::mac::MacAddress;
use crate::time::Instant;

/// An entry in the ARP cache.
#[derive(Debug, Clone)]
struct ArpEntry {
    mac: MacAddress,
    expires_at: Instant,
}

/// Time-to-live for ARP entries (milliseconds).
const ARP_TTL_MS: i64 = 60_000; // 60 seconds

/// A cache mapping IPv4 addresses to their resolved MAC addresses.
pub struct ArpCache {
    entries: HashMap<[u8; 4], ArpEntry>,
}

impl ArpCache {
    /// Create a new, empty ARP cache.
    pub fn new() -> Self {
        ArpCache {
            entries: HashMap::new(),
        }
    }

    /// Look up the MAC address for the given IPv4 address.
    pub fn lookup(&self, ip: &[u8; 4]) -> Option<MacAddress> {
        self.entries.get(ip).map(|e| e.mac)
    }

    /// Insert or update an ARP cache entry.
    pub fn insert(&mut self, ip: [u8; 4], mac: MacAddress, now: Instant) {
        let entry = ArpEntry {
            mac,
            expires_at: now + crate::time::Duration::from_millis(ARP_TTL_MS),
        };
        self.entries.insert(ip, entry);
    }

    /// Remove expired entries from the cache.
    pub fn expire_entries(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let now = Instant::from_millis(0);

        cache.insert(ip, mac, now);
        assert_eq!(cache.lookup(&ip), Some(mac));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_miss() {
        let cache = ArpCache::new();
        assert_eq!(cache.lookup(&[10, 0, 0, 99]), None);
    }

    #[test]
    fn test_expiry() {
        let mut cache = ArpCache::new();
        let ip = [10, 0, 0, 1];
        let mac = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let now = Instant::from_millis(0);

        cache.insert(ip, mac, now);
        assert_eq!(cache.len(), 1);

        // Not expired yet
        cache.expire_entries(Instant::from_millis(30_000));
        assert_eq!(cache.len(), 1);

        // Now expired
        cache.expire_entries(Instant::from_millis(61_000));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.lookup(&ip), None);
    }
}
