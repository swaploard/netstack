//! Socket table — maps flow keys to socket indices.

use std::collections::HashMap;
use crate::socket::tcp::connection::ConnectionId;

/// A socket handle used to index into the socket table.
pub type SocketHandle = usize;

/// A table mapping TCP four-tuples to socket handles.
///
/// This enables O(1) lookup of connections by their flow key.
pub struct SocketTable {
    tcp_connections: HashMap<ConnectionId, SocketHandle>,
    next_handle: SocketHandle,
}

impl SocketTable {
    pub fn new() -> Self {
        SocketTable {
            tcp_connections: HashMap::new(),
            next_handle: 0,
        }
    }

    /// Register a new TCP connection and return its handle.
    pub fn insert_tcp(&mut self, id: ConnectionId) -> SocketHandle {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.tcp_connections.insert(id, handle);
        handle
    }

    /// Look up a TCP connection by its four-tuple.
    pub fn lookup_tcp(&self, id: &ConnectionId) -> Option<SocketHandle> {
        self.tcp_connections.get(id).copied()
    }

    /// Remove a TCP connection from the table.
    pub fn remove_tcp(&mut self, id: &ConnectionId) -> Option<SocketHandle> {
        self.tcp_connections.remove(id)
    }

    /// Returns the number of TCP connections tracked.
    pub fn tcp_count(&self) -> usize {
        self.tcp_connections.len()
    }
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_lookup_remove() {
        let mut table = SocketTable::new();
        let id = ConnectionId {
            local_addr: [10, 0, 0, 1],
            local_port: 50000,
            remote_addr: [10, 0, 0, 2],
            remote_port: 80,
        };

        let handle = table.insert_tcp(id);
        assert_eq!(table.lookup_tcp(&id), Some(handle));
        assert_eq!(table.tcp_count(), 1);

        table.remove_tcp(&id);
        assert_eq!(table.lookup_tcp(&id), None);
        assert_eq!(table.tcp_count(), 0);
    }
}
