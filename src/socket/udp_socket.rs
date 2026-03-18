//! UDP socket — minimal send/receive interface.

use crate::error::{NetError, Result};
use crate::wire::udp::{self, UdpPacket};
use crate::buffer::ring_buffer::RingBuffer;

/// A received UDP datagram.
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    pub src_addr: [u8; 4],
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// A minimal UDP socket bound to a local address and port.
pub struct UdpSocket {
    local_addr: [u8; 4],
    local_port: u16,
    recv_queue: RingBuffer<UdpDatagram>,
}

impl UdpSocket {
    /// Create a new UDP socket bound to the given address and port.
    pub fn bind(local_addr: [u8; 4], local_port: u16) -> Self {
        UdpSocket {
            local_addr,
            local_port,
            recv_queue: RingBuffer::new(64),
        }
    }

    /// Returns the local port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> [u8; 4] {
        self.local_addr
    }

    /// Build a UDP datagram for sending.
    ///
    /// Returns the serialized UDP segment bytes.
    pub fn send_to(
        &self,
        data: &[u8],
        dst_addr: &[u8; 4],
        dst_port: u16,
    ) -> Result<Vec<u8>> {
        let total = udp::HEADER_LEN + data.len();
        let mut buf = vec![0u8; total];
        udp::build_udp(
            &mut buf,
            self.local_port,
            dst_port,
            data,
            &self.local_addr,
            dst_addr,
        )?;
        Ok(buf)
    }

    /// Deliver a received UDP segment to this socket.
    pub fn deliver(&mut self, src_addr: [u8; 4], data: &[u8]) -> Result<()> {
        let pkt = UdpPacket::new(data)?;

        // Verify destination port matches
        if pkt.dst_port() != self.local_port {
            return Err(NetError::InvalidHeader);
        }

        let datagram = UdpDatagram {
            src_addr,
            src_port: pkt.src_port(),
            data: pkt.payload().to_vec(),
        };

        self.recv_queue.push(datagram)
    }

    /// Receive the next datagram from the receive queue.
    pub fn recv_from(&mut self) -> Result<UdpDatagram> {
        self.recv_queue.pop()
    }

    /// Returns `true` if there are datagrams waiting to be received.
    pub fn can_recv(&self) -> bool {
        !self.recv_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_to() {
        let sock = UdpSocket::bind([10, 0, 0, 1], 12345);
        let data = sock.send_to(b"hello", &[10, 0, 0, 2], 80).unwrap();
        let pkt = UdpPacket::new(&data[..]).unwrap();
        assert_eq!(pkt.src_port(), 12345);
        assert_eq!(pkt.dst_port(), 80);
        assert_eq!(pkt.payload(), b"hello");
    }

    #[test]
    fn test_deliver_and_recv() {
        let mut sock = UdpSocket::bind([10, 0, 0, 2], 80);

        // Build a UDP packet to deliver
        let mut buf = [0u8; 64];
        let n = udp::build_udp(
            &mut buf,
            12345,
            80,
            b"test data",
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )
        .unwrap();

        sock.deliver([10, 0, 0, 1], &buf[..n]).unwrap();
        assert!(sock.can_recv());

        let dgram = sock.recv_from().unwrap();
        assert_eq!(dgram.src_addr, [10, 0, 0, 1]);
        assert_eq!(dgram.src_port, 12345);
        assert_eq!(dgram.data, b"test data");
    }
}
