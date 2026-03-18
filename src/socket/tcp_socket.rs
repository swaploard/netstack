//! High-level TCP socket API.
//!
//! Provides `tcp_connect`, `tcp_listen`, `tcp_send`, `tcp_receive` —
//! a user-facing interface over the TCP connection engine.

use crate::error::Result;
use crate::wire::tcp::{self, TcpPacket};
use crate::socket::tcp::connection::{TcpConnection, ConnectionId, TcpSegmentOut};

/// A high-level TCP socket wrapping a [`TcpConnection`].
pub struct TcpSocket {
    conn: TcpConnection,
}

impl TcpSocket {
    /// Create a new TCP socket.
    fn new(conn: TcpConnection) -> Self {
        TcpSocket { conn }
    }

    /// Active open: connect to a remote endpoint.
    ///
    /// Returns the SYN segment to transmit.
    pub fn tcp_connect(
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        isn: u32,
    ) -> Result<(Self, Vec<u8>)> {
        let id = ConnectionId {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };
        let mut conn = TcpConnection::new(id);
        let seg_out = conn.connect(isn)?;
        let bytes = serialize_segment(&seg_out, &local_addr, &remote_addr);
        Ok((TcpSocket::new(conn), bytes))
    }

    /// Passive open: listen for incoming connections.
    pub fn tcp_listen(
        local_addr: [u8; 4],
        local_port: u16,
    ) -> Result<Self> {
        let id = ConnectionId {
            local_addr,
            local_port,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
        };
        let mut conn = TcpConnection::new(id);
        conn.listen()?;
        Ok(TcpSocket::new(conn))
    }

    /// Accept an incoming SYN on a listening socket.
    ///
    /// Returns a new connected socket and the SYN-ACK segment to transmit.
    pub fn accept(
        &mut self,
        syn_data: &[u8],
        remote_addr: [u8; 4],
        remote_port: u16,
        isn: u32,
    ) -> Result<Vec<u8>> {
        let syn_pkt = TcpPacket::new(syn_data)?;

        // Update the connection ID with remote info
        self.conn.id.remote_addr = remote_addr;
        self.conn.id.remote_port = remote_port;

        let seg_out = self.conn.accept(&syn_pkt, isn)?;
        Ok(serialize_segment(
            &seg_out,
            &self.conn.id.local_addr,
            &self.conn.id.remote_addr,
        ))
    }

    /// Process an incoming TCP segment.
    ///
    /// Returns any response segment that should be transmitted.
    pub fn on_segment(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let pkt = TcpPacket::new(data)?;
        match self.conn.on_segment(&pkt)? {
            Some(seg_out) => Ok(Some(serialize_segment(
                &seg_out,
                &self.conn.id.local_addr,
                &self.conn.id.remote_addr,
            ))),
            None => Ok(None),
        }
    }

    /// Send application data.
    ///
    /// Queues data in the send buffer and returns a segment to transmit,
    /// if any data is ready.
    pub fn tcp_send(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        self.conn.send(data)?;
        match self.conn.flush_send() {
            Some(seg_out) => Ok(Some(serialize_segment(
                &seg_out,
                &self.conn.id.local_addr,
                &self.conn.id.remote_addr,
            ))),
            None => Ok(None),
        }
    }

    /// Receive application data from the receive buffer.
    pub fn tcp_receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.conn.receive(buf)
    }

    /// Initiate a connection close.
    ///
    /// Returns the FIN segment to transmit.
    pub fn close(&mut self) -> Result<Vec<u8>> {
        let seg_out = self.conn.close()?;
        Ok(serialize_segment(
            &seg_out,
            &self.conn.id.local_addr,
            &self.conn.id.remote_addr,
        ))
    }

    /// Returns the current TCP state.
    pub fn state(&self) -> crate::socket::tcp::state::TcpState {
        self.conn.state()
    }

    /// Returns the connection ID.
    pub fn connection_id(&self) -> &ConnectionId {
        &self.conn.id
    }
}

/// Serialize a `TcpSegmentOut` into wire-format bytes.
fn serialize_segment(seg: &TcpSegmentOut, src_addr: &[u8; 4], dst_addr: &[u8; 4]) -> Vec<u8> {
    let total = tcp::MIN_HEADER_LEN + seg.payload.len();
    let mut buf = vec![0u8; total];
    tcp::build_tcp(
        &mut buf,
        seg.src_port,
        seg.dst_port,
        seg.seq,
        seg.ack,
        seg.flags,
        seg.window,
        &seg.payload,
        src_addr,
        dst_addr,
    )
    .expect("serialize_segment: buffer too small");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::tcp::state::TcpState;

    #[test]
    fn test_full_lifecycle_via_socket_api() {
        // Client connects
        let (mut client, syn_bytes) = TcpSocket::tcp_connect(
            [10, 0, 0, 1], 50000,
            [10, 0, 0, 2], 80,
            1000,
        )
        .unwrap();
        assert_eq!(client.state(), TcpState::SynSent);

        // Server listens and accepts
        let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80).unwrap();
        assert_eq!(server.state(), TcpState::Listen);

        let syn_ack_bytes = server.accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000).unwrap();
        assert_eq!(server.state(), TcpState::SynReceived);

        // Client receives SYN-ACK → ESTABLISHED
        let ack_bytes = client.on_segment(&syn_ack_bytes).unwrap();
        assert_eq!(client.state(), TcpState::Established);
        assert!(ack_bytes.is_some());

        // Server receives ACK → ESTABLISHED
        server.on_segment(&ack_bytes.unwrap()).unwrap();
        assert_eq!(server.state(), TcpState::Established);

        // Client sends data
        let data_seg = client.tcp_send(b"Hello!").unwrap().unwrap();

        // Server receives data
        let ack_seg = server.on_segment(&data_seg).unwrap();
        assert!(ack_seg.is_some());

        // Server reads data
        let mut recv_buf = [0u8; 32];
        let n = server.tcp_receive(&mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..n], b"Hello!");

        // Client closes
        let fin_bytes = client.close().unwrap();
        assert_eq!(client.state(), TcpState::FinWait1);

        // Server receives FIN
        let ack_for_fin = server.on_segment(&fin_bytes).unwrap().unwrap();
        assert_eq!(server.state(), TcpState::CloseWait);

        // Client receives ACK for FIN
        client.on_segment(&ack_for_fin).unwrap();
        assert_eq!(client.state(), TcpState::FinWait2);

        // Server closes
        let server_fin = server.close().unwrap();
        assert_eq!(server.state(), TcpState::LastAck);

        // Client receives server FIN → TimeWait
        let final_ack = client.on_segment(&server_fin).unwrap().unwrap();
        assert_eq!(client.state(), TcpState::TimeWait);

        // Server receives final ACK → Closed
        server.on_segment(&final_ack).unwrap();
        assert_eq!(server.state(), TcpState::Closed);
    }
}
