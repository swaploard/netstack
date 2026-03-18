//! Network interface — the core stack loop.
//!
//! `Interface` ties together a `Device`, ARP cache, routing, and socket
//! dispatch. Its [`poll`] method processes one frame at a time through the
//! full protocol pipeline:
//!
//! ```text
//! device → ethernet → ARP / IPv4 → TCP / UDP → socket
//! ```

use crate::error::{NetError, Result};
use crate::phy::Device;
use crate::wire::mac::MacAddress;
use crate::wire::ethernet::{self, EthernetFrame};
use crate::wire::arp::{self, ArpPacket, ArpOperation};
use crate::wire::ipv4::Ipv4Packet;
use crate::wire::{EtherType, IpProtocol};
use super::arp_cache::ArpCache;
use crate::time::Instant;

/// Describes a received transport-layer segment after L2/L3 processing.
#[derive(Debug)]
pub enum TransportEvent {
    Tcp {
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
        payload: Vec<u8>,
    },
    Udp {
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
        payload: Vec<u8>,
    },
}

/// Configuration for a network interface.
pub struct InterfaceConfig {
    pub mac_addr: MacAddress,
    pub ip_addr: [u8; 4],
}

/// The core network interface that drives the packet pipeline.
pub struct Interface<D: Device> {
    device: D,
    config: InterfaceConfig,
    arp_cache: ArpCache,
    recv_buf: Vec<u8>,
}

impl<D: Device> Interface<D> {
    /// Create a new interface.
    pub fn new(device: D, config: InterfaceConfig) -> Self {
        let mtu = device.mtu();
        Interface {
            device,
            config,
            arp_cache: ArpCache::new(),
            recv_buf: vec![0u8; mtu + ethernet::HEADER_LEN + 4],
        }
    }

    /// Returns a reference to the ARP cache.
    pub fn arp_cache(&self) -> &ArpCache {
        &self.arp_cache
    }

    /// Returns a mutable reference to the underlying device.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Returns the interface's MAC address.
    pub fn mac_addr(&self) -> MacAddress {
        self.config.mac_addr
    }

    /// Returns the interface's IPv4 address.
    pub fn ip_addr(&self) -> [u8; 4] {
        self.config.ip_addr
    }

    /// Poll the device for one incoming frame and process it through the
    /// protocol stack.
    ///
    /// Returns `Ok(Some(event))` if a transport-layer segment was delivered,
    /// `Ok(None)` if the frame was handled internally (e.g., ARP), or
    /// `Err(WouldBlock)` if no frame was available.
    pub fn poll(&mut self, now: Instant) -> Result<Option<TransportEvent>> {
        // Expire stale ARP entries
        self.arp_cache.expire_entries(now);

        // Receive a frame from the device
        let n = self.device.recv(&mut self.recv_buf)?;

        // Parse the Ethernet header and extract what we need before
        // releasing the borrow on self.recv_buf.
        let (dst_addr, ethertype, payload_data) = {
            let frame_data = &self.recv_buf[..n];
            let eth = EthernetFrame::new(frame_data)?;
            let dst = eth.dst_addr();
            let etype = eth.ethertype();
            let payload = eth.payload().to_vec();
            (dst, etype, payload)
        };

        // Check destination MAC (accept unicast to us or broadcast)
        if dst_addr != self.config.mac_addr && !dst_addr.is_broadcast() {
            return Ok(None); // not for us
        }

        match ethertype {
            Some(EtherType::Arp) => {
                self.handle_arp(&payload_data, now)?;
                Ok(None)
            }
            Some(EtherType::Ipv4) => {
                self.handle_ipv4(&payload_data)
            }
            _ => Ok(None), // unsupported ethertype
        }
    }

    /// Handle an incoming ARP packet.
    fn handle_arp(&mut self, data: &[u8], now: Instant) -> Result<()> {
        let arp_pkt = ArpPacket::new(data)?;

        // Learn sender's MAC/IP mapping
        self.arp_cache.insert(
            arp_pkt.sender_proto_addr(),
            arp_pkt.sender_hw_addr(),
            now,
        );

        // If it's a request for our IP, send a reply
        if arp_pkt.operation() == Some(ArpOperation::Request)
            && arp_pkt.target_proto_addr() == self.config.ip_addr
        {
            let mut reply_buf = vec![0u8; ethernet::HEADER_LEN + arp::HEADER_LEN];
            arp::build_arp_ipv4(
                &mut reply_buf[ethernet::HEADER_LEN..],
                ArpOperation::Reply,
                self.config.mac_addr,
                self.config.ip_addr,
                arp_pkt.sender_hw_addr(),
                arp_pkt.sender_proto_addr(),
            )?;
            // Copy the ARP payload before passing to build_frame to avoid
            // simultaneous mutable + immutable borrow of reply_buf.
            let arp_payload = reply_buf[ethernet::HEADER_LEN..].to_vec();
            ethernet::build_frame(
                &mut reply_buf,
                arp_pkt.sender_hw_addr(),
                self.config.mac_addr,
                EtherType::Arp,
                &arp_payload,
            )?;
            self.device.send(&reply_buf)?;
        }

        Ok(())
    }

    /// Handle an incoming IPv4 packet.
    fn handle_ipv4(&self, data: &[u8]) -> Result<Option<TransportEvent>> {
        let ip_pkt = Ipv4Packet::new(data)?;

        // Validate checksum
        if !ip_pkt.verify_checksum() {
            return Err(NetError::BadChecksum);
        }

        // Check destination (accept our IP or broadcast)
        if ip_pkt.dst_addr() != self.config.ip_addr
            && ip_pkt.dst_addr() != [255, 255, 255, 255]
        {
            return Ok(None); // not for us
        }

        let protocol = IpProtocol::from_u8(ip_pkt.protocol());
        let transport_payload = ip_pkt.payload().to_vec();

        match protocol {
            Some(IpProtocol::Tcp) => Ok(Some(TransportEvent::Tcp {
                src_addr: ip_pkt.src_addr(),
                dst_addr: ip_pkt.dst_addr(),
                payload: transport_payload,
            })),
            Some(IpProtocol::Udp) => Ok(Some(TransportEvent::Udp {
                src_addr: ip_pkt.src_addr(),
                dst_addr: ip_pkt.dst_addr(),
                payload: transport_payload,
            })),
            _ => Ok(None),
        }
    }

    /// Transmit a TCP segment wrapped in IPv4 and Ethernet.
    pub fn send_tcp(
        &mut self,
        tcp_data: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        dst_mac: MacAddress,
    ) -> Result<()> {
        let mut ip_buf = vec![0u8; crate::wire::ipv4::MIN_HEADER_LEN + tcp_data.len()];
        let ip_len = crate::wire::ipv4::build_ipv4(
            &mut ip_buf,
            src_ip,
            dst_ip,
            6, // TCP
            64,
            0,
            tcp_data,
        )?;

        let mut frame_buf = vec![0u8; ethernet::HEADER_LEN + ip_len];
        ethernet::build_frame(
            &mut frame_buf,
            dst_mac,
            self.config.mac_addr,
            EtherType::Ipv4,
            &ip_buf[..ip_len],
        )?;

        self.device.send(&frame_buf)
    }

    /// Transmit a UDP datagram wrapped in IPv4 and Ethernet.
    pub fn send_udp(
        &mut self,
        udp_data: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        dst_mac: MacAddress,
    ) -> Result<()> {
        let mut ip_buf = vec![0u8; crate::wire::ipv4::MIN_HEADER_LEN + udp_data.len()];
        let ip_len = crate::wire::ipv4::build_ipv4(
            &mut ip_buf,
            src_ip,
            dst_ip,
            17, // UDP
            64,
            0,
            udp_data,
        )?;

        let mut frame_buf = vec![0u8; ethernet::HEADER_LEN + ip_len];
        ethernet::build_frame(
            &mut frame_buf,
            dst_mac,
            self.config.mac_addr,
            EtherType::Ipv4,
            &ip_buf[..ip_len],
        )?;

        self.device.send(&frame_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::loopback::LoopbackDevice;

    fn make_interface() -> Interface<LoopbackDevice> {
        let device = LoopbackDevice::new(1500);
        let config = InterfaceConfig {
            mac_addr: MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ip_addr: [10, 0, 0, 1],
        };
        Interface::new(device, config)
    }

    #[test]
    fn test_poll_no_frame() {
        let mut iface = make_interface();
        let result = iface.poll(Instant::from_millis(0));
        assert_eq!(result.err(), Some(NetError::WouldBlock));
    }

    #[test]
    fn test_arp_request_reply() {
        let mut iface = make_interface();
        let now = Instant::from_millis(0);

        // Build an ARP request for our IP
        let mut arp_buf = [0u8; arp::HEADER_LEN];
        let sender_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        arp::build_arp_ipv4(
            &mut arp_buf,
            ArpOperation::Request,
            sender_mac,
            [10, 0, 0, 2],
            MacAddress::UNSPECIFIED,
            [10, 0, 0, 1],
        )
        .unwrap();

        // Wrap in Ethernet frame
        let mut frame_buf = vec![0u8; ethernet::HEADER_LEN + arp::HEADER_LEN];
        ethernet::build_frame(
            &mut frame_buf,
            MacAddress::BROADCAST,
            sender_mac,
            EtherType::Arp,
            &arp_buf,
        )
        .unwrap();

        // Inject into loopback
        iface.device_mut().send(&frame_buf).unwrap();

        // Poll should handle ARP and send reply
        let result = iface.poll(now);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // ARP handled internally

        // ARP cache should have learned the sender
        assert_eq!(iface.arp_cache().lookup(&[10, 0, 0, 2]), Some(sender_mac));
    }
}
