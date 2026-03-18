//! Utility helpers shared across netstack examples.
//!
//! This module provides convenience functions for formatting addresses
//! and building common packet structures used by other examples.
//!
//! Run with: `cargo run --example utils`

use netstack::wire::mac::MacAddress;
use netstack::wire::ethernet::{self, EthernetFrame};
use netstack::wire::ipv4::{self, Ipv4Packet};
use netstack::wire::tcp::{self, TcpPacket};
use netstack::wire::udp;
use netstack::wire::EtherType;

fn main() {
    println!("╔═════════════════════════════════════════════╗");
    println!("║    netstack — Utility Functions Demo        ║");
    println!("╚═════════════════════════════════════════════╝");
    println!();

    // ── MAC address utilities ──────────────────────────────────────
    println!("─── MAC Address Utilities ──────────────────────────────");
    let macs = [
        MacAddress::new([0x02, 0x42, 0xac, 0x11, 0x00, 0x02]),
        MacAddress::BROADCAST,
        MacAddress::UNSPECIFIED,
        MacAddress::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]),
    ];
    for mac in &macs {
        println!(
            "  {}  broadcast={:<5} multicast={:<5} unspec={}",
            mac,
            mac.is_broadcast(),
            mac.is_multicast(),
            mac.is_unspecified(),
        );
    }
    println!();

    // ── IPv4 formatting ────────────────────────────────────────────
    println!("─── IPv4 Address Formatting ────────────────────────────");
    let addrs: Vec<[u8; 4]> = vec![
        [10, 0, 0, 1],
        [192, 168, 1, 1],
        [127, 0, 0, 1],
        [255, 255, 255, 255],
        [224, 0, 0, 251],
    ];
    for addr in &addrs {
        let kind = classify_ip(addr);
        println!("  {:>3}.{:>3}.{:>3}.{:>3}  → {}", addr[0], addr[1], addr[2], addr[3], kind);
    }
    println!();

    // ── Packet size calculator ─────────────────────────────────────
    println!("─── Packet Size Breakdown ────────────────────────────────");
    let payload_sizes = [0, 64, 512, 1400, 1460];
    println!("  {:<10} {:<8} {:<8} {:<8} {:<8}",
        "Payload", "TCP", "UDP", "IPv4+TCP", "Eth+IP+TCP");
    for &ps in &payload_sizes {
        let tcp_total = tcp::MIN_HEADER_LEN + ps;
        let udp_total = udp::HEADER_LEN + ps;
        let ip_tcp = ipv4::MIN_HEADER_LEN + tcp_total;
        let eth_ip_tcp = ethernet::HEADER_LEN + ip_tcp;
        println!("  {:<10} {:<8} {:<8} {:<8} {:<8}", ps, tcp_total, udp_total, ip_tcp, eth_ip_tcp);
    }
    println!();

    // ── Build & parse round-trip demo ──────────────────────────────
    println!("─── Build & Parse Round-Trip ─────────────────────────────");
    let msg = b"Hello, netstack!";

    // Build full Ethernet/IP/TCP frame
    let mut tcp_buf = vec![0u8; tcp::MIN_HEADER_LEN + msg.len()];
    tcp::build_tcp(&mut tcp_buf, 8080, 80, 42, 0, 0x18, 65535, msg,
        &[10,0,0,1], &[10,0,0,2]).unwrap();
    let tl = tcp_buf.len();

    let mut ip_buf = vec![0u8; ipv4::MIN_HEADER_LEN + tl];
    let il = ipv4::build_ipv4(&mut ip_buf, [10,0,0,1], [10,0,0,2], 6, 64, 1, &tcp_buf[..tl]).unwrap();

    let src_mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    let dst_mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
    let mut frame = vec![0u8; ethernet::HEADER_LEN + il];
    ethernet::build_frame(&mut frame, dst_mac, src_mac, EtherType::Ipv4, &ip_buf[..il]).unwrap();

    // Parse it back
    let eth = EthernetFrame::new(&frame[..]).unwrap();
    let ip = Ipv4Packet::new(eth.payload()).unwrap();
    let tcp_pkt = TcpPacket::new(ip.payload()).unwrap();

    println!("  Frame size:    {} bytes", frame.len());
    println!("  Ethernet:      {} → {}", eth.src_addr(), eth.dst_addr());
    let s = ip.src_addr(); let d = ip.dst_addr();
    println!("  IPv4:          {}.{}.{}.{} → {}.{}.{}.{}",
        s[0],s[1],s[2],s[3], d[0],d[1],d[2],d[3]);
    println!("  TCP:           {} → {} seq={}", tcp_pkt.src_port(), tcp_pkt.dst_port(), tcp_pkt.seq_number());
    println!("  Payload:       \"{}\"", String::from_utf8_lossy(tcp_pkt.payload()));
    println!("  Checksum OK:   {}", ip.verify_checksum());
    println!();
    println!("  ✓ Utils demo complete.");
}

fn classify_ip(addr: &[u8; 4]) -> &'static str {
    match addr[0] {
        0..=0 => "current network",
        1..=126 => "class A",
        127 => "loopback",
        128..=191 => "class B",
        192..=223 => "class C",
        224..=239 => "multicast",
        240..=255 => "reserved/broadcast",
    }
}
