//! Ping example — demonstrates crafting and parsing ICMP-like echo
//! packets over IPv4 using the wire layer.
//!
//! Since the stack doesn't have a full ICMP implementation, this
//! example constructs raw IPv4 packets with protocol=1 (ICMP) and
//! routes them through the loopback interface.
//!
//! Run with: `cargo run --example ping`

use netstack::iface::interface::{Interface, InterfaceConfig};
use netstack::phy::loopback::LoopbackDevice;
use netstack::phy::Device;
use netstack::wire::ethernet;
use netstack::wire::ipv4;
use netstack::wire::mac::MacAddress;
use netstack::wire::EtherType;
use netstack::time::Instant;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — Ping (ICMP Echo) Example            ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let device = LoopbackDevice::new(1500);
    let config = InterfaceConfig {
        mac_addr: MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        ip_addr: [10, 0, 0, 1],
    };
    let mut iface = Interface::new(device, config);

    // ── Build an ICMP echo request ─────────────────────────────────
    println!("─── Sending Echo Request ────────────────────────────────");
    // Minimal ICMP echo: type=8, code=0, checksum, id, seq, payload
    let icmp_payload = build_icmp_echo_request(1, 1, b"netstack ping data");
    println!("  ICMP echo request: {} bytes", icmp_payload.len());

    // Wrap in IPv4
    let mut ip_buf = vec![0u8; ipv4::MIN_HEADER_LEN + icmp_payload.len()];
    let ip_len = ipv4::build_ipv4(
        &mut ip_buf,
        [10, 0, 0, 1], // src
        [10, 0, 0, 1], // dst  (loopback to self)
        1,             // ICMP
        64,
        0x1234,
        &icmp_payload,
    )
    .expect("build_ipv4 failed");

    // Wrap in Ethernet
    let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let mut frame_buf = vec![0u8; ethernet::HEADER_LEN + ip_len];
    ethernet::build_frame(
        &mut frame_buf,
        mac,
        mac,
        EtherType::Ipv4,
        &ip_buf[..ip_len],
    )
    .expect("build_frame failed");

    // Inject into loopback
    iface.device_mut().send(&frame_buf).expect("device send failed");
    println!("  Injected {} byte frame into loopback", frame_buf.len());

    // ── Poll for the response ──────────────────────────────────────
    println!();
    println!("─── Receiving ────────────────────────────────────────────");
    let now = Instant::from_millis(0);
    match iface.poll(now) {
        Ok(Some(event)) => println!("  Received transport event: {:?}", event),
        Ok(None) => println!("  Frame handled internally (no transport event)"),
        Err(e) => println!("  Poll error: {}", e),
    }

    // Parse the IPv4 packet we built to show the fields
    println!();
    println!("─── Parsed IPv4 Packet ────────────────────────────────");
    let ip_pkt = ipv4::Ipv4Packet::new(&ip_buf[..ip_len]).expect("parse failed");
    println!("  Version:    {}", ip_pkt.version());
    println!("  Header len: {} bytes", ip_pkt.header_len());
    println!("  Total len:  {} bytes", ip_pkt.total_len());
    println!("  TTL:        {}", ip_pkt.ttl());
    println!("  Protocol:   {} (ICMP)", ip_pkt.protocol());
    println!(
        "  Src:        {}.{}.{}.{}",
        ip_pkt.src_addr()[0], ip_pkt.src_addr()[1],
        ip_pkt.src_addr()[2], ip_pkt.src_addr()[3]
    );
    println!(
        "  Dst:        {}.{}.{}.{}",
        ip_pkt.dst_addr()[0], ip_pkt.dst_addr()[1],
        ip_pkt.dst_addr()[2], ip_pkt.dst_addr()[3]
    );
    println!("  Checksum:   valid={}", ip_pkt.verify_checksum());
    println!();
    println!("  ✓ Ping example complete.");
}

/// Build a minimal ICMP echo request.
fn build_icmp_echo_request(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + data.len()];
    buf[0] = 8; // Type: Echo Request
    buf[1] = 0; // Code: 0
    // Checksum placeholder at [2..4]
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..].copy_from_slice(data);

    // Compute ICMP checksum (ones-complement sum)
    let csum = internet_checksum(&buf);
    buf[2..4].copy_from_slice(&csum.to_be_bytes());
    buf
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
