//! Multicast example — demonstrates IPv4 multicast group membership
//! and sending/receiving multicast packets through the loopback interface.
//!
//! Run with: `cargo run --example multicast`

use netstack::wire::ethernet;
use netstack::wire::ipv4;
use netstack::wire::udp;
use netstack::wire::mac::MacAddress;
use netstack::wire::EtherType;

/// Map an IPv4 multicast address to its corresponding MAC address.
/// RFC 1112: low 23 bits of the IP mapped into 01:00:5e:xx:xx:xx.
fn multicast_mac(ip: [u8; 4]) -> MacAddress {
    MacAddress::new([0x01, 0x00, 0x5e, ip[1] & 0x7f, ip[2], ip[3]])
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — IPv4 Multicast Example              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Multicast group ────────────────────────────────────────────
    let mcast_group: [u8; 4] = [224, 0, 0, 251]; // mDNS multicast group
    let mcast_mac = multicast_mac(mcast_group);

    println!("─── Multicast Group ────────────────────────────────────");
    println!(
        "  Group IP:  {}.{}.{}.{}",
        mcast_group[0], mcast_group[1], mcast_group[2], mcast_group[3]
    );
    println!("  Group MAC: {}", mcast_mac);
    println!("  MAC is multicast: {}", mcast_mac.is_multicast());
    println!();

    // ── Send a multicast UDP packet ────────────────────────────────
    println!("─── Sending Multicast Packet ────────────────────────────");
    let payload = b"Hello, multicast group!";

    // Build UDP
    let mut udp_buf = vec![0u8; udp::HEADER_LEN + payload.len()];
    let udp_len = udp::build_udp(
        &mut udp_buf,
        5353,         // src port (mDNS)
        5353,         // dst port
        payload,
        &[10, 0, 0, 1],
        &mcast_group,
    )
    .expect("build_udp failed");

    // Build IPv4 with TTL=1 (link-local multicast)
    let mut ip_buf = vec![0u8; ipv4::MIN_HEADER_LEN + udp_len];
    let ip_len = ipv4::build_ipv4(
        &mut ip_buf,
        [10, 0, 0, 1],
        mcast_group,
        17, // UDP
        1,  // TTL=1 for link-local
        0,
        &udp_buf[..udp_len],
    )
    .expect("build_ipv4 failed");

    // Build Ethernet with multicast MAC destination
    let mut frame_buf = vec![0u8; ethernet::HEADER_LEN + ip_len];
    ethernet::build_frame(
        &mut frame_buf,
        mcast_mac,
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        EtherType::Ipv4,
        &ip_buf[..ip_len],
    )
    .expect("build_frame failed");

    println!("  Built multicast frame: {} bytes", frame_buf.len());
    println!("  UDP payload: \"{}\"", String::from_utf8_lossy(payload));
    println!();

    // ── Parse the constructed packet ───────────────────────────────
    println!("─── Parsing Multicast Packet ─────────────────────────────");
    let eth = netstack::wire::ethernet::EthernetFrame::new(&frame_buf[..]).expect("parse eth");
    println!("  Ethernet dst: {} (multicast={})", eth.dst_addr(), eth.dst_addr().is_multicast());
    println!("  Ethernet src: {}", eth.src_addr());
    println!("  EtherType:    {:?}", eth.ethertype());

    let ip_pkt = ipv4::Ipv4Packet::new(eth.payload()).expect("parse ip");
    println!(
        "  IPv4 src:     {}.{}.{}.{}",
        ip_pkt.src_addr()[0], ip_pkt.src_addr()[1],
        ip_pkt.src_addr()[2], ip_pkt.src_addr()[3]
    );
    println!(
        "  IPv4 dst:     {}.{}.{}.{}",
        ip_pkt.dst_addr()[0], ip_pkt.dst_addr()[1],
        ip_pkt.dst_addr()[2], ip_pkt.dst_addr()[3]
    );
    println!("  TTL:          {}", ip_pkt.ttl());

    let udp_pkt = netstack::wire::udp::UdpPacket::new(ip_pkt.payload()).expect("parse udp");
    println!("  UDP src port: {}", udp_pkt.src_port());
    println!("  UDP dst port: {}", udp_pkt.dst_port());
    println!("  UDP payload:  \"{}\"", String::from_utf8_lossy(udp_pkt.payload()));
    println!();
    println!("  ✓ Multicast example complete.");
}
