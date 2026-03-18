//! IPv6 multicast example — demonstrates building and parsing IPv6
//! multicast packets using raw wire-format construction.
//!
//! Since the stack currently focuses on IPv4, this example manually
//! constructs IPv6 frames to illustrate multicast address handling.
//!
//! Run with: `cargo run --example multicast6`

use std::net::Ipv6Addr;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — IPv6 Multicast Example              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── IPv6 multicast addresses ───────────────────────────────────
    println!("─── Well-Known IPv6 Multicast Addresses ──────────────────");
    let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
    let all_routers: Ipv6Addr = "ff02::2".parse().unwrap();
    let mdns: Ipv6Addr = "ff02::fb".parse().unwrap();
    let solicited_node: Ipv6Addr = "ff02::1:ff00:1".parse().unwrap();

    let addrs = [
        ("All nodes (link-local)", all_nodes),
        ("All routers (link-local)", all_routers),
        ("mDNS", mdns),
        ("Solicited-node", solicited_node),
    ];

    for (name, addr) in &addrs {
        let mac = ipv6_multicast_mac(addr);
        println!(
            "  {:<28} {} → {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            name, addr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );
    }
    println!();

    // ── Build a raw IPv6 packet ────────────────────────────────────
    println!("─── Building IPv6 Multicast Packet ───────────────────────");
    let src: Ipv6Addr = "fe80::1".parse().unwrap();
    let dst = all_nodes;
    let payload = b"Hello, IPv6 multicast!";

    let packet = build_ipv6_packet(&src, &dst, 17, 1, payload);
    println!("  Source:       {}", src);
    println!("  Destination:  {}", dst);
    println!("  Payload len:  {} bytes", payload.len());
    println!("  Packet len:   {} bytes", packet.len());
    println!();

    // ── Parse the IPv6 header ──────────────────────────────────────
    println!("─── Parsing IPv6 Header ──────────────────────────────────");
    parse_ipv6_header(&packet);
    println!();

    // ── Scope analysis ─────────────────────────────────────────────
    println!("─── Multicast Scope Analysis ─────────────────────────────");
    let test_addrs: Vec<Ipv6Addr> = vec![
        "ff01::1".parse().unwrap(),  // Interface-local
        "ff02::1".parse().unwrap(),  // Link-local
        "ff05::1".parse().unwrap(),  // Site-local
        "ff0e::1".parse().unwrap(),  // Global
    ];

    for addr in &test_addrs {
        let scope = multicast_scope(addr);
        println!("  {} → scope: {}", addr, scope);
    }

    println!();
    println!("  ✓ IPv6 multicast example complete.");
}

/// Map an IPv6 multicast address to its Ethernet multicast MAC.
/// RFC 2464: 33:33:xx:xx:xx:xx using the low 32 bits of the IPv6 addr.
fn ipv6_multicast_mac(addr: &Ipv6Addr) -> [u8; 6] {
    let octets = addr.octets();
    [0x33, 0x33, octets[12], octets[13], octets[14], octets[15]]
}

/// Build a minimal IPv6 packet (40-byte header + payload).
fn build_ipv6_packet(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 40 + payload.len()];

    // Version (6), Traffic Class, Flow Label
    buf[0] = 0x60; // Version 6

    // Payload length
    let plen = payload.len() as u16;
    buf[4..6].copy_from_slice(&plen.to_be_bytes());

    // Next header
    buf[6] = next_header;

    // Hop limit
    buf[7] = hop_limit;

    // Source address
    buf[8..24].copy_from_slice(&src.octets());

    // Destination address
    buf[24..40].copy_from_slice(&dst.octets());

    // Payload
    buf[40..].copy_from_slice(payload);

    buf
}

fn parse_ipv6_header(data: &[u8]) {
    if data.len() < 40 {
        println!("  Packet too short for IPv6 header");
        return;
    }
    let version = data[0] >> 4;
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    println!("  Version:      {}", version);
    println!("  Payload len:  {}", payload_len);
    println!("  Next header:  {} ({})", next_header, nh_name(next_header));
    println!("  Hop limit:    {}", hop_limit);
    println!("  Source:        {}", src);
    println!("  Destination:   {}", dst);
    println!("  Is multicast:  {}", dst.is_multicast());
}

fn nh_name(nh: u8) -> &'static str {
    match nh {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "other",
    }
}

fn multicast_scope(addr: &Ipv6Addr) -> &'static str {
    let octets = addr.octets();
    if octets[0] != 0xff {
        return "not multicast";
    }
    match octets[1] & 0x0f {
        1 => "interface-local",
        2 => "link-local",
        4 => "admin-local",
        5 => "site-local",
        8 => "organization-local",
        0xe => "global",
        _ => "unknown",
    }
}
