//! 6LoWPAN example — demonstrates building and parsing compressed
//! IPv6 headers for IEEE 802.15.4 low-power wireless networks.
//!
//! This is a simplified demonstration of the IPHC compression scheme
//! used in 6LoWPAN (RFC 6282).
//!
//! Run with: `cargo run --example sixlowpan`

use std::net::Ipv6Addr;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — 6LoWPAN Example                     ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── 802.15.4 addressing ────────────────────────────────────────
    println!("─── IEEE 802.15.4 Addresses ──────────────────────────────");
    let src_short: u16 = 0x0001;
    let dst_short: u16 = 0x0002;
    let pan_id: u16 = 0xABCD;

    let src_eui64: [u8; 8] = [0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01];
    let dst_eui64: [u8; 8] = [0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x02];

    println!("  PAN ID:      0x{:04X}", pan_id);
    println!("  Src short:   0x{:04X}", src_short);
    println!("  Dst short:   0x{:04X}", dst_short);
    println!(
        "  Src EUI-64:  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        src_eui64[0], src_eui64[1], src_eui64[2], src_eui64[3],
        src_eui64[4], src_eui64[5], src_eui64[6], src_eui64[7],
    );
    println!();

    // ── Derive link-local IPv6 from EUI-64 ─────────────────────────
    println!("─── Link-Local IPv6 Address Derivation ───────────────────");
    let src_ipv6 = eui64_to_link_local(&src_eui64);
    let dst_ipv6 = eui64_to_link_local(&dst_eui64);
    println!("  Src IPv6: {}", src_ipv6);
    println!("  Dst IPv6: {}", dst_ipv6);
    println!();

    // ── Simulate IPHC compression ──────────────────────────────────
    println!("─── IPHC Header Compression ──────────────────────────────");
    let payload = b"Hello, 6LoWPAN!";

    // Full IPv6 header is 40 bytes
    let full_header_size = 40;
    println!("  Full IPv6 header:      {} bytes", full_header_size);

    // IPHC can compress to as few as 2 bytes when using stateless
    // compression with EUI-64 derived addresses
    let compressed = compress_iphc(&src_ipv6, &dst_ipv6, payload);
    println!("  IPHC compressed header: {} bytes", compressed.dispatch_len);
    println!(
        "  Compression ratio:     {:.1}%",
        (1.0 - compressed.dispatch_len as f64 / full_header_size as f64) * 100.0
    );
    println!("  Total frame:           {} bytes", compressed.data.len());
    println!();

    // ── Parse compressed header ────────────────────────────────────
    println!("─── Parsing IPHC Frame ─────────────────────────────────");
    parse_iphc_frame(&compressed.data);
    println!();

    // ── 6LoWPAN fragmentation ──────────────────────────────────────
    println!("─── 6LoWPAN Fragmentation ────────────────────────────────");
    let large_payload = vec![0xAA; 200];
    let mtu = 127; // IEEE 802.15.4 max frame size
    let fragments = fragment_6lowpan(&large_payload, mtu);
    println!("  Payload size:  {} bytes", large_payload.len());
    println!("  802.15.4 MTU:  {} bytes", mtu);
    println!("  Fragments:     {}", fragments.len());
    for (i, frag) in fragments.iter().enumerate() {
        println!("    Fragment {}: {} bytes (offset {})", i, frag.len, frag.offset);
    }

    println!();
    println!("  ✓ 6LoWPAN example complete.");
}

fn eui64_to_link_local(eui64: &[u8; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    // bytes 2..8 are zero (link-local prefix padding)
    octets[8..16].copy_from_slice(eui64);
    // Toggle the universal/local bit (bit 6 of byte 8)
    octets[8] ^= 0x02;
    Ipv6Addr::from(octets)
}

struct CompressedFrame {
    data: Vec<u8>,
    dispatch_len: usize,
}

fn compress_iphc(src: &Ipv6Addr, dst: &Ipv6Addr, payload: &[u8]) -> CompressedFrame {
    let mut data = Vec::new();

    // IPHC dispatch: 011xxxxx xxxxxxxx (2 bytes minimum)
    // We simulate simple stateless compression
    let dispatch_hi: u8 = 0x7A; // 011 11010 — TF=11, NH=1, HLIM=01 (64)
    let dispatch_lo: u8 = 0x33; // SAC=0 SAM=11, M=0, DAC=0, DAM=11

    data.push(dispatch_hi);
    data.push(dispatch_lo);

    let dispatch_len = 2;

    // In full compression with EUI-64 derived addresses (SAM=11, DAM=11),
    // the addresses are fully elided. We still include them for demo.
    // In a real implementation, addresses would be elided.
    data.extend_from_slice(&src.octets()[8..16]); // IID only
    data.extend_from_slice(&dst.octets()[8..16]); // IID only

    data.extend_from_slice(payload);

    CompressedFrame { data, dispatch_len }
}

fn parse_iphc_frame(data: &[u8]) {
    if data.len() < 2 {
        println!("  Frame too short");
        return;
    }
    let dispatch = u16::from_be_bytes([data[0], data[1]]);
    let is_iphc = (dispatch >> 13) == 0b011;

    println!("  Dispatch:     0x{:04X}", dispatch);
    println!("  Is IPHC:      {}", is_iphc);

    if is_iphc {
        let tf = (data[0] >> 3) & 0x03;
        let nh = (data[0] >> 2) & 0x01;
        let hlim = data[0] & 0x03;
        let sam = (data[1] >> 4) & 0x03;
        let dam = data[1] & 0x03;

        println!("  TF:           {} (traffic class/flow label)", tf);
        println!("  NH:           {} (next header compressed={})", nh, nh == 1);
        println!("  HLIM:         {} (hop limit encoding)", hlim);
        println!("  SAM:          {} (source addr mode)", sam);
        println!("  DAM:          {} (dest addr mode)", dam);

        if data.len() > 18 {
            let payload = &data[18..];
            println!(
                "  Payload:      {} bytes — \"{}\"",
                payload.len(),
                String::from_utf8_lossy(payload)
            );
        }
    }
}

struct Fragment {
    offset: usize,
    len: usize,
}

fn fragment_6lowpan(payload: &[u8], mtu: usize) -> Vec<Fragment> {
    let header_overhead = 4; // Fragmentation header
    let frag_payload = mtu - header_overhead;
    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let len = (payload.len() - offset).min(frag_payload);
        fragments.push(Fragment { offset, len });
        offset += len;
    }

    fragments
}
