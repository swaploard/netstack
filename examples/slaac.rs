//! SLAAC example — demonstrates IPv6 Stateless Address Auto-
//! Configuration (RFC 4862) by deriving a global IPv6 address from
//! a Router Advertisement prefix and the interface identifier.
//!
//! Run with: `cargo run --example slaac`

use std::net::Ipv6Addr;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — IPv6 SLAAC Example                  ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Interface identifier from MAC address ──────────────────────
    println!("─── Interface Identifier from MAC ────────────────────────");
    let mac = [0x02, 0x42, 0xac, 0x11, 0x00, 0x02u8];
    println!(
        "  MAC address:    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let iid = mac_to_eui64(&mac);
    println!(
        "  EUI-64 IID:     {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7]
    );
    println!();

    // ── Link-local address ─────────────────────────────────────────
    println!("─── Link-Local Address ─────────────────────────────────");
    let link_local = derive_link_local(&iid);
    println!("  Link-local:     {}", link_local);
    println!();

    // ── Simulate Router Advertisement ──────────────────────────────
    println!("─── Router Advertisement (simulated) ─────────────────────");
    let ra = RouterAdvertisement {
        prefix: [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01],
        prefix_len: 64,
        valid_lifetime: 86400,
        preferred_lifetime: 14400,
        flags: PrefixFlags {
            on_link: true,
            autonomous: true,
        },
    };

    println!("  Prefix:         {}", format_prefix(&ra.prefix, ra.prefix_len));
    println!("  Prefix length:  /{}", ra.prefix_len);
    println!("  Valid lifetime:  {} seconds ({} hours)", ra.valid_lifetime, ra.valid_lifetime / 3600);
    println!(
        "  Pref lifetime:   {} seconds ({} hours)",
        ra.preferred_lifetime, ra.preferred_lifetime / 3600
    );
    println!("  On-link:        {}", ra.flags.on_link);
    println!("  Autonomous:     {}", ra.flags.autonomous);
    println!();

    // ── SLAAC address derivation ───────────────────────────────────
    println!("─── SLAAC Address Derivation ─────────────────────────────");
    if ra.flags.autonomous {
        let global_addr = derive_global_address(&ra.prefix, &iid);
        println!("  Global address: {}", global_addr);
        println!("  Full:           {}/{}", global_addr, ra.prefix_len);

        // Verify the address components
        let octets = global_addr.octets();
        let prefix_match = octets[..8] == ra.prefix;
        let iid_match = octets[8..] == iid;
        println!("  Prefix match:   {}", prefix_match);
        println!("  IID match:      {}", iid_match);
    } else {
        println!("  Skipping: autonomous flag not set");
    }
    println!();

    // ── Duplicate Address Detection ────────────────────────────────
    println!("─── Duplicate Address Detection (DAD) ────────────────────");
    let tentative_addr = derive_global_address(&ra.prefix, &iid);
    let solicited_node = derive_solicited_node(&tentative_addr);
    println!("  Tentative:      {}", tentative_addr);
    println!("  Solicited-node: {}", solicited_node);
    println!("  DAD probe:      NS for {} via {}", tentative_addr, solicited_node);
    println!("  Result:         No conflict (simulated) — address confirmed!");

    println!();
    println!("  ✓ SLAAC example complete.");
}

/// Convert a 48-bit MAC address to a 64-bit EUI-64 interface identifier.
fn mac_to_eui64(mac: &[u8; 6]) -> [u8; 8] {
    let mut iid = [0u8; 8];
    iid[0] = mac[0] ^ 0x02; // Toggle universal/local bit
    iid[1] = mac[1];
    iid[2] = mac[2];
    iid[3] = 0xff;
    iid[4] = 0xfe;
    iid[5] = mac[3];
    iid[6] = mac[4];
    iid[7] = mac[5];
    iid
}

/// Derive a link-local address (fe80::/10) from an interface identifier.
fn derive_link_local(iid: &[u8; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    octets[8..16].copy_from_slice(iid);
    Ipv6Addr::from(octets)
}

/// Derive a global address by combining a /64 prefix with an IID.
fn derive_global_address(prefix: &[u8; 8], iid: &[u8; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(prefix);
    octets[8..].copy_from_slice(iid);
    Ipv6Addr::from(octets)
}

/// Derive the solicited-node multicast address for DAD.
fn derive_solicited_node(addr: &Ipv6Addr) -> Ipv6Addr {
    let octets = addr.octets();
    let mut sn = [0u8; 16];
    sn[0] = 0xff;
    sn[1] = 0x02;
    sn[11] = 0x01;
    sn[12] = 0xff;
    sn[13] = octets[13];
    sn[14] = octets[14];
    sn[15] = octets[15];
    Ipv6Addr::from(sn)
}

fn format_prefix(prefix: &[u8; 8], prefix_len: u8) -> String {
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/{prefix_len}",
        prefix[0], prefix[1], prefix[2], prefix[3],
        prefix[4], prefix[5], prefix[6], prefix[7],
    )
}

struct PrefixFlags {
    on_link: bool,
    autonomous: bool,
}

struct RouterAdvertisement {
    prefix: [u8; 8],
    prefix_len: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    flags: PrefixFlags,
}
