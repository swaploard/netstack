//! DHCP client example — demonstrates a simplified DHCP discover/offer
//! exchange using the UDP socket layer.
//!
//! Run with: `cargo run --example dhcp_client`

use netstack::socket::udp_socket::UdpSocket;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — DHCP Client Example                 ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let client = UdpSocket::bind([0, 0, 0, 0], 68);
    let mut server = UdpSocket::bind([10, 0, 0, 1], 67);

    // ── DHCP Discover ──────────────────────────────────────────────
    println!("─── DHCP Discover ────────────────────────────────────────");
    let discover = build_dhcp_discover(0xDEADBEEF, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    println!("  Transaction ID: 0xDEADBEEF");
    println!("  Client MAC:     02:00:00:00:00:01");
    println!("  Message size:   {} bytes", discover.len());

    let udp_bytes = client
        .send_to(&discover, &[255, 255, 255, 255], 67)
        .expect("send_to failed");
    println!("  [CLIENT] Sent DHCP Discover ({} UDP bytes)", udp_bytes.len());

    // Deliver to server
    server
        .deliver([0, 0, 0, 0], &udp_bytes)
        .expect("deliver failed");
    let dgram = server.recv_from().expect("recv_from failed");
    println!(
        "  [SERVER] Received DHCP Discover ({} bytes)",
        dgram.data.len()
    );
    println!();

    // ── Parse Discover ─────────────────────────────────────────────
    println!("─── Parsing DHCP Discover ──────────────────────────────");
    parse_dhcp_message(&dgram.data);
    println!();

    // ── DHCP Offer ─────────────────────────────────────────────────
    println!("─── DHCP Offer ─────────────────────────────────────────");
    let offer = build_dhcp_offer(
        0xDEADBEEF,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [10, 0, 0, 100],   // offered IP
        [10, 0, 0, 1],     // server IP
        [255, 255, 255, 0], // subnet mask
    );
    println!("  Offered IP:    10.0.0.100");
    println!("  Server IP:     10.0.0.1");
    println!("  Subnet mask:   255.255.255.0");

    let offer_udp = server
        .send_to(&offer, &[255, 255, 255, 255], 68)
        .expect("send_to failed");
    println!("  [SERVER] Sent DHCP Offer ({} UDP bytes)", offer_udp.len());
    println!();

    // ── Parse Offer ────────────────────────────────────────────────
    println!("─── Parsing DHCP Offer ───────────────────────────────────");
    parse_dhcp_message(&offer);
    println!();
    println!("  ✓ DHCP client example complete.");
}

/// Build a minimal DHCP Discover message.
fn build_dhcp_discover(xid: u32, chaddr: [u8; 6]) -> Vec<u8> {
    let mut buf = vec![0u8; 240]; // Minimum DHCP message size
    buf[0] = 1; // op: BOOTREQUEST
    buf[1] = 1; // htype: Ethernet
    buf[2] = 6; // hlen: 6
    buf[3] = 0; // hops
    buf[4..8].copy_from_slice(&xid.to_be_bytes()); // xid
    // secs, flags, ciaddr, yiaddr, siaddr, giaddr all zero
    buf[28..34].copy_from_slice(&chaddr); // chaddr (first 6 bytes)
    // Magic cookie
    buf[236..240].copy_from_slice(&[99, 130, 83, 99]);
    // Option 53: DHCP Message Type = 1 (Discover)
    buf.push(53); // option type
    buf.push(1);  // length
    buf.push(1);  // Discover
    // Option 255: End
    buf.push(255);
    buf
}

/// Build a minimal DHCP Offer message.
fn build_dhcp_offer(
    xid: u32,
    chaddr: [u8; 6],
    offered_ip: [u8; 4],
    server_ip: [u8; 4],
    subnet_mask: [u8; 4],
) -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = 2; // op: BOOTREPLY
    buf[1] = 1; // htype
    buf[2] = 6; // hlen
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&offered_ip); // yiaddr
    buf[20..24].copy_from_slice(&server_ip); // siaddr
    buf[28..34].copy_from_slice(&chaddr);
    buf[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie
    // Option 53: DHCP Message Type = 2 (Offer)
    buf.push(53);
    buf.push(1);
    buf.push(2);
    // Option 1: Subnet Mask
    buf.push(1);
    buf.push(4);
    buf.extend_from_slice(&subnet_mask);
    // Option 255: End
    buf.push(255);
    buf
}

fn parse_dhcp_message(data: &[u8]) {
    if data.len() < 240 {
        println!("  DHCP message too short ({} bytes)", data.len());
        return;
    }
    let op = match data[0] {
        1 => "BOOTREQUEST",
        2 => "BOOTREPLY",
        _ => "UNKNOWN",
    };
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let yiaddr = &data[16..20];
    let chaddr = &data[28..34];

    println!("  Op:           {}", op);
    println!("  Transaction:  0x{:08X}", xid);
    println!(
        "  Your IP:      {}.{}.{}.{}",
        yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]
    );
    println!(
        "  Client MAC:   {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]
    );

    // Parse options after magic cookie (offset 240)
    if data.len() > 240 {
        let mut i = 240;
        while i < data.len() && data[i] != 255 {
            let opt = data[i];
            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            if opt == 53 && len == 1 && i + 2 < data.len() {
                let msg_type = match data[i + 2] {
                    1 => "Discover",
                    2 => "Offer",
                    3 => "Request",
                    5 => "ACK",
                    _ => "Unknown",
                };
                println!("  DHCP Type:    {}", msg_type);
            }
            i += 2 + len;
        }
    }
}
