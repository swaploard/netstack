//! DNS example — demonstrates building and parsing a minimal DNS
//! query and response using the UDP socket layer.
//!
//! Run with: `cargo run --example dns`

use netstack::socket::udp_socket::UdpSocket;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — DNS Query Example                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Build a DNS query ──────────────────────────────────────────
    println!("─── Building DNS Query ────────────────────────────────");

    let client = UdpSocket::bind([10, 0, 0, 1], 12345);
    let mut dns_server = UdpSocket::bind([10, 0, 0, 2], 53);

    // Minimal DNS query for "example.com" A record
    let query = build_dns_query(0xABCD, b"\x07example\x03com\x00");
    println!("  Query for: example.com (A record)");
    println!("  Transaction ID: 0xABCD");
    println!("  Query size: {} bytes", query.len());
    println!();

    // ── Send the query ─────────────────────────────────────────────
    println!("─── Sending Query via UDP ─────────────────────────────");
    let udp_bytes = client
        .send_to(&query, &[10, 0, 0, 2], 53)
        .expect("send_to failed");
    println!("  [CLIENT] Sent UDP packet: {} bytes", udp_bytes.len());

    // Deliver to DNS server socket
    dns_server
        .deliver([10, 0, 0, 1], &udp_bytes)
        .expect("deliver failed");

    let datagram = dns_server.recv_from().expect("recv_from failed");
    println!(
        "  [SERVER] Received {} bytes from {}.{}.{}.{}:{}",
        datagram.data.len(),
        datagram.src_addr[0], datagram.src_addr[1],
        datagram.src_addr[2], datagram.src_addr[3],
        datagram.src_port,
    );
    println!();

    // ── Parse the query ────────────────────────────────────────────
    println!("─── Parsing DNS Query ──────────────────────────────────");
    parse_dns_header(&datagram.data);
    println!();

    // ── Build and send a response ──────────────────────────────────
    println!("─── Building DNS Response ────────────────────────────────");
    let response = build_dns_response(0xABCD, b"\x07example\x03com\x00", [93, 184, 216, 34]);
    println!("  Response: example.com → 93.184.216.34");
    println!("  Response size: {} bytes", response.len());

    let resp_udp = dns_server
        .send_to(&response, &[10, 0, 0, 1], 12345)
        .expect("send_to failed");
    println!("  [SERVER] Sent UDP response: {} bytes", resp_udp.len());
    println!();

    // ── Verify the response ────────────────────────────────────────
    println!("─── Parsing DNS Response ─────────────────────────────────");
    parse_dns_header(&response);

    // Extract the IP from the answer section (last 4 bytes)
    let ip = &response[response.len() - 4..];
    println!("  Resolved address: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    println!();
    println!("  ✓ DNS example complete.");
}

/// Build a minimal DNS query packet.
fn build_dns_query(transaction_id: u16, qname: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header (12 bytes)
    buf.extend_from_slice(&transaction_id.to_be_bytes()); // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT: 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0
    // Question
    buf.extend_from_slice(qname); // QNAME
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE: A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN
    buf
}

/// Build a minimal DNS response with a single A record answer.
fn build_dns_response(transaction_id: u16, qname: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header
    buf.extend_from_slice(&transaction_id.to_be_bytes());
    buf.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: response, recursion available
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question (echoed back)
    buf.extend_from_slice(qname);
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE: A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN
    // Answer
    buf.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Name pointer to offset 12
    buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE: A
    buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS: IN
    buf.extend_from_slice(&300u32.to_be_bytes()); // TTL: 300s
    buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH: 4
    buf.extend_from_slice(&ip); // RDATA: IP address
    buf
}

fn parse_dns_header(data: &[u8]) {
    if data.len() < 12 {
        println!("  DNS packet too short");
        return;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    println!("  Transaction ID: 0x{:04X}", id);
    println!("  Type:           {}", if qr == 0 { "Query" } else { "Response" });
    println!("  Questions:      {}", qdcount);
    println!("  Answers:        {}", ancount);
}
