//! Tcpdump example — captures and dissects raw frames through
//! the protocol stack, similar to the `tcpdump` CLI tool.
//!
//! Run with: `cargo run --example tcpdump`

use netstack::phy::loopback::LoopbackDevice;
use netstack::phy::Device;
use netstack::wire::ethernet::{self, EthernetFrame};
use netstack::wire::arp::{self, ArpPacket, ArpOperation};
use netstack::wire::ipv4::{self, Ipv4Packet};
use netstack::wire::tcp::{self, TcpPacket};
use netstack::wire::udp::{self, UdpPacket};
use netstack::wire::mac::MacAddress;
use netstack::wire::{EtherType, IpProtocol};

fn main() {
    println!("╔═════════════════════════════════════════╗");
    println!("║    netstack — tcpdump Example           ║");
    println!("╚═════════════════════════════════════════╝");
    println!();

    let mut dev = LoopbackDevice::new(1500);

    // Inject test frames
    let src_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let dst_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

    // 1) ARP request
    inject_arp(&mut dev, src_mac);
    // 2) TCP SYN
    inject_tcp(&mut dev, src_mac, dst_mac, 0x02, b"");
    // 3) UDP
    inject_udp(&mut dev, src_mac, dst_mac, b"DNS query");
    // 4) TCP PSH+ACK with payload
    inject_tcp(&mut dev, src_mac, dst_mac, 0x18, b"GET / HTTP/1.1\r\n");

    println!("  Injected 4 frames.\n");

    // Capture loop
    let mut buf = [0u8; 2048];
    let mut pkt = 0u32;
    while dev.pending() > 0 {
        let n = dev.recv(&mut buf).unwrap();
        pkt += 1;
        println!("── Packet #{} ({} bytes) ──", pkt, n);
        dissect(&buf[..n]);
        println!();
    }
    println!("  Captured {} packets. Done.", pkt);
}

fn dissect(data: &[u8]) {
    let eth = EthernetFrame::new(data).expect("eth parse");
    println!("  {} → {}  type=0x{:04X}", eth.src_addr(), eth.dst_addr(), eth.ethertype_raw());
    match eth.ethertype() {
        Some(EtherType::Arp) => dissect_arp(eth.payload()),
        Some(EtherType::Ipv4) => dissect_ipv4(eth.payload()),
        _ => println!("  [unknown ethertype]"),
    }
}

fn dissect_arp(data: &[u8]) {
    let p = ArpPacket::new(data).expect("arp parse");
    let spa = p.sender_proto_addr();
    let tpa = p.target_proto_addr();
    let op = match p.operation() {
        Some(ArpOperation::Request) => "REQUEST",
        Some(ArpOperation::Reply) => "REPLY",
        None => "?",
    };
    println!("  ARP {} {}.{}.{}.{} → {}.{}.{}.{}",
        op, spa[0], spa[1], spa[2], spa[3],
        tpa[0], tpa[1], tpa[2], tpa[3]);
}

fn dissect_ipv4(data: &[u8]) {
    let ip = Ipv4Packet::new(data).expect("ipv4 parse");
    let s = ip.src_addr(); let d = ip.dst_addr();
    println!("  IPv4 {}.{}.{}.{} → {}.{}.{}.{}  ttl={} len={}",
        s[0],s[1],s[2],s[3], d[0],d[1],d[2],d[3], ip.ttl(), ip.total_len());
    match IpProtocol::from_u8(ip.protocol()) {
        Some(IpProtocol::Tcp) => dissect_tcp(ip.payload()),
        Some(IpProtocol::Udp) => dissect_udp(ip.payload()),
        _ => println!("  proto={}", ip.protocol()),
    }
}

fn dissect_tcp(data: &[u8]) {
    let t = TcpPacket::new(data).expect("tcp parse");
    let mut fl = String::new();
    if t.syn() { fl.push_str("SYN "); }
    if t.ack() { fl.push_str("ACK "); }
    if t.fin() { fl.push_str("FIN "); }
    if t.psh() { fl.push_str("PSH "); }
    if t.rst() { fl.push_str("RST "); }
    println!("  TCP {} → {} [{}] seq={} ack={} win={}",
        t.src_port(), t.dst_port(), fl.trim(), t.seq_number(), t.ack_number(), t.window());
    if !t.payload().is_empty() {
        println!("  payload({})=\"{}\"", t.payload().len(), String::from_utf8_lossy(t.payload()));
    }
}

fn dissect_udp(data: &[u8]) {
    let u = UdpPacket::new(data).expect("udp parse");
    println!("  UDP {} → {} len={}", u.src_port(), u.dst_port(), u.length());
    if !u.payload().is_empty() {
        println!("  payload({})=\"{}\"", u.payload().len(), String::from_utf8_lossy(u.payload()));
    }
}

fn inject_arp(dev: &mut LoopbackDevice, src_mac: MacAddress) {
    let mut buf = vec![0u8; ethernet::HEADER_LEN + arp::HEADER_LEN];
    arp::build_arp_ipv4(
        &mut buf[ethernet::HEADER_LEN..], ArpOperation::Request,
        src_mac, [10,0,0,1], MacAddress::UNSPECIFIED, [10,0,0,2],
    ).unwrap();
    let payload = buf[ethernet::HEADER_LEN..].to_vec();
    ethernet::build_frame(&mut buf, MacAddress::BROADCAST, src_mac, EtherType::Arp, &payload).unwrap();
    dev.send(&buf).unwrap();
}

fn inject_tcp(dev: &mut LoopbackDevice, src_mac: MacAddress, dst_mac: MacAddress, flags: u8, payload: &[u8]) {
    let mut tcp_buf = vec![0u8; tcp::MIN_HEADER_LEN + payload.len()];
    let tl = tcp::build_tcp(&mut tcp_buf, 50000, 80, 1000, 0, flags, 65535, payload, &[10,0,0,1], &[10,0,0,2]).unwrap();
    let mut ip_buf = vec![0u8; ipv4::MIN_HEADER_LEN + tl];
    let il = ipv4::build_ipv4(&mut ip_buf, [10,0,0,1], [10,0,0,2], 6, 64, 0, &tcp_buf[..tl]).unwrap();
    let mut frame = vec![0u8; ethernet::HEADER_LEN + il];
    ethernet::build_frame(&mut frame, dst_mac, src_mac, EtherType::Ipv4, &ip_buf[..il]).unwrap();
    dev.send(&frame).unwrap();
}

fn inject_udp(dev: &mut LoopbackDevice, src_mac: MacAddress, dst_mac: MacAddress, payload: &[u8]) {
    let mut ubuf = vec![0u8; udp::HEADER_LEN + payload.len()];
    let ul = udp::build_udp(&mut ubuf, 12345, 53, payload, &[10,0,0,1], &[10,0,0,2]).unwrap();
    let mut ip_buf = vec![0u8; ipv4::MIN_HEADER_LEN + ul];
    let il = ipv4::build_ipv4(&mut ip_buf, [10,0,0,1], [10,0,0,2], 17, 64, 0, &ubuf[..ul]).unwrap();
    let mut frame = vec![0u8; ethernet::HEADER_LEN + il];
    ethernet::build_frame(&mut frame, dst_mac, src_mac, EtherType::Ipv4, &ip_buf[..il]).unwrap();
    dev.send(&frame).unwrap();
}
