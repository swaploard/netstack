//! TCP server example — listens for a connection, receives data, and
//! sends a reply.
//!
//! Run with: `cargo run --example server`

use netstack::socket::tcp_socket::TcpSocket;
use netstack::socket::tcp::state::TcpState;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — TCP Server Example                  ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Listen for connections ─────────────────────────────────────
    println!("─── Listening on 10.0.0.2:80 ───────────────────────────");
    let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80)
        .expect("listen failed");
    println!("  [SERVER] state: {}", server.state());

    // Simulate a client connecting
    let (mut client, syn_bytes) = TcpSocket::tcp_connect(
        [10, 0, 0, 1], 50000,
        [10, 0, 0, 2], 80,
        1000,
    )
    .expect("client connect failed");

    // ── Accept connection ──────────────────────────────────────────
    println!();
    println!("─── Accepting Connection ───────────────────────────────");
    let syn_ack_bytes = server
        .accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000)
        .expect("accept failed");
    println!("  [SERVER] SYN-ACK sent     | state: {}", server.state());

    let ack_bytes = client
        .on_segment(&syn_ack_bytes)
        .expect("client SYN-ACK failed")
        .expect("expected ACK");
    server.on_segment(&ack_bytes).expect("server ACK failed");
    println!("  [SERVER] Connection open  | state: {}", server.state());
    assert_eq!(server.state(), TcpState::Established);
    println!();

    // ── Receive data from client ───────────────────────────────────
    println!("─── Receiving Data ───────────────────────────────────────");
    let message = b"Hello, server!";
    let data_seg = client
        .tcp_send(message)
        .expect("client send failed")
        .expect("expected segment");

    let ack = server.on_segment(&data_seg).expect("server data failed");
    if let Some(a) = ack {
        client.on_segment(&a).expect("client ack failed");
    }

    let mut recv_buf = [0u8; 256];
    let n = server.tcp_receive(&mut recv_buf).expect("receive failed");
    println!(
        "  [SERVER] Received {} bytes: \"{}\"",
        n,
        String::from_utf8_lossy(&recv_buf[..n])
    );

    // ── Send reply ─────────────────────────────────────────────────
    println!();
    println!("─── Sending Reply ────────────────────────────────────────");
    let reply = b"Hello, client!";
    let reply_seg = server
        .tcp_send(reply)
        .expect("server send failed")
        .expect("expected reply segment");
    println!("  [SERVER] Sent {} bytes: \"{}\"", reply.len(), String::from_utf8_lossy(reply));

    let ack_reply = client
        .on_segment(&reply_seg)
        .expect("client reply failed");
    if let Some(a) = ack_reply {
        server.on_segment(&a).expect("server ack failed");
    }

    let mut client_buf = [0u8; 256];
    let n = client.tcp_receive(&mut client_buf).expect("client recv failed");
    println!(
        "  [CLIENT] Received: \"{}\"",
        String::from_utf8_lossy(&client_buf[..n])
    );
    println!();

    // ── Teardown ───────────────────────────────────────────────────
    println!("─── Connection Teardown ──────────────────────────────────");
    let fin = client.close().expect("close failed");
    let ack_fin = server
        .on_segment(&fin)
        .expect("server FIN failed")
        .expect("expected ACK");
    client.on_segment(&ack_fin).expect("ack failed");
    let srv_fin = server.close().expect("server close failed");
    let fack = client
        .on_segment(&srv_fin)
        .expect("client FIN failed")
        .expect("expected final ACK");
    server.on_segment(&fack).expect("final ack failed");
    println!("  [SERVER] state: {} | [CLIENT] state: {}", server.state(), client.state());
    println!();
    println!("  ✓ Server example complete.");
}
