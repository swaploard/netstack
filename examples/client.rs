//! TCP client example — connects to a server, sends a message, and
//! receives a reply.
//!
//! Run with: `cargo run --example client`

use netstack::socket::tcp_socket::TcpSocket;
use netstack::socket::tcp::state::TcpState;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — TCP Client Example                  ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Connect to server ──────────────────────────────────────────
    println!("─── Connecting to 10.0.0.2:80 ──────────────────────────");
    let (mut client, syn_bytes) = TcpSocket::tcp_connect(
        [10, 0, 0, 1], 50000,
        [10, 0, 0, 2], 80,
        1000,
    )
    .expect("connect failed");
    println!("  [CLIENT] SYN sent         | state: {}", client.state());

    // Simulate the server side for this example
    let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80)
        .expect("server listen failed");

    let syn_ack_bytes = server
        .accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000)
        .expect("server accept failed");

    let ack_bytes = client
        .on_segment(&syn_ack_bytes)
        .expect("client SYN-ACK processing failed")
        .expect("expected ACK");
    println!("  [CLIENT] Connected        | state: {}", client.state());

    server.on_segment(&ack_bytes).expect("server ACK failed");

    assert_eq!(client.state(), TcpState::Established);
    println!();

    // ── Send request ───────────────────────────────────────────────
    println!("─── Sending Request ──────────────────────────────────────");
    let request = b"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n";
    let data_seg = client
        .tcp_send(request)
        .expect("send failed")
        .expect("expected data segment");
    println!("  [CLIENT] Sent {} bytes", request.len());

    // Server receives and replies
    let ack = server.on_segment(&data_seg).expect("server data failed");
    if let Some(a) = ack {
        client.on_segment(&a).expect("client ack failed");
    }
    let mut recv_buf = [0u8; 512];
    let n = server.tcp_receive(&mut recv_buf).expect("server recv failed");
    println!("  [SERVER] Received: \"{}\"", String::from_utf8_lossy(&recv_buf[..n]));

    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    let reply_seg = server
        .tcp_send(reply)
        .expect("server send failed")
        .expect("expected reply segment");

    let ack_reply = client
        .on_segment(&reply_seg)
        .expect("client reply processing failed");
    if let Some(a) = ack_reply {
        server.on_segment(&a).expect("server ack failed");
    }

    let mut client_recv = [0u8; 512];
    let n = client.tcp_receive(&mut client_recv).expect("client recv failed");
    println!("  [CLIENT] Received: \"{}\"", String::from_utf8_lossy(&client_recv[..n]));
    println!();

    // ── Close connection ───────────────────────────────────────────
    println!("─── Closing Connection ───────────────────────────────────");
    let fin_bytes = client.close().expect("close failed");
    let ack_for_fin = server
        .on_segment(&fin_bytes)
        .expect("server FIN failed")
        .expect("expected ACK");
    client.on_segment(&ack_for_fin).expect("client ack failed");
    let server_fin = server.close().expect("server close failed");
    let final_ack = client
        .on_segment(&server_fin)
        .expect("client FIN failed")
        .expect("expected final ACK");
    server.on_segment(&final_ack).expect("server final ack failed");
    println!("  [CLIENT] state: {}", client.state());
    println!("  [SERVER] state: {}", server.state());
    println!();
    println!("  ✓ Done");
}
