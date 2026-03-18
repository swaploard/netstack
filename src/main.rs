//! # netstack — TCP/IP Stack Demo
//!
//! Demonstrates a complete TCP three-way handshake, bidirectional data
//! transfer, and connection teardown using the socket API.

use netstack::socket::tcp_socket::TcpSocket;
use netstack::socket::tcp::state::TcpState;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — TCP/IP Stack Demo                   ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Three-way handshake ──────────────────────────────────────

    println!("─── Phase 1: TCP Three-Way Handshake ─────────────────────");
    println!();

    // Client: active open → SYN
    let (mut client, syn_bytes) = TcpSocket::tcp_connect(
        [10, 0, 0, 1], 50000,
        [10, 0, 0, 2], 80,
        1000, // Initial Sequence Number
    )
    .expect("client connect failed");
    println!("  [CLIENT] SYN sent         | state: {}", client.state());

    // Server: passive open + accept SYN → SYN-ACK
    let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80)
        .expect("server listen failed");
    println!("  [SERVER] Listening         | state: {}", server.state());

    let syn_ack_bytes = server
        .accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000)
        .expect("server accept failed");
    println!("  [SERVER] SYN-ACK sent      | state: {}", server.state());

    // Client: receives SYN-ACK → ACK
    let ack_bytes = client
        .on_segment(&syn_ack_bytes)
        .expect("client SYN-ACK processing failed")
        .expect("expected ACK segment");
    println!("  [CLIENT] ACK sent          | state: {}", client.state());

    // Server: receives ACK → ESTABLISHED
    server
        .on_segment(&ack_bytes)
        .expect("server ACK processing failed");
    println!("  [SERVER] Connection open   | state: {}", server.state());

    assert_eq!(client.state(), TcpState::Established);
    assert_eq!(server.state(), TcpState::Established);
    println!();
    println!("  ✓ Handshake complete — both sides ESTABLISHED");

    // ── Data transfer ────────────────────────────────────────────

    println!();
    println!("─── Phase 2: Data Transfer ─────────────────────────────");
    println!();

    // Client → Server
    let message = b"Hello from the netstack TCP client!";
    let data_seg = client
        .tcp_send(message)
        .expect("client send failed")
        .expect("expected data segment");
    println!("  [CLIENT] Sent {} bytes: \"{}\"", message.len(), String::from_utf8_lossy(message));

    let ack_response = server
        .on_segment(&data_seg)
        .expect("server data processing failed");
    assert!(ack_response.is_some());

    let mut recv_buf = [0u8; 256];
    let n = server.tcp_receive(&mut recv_buf).expect("server receive failed");
    println!("  [SERVER] Received {} bytes: \"{}\"", n, String::from_utf8_lossy(&recv_buf[..n]));
    assert_eq!(&recv_buf[..n], message);

    // Server → Client
    let reply = b"Hello from the netstack TCP server!";
    let reply_seg = server
        .tcp_send(reply)
        .expect("server send failed")
        .expect("expected reply segment");
    println!("  [SERVER] Sent {} bytes: \"{}\"", reply.len(), String::from_utf8_lossy(reply));

    let ack_for_reply = client
        .on_segment(&reply_seg)
        .expect("client reply processing failed");
    assert!(ack_for_reply.is_some());

    let mut client_recv = [0u8; 256];
    let n = client.tcp_receive(&mut client_recv).expect("client receive failed");
    println!("  [CLIENT] Received {} bytes: \"{}\"", n, String::from_utf8_lossy(&client_recv[..n]));
    assert_eq!(&client_recv[..n], reply);

    println!();
    println!("  ✓ Bidirectional data transfer successful");

    // ── Connection teardown ──────────────────────────────────────

    println!();
    println!("─── Phase 3: Connection Teardown ─────────────────────────");
    println!();

    // Client initiates close → FIN
    let fin_bytes = client.close().expect("client close failed");
    println!("  [CLIENT] FIN sent          | state: {}", client.state());

    // Server receives FIN → CloseWait
    let ack_for_fin = server
        .on_segment(&fin_bytes)
        .expect("server FIN processing failed")
        .expect("expected ACK for FIN");
    println!("  [SERVER] ACK for FIN sent  | state: {}", server.state());

    // Client receives ACK → FinWait2
    client
        .on_segment(&ack_for_fin)
        .expect("client ACK processing failed");
    println!("  [CLIENT] FIN ACKed         | state: {}", client.state());

    // Server closes → FIN
    let server_fin = server.close().expect("server close failed");
    println!("  [SERVER] FIN sent          | state: {}", server.state());

    // Client receives server FIN → TimeWait
    let final_ack = client
        .on_segment(&server_fin)
        .expect("client server-FIN processing failed")
        .expect("expected final ACK");
    println!("  [CLIENT] Final ACK sent    | state: {}", client.state());

    // Server receives final ACK → Closed
    server
        .on_segment(&final_ack)
        .expect("server final ACK processing failed");
    println!("  [SERVER] Connection closed | state: {}", server.state());

    assert_eq!(client.state(), TcpState::TimeWait);
    assert_eq!(server.state(), TcpState::Closed);

    println!();
    println!("  ✓ Connection teardown complete");
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  All phases completed successfully!                     ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}
