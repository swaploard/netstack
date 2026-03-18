//! HTTP client example — demonstrates sending an HTTP/1.1 GET request
//! and receiving a response using the TCP socket API.
//!
//! Run with: `cargo run --example httpclient`

use netstack::socket::tcp_socket::TcpSocket;
use netstack::socket::tcp::state::TcpState;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — HTTP Client Example                 ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Establish connection ───────────────────────────────────────
    println!("─── Connecting to 10.0.0.2:80 ──────────────────────────");
    let (mut client, syn_bytes) = TcpSocket::tcp_connect(
        [10, 0, 0, 1], 50000,
        [10, 0, 0, 2], 80,
        1000,
    )
    .expect("connect failed");

    let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80).expect("listen failed");
    let syn_ack = server
        .accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000)
        .expect("accept failed");
    let ack = client
        .on_segment(&syn_ack)
        .expect("failed")
        .expect("expected ACK");
    server.on_segment(&ack).expect("failed");

    assert_eq!(client.state(), TcpState::Established);
    println!("  Connected!");
    println!();

    // ── Send HTTP request ──────────────────────────────────────────
    println!("─── HTTP Request ─────────────────────────────────────────");
    let request = b"GET /index.html HTTP/1.1\r\n\
                    Host: 10.0.0.2\r\n\
                    User-Agent: netstack/0.1\r\n\
                    Accept: text/html\r\n\
                    Connection: close\r\n\
                    \r\n";

    let data_seg = client
        .tcp_send(request)
        .expect("send failed")
        .expect("segment");
    println!("  [CLIENT →]");
    for line in String::from_utf8_lossy(request).lines() {
        println!("    {}", line);
    }
    println!();

    // Server receives the request
    let s_ack = server.on_segment(&data_seg).expect("failed");
    if let Some(a) = s_ack {
        client.on_segment(&a).expect("failed");
    }
    let mut req_buf = [0u8; 1024];
    let n = server.tcp_receive(&mut req_buf).expect("recv failed");
    println!("  [← SERVER] Received {} bytes", n);
    println!();

    // ── Send HTTP response ─────────────────────────────────────────
    println!("─── HTTP Response ────────────────────────────────────────");
    let body = "<html><body><h1>Hello from netstack!</h1></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Server: netstack/0.1\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body,
    );

    let resp_seg = server
        .tcp_send(response.as_bytes())
        .expect("send failed")
        .expect("segment");

    let c_ack = client.on_segment(&resp_seg).expect("failed");
    if let Some(a) = c_ack {
        server.on_segment(&a).expect("failed");
    }

    let mut resp_buf = [0u8; 2048];
    let n = client.tcp_receive(&mut resp_buf).expect("recv failed");
    println!("  [← CLIENT] Received {} bytes", n);
    println!();
    for line in String::from_utf8_lossy(&resp_buf[..n]).lines() {
        println!("    {}", line);
    }
    println!();

    // ── Close ──────────────────────────────────────────────────────
    println!("─── Closing Connection ───────────────────────────────────");
    let fin = client.close().expect("close failed");
    let ack_fin = server.on_segment(&fin).expect("failed").expect("ack");
    client.on_segment(&ack_fin).expect("failed");
    let srv_fin = server.close().expect("close failed");
    let fack = client.on_segment(&srv_fin).expect("failed").expect("ack");
    server.on_segment(&fack).expect("failed");
    println!("  Connection closed.");
    println!();
    println!("  ✓ HTTP client example complete.");
}
