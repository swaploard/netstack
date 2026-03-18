//! Benchmark: measures TCP throughput via the socket API.
//!
//! Performs a bulk data transfer from client to server through the
//! netstack socket API and reports the achieved throughput.
//!
//! Run with: `cargo run --example benchmark`

use netstack::socket::tcp_socket::TcpSocket;
use netstack::socket::tcp::state::TcpState;
use std::time;

const TOTAL_BYTES: usize = 1024 * 1024; // 1 MiB
const CHUNK_SIZE: usize = 1400;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — TCP Throughput Benchmark            ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Set up connection ──────────────────────────────────────────
    let (mut client, syn_bytes) = TcpSocket::tcp_connect(
        [10, 0, 0, 1], 50000,
        [10, 0, 0, 2], 80,
        1000,
    )
    .expect("client connect failed");

    let mut server = TcpSocket::tcp_listen([10, 0, 0, 2], 80)
        .expect("server listen failed");

    let syn_ack_bytes = server
        .accept(&syn_bytes, [10, 0, 0, 1], 50000, 2000)
        .expect("server accept failed");

    let ack_bytes = client
        .on_segment(&syn_ack_bytes)
        .expect("client SYN-ACK processing failed")
        .expect("expected ACK segment");

    server
        .on_segment(&ack_bytes)
        .expect("server ACK processing failed");

    assert_eq!(client.state(), TcpState::Established);
    assert_eq!(server.state(), TcpState::Established);
    println!("  Connection established.");
    println!();

    // ── Bulk data transfer ─────────────────────────────────────────
    let payload = vec![0xABu8; CHUNK_SIZE];
    let mut bytes_sent: usize = 0;
    let mut chunks = 0u64;

    println!("  Transferring {} bytes in {}-byte chunks...", TOTAL_BYTES, CHUNK_SIZE);
    let start = time::Instant::now();

    while bytes_sent < TOTAL_BYTES {
        let data_seg = client
            .tcp_send(&payload)
            .expect("client send failed")
            .expect("expected data segment");

        let ack_response = server
            .on_segment(&data_seg)
            .expect("server data processing failed");

        if let Some(ack) = ack_response {
            client
                .on_segment(&ack)
                .expect("client ACK processing failed");
        }

        let mut recv_buf = [0u8; 2048];
        let n = server.tcp_receive(&mut recv_buf).expect("server receive failed");
        bytes_sent += n;
        chunks += 1;
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let throughput_mbps = (bytes_sent as f64 / 1_000_000.0) / secs;

    println!();
    println!("  ── Results ──────────────────────────────────────────");
    println!("  Total bytes transferred: {}", bytes_sent);
    println!("  Chunks sent:             {}", chunks);
    println!("  Elapsed time:            {:.3} ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Throughput:              {:.2} MB/s", throughput_mbps);
    println!();

    // ── Teardown ───────────────────────────────────────────────────
    let fin_bytes = client.close().expect("client close failed");
    let ack_for_fin = server
        .on_segment(&fin_bytes)
        .expect("server FIN processing failed")
        .expect("expected ACK for FIN");
    client
        .on_segment(&ack_for_fin)
        .expect("client ACK processing failed");
    let server_fin = server.close().expect("server close failed");
    let final_ack = client
        .on_segment(&server_fin)
        .expect("client server-FIN processing failed")
        .expect("expected final ACK");
    server
        .on_segment(&final_ack)
        .expect("server final ACK processing failed");

    println!("  Connection closed cleanly.");
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Benchmark complete!                                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}
