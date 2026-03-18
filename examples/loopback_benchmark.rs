//! Loopback benchmark — measures raw frame throughput of the loopback
//! device without any protocol overhead.
//!
//! Run with: `cargo run --example loopback_benchmark`

use netstack::phy::loopback::LoopbackDevice;
use netstack::phy::Device;
use std::time;

const FRAME_SIZE: usize = 1500;
const NUM_FRAMES: usize = 100_000;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║      netstack — Loopback Device Benchmark              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let mut dev = LoopbackDevice::new(FRAME_SIZE);
    let frame = vec![0xAAu8; FRAME_SIZE];
    let mut recv_buf = vec![0u8; FRAME_SIZE + 64];

    // ── Send benchmark ─────────────────────────────────────────────
    println!("─── Send Benchmark ─────────────────────────────────────");
    println!("  Sending {} frames of {} bytes each...", NUM_FRAMES, FRAME_SIZE);

    let start = time::Instant::now();
    for _ in 0..NUM_FRAMES {
        dev.send(&frame).expect("send failed");
    }
    let send_elapsed = start.elapsed();

    println!(
        "  Send: {:.3} ms ({:.2} Mframes/s, {:.2} Gbit/s)",
        send_elapsed.as_secs_f64() * 1000.0,
        NUM_FRAMES as f64 / send_elapsed.as_secs_f64() / 1_000_000.0,
        (NUM_FRAMES as f64 * FRAME_SIZE as f64 * 8.0)
            / send_elapsed.as_secs_f64()
            / 1_000_000_000.0,
    );

    // ── Receive benchmark ──────────────────────────────────────────
    println!();
    println!("─── Receive Benchmark ────────────────────────────────────");
    println!("  Receiving {} frames...", dev.pending());

    let start = time::Instant::now();
    let mut received = 0usize;
    while dev.pending() > 0 {
        let n = dev.recv(&mut recv_buf).expect("recv failed");
        received += n;
    }
    let recv_elapsed = start.elapsed();

    println!(
        "  Recv: {:.3} ms ({:.2} Mframes/s, {:.2} Gbit/s)",
        recv_elapsed.as_secs_f64() * 1000.0,
        NUM_FRAMES as f64 / recv_elapsed.as_secs_f64() / 1_000_000.0,
        (received as f64 * 8.0) / recv_elapsed.as_secs_f64() / 1_000_000_000.0,
    );

    // ── Round-trip benchmark ───────────────────────────────────────
    println!();
    println!("─── Round-Trip Benchmark ─────────────────────────────────");
    println!("  Send-then-receive for {} frames...", NUM_FRAMES);

    let start = time::Instant::now();
    for _ in 0..NUM_FRAMES {
        dev.send(&frame).expect("send failed");
        dev.recv(&mut recv_buf).expect("recv failed");
    }
    let rt_elapsed = start.elapsed();

    println!(
        "  Round-trip: {:.3} ms ({:.2} Mframes/s, {:.0} ns/frame)",
        rt_elapsed.as_secs_f64() * 1000.0,
        NUM_FRAMES as f64 / rt_elapsed.as_secs_f64() / 1_000_000.0,
        rt_elapsed.as_nanos() as f64 / NUM_FRAMES as f64,
    );

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Benchmark complete!                                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}
