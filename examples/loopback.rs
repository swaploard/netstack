//! Loopback device example — demonstrates sending and receiving
//! frames through the loopback device.
//!
//! Run with: `cargo run --example loopback`

use netstack::phy::loopback::LoopbackDevice;
use netstack::phy::Device;
use std::sync::atomic::{AtomicU64, Ordering};

static TIMESTAMP: AtomicU64 = AtomicU64::new(0);

fn next_timestamp() -> u64 {
    TIMESTAMP.fetch_add(1, Ordering::Relaxed)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          netstack — Loopback Device Example             ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let mut dev = LoopbackDevice::new(1500);
    println!("  Created loopback device (MTU: {})", dev.mtu());
    println!();

    // ── Send some frames ───────────────────────────────────────────
    println!("─── Sending Frames ─────────────────────────────────────");
    let frames: Vec<&[u8]> = vec![
        b"Frame 1: Hello, loopback!",
        b"Frame 2: Testing the device.",
        b"Frame 3: Last frame.",
    ];

    for (i, frame) in frames.iter().enumerate() {
        let ts = next_timestamp();
        dev.send(frame).expect("send failed");
        println!("  [TX] ts={} frame {}: {} bytes", ts, i + 1, frame.len());
    }

    println!();
    println!("  Pending frames in queue: {}", dev.pending());
    println!();

    // ── Receive all frames ─────────────────────────────────────────
    println!("─── Receiving Frames ───────────────────────────────────");
    let mut buf = [0u8; 2048];
    let mut count = 0;

    while dev.pending() > 0 {
        let ts = next_timestamp();
        match dev.recv(&mut buf) {
            Ok(n) => {
                count += 1;
                println!(
                    "  [RX] ts={} frame {}: {} bytes — \"{}\"",
                    ts,
                    count,
                    n,
                    String::from_utf8_lossy(&buf[..n])
                );
            }
            Err(e) => {
                println!("  [RX] Error: {}", e);
                break;
            }
        }
    }

    println!();
    println!("  Total frames received: {}", count);
    println!("  Pending after drain:   {}", dev.pending());
    println!();

    // ── Empty receive attempt ──────────────────────────────────────
    println!("─── Empty Receive Attempt ────────────────────────────────");
    match dev.recv(&mut buf) {
        Ok(n) => println!("  Unexpected: received {} bytes", n),
        Err(e) => println!("  Expected error: {}", e),
    }

    println!();
    println!("  ✓ Loopback example complete.");
}
