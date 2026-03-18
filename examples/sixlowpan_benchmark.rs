//! 6LoWPAN benchmark — measures IPHC header compression and
//! fragmentation throughput for low-power wireless scenarios.
//!
//! Run with: `cargo run --example sixlowpan_benchmark`

use std::time;

const ITERATIONS: usize = 100_000;
const MTU: usize = 127; // IEEE 802.15.4 max frame
const FRAG_HEADER: usize = 4;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║      netstack — 6LoWPAN Benchmark                      ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── IPHC compression benchmark ─────────────────────────────────
    println!("─── IPHC Compression Benchmark ───────────────────────────");
    println!("  Iterations: {}", ITERATIONS);
    println!();

    let payload_sizes: Vec<usize> = vec![8, 32, 64, 128];

    for &size in &payload_sizes {
        let payload = vec![0xAAu8; size];

        let start = time::Instant::now();
        let mut total_compressed = 0usize;
        for _ in 0..ITERATIONS {
            let compressed = compress_iphc(&payload);
            total_compressed += compressed.len();
        }
        let elapsed = start.elapsed();

        let full_hdr_size = 40; // Full IPv6 header
        let compressed_hdr = 2; // IPHC minimum
        let ratio = (1.0 - compressed_hdr as f64 / full_hdr_size as f64) * 100.0;

        println!(
            "  payload={:>4}B  compressed_total={:>8}B  ratio={:.1}%  time={:>8.3}ms  {:.2}M ops/s",
            size,
            total_compressed,
            ratio,
            elapsed.as_secs_f64() * 1000.0,
            ITERATIONS as f64 / elapsed.as_secs_f64() / 1_000_000.0,
        );
    }
    println!();

    // ── Fragmentation benchmark ────────────────────────────────────
    println!("─── Fragmentation Benchmark ──────────────────────────────");
    println!("  802.15.4 MTU: {} bytes", MTU);
    println!("  Iterations per size: {}", ITERATIONS);
    println!();

    let large_sizes: Vec<usize> = vec![100, 200, 500, 1280];

    for &size in &large_sizes {
        let payload = vec![0xBBu8; size];

        let start = time::Instant::now();
        let mut total_frags = 0usize;
        for _ in 0..ITERATIONS {
            let frags = fragment(&payload);
            total_frags += frags;
        }
        let elapsed = start.elapsed();

        let frags_per_pkt = total_frags / ITERATIONS;
        println!(
            "  payload={:>5}B  frags/pkt={:>2}  time={:>8.3}ms  {:.2}M ops/s",
            size,
            frags_per_pkt,
            elapsed.as_secs_f64() * 1000.0,
            ITERATIONS as f64 / elapsed.as_secs_f64() / 1_000_000.0,
        );
    }
    println!();

    // ── Reassembly benchmark ───────────────────────────────────────
    println!("─── Reassembly Benchmark ─────────────────────────────────");
    println!("  Iterations: {}", ITERATIONS);
    println!();

    for &size in &large_sizes {
        let payload = vec![0xCCu8; size];
        let fragments = create_fragments(&payload);

        let start = time::Instant::now();
        let mut _total_reassembled = 0usize;
        for _ in 0..ITERATIONS {
            let reassembled = reassemble(&fragments);
            _total_reassembled += reassembled.len();
        }
        let elapsed = start.elapsed();

        println!(
            "  payload={:>5}B  fragments={}  time={:>8.3}ms  {:.2}M ops/s",
            size,
            fragments.len(),
            elapsed.as_secs_f64() * 1000.0,
            ITERATIONS as f64 / elapsed.as_secs_f64() / 1_000_000.0,
        );
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Benchmark complete!                                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

/// Simulate IPHC compression.
fn compress_iphc(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.push(0x7A); // IPHC dispatch byte 1
    buf.push(0x33); // IPHC dispatch byte 2
    buf.extend_from_slice(payload);
    buf
}

/// Count fragments needed for a payload.
fn fragment(payload: &[u8]) -> usize {
    let frag_payload = MTU - FRAG_HEADER;
    (payload.len() + frag_payload - 1) / frag_payload
}

/// Create fragment buffers from a payload.
fn create_fragments(payload: &[u8]) -> Vec<Vec<u8>> {
    let frag_payload = MTU - FRAG_HEADER;
    let mut frags = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + frag_payload).min(payload.len());
        frags.push(payload[offset..end].to_vec());
        offset = end;
    }
    frags
}

/// Reassemble fragments back into the original payload.
fn reassemble(fragments: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = fragments.iter().map(|f| f.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for frag in fragments {
        buf.extend_from_slice(frag);
    }
    buf
}
