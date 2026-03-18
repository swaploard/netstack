//! # netstack — A production-grade TCP/IP networking stack
//!
//! This crate implements a modular, zero-copy TCP/IP networking stack
//! suitable for embedded systems, userspace networking, and education.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │           Socket API                │
//! │   tcp_socket · udp_socket           │
//! ├─────────────────────────────────────┤
//! │         Interface (iface)           │
//! │   poll · dispatch · arp_cache       │
//! ├─────────────────────────────────────┤
//! │         Wire Protocols              │
//! │  ethernet · arp · ipv4 · tcp · udp  │
//! ├─────────────────────────────────────┤
//! │         Physical (phy)              │
//! │   Device trait · loopback           │
//! ├─────────────────────────────────────┤
//! │       Buffers & Utilities           │
//! │  ring_buffer · packet_buffer · csum │
//! └─────────────────────────────────────┘
//! ```

pub mod error;
pub mod util;
pub mod buffer;
pub mod wire;
pub mod phy;
pub mod iface;
pub mod socket;
pub mod time;
