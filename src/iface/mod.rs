//! Network interface layer — packet dispatch and ARP cache.
//!
//! The interface sits between the physical device and the socket layer,
//! processing incoming frames through the protocol stack and transmitting
//! outgoing frames constructed by sockets.

pub mod arp_cache;
pub mod interface;
