//! RFC 1071 Internet Checksum implementation.
//!
//! Used by IPv4, TCP, and UDP for header and data integrity verification.
//! The algorithm computes a ones-complement sum over 16-bit words.

/// Compute the RFC 1071 internet checksum over the given byte slice.
///
/// Returns the ones-complement of the ones-complement sum of all 16-bit
/// words in `data`. If `data` has an odd length, it is padded with a
/// trailing zero byte.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = raw_checksum(data);
    fold_checksum(&mut sum);
    !sum as u16
}

/// Verify that a checksum over `data` (which includes the checksum field)
/// produces the expected zero result.
pub fn verify_checksum(data: &[u8]) -> bool {
    let mut sum = raw_checksum(data);
    fold_checksum(&mut sum);
    sum == 0xffff
}

/// Compute the pseudo-header checksum contribution for TCP/UDP over IPv4.
///
/// The pseudo-header consists of:
/// - source IP (4 bytes)
/// - destination IP (4 bytes)
/// - zero byte + protocol (2 bytes)
/// - transport length (2 bytes)
pub fn pseudo_header_checksum(
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
    protocol: u8,
    length: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source address
    sum += u16::from_be_bytes([src_addr[0], src_addr[1]]) as u32;
    sum += u16::from_be_bytes([src_addr[2], src_addr[3]]) as u32;

    // Destination address
    sum += u16::from_be_bytes([dst_addr[0], dst_addr[1]]) as u32;
    sum += u16::from_be_bytes([dst_addr[2], dst_addr[3]]) as u32;

    // Protocol (zero-padded to 16 bits)
    sum += protocol as u32;

    // Transport-layer length
    sum += length as u32;

    sum
}

/// Combine a raw sum with a pseudo-header partial sum and finalize.
pub fn combine_checksums(raw_sum: u32, pseudo_sum: u32) -> u16 {
    let mut sum = raw_sum + pseudo_sum;
    fold_checksum(&mut sum);
    !sum as u16
}

/// Compute the raw (unfolded) ones-complement sum.
fn raw_checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 16-bit words
    while i + 1 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle trailing odd byte
    if i < len {
        sum += (data[i] as u32) << 8;
    }

    sum
}

/// Fold 32-bit accumulator into 16 bits.
fn fold_checksum(sum: &mut u32) {
    while *sum >> 16 != 0 {
        *sum = (*sum & 0xffff) + (*sum >> 16);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_rfc_example() {
        // RFC 1071 example: 0x0001 + 0x00f2 + ... etc.
        let data: [u8; 8] = [0x00, 0x01, 0x00, 0xf2, 0x00, 0x03, 0x00, 0xf4];
        let csum = internet_checksum(&data);
        // Verify that appending the checksum yields valid
        let mut check_data = data.to_vec();
        check_data.extend_from_slice(&csum.to_be_bytes());
        assert!(verify_checksum(&check_data));
    }

    #[test]
    fn test_checksum_zeros() {
        let data = [0u8; 20];
        let csum = internet_checksum(&data);
        assert_eq!(csum, 0xffff);
    }

    #[test]
    fn test_checksum_odd_length() {
        let data: [u8; 3] = [0x01, 0x02, 0x03];
        let csum = internet_checksum(&data);
        // Should still produce a valid checksum
        assert_ne!(csum, 0);
    }

    #[test]
    fn test_pseudo_header_checksum() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let sum = pseudo_header_checksum(&src, &dst, 6, 20); // TCP, 20 bytes
        assert!(sum > 0);
    }

    #[test]
    fn test_verify_valid_ipv4_header() {
        // Minimal IPv4 header with correct checksum
        let mut header = [0u8; 20];
        header[0] = 0x45; // Version 4, IHL 5
        header[8] = 64;   // TTL
        header[9] = 6;    // Protocol: TCP
        header[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        header[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        // Total length
        header[2] = 0;
        header[3] = 20;
        // Compute and embed checksum
        let csum = internet_checksum(&header);
        header[10] = (csum >> 8) as u8;
        header[11] = csum as u8;
        assert!(verify_checksum(&header));
    }
}
