/// Padding Module
///
/// Implements the padding rule used by Ascon algorithms:
/// pad(X, r) = X ∥ 1 ∥ 0^j where j = (-|X| - 1) mod r
///
/// This ensures the output length is a multiple of r bits.

/// Pad a byte slice to the specified block size (in bytes)
///
/// # Arguments
/// * `data` - The data to pad
/// * `block_size` - The target block size in bytes
///
/// # Returns
/// A vector containing the padded data
///
/// # Example
/// ```
/// let data = vec![0xFF, 0xFF];
/// let padded = pad(&data, 8);
/// // Result: [0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]
/// // In little-endian: 0xFF, 0xFF, then padding bit 1 (0x80), then zeros
/// ```
pub fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded = data.to_vec();

    // Add the '1' bit: append 0x80 (10000000 in binary)
    padded.push(0x80);

    // Add zeros until we reach a multiple of block_size
    while padded.len() % block_size != 0 {
        padded.push(0x00);
    }

    padded
}

/// Pad a u64 value (for integer-based implementations)
///
/// This function adds padding to an integer representing n bytes of data.
/// The result is a 64-bit value with padding applied.
///
/// # Arguments
/// * `value` - The integer value to pad
/// * `n_bytes` - Number of bytes represented (0-7)
///
/// # Returns
/// A 64-bit value with padding applied
///
/// # Example
/// For a value representing 2 bytes (0xFF, 0xFF):
/// ```
/// let padded = pad_u64(0x000000000000FFFF, 2);
/// // Result: 0x00000001000000FFFF (in little-endian representation)
/// ```
pub fn pad_u64(value: u64, n_bytes: usize) -> u64 {
    if n_bytes >= 8 {
        // No padding needed for full block
        return value;
    }

    // Add the padding bit '1' at the appropriate position
    // In little-endian: the padding bit goes after the last data byte
    value ^ (0x0000000000000001u64 << (n_bytes * 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_empty() {
        let data = vec![];
        let padded = pad(&data, 8);
        assert_eq!(padded.len(), 8);
        assert_eq!(padded[0], 0x80); // First byte should be the padding bit
        assert_eq!(&padded[1..], &[0x00; 7]);
    }

    #[test]
    fn test_pad_partial_block() {
        let data = vec![0xFF, 0xFF];
        let padded = pad(&data, 8);
        assert_eq!(padded.len(), 8);
        assert_eq!(padded[0], 0xFF);
        assert_eq!(padded[1], 0xFF);
        assert_eq!(padded[2], 0x80); // Padding bit
        assert_eq!(&padded[3..], &[0x00; 5]);
    }

    #[test]
    fn test_pad_full_block() {
        let data = vec![0xFF; 8];
        let padded = pad(&data, 8);
        // Should create a new block with just padding
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[0..8], &[0xFF; 8]);
        assert_eq!(padded[8], 0x80);
        assert_eq!(&padded[9..], &[0x00; 7]);
    }

    #[test]
    fn test_pad_u64() {
        // Test padding for different byte lengths
        assert_eq!(pad_u64(0x0000000000000000, 0), 0x0000000000000001);
        assert_eq!(pad_u64(0x00000000000000FF, 1), 0x00000000000001FF);
        assert_eq!(pad_u64(0x000000000000FFFF, 2), 0x000000000001FFFF);
        assert_eq!(pad_u64(0x0000000000FFFFFF, 3), 0x0000000001FFFFFF);
    }
}
