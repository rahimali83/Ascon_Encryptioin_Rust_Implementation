/// Parsing Module
///
/// Implements the parse function used by Ascon algorithms:
/// parse(X, r) splits bitstring X into blocks of r bits
///
/// Returns: (X0, X1, ..., X_{ℓ-1}, X̃_ℓ)
/// where each Xi has length r, and 0 ≤ |X̃_ℓ| < r

/// Parse data into blocks of the specified size
///
/// # Arguments
/// * `data` - The data to parse
/// * `block_size` - Block size in bytes
///
/// # Returns
/// A vector of byte slices, where all but the last have length `block_size`.
/// The last slice may be shorter (partial block).
///
/// # Example
/// ```
/// let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
/// let blocks = parse(&data, 4);
/// // Result: [[1,2,3,4], [5,6,7,8], [9,10]]
/// ```
pub fn parse(data: &[u8], block_size: usize) -> Vec<&[u8]> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        blocks.push(&data[offset..end]);
        offset = end;
    }

    blocks
}

/// Parse data into owned blocks (returns Vec<Vec<u8>> instead of Vec<&[u8]>)
///
/// This is useful when you need to modify the blocks or when the lifetime
/// of the original data doesn't work.
pub fn parse_owned(data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        blocks.push(data[offset..end].to_vec());
        offset = end;
    }

    blocks
}

/// Get the number of full blocks and the size of the partial block
///
/// # Returns
/// (number of full blocks, size of partial block in bytes)
pub fn block_info(data_len: usize, block_size: usize) -> (usize, usize) {
    let full_blocks = data_len / block_size;
    let partial_size = data_len % block_size;
    (full_blocks, partial_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let data = vec![];
        let blocks = parse(&data, 8);
        assert_eq!(blocks.len(), 0);
    }

    #[test]
    fn test_parse_exact_blocks() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let blocks = parse(&data, 4);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], &[1, 2, 3, 4]);
        assert_eq!(blocks[1], &[5, 6, 7, 8]);
    }

    #[test]
    fn test_parse_partial_block() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let blocks = parse(&data, 4);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], &[1, 2, 3, 4]);
        assert_eq!(blocks[1], &[5, 6, 7, 8]);
        assert_eq!(blocks[2], &[9, 10]);
    }

    #[test]
    fn test_parse_single_block() {
        let data = vec![1, 2, 3];
        let blocks = parse(&data, 8);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], &[1, 2, 3]);
    }

    #[test]
    fn test_block_info() {
        assert_eq!(block_info(0, 8), (0, 0));
        assert_eq!(block_info(8, 8), (1, 0));
        assert_eq!(block_info(10, 8), (1, 2));
        assert_eq!(block_info(16, 8), (2, 0));
        assert_eq!(block_info(17, 8), (2, 1));
    }

    #[test]
    fn test_parse_owned() {
        let data = vec![1, 2, 3, 4, 5];
        let blocks = parse_owned(&data, 2);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], vec![1, 2]);
        assert_eq!(blocks[1], vec![3, 4]);
        assert_eq!(blocks[2], vec![5]);
    }
}
