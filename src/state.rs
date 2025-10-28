/// Ascon State Module
///
/// This module implements the 320-bit internal state used by all Ascon algorithms.
/// The state consists of 5 × 64-bit words (S0, S1, S2, S3, S4).
///
/// The specification uses little-endian byte ordering, meaning bytes can be loaded
/// directly from memory on little-endian machines without conversion.

use crate::constants::STATE_WORDS;

/// The Ascon state: 320 bits represented as five 64-bit words
///
/// State representation: S = S0 ∥ S1 ∥ S2 ∥ S3 ∥ S4
/// where each Si is a 64-bit unsigned integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsconState {
    /// Five 64-bit state words
    pub words: [u64; STATE_WORDS],
}

impl AsconState {
    /// Create a new state initialized to zeros
    pub fn new() -> Self {
        Self {
            words: [0u64; STATE_WORDS],
        }
    }

    /// Create a state from five 64-bit words
    pub fn from_words(words: [u64; 5]) -> Self {
        Self { words }
    }

    /// Create a state from a 40-byte array (320 bits)
    ///
    /// Bytes are loaded in little-endian order:
    /// - bytes[0..8] → S0
    /// - bytes[8..16] → S1
    /// - bytes[16..24] → S2
    /// - bytes[24..32] → S3
    /// - bytes[32..40] → S4
    pub fn from_bytes(bytes: &[u8; 40]) -> Self {
        let mut words = [0u64; 5];
        for i in 0..5 {
            words[i] = u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
        }
        Self { words }
    }

    /// Convert state to a 40-byte array
    ///
    /// Words are stored in little-endian byte order
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        for i in 0..5 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.words[i].to_le_bytes());
        }
        bytes
    }

    /// Get a specific state word (S0 through S4)
    #[inline]
    pub fn get(&self, index: usize) -> u64 {
        self.words[index]
    }

    /// Set a specific state word
    #[inline]
    pub fn set(&mut self, index: usize, value: u64) {
        self.words[index] = value;
    }

    /// XOR a value into a specific state word
    #[inline]
    pub fn xor(&mut self, index: usize, value: u64) {
        self.words[index] ^= value;
    }

    /// XOR a byte slice into the first part of the state
    ///
    /// This is used for absorbing blocks of data.
    /// The data is XORed in little-endian byte order.
    pub fn xor_bytes(&mut self, data: &[u8], offset: usize) {
        let full_words = data.len() / 8;
        let remaining_bytes = data.len() % 8;

        // XOR full 64-bit words
        for i in 0..full_words {
            let word = u64::from_le_bytes([
                data[i * 8],
                data[i * 8 + 1],
                data[i * 8 + 2],
                data[i * 8 + 3],
                data[i * 8 + 4],
                data[i * 8 + 5],
                data[i * 8 + 6],
                data[i * 8 + 7],
            ]);
            self.words[offset + i] ^= word;
        }

        // XOR remaining bytes (if any)
        if remaining_bytes > 0 {
            let mut partial = [0u8; 8];
            partial[..remaining_bytes].copy_from_slice(&data[full_words * 8..]);
            let word = u64::from_le_bytes(partial);
            self.words[offset + full_words] ^= word;
        }
    }

    /// Extract bytes from the state starting at a word offset
    ///
    /// This is used for squeezing output from the state.
    pub fn extract_bytes(&self, offset: usize, length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        let mut remaining = length;
        let mut word_idx = offset;

        while remaining > 0 {
            let bytes = self.words[word_idx].to_le_bytes();
            let to_copy = remaining.min(8);
            result.extend_from_slice(&bytes[..to_copy]);
            remaining -= to_copy;
            word_idx += 1;
        }

        result
    }

    /// Initialize state with an IV and optional key/nonce for AEAD
    ///
    /// State layout for AEAD: S = IV ∥ K ∥ N
    /// where IV is 64 bits, K is 128 bits, N is 128 bits
    pub fn init_aead(iv: u64, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let n0 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());

        Self::from_words([iv, k0, k1, n0, n1])
    }

    /// Initialize state with an IV for hash/XOF functions
    ///
    /// State layout: S = IV ∥ 0^256
    pub fn init_hash(iv: u64) -> Self {
        Self::from_words([iv, 0, 0, 0, 0])
    }
}

impl Default for AsconState {
    fn default() -> Self {
        Self::new()
    }
}

// Display for debugging
impl std::fmt::Display for AsconState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "AsconState {{")?;
        for (i, word) in self.words.iter().enumerate() {
            writeln!(f, "  S{}: 0x{:016x}", i, word)?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        let state = AsconState::new();
        assert_eq!(state.words, [0u64; 5]);
    }

    #[test]
    fn test_state_from_words() {
        let words = [1, 2, 3, 4, 5];
        let state = AsconState::from_words(words);
        assert_eq!(state.words, words);
    }

    #[test]
    fn test_state_get_set() {
        let mut state = AsconState::new();
        state.set(0, 0x0123456789abcdef);
        assert_eq!(state.get(0), 0x0123456789abcdef);
    }

    #[test]
    fn test_state_xor() {
        let mut state = AsconState::new();
        state.set(0, 0xFFFFFFFFFFFFFFFF);
        state.xor(0, 0x0F0F0F0F0F0F0F0F);
        assert_eq!(state.get(0), 0xF0F0F0F0F0F0F0F0);
    }

    #[test]
    fn test_bytes_conversion() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // S0
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // S1
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // S2
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // S3
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, // S4
        ];

        let state = AsconState::from_bytes(&bytes);
        let recovered = state.to_bytes();
        assert_eq!(bytes, recovered);

        // Verify little-endian interpretation
        assert_eq!(state.get(0), 0x0706050403020100);
        assert_eq!(state.get(4), 0x2726252423222120);
    }
}
