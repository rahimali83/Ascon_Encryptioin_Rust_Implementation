/// Ascon Constants Module
///
/// This module contains all constant values used in the Ascon family of algorithms
/// as specified in NIST SP 800-232.

/// Round constants for Ascon permutations (Table 5 from specification)
/// These are used in the constant-addition layer (pC)
///
/// The constants const_0 through const_15 support up to 16 rounds
pub const ROUND_CONSTANTS: [u64; 16] = [
    0x000000000000003c, // const_0
    0x000000000000002d, // const_1
    0x000000000000001e, // const_2
    0x000000000000000f, // const_3
    0x00000000000000f0, // const_4
    0x00000000000000e1, // const_5
    0x00000000000000d2, // const_6
    0x00000000000000c3, // const_7
    0x00000000000000b4, // const_8
    0x00000000000000a5, // const_9
    0x0000000000000096, // const_10
    0x0000000000000087, // const_11
    0x0000000000000078, // const_12
    0x0000000000000069, // const_13
    0x000000000000005a, // const_14
    0x000000000000004b, // const_15
];

/// Initial value (IV) for Ascon-AEAD128
/// Constructed as: v=1, a=12, b=8, t=128, r/8=16
pub const IV_AEAD128: u64 = 0x00001000808c0001;

/// Initial value (IV) for Ascon-Hash256
/// Constructed as: v=2, a=12, b=12, t=256, r/8=8
pub const IV_HASH256: u64 = 0x0000080100cc0002;

/// Initial value (IV) for Ascon-XOF128
/// Constructed as: v=3, a=12, b=12, t=0, r/8=8
pub const IV_XOF128: u64 = 0x0000080000cc0003;

/// Initial value (IV) for Ascon-CXOF128
/// Constructed as: v=4, a=12, b=12, t=0, r/8=8
pub const IV_CXOF128: u64 = 0x0000080000cc0004;

/// Domain separation constant (added to S4 between AD and plaintext processing)
pub const DOMAIN_SEP: u64 = 0x8000000000000000;

/// Padding constant for a 64-bit block (the bit '1' followed by zeros)
pub const PADDING_64: u64 = 0x0000000000000001;

/// Rate for AEAD (in bytes)
pub const RATE_AEAD: usize = 16; // 128 bits

/// Rate for Hash/XOF (in bytes)
pub const RATE_HASH: usize = 8; // 64 bits

/// Key size in bytes
pub const KEY_SIZE: usize = 16; // 128 bits

/// Nonce size in bytes
pub const NONCE_SIZE: usize = 16; // 128 bits

/// Tag size in bytes
pub const TAG_SIZE: usize = 16; // 128 bits

/// State size in bytes
pub const STATE_SIZE: usize = 40; // 320 bits (5 × 64-bit words)

/// Number of state words
pub const STATE_WORDS: usize = 5;

/// Lookup table for the 5-bit S-box (Table 6 from specification)
/// Maps 5-bit input (0x00-0x1f) to 5-bit output
pub const SBOX: [u8; 32] = [
    0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
    0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
    0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
    0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17,
];

/// Rotation amounts for the linear diffusion layer (Section 3.4)
/// Each state word S_i has specific rotation amounts
pub const ROTATION_AMOUNTS: [(usize, usize); 5] = [
    (19, 28), // S0: Σ0(S0) = S0 ⊕ (S0 ⋙ 19) ⊕ (S0 ⋙ 28)
    (61, 39), // S1: Σ1(S1) = S1 ⊕ (S1 ⋙ 61) ⊕ (S1 ⋙ 39)
    (1, 6),   // S2: Σ2(S2) = S2 ⊕ (S2 ⋙ 1) ⊕ (S2 ⋙ 6)
    (10, 17), // S3: Σ3(S3) = S3 ⊕ (S3 ⋙ 10) ⊕ (S3 ⋙ 17)
    (7, 41),  // S4: Σ4(S4) = S4 ⊕ (S4 ⋙ 7) ⊕ (S4 ⋙ 41)
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_constants() {
        // Verify we have 16 round constants
        assert_eq!(ROUND_CONSTANTS.len(), 16);

        // Verify first and last constants match specification
        assert_eq!(ROUND_CONSTANTS[0], 0x000000000000003c);
        assert_eq!(ROUND_CONSTANTS[15], 0x000000000000004b);
    }

    #[test]
    fn test_sbox_size() {
        // S-box should have 32 entries (5-bit input = 2^5 = 32)
        assert_eq!(SBOX.len(), 32);

        // All values should be < 32 (5-bit output)
        for &val in &SBOX {
            assert!(val < 32);
        }
    }

    #[test]
    fn test_initial_values() {
        // Verify IVs match specification (Table 14)
        assert_eq!(IV_AEAD128, 0x00001000808c0001);
        assert_eq!(IV_HASH256, 0x0000080100cc0002);
        assert_eq!(IV_XOF128, 0x0000080000cc0003);
        assert_eq!(IV_CXOF128, 0x0000080000cc0004);
    }
}
