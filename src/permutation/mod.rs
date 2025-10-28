/// Ascon Permutation Module
///
/// Implements the Ascon permutation with up to 16 rounds.
/// Each round consists of three layers:
/// 1. Constant-addition layer (pC)
/// 2. Substitution layer (pS)
/// 3. Linear diffusion layer (pL)
///
/// The permutation is defined as: p = pL ∘ pS ∘ pC

use crate::constants::{ROUND_CONSTANTS, ROTATION_AMOUNTS, SBOX};
use crate::state::AsconState;

/// Apply the constant-addition layer (pC) for a specific round
///
/// This layer XORs a round constant into state word S2.
/// The constant depends on the round number and total rounds.
///
/// For Ascon-p[rnd], round i uses: c_i = const_{16-rnd+i}
///
/// # Arguments
/// * `state` - The current state
/// * `round` - The current round number (0-based)
/// * `total_rounds` - Total number of rounds in the permutation
#[inline]
fn constant_addition(state: &mut AsconState, round: usize, total_rounds: usize) {
    let const_index = 16 - total_rounds + round;
    state.xor(2, ROUND_CONSTANTS[const_index]);
}

/// Apply the substitution layer (pS)
///
/// This layer applies a 5-bit S-box to the state in parallel.
/// For each bit position j (0..64), the S-box is applied to
/// the column (s(0,j), s(1,j), s(2,j), s(3,j), s(4,j)).
///
/// The S-box can be computed using Boolean formulas or a lookup table.
/// This implementation uses the lookup table for clarity.
#[inline]
fn substitution(state: &mut AsconState) {
    let mut new_words = [0u64; 5];

    // Process each bit position
    for bit_pos in 0..64 {
        // Extract 5 bits (one from each word) at this position
        let input = ((state.words[0] >> bit_pos) & 1)
            | (((state.words[1] >> bit_pos) & 1) << 1)
            | (((state.words[2] >> bit_pos) & 1) << 2)
            | (((state.words[3] >> bit_pos) & 1) << 3)
            | (((state.words[4] >> bit_pos) & 1) << 4);

        // Apply S-box
        let output = SBOX[input as usize];

        // Distribute output bits back to the state words
        new_words[0] |= ((output & 0x01) as u64) << bit_pos;
        new_words[1] |= (((output >> 1) & 0x01) as u64) << bit_pos;
        new_words[2] |= (((output >> 2) & 0x01) as u64) << bit_pos;
        new_words[3] |= (((output >> 3) & 0x01) as u64) << bit_pos;
        new_words[4] |= (((output >> 4) & 0x01) as u64) << bit_pos;
    }

    state.words = new_words;
}

/// Apply the linear diffusion layer (pL)
///
/// This layer applies linear transformations to each state word independently.
/// For each word Si, apply: Σi(Si) = Si ⊕ (Si ⋙ r1) ⊕ (Si ⋙ r2)
/// where ⋙ denotes right rotation and r1, r2 are rotation amounts specific to each word.
#[inline]
fn linear_diffusion(state: &mut AsconState) {
    for i in 0..5 {
        let (r1, r2) = ROTATION_AMOUNTS[i];
        let s = state.words[i];
        state.words[i] = s ^ s.rotate_right(r1 as u32) ^ s.rotate_right(r2 as u32);
    }
}

/// Apply one round of the Ascon permutation
///
/// A round consists of: pL(pS(pC(state)))
#[inline]
fn round(state: &mut AsconState, round_num: usize, total_rounds: usize) {
    constant_addition(state, round_num, total_rounds);
    substitution(state);
    linear_diffusion(state);
}

/// Apply the Ascon permutation with a specified number of rounds
///
/// # Arguments
/// * `state` - The state to permute (modified in-place)
/// * `rounds` - Number of rounds (1-16)
///
/// # Panics
/// Panics if rounds > 16
pub fn permute(state: &mut AsconState, rounds: usize) {
    assert!(rounds <= 16, "Ascon permutation supports up to 16 rounds");

    for i in 0..rounds {
        round(state, i, rounds);
    }
}

/// Apply Ascon-p[8] permutation (8 rounds)
///
/// This is used in the processing phases of Ascon-AEAD128
pub fn ascon_p8(state: &mut AsconState) {
    permute(state, 8);
}

/// Apply Ascon-p[12] permutation (12 rounds)
///
/// This is used in:
/// - Initialization and finalization of Ascon-AEAD128
/// - All phases of Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128
pub fn ascon_p12(state: &mut AsconState) {
    permute(state, 12);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_addition() {
        let mut state = AsconState::new();
        constant_addition(&mut state, 0, 12);
        // For 12 rounds, round 0 uses const_4 = 0xF0
        assert_eq!(state.get(2), 0x00000000000000f0);
    }

    #[test]
    fn test_sbox_lookup() {
        // Test a few known S-box values from Table 6
        assert_eq!(SBOX[0x00], 0x04);
        assert_eq!(SBOX[0x01], 0x0b);
        assert_eq!(SBOX[0x1f], 0x17);
    }

    #[test]
    fn test_rotation() {
        let x: u64 = 0x0000000000000001;
        assert_eq!(x.rotate_right(1), 0x8000000000000000);
        assert_eq!(x.rotate_right(64), 0x0000000000000001);
    }

    #[test]
    fn test_permutation_changes_state() {
        let mut state = AsconState::from_words([1, 2, 3, 4, 5]);
        let original = state;

        ascon_p12(&mut state);

        // After permutation, state should be different
        assert_ne!(state, original);
    }

    #[test]
    fn test_permutation_deterministic() {
        let mut state1 = AsconState::from_words([1, 2, 3, 4, 5]);
        let mut state2 = AsconState::from_words([1, 2, 3, 4, 5]);

        ascon_p12(&mut state1);
        ascon_p12(&mut state2);

        // Same input should produce same output
        assert_eq!(state1, state2);
    }
}
