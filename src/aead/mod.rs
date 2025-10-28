/// Ascon-AEAD128 Module
///
/// Implements Authenticated Encryption with Associated Data (AEAD)
/// using the Ascon-AEAD128 algorithm as specified in NIST SP 800-232.
///
/// Features:
/// - 128-bit key
/// - 128-bit nonce
/// - 128-bit authentication tag
/// - Variable-length plaintext and associated data
/// - 128-bit security strength in single-key setting

use crate::constants::{DOMAIN_SEP, IV_AEAD128, KEY_SIZE, NONCE_SIZE, RATE_AEAD, TAG_SIZE};
use crate::permutation::{ascon_p12, ascon_p8};
use crate::state::AsconState;
use crate::utils::{pad, parse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AeadError {
    #[error("Invalid key size: expected {KEY_SIZE} bytes, got {0}")]
    InvalidKeySize(usize),

    #[error("Invalid nonce size: expected {NONCE_SIZE} bytes, got {0}")]
    InvalidNonceSize(usize),

    #[error("Invalid tag size: expected {TAG_SIZE} bytes, got {0}")]
    InvalidTagSize(usize),

    #[error("Authentication tag verification failed")]
    AuthenticationFailed,
}

pub type Result<T> = std::result::Result<T, AeadError>;

/// Encrypt plaintext using Ascon-AEAD128
///
/// # Arguments
/// * `key` - 128-bit (16-byte) secret key
/// * `nonce` - 128-bit (16-byte) nonce (must be unique per key)
/// * `associated_data` - Additional data to authenticate (not encrypted)
/// * `plaintext` - Data to encrypt and authenticate
///
/// # Returns
/// (ciphertext, tag) where tag is the 128-bit authentication tag
///
/// # Errors
/// Returns error if key or nonce have incorrect sizes
///
/// # Security Requirements
/// - Nonce MUST be unique for each encryption with the same key
/// - Key should be generated using an approved random bit generator
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Validate inputs
    if key.len() != KEY_SIZE {
        return Err(AeadError::InvalidKeySize(key.len()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize(nonce.len()));
    }

    let key_array: &[u8; 16] = key.try_into().unwrap();
    let nonce_array: &[u8; 16] = nonce.try_into().unwrap();

    // PHASE 1: Initialization
    let mut state = AsconState::init_aead(IV_AEAD128, key_array, nonce_array);
    ascon_p12(&mut state);

    // XOR key into state (S3, S4)
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    state.xor(3, k0);
    state.xor(4, k1);

    // PHASE 2: Process Associated Data
    if !associated_data.is_empty() {
        let ad_blocks = parse(associated_data, RATE_AEAD);

        for (i, block) in ad_blocks.iter().enumerate() {
            let is_last = i == ad_blocks.len() - 1;

            if block.len() == RATE_AEAD {
                // Full block
                state.xor_bytes(block, 0);
                ascon_p8(&mut state);
            } else if is_last {
                // Partial last block - pad it
                let padded = pad(block, RATE_AEAD);
                state.xor_bytes(&padded, 0);
                ascon_p8(&mut state);
            }
        }
    }

    // Domain separation
    state.xor(4, DOMAIN_SEP);

    // PHASE 3: Process Plaintext
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let pt_blocks = parse(plaintext, RATE_AEAD);

    for (i, block) in pt_blocks.iter().enumerate() {
        let is_last = i == pt_blocks.len() - 1;

        if block.len() == RATE_AEAD && !is_last {
            // Full block (not last)
            state.xor_bytes(block, 0);
            let ct_block = state.extract_bytes(0, RATE_AEAD);
            ciphertext.extend_from_slice(&ct_block);
            ascon_p8(&mut state);
        } else {
            // Last block (full or partial)
            state.xor_bytes(block, 0);
            let ct_block = state.extract_bytes(0, block.len());
            ciphertext.extend_from_slice(&ct_block);

            // Apply padding: XOR 0x80 at byte position block.len()
            let byte_pos = block.len();
            let word_idx = byte_pos / 8;
            let byte_offset = byte_pos % 8;
            state.words[word_idx] ^= (0x80 as u64) << (byte_offset * 8);
        }
    }

    // PHASE 4: Finalization
    state.xor(2, k0);
    state.xor(3, k1);
    ascon_p12(&mut state);

    // Generate tag
    state.xor(3, k0);
    state.xor(4, k1);
    let tag = state.extract_bytes(3, TAG_SIZE);

    Ok((ciphertext, tag))
}

/// Decrypt ciphertext using Ascon-AEAD128
///
/// # Arguments
/// * `key` - 128-bit (16-byte) secret key
/// * `nonce` - 128-bit (16-byte) nonce (same as used for encryption)
/// * `associated_data` - Associated data (same as used for encryption)
/// * `ciphertext` - Encrypted data
/// * `tag` - 128-bit authentication tag from encryption
///
/// # Returns
/// The decrypted plaintext if authentication succeeds
///
/// # Errors
/// - Returns error if tag verification fails
/// - Returns error if key, nonce, or tag have incorrect sizes
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    // Validate inputs
    if key.len() != KEY_SIZE {
        return Err(AeadError::InvalidKeySize(key.len()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(AeadError::InvalidNonceSize(nonce.len()));
    }
    if tag.len() != TAG_SIZE {
        return Err(AeadError::InvalidTagSize(tag.len()));
    }

    let key_array: &[u8; 16] = key.try_into().unwrap();
    let nonce_array: &[u8; 16] = nonce.try_into().unwrap();

    // PHASE 1: Initialization (same as encryption)
    let mut state = AsconState::init_aead(IV_AEAD128, key_array, nonce_array);
    ascon_p12(&mut state);

    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    state.xor(3, k0);
    state.xor(4, k1);

    // PHASE 2: Process Associated Data (same as encryption)
    if !associated_data.is_empty() {
        let ad_blocks = parse(associated_data, RATE_AEAD);

        for (i, block) in ad_blocks.iter().enumerate() {
            let is_last = i == ad_blocks.len() - 1;

            if block.len() == RATE_AEAD {
                state.xor_bytes(block, 0);
                ascon_p8(&mut state);
            } else if is_last {
                let padded = pad(block, RATE_AEAD);
                state.xor_bytes(&padded, 0);
                ascon_p8(&mut state);
            }
        }
    }

    // Domain separation
    state.xor(4, DOMAIN_SEP);

    // PHASE 3: Process Ciphertext
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let ct_blocks = parse(ciphertext, RATE_AEAD);

    for (i, block) in ct_blocks.iter().enumerate() {
        let is_last = i == ct_blocks.len() - 1;

        if block.len() == RATE_AEAD && !is_last {
            // Full block (not last)
            let state_rate = state.extract_bytes(0, RATE_AEAD);
            let pt_block: Vec<u8> = state_rate
                .iter()
                .zip(block.iter())
                .map(|(s, c)| s ^ c)
                .collect();
            plaintext.extend_from_slice(&pt_block);

            // Update state: replace rate portion with ciphertext
            // XOR (state_rate ⊕ ciphertext) to transform state_rate into ciphertext
            state.xor_bytes(&pt_block, 0);
            ascon_p8(&mut state);
        } else {
            // Last block (full or partial)
            let state_bytes = state.extract_bytes(0, block.len());
            let pt_block: Vec<u8> = state_bytes
                .iter()
                .zip(block.iter())
                .map(|(s, c)| s ^ c)
                .collect();
            plaintext.extend_from_slice(&pt_block);

            // Update state: replace extracted portion with ciphertext
            state.xor_bytes(&pt_block, 0);

            // Apply padding: XOR 0x80 at byte position block.len()
            let byte_pos = block.len();
            let word_idx = byte_pos / 8;
            let byte_offset = byte_pos % 8;
            state.words[word_idx] ^= (0x80 as u64) << (byte_offset * 8);
        }
    }

    // PHASE 4: Finalization and Tag Verification
    state.xor(2, k0);
    state.xor(3, k1);
    ascon_p12(&mut state);

    state.xor(3, k0);
    state.xor(4, k1);
    let computed_tag = state.extract_bytes(3, TAG_SIZE);

    // Constant-time tag comparison
    let mut tag_match = true;
    for (a, b) in computed_tag.iter().zip(tag.iter()) {
        tag_match &= a == b;
    }

    if tag_match {
        Ok(plaintext)
    } else {
        Err(AeadError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let ad = [];
        let pt = [];

        let (ct, tag) = encrypt(&key, &nonce, &ad, &pt).unwrap();
        let decrypted = decrypt(&key, &nonce, &ad, &ct, &tag).unwrap();

        assert_eq!(pt, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_simple() {
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let ad = b"additional data";
        let pt = b"Hello, Ascon!";

        let (ct, tag) = encrypt(&key, &nonce, ad, pt).unwrap();
        let decrypted = decrypt(&key, &nonce, ad, &ct, &tag).unwrap();

        assert_eq!(pt, decrypted.as_slice());
        assert_ne!(pt, ct.as_slice()); // Ciphertext should differ from plaintext
    }

    #[test]
    fn test_decrypt_wrong_tag_fails() {
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let ad = b"additional data";
        let pt = b"Hello, Ascon!";

        let (ct, mut tag) = encrypt(&key, &nonce, ad, pt).unwrap();

        // Tamper with tag
        tag[0] ^= 1;

        let result = decrypt(&key, &nonce, ad, &ct, &tag);
        assert!(result.is_err());
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }

    #[test]
    fn test_different_nonce_different_ciphertext() {
        let key = [0x42u8; 16];
        let nonce1 = [0x13u8; 16];
        let mut nonce2 = [0x13u8; 16];
        nonce2[0] = 0x14;
        let ad = b"additional data";
        let pt = b"Hello, Ascon!";

        let (ct1, _) = encrypt(&key, &nonce1, ad, pt).unwrap();
        let (ct2, _) = encrypt(&key, &nonce2, ad, pt).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_encrypt_decrypt_16bytes() {
        // Test with exactly 1 block (16 bytes)
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let pt = b"Exactly 16 byte!";

        let (ct, tag) = encrypt(&key, &nonce, b"", pt).unwrap();
        let decrypted = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();

        assert_eq!(pt.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_17bytes() {
        // Test with 1 block + 1 byte
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let pt = b"Exactly 17 bytes!";

        let (ct, tag) = encrypt(&key, &nonce, b"", pt).unwrap();
        let decrypted = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();

        assert_eq!(pt.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_32bytes() {
        // Test with exactly 2 blocks (32 bytes)
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let pt = b"This message is exactly 32 bytes";

        let (ct, tag) = encrypt(&key, &nonce, b"", pt).unwrap();
        let decrypted = decrypt(&key, &nonce, b"", &ct, &tag).unwrap();

        assert_eq!(pt.as_ref(), decrypted.as_slice());
    }
}
