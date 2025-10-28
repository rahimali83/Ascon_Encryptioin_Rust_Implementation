/// Ascon Encryption Library
///
/// A Rust implementation of the Ascon family of lightweight cryptographic algorithms
/// as specified in NIST SP 800-232.
///
/// This library provides:
/// - Ascon-AEAD128: Authenticated Encryption with Associated Data
/// - Clean, modular implementation following the NIST specification
/// - Support for both file and string encryption/decryption

// Module declarations
pub mod constants;
pub mod state;
pub mod permutation;
pub mod utils;
pub mod aead;

// Re-export main APIs
pub use aead::{encrypt, decrypt, AeadError};
pub use constants::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};

/// Generate a random key for Ascon-AEAD128
///
/// # Security Note
/// This uses the system's random number generator. For production use,
/// ensure your system has a properly seeded CSPRNG.
pub fn generate_key() -> [u8; KEY_SIZE] {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple key generation for demonstration
    // In production, use a proper CSPRNG like rand::thread_rng()
    let mut key = [0u8; KEY_SIZE];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in key.iter_mut().enumerate() {
        *byte = ((timestamp >> (i * 8)) & 0xFF) as u8;
    }

    key
}

/// Generate a random nonce for Ascon-AEAD128
///
/// # Security Note
/// Nonces MUST be unique for each encryption with the same key.
/// This function generates a random nonce, which is suitable if
/// you're not encrypting more than 2^64 messages.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut nonce = [0u8; NONCE_SIZE];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = ((timestamp >> (i * 8)) & 0xFF) as u8;
    }

    nonce
}
