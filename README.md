# Ascon_Encryptioin_Rust_Implementation

A comprehensive Rust implementation of the **Ascon-AEAD128** lightweight cryptographic algorithm as specified in **NIST SP 800-232**. This project provides authenticated encryption with associated data (AEAD) in a clean, modular, and well-tested implementation.

Note: This implementation is for educational and experimental purposes. Do not use in production without thorough review, testing against official test vectors, and hardening.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Building the Project](#building-the-project)
- [Usage Guide](#usage-guide)
  - [Command-Line Interface](#command-line-interface)
  - [Interactive Mode](#interactive-mode)
- [Understanding Ascon-AEAD128](#understanding-ascon-aead128)
- [Implementation Details](#implementation-details)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

---

## Features

- ✅ **Ascon-AEAD128** - Full implementation of authenticated encryption with associated data
- ✅ **Dual Interface** - Both command-line and interactive menu-driven modes
- ✅ **File & String Support** - Encrypt/decrypt files or text strings
- ✅ **Metadata Management** - Save and load encryption keys, nonces, and tags
- ✅ **128-bit Security** - Industry-standard security strength
- ✅ **Modular Design** - Clean separation of cryptographic primitives
- ✅ **Comprehensive Testing** - 30+ unit tests covering all edge cases
- ✅ **IDE Compatible** - Works with RustRover, VSCode, and other Rust IDEs

---

## Quick Start

```bash
# Clone or navigate to the project
cd /path/to/Ascon_Encryptioin

# Build the project
cargo build --release

# Encrypt a string
cargo run --bin ascon -- encrypt --input "Hello, Ascon!" --string --save-metadata hello.meta

# Decrypt it back
cargo run --bin ascon -- decrypt --input <ciphertext_hex> --string --load-metadata hello.meta

# Or use interactive mode
cargo run --bin ascon -- interactive
```

---

## Project Structure

```
Ascon_Encryptioin/
├── Cargo.toml                 # Project configuration with dependencies
├── README.md                  # This file
├── Docs/
│   └── NIST.SP.800-232.pdf   # Official NIST specification
└── src/
    ├── lib.rs                # Public API and library interface
    ├── main.rs               # CLI application entry point
    ├── constants.rs          # NIST-specified constants (S-box, IVs, etc.)
    ├── state.rs              # 320-bit state management
    ├── aead/
    │   └── mod.rs           # AEAD128 encryption/decryption implementation
    ├── permutation/
    │   └── mod.rs           # Ascon permutation (p^8 and p^12)
    └── utils/
        ├── mod.rs           # Utility module re-exports
        ├── padding.rs       # Padding functions (pad rule)
        └── parsing.rs       # Data parsing into blocks
```

### Key Components Explained

- **`lib.rs`**: Exposes the public API (`encrypt()`, `decrypt()`, key/nonce generators)
- **`main.rs`**: Command-line interface with clap argument parsing
- **`constants.rs`**: All algorithm constants from NIST SP 800-232 (round constants, S-box, rotation amounts)
- **`state.rs`**: Manages the 320-bit internal state (5 × 64-bit words) with little-endian byte ordering
- **`aead/mod.rs`**: Implements the four-phase AEAD process (initialization, associated data, plaintext, finalization)
- **`permutation/mod.rs`**: Implements the SPN (Substitution-Permutation Network) with three layers
- **`utils/`**: Helper functions for padding and block parsing

---

## Building the Project

### Prerequisites

- **Rust** 1.70 or later (Install from [rustup.rs](https://rustup.rs/))
- **Cargo** (comes with Rust)

### Build Commands

```bash
# Development build (faster compilation, includes debug symbols)
cargo build

# Release build (optimized, recommended for actual use)
cargo build --release

# Run all tests
cargo test

# Run tests with detailed output
cargo test -- --nocapture

# Check code without building
cargo check
```

### Building from IDEs

**JetBrains RustRover / IntelliJ IDEA:**
- Open the project folder in RustRover
- The IDE will automatically detect `Cargo.toml`
- Use the build/run configurations or toolbar buttons
- Binary targets: `Ascon_Encryptioin` (full name) or `ascon` (short name)

**VS Code:**
- Install the "rust-analyzer" extension
- Open the project folder
- Use the terminal or CodeLLDB extension for debugging

---

## Usage Guide

### Command-Line Interface

The CLI provides powerful options for encrypting and decrypting data directly from the terminal.

#### Basic String Encryption

```bash
# Encrypt a string (auto-generates key and nonce)
cargo run --bin ascon -- encrypt --input "My secret message" --string

# Output:
# Generated random key: <hex_key>
# Generated random nonce: <hex_nonce>
# Ciphertext (hex): <hex_ciphertext>
# Tag (hex): <hex_tag>
```

#### String Encryption with Metadata

```bash
# Save all encryption parameters for easy decryption later
cargo run --bin ascon -- encrypt \
  --input "Confidential data" \
  --string \
  --save-metadata confidential.meta

# Decrypt using the metadata file
cargo run --bin ascon -- decrypt \
  --input <ciphertext_from_above> \
  --string \
  --load-metadata confidential.meta

# Output: Plaintext: Confidential data
```

#### File Encryption

```bash
# Encrypt a file (creates filename.enc)
cargo run --bin ascon -- encrypt --input document.pdf --save-metadata document.meta

# Encrypt with custom output filename
cargo run --bin ascon -- encrypt \
  --input document.pdf \
  --output encrypted_doc.bin \
  --save-metadata document.meta
```

#### File Decryption

```bash
# Decrypt using metadata file
cargo run --bin ascon -- decrypt \
  --input document.pdf.enc \
  --load-metadata document.meta

# Decrypt to custom output location
cargo run --bin ascon -- decrypt \
  --input encrypted_doc.bin \
  --load-metadata document.meta \
  --output recovered.pdf
```

#### Using Explicit Keys/Nonces/Tags

```bash
# Create hex-encoded key and nonce files (each must be 32 hex chars = 16 bytes)
echo "0123456789abcdef0123456789abcdef" > my_key.txt
echo "fedcba9876543210fedcba9876543210" > my_nonce.txt

# Encrypt with explicit parameters
cargo run --bin ascon -- encrypt \
  --input message.txt \
  --key my_key.txt \
  --nonce my_nonce.txt

# Note the tag from the output, save it
echo "<tag_hex_from_output>" > my_tag.txt

# Decrypt with explicit parameters
cargo run --bin ascon -- decrypt \
  --input message.txt.enc \
  --key my_key.txt \
  --nonce my_nonce.txt \
  --tag my_tag.txt
```

#### Associated Data (AD)

Associated data is authenticated but NOT encrypted. Use it for metadata that must be verified.

```bash
# Encrypt with associated data
cargo run --bin ascon -- encrypt \
  --input "Payment: $100" \
  --string \
  --associated-data "user_id:12345" \
  --save-metadata payment.meta

# Decrypt - MUST provide the same associated data
cargo run --bin ascon -- decrypt \
  --input <ciphertext> \
  --string \
  --load-metadata payment.meta \
  --associated-data "user_id:12345"  # Must match exactly!
```

**Important**: If the associated data doesn't match, authentication will fail.

---

### Interactive Mode

For users who prefer a menu-driven interface:

```bash
cargo run --bin ascon -- interactive
```

**Menu Options:**

```
=== Ascon-AEAD128 Interactive Mode ===

Select an operation:
1. Encrypt a string
2. Decrypt a string
3. Encrypt a file
4. Decrypt a file
5. Generate random key
6. Generate random nonce
7. Exit
```

**Features:**
- Guided prompts for all inputs
- Auto-generation of keys/nonces with user confirmation
- Input validation and helpful error messages
- Great for learning and experimentation

---

## Understanding Ascon-AEAD128

### What is AEAD?

**AEAD** stands for **Authenticated Encryption with Associated Data**. It provides:
1. **Confidentiality**: Data is encrypted (unreadable without the key)
2. **Authenticity**: Data integrity is verified (tampering is detected)
3. **Associated Data**: Additional metadata can be authenticated without encryption

### Algorithm Parameters

| Parameter | Size | Description |
|-----------|------|-------------|
| **Key** | 128 bits (16 bytes) | Secret encryption key |
| **Nonce** | 128 bits (16 bytes) | Number used once (must be unique per key) |
| **Tag** | 128 bits (16 bytes) | Authentication tag for verification |
| **Rate** | 128 bits (16 bytes) | Amount of data processed per permutation |
| **Capacity** | 192 bits | Internal state reserved for security |

### How It Works

**Four-Phase Process:**

1. **Initialization**: Combine IV, Key, and Nonce → Apply 12-round permutation
2. **Associated Data Processing**: Absorb AD blocks → Apply 8-round permutation per block
3. **Plaintext Processing**: Encrypt plaintext blocks → Apply 8-round permutation per block
4. **Finalization**: Generate authentication tag → Verify on decryption

**Internal State:**
- 320 bits total = 5 words × 64 bits each
- Organized as: `S0 ∥ S1 ∥ S2 ∥ S3 ∥ S4`
- Little-endian byte ordering (matches most modern systems)

---

## Implementation Details

### Cryptographic Primitives

#### State Management (`state.rs`)

The 320-bit state is represented as five 64-bit words:

```rust
pub struct AsconState {
    pub words: [u64; 5],  // S0, S1, S2, S3, S4
}
```

**Key Methods:**
- `from_bytes()` / `to_bytes()`: Convert between byte arrays and state
- `xor()`: XOR a value into a specific word
- `xor_bytes()`: XOR byte data into the state (for absorbing)
- `extract_bytes()`: Extract bytes from the state (for squeezing)

#### Permutation (`permutation/mod.rs`)

The Ascon permutation consists of three layers applied in sequence:

1. **Constant Addition (pC)**: XOR round constant into S2
2. **Substitution Layer (pS)**: Apply 5-bit S-box to all 64 bit positions
3. **Linear Diffusion (pL)**: Apply rotations and XORs to each word

**Two Variants:**
- `ascon_p12()`: 12 rounds (used in initialization and finalization)
- `ascon_p8()`: 8 rounds (used in data processing)

#### AEAD Encryption (`aead/mod.rs`)

**Encryption Process:**

```
Input: key, nonce, associated_data, plaintext
Output: (ciphertext, tag)

1. Initialize state with IV ∥ Key ∥ Nonce
2. Apply p^12, then XOR key into S3∥S4
3. Process associated data blocks with p^8
4. Apply domain separation
5. Process plaintext blocks with p^8, producing ciphertext
6. Finalize with p^12, generate tag
```

**Decryption Process:**
- Same as encryption but reverses the plaintext/ciphertext transformation
- Verifies the authentication tag using constant-time comparison
- Returns error if tag doesn't match (data tampered or wrong key)

---

## Security Considerations

### ⚠️ Important Security Notes

1. **Nonce Uniqueness (Critical)**
   - **Never reuse** a nonce with the same key
   - Each encryption must use a unique nonce
   - Nonce reuse completely breaks security
   - Use counters or random generation (with sufficient entropy)

2. **Key Generation (Production Warning)**
   - The default `generate_key()` function uses timestamps
   - **This is for testing/demonstration only**
   - For production: Use a cryptographically secure random number generator (CSPRNG)
   - Example: Use the `rand` crate with `OsRng`

3. **Associated Data**
   - Must be identical during encryption and decryption
   - Mismatch causes authentication failure
   - Can be empty if not needed

4. **Authentication Tag**
   - The tag verification uses constant-time comparison
   - This prevents timing attacks
   - Never proceed with decrypted data if tag verification fails

5. **Key Storage**
   - Store keys securely (hardware security modules, key management systems)
   - Never hardcode keys in source code
   - Protect metadata files (they contain keys and nonces)

### Production Recommendations

```rust
// For production use, replace generate_key() with:
use rand::rngs::OsRng;
use rand::RngCore;

fn generate_production_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    key
}
```

---

## Testing

### Test Coverage

The implementation includes **30 comprehensive unit tests** covering:

✅ Empty message encryption/decryption
✅ Various message lengths (1 byte, 13 bytes, 16 bytes, 17 bytes, 32 bytes, 42 bytes)
✅ Full block and partial block handling
✅ Multiple block messages
✅ Authentication tag verification (positive and negative tests)
✅ Associated data processing
✅ Nonce uniqueness verification
✅ State management operations
✅ Permutation determinism
✅ Padding and parsing edge cases

### Running Tests

```bash
# Run all tests
cargo test

# Run only library tests (excludes doc tests)
cargo test --lib

# Run tests with output visible
cargo test -- --nocapture

# Run specific test module
cargo test aead::tests
cargo test state::tests
cargo test permutation::tests

# Run a specific test
cargo test test_encrypt_decrypt_simple

# Run tests in release mode (faster)
cargo test --release
```

### Test Output Example

```
running 30 tests
test aead::tests::test_decrypt_wrong_tag_fails ... ok
test aead::tests::test_different_nonce_different_ciphertext ... ok
test aead::tests::test_encrypt_decrypt_16bytes ... ok
test aead::tests::test_encrypt_decrypt_17bytes ... ok
test aead::tests::test_encrypt_decrypt_32bytes ... ok
test aead::tests::test_encrypt_decrypt_empty ... ok
test aead::tests::test_encrypt_decrypt_simple ... ok
...
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

---

## Examples

### Example 1: Complete File Encryption Workflow

```bash
# Create a test document
echo "This is a confidential business document." > business.txt

# Encrypt it with metadata
cargo run --bin ascon -- encrypt \
  --input business.txt \
  --save-metadata business.meta

# Output shows:
# Generated random key: ...
# Generated random nonce: ...
# Encrypted file written to: business.txt.enc
# Tag (hex): ...
# Metadata saved to: business.meta

# Later, decrypt it
cargo run --bin ascon -- decrypt \
  --input business.txt.enc \
  --load-metadata business.meta \
  --output recovered.txt

# Verify they match
diff business.txt recovered.txt
echo $?  # Should output 0 (files identical)
```

### Example 2: String Encryption for Messaging

```bash
# Alice encrypts a message
cargo run --bin ascon -- encrypt \
  --input "Meet at the usual place at 3pm" \
  --string \
  --save-metadata alice_msg.meta

# Alice sends Bob:
# - The ciphertext (hex string from output)
# - The metadata file (or just key, nonce, tag separately)

# Bob decrypts it
cargo run --bin ascon -- decrypt \
  --input "a3f8d9e2..." \
  --string \
  --load-metadata alice_msg.meta

# Output: Plaintext: Meet at the usual place at 3pm
```

### Example 3: Using Associated Data for User Context

```bash
# Encrypt user data with user ID as associated data
cargo run --bin ascon -- encrypt \
  --input "Credit card: 1234-5678-9012-3456" \
  --string \
  --associated-data "user_id:alice@example.com" \
  --save-metadata user_data.meta

# This ensures the data is bound to this specific user
# Attempting to decrypt with wrong associated data fails

cargo run --bin ascon -- decrypt \
  --input <ciphertext> \
  --string \
  --load-metadata user_data.meta \
  --associated-data "user_id:alice@example.com"  # Must match!
```

### Example 4: Batch File Encryption

```bash
# Encrypt multiple files with a script
for file in document1.pdf document2.pdf document3.pdf; do
  cargo run --bin ascon -- encrypt \
    --input "$file" \
    --save-metadata "${file}.meta"
  echo "Encrypted: $file"
done

# Decrypt them all
for file in document1.pdf document2.pdf document3.pdf; do
  cargo run --bin ascon -- decrypt \
    --input "${file}.enc" \
    --load-metadata "${file}.meta" \
    --output "decrypted_${file}"
  echo "Decrypted: $file"
done
```

---

## Troubleshooting

### Build Issues

**Problem: "package ID specification `Ascon_Encryptioin` did not match any packages"**

**Solution**: The package name in `Cargo.toml` must match. Current configuration supports both:
- `cargo run --bin Ascon_Encryptioin` (full name for IDE compatibility)
- `cargo run --bin ascon` (short name for convenience)

**Problem: "error: could not compile" with linking errors**

**Solution**:
```bash
cargo clean
cargo build
```

### Runtime Issues

**Problem: "Authentication tag verification failed"**

**Causes & Solutions:**
1. Wrong key, nonce, or tag → Verify you're using the correct metadata file
2. Ciphertext was modified → The data has been tampered with
3. Associated data mismatch → Ensure AD is identical for encrypt/decrypt
4. Wrong ciphertext → Check you copied the full hex string

**Problem: "Invalid hex string"**

**Solution**: Ensure hex strings:
- Contain only characters 0-9, a-f, A-F
- Have even length (2 hex chars = 1 byte)
- Match the expected size (32 hex chars = 16 bytes for key/nonce/tag)

**Problem: Files don't match after encryption/decryption**

**Solution**:
```bash
# Check file sizes
ls -lh original.txt decrypted.txt

# Compare files
diff original.txt decrypted.txt

# Check if you used the correct metadata file
cat metadata.meta
```

### IDE Issues (RustRover)

**Problem: Build works in terminal but not in RustRover**

**Solution**:
1. File → Reload Cargo Project
2. File → Invalidate Caches → Invalidate and Restart
3. Ensure the correct binary target is selected in run configuration

**Problem: "Cannot find function/module" errors in IDE**

**Solution**: Wait for rust-analyzer to finish indexing (check bottom-right status bar)

---

## Algorithm Specification Reference

This implementation strictly follows:
- **NIST SP 800-232**: [Ascon Cryptographic Family](https://csrc.nist.gov/pubs/sp/800/232/final)
- **Ascon v1.2**: The official specification

### Standards Compliance

- ✅ Correct S-box from Table 6 of NIST SP 800-232
- ✅ Correct round constants (0xF0, 0xE1, ..., 0x2D, 0x1E)
- ✅ Correct rotation amounts for linear diffusion
- ✅ Correct initialization vectors for AEAD128
- ✅ Little-endian byte ordering as specified
- ✅ Proper padding rule: `pad(X, r) = X ∥ 1 ∥ 0^j`

---

## Contributing & Development

### Code Style

- Follow Rust naming conventions (snake_case for functions/variables)
- Add documentation comments (`///`) for public APIs
- Include examples in doc comments where appropriate
- Run `cargo fmt` before committing
- Run `cargo clippy` to catch common mistakes

### Adding New Features

1. Create a new module in `src/` or appropriate subdirectory
2. Add comprehensive unit tests in the same file
3. Update `src/lib.rs` to export new public APIs
4. Document the feature in this README
5. Run all tests to ensure nothing breaks

---

## License

This is an educational implementation of the NIST-specified Ascon algorithm for learning and research purposes.

---

## References

- [NIST SP 800-232 Official Document](https://csrc.nist.gov/pubs/sp/800/232/final)
- [Ascon Official Website](https://ascon.iaik.tugraz.at/)
- [Rust Programming Language](https://www.rust-lang.org/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

---

**Questions or Issues?** Check the troubleshooting section or review the comprehensive inline code documentation in each module.
