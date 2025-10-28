# Ascon Encryption Implementation

A Rust implementation of the Ascon family of lightweight cryptographic algorithms as specified in NIST SP 800-232.

## Features

- **Ascon-AEAD128**: Authenticated Encryption with Associated Data
- **Clean, modular implementation** following the NIST specification
- **CLI and interactive modes** for easy use
- **File and string encryption/decryption** support
- **128-bit security strength** in single-key setting

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test
```

## Usage

### Command-Line Interface

#### Encrypt a String

```bash
# Basic string encryption (generates random key and nonce)
cargo run -- encrypt --input "Hello, Ascon!" --string

# Save metadata for later decryption
cargo run -- encrypt --input "Secret message" --string --save-metadata secret.meta
```

#### Decrypt a String

```bash
# Decrypt using metadata file
cargo run -- decrypt --input "0f3b999dbe83ddebd75dd0a3ac" --string --load-metadata secret.meta

# Decrypt using explicit key, nonce, and tag files
cargo run -- decrypt --input "ciphertext_hex" --string --key key.txt --nonce nonce.txt --tag tag.txt
```

#### Encrypt a File

```bash
# Encrypt a file (output will be input_file.enc)
cargo run -- encrypt --input document.txt

# Encrypt with custom output and save metadata
cargo run -- encrypt --input document.txt --output encrypted.bin --save-metadata document.meta
```

#### Decrypt a File

```bash
# Decrypt using metadata file
cargo run -- decrypt --input document.txt.enc --load-metadata document.meta

# Decrypt with custom output
cargo run -- decrypt --input encrypted.bin --load-metadata document.meta --output decrypted.txt
```

### Interactive Mode

```bash
cargo run -- interactive
```

The interactive mode provides a menu-driven interface where you can:
1. Encrypt a string
2. Decrypt a string
3. Encrypt a file
4. Decrypt a file
5. Generate random key
6. Generate random nonce

### Advanced Options

#### Associated Data

You can include authenticated but unencrypted data:

```bash
cargo run -- encrypt --input "message" --string --associated-data "user123" --save-metadata msg.meta
cargo run -- decrypt --input "ciphertext" --string --load-metadata msg.meta --associated-data "user123"
```

**Note**: The same associated data must be provided during decryption, or authentication will fail.

## Implementation Details

### Module Structure

- `src/lib.rs` - Public API and helper functions
- `src/main.rs` - CLI interface
- `src/constants.rs` - Algorithm constants from NIST spec
- `src/state.rs` - 320-bit state management
- `src/permutation/` - Ascon permutation (p^a and p^b)
- `src/utils/` - Padding and parsing utilities
- `src/aead/` - AEAD128 encryption/decryption

### Security Notes

1. **Key Generation**: The default key/nonce generation uses timestamps and is suitable for testing only. For production use, implement proper CSPRNG-based key generation.

2. **Nonce Uniqueness**: Nonces MUST be unique for each encryption with the same key. Never reuse a key-nonce pair.

3. **Associated Data**: Must be identical during encryption and decryption for authentication to succeed.

## Algorithm Specification

This implementation follows [NIST SP 800-232: Ascon Cryptographic Family](https://csrc.nist.gov/pubs/sp/800/232/final).

### Ascon-AEAD128 Parameters

- **Key size**: 128 bits (16 bytes)
- **Nonce size**: 128 bits (16 bytes)
- **Tag size**: 128 bits (16 bytes)
- **Rate**: 128 bits (16 bytes)
- **Capacity**: 192 bits

## Examples

### Encrypt and Decrypt a File

```bash
# Create a test file
echo "This is a secret document" > secret.txt

# Encrypt it
cargo run -- encrypt --input secret.txt --save-metadata secret.meta

# Decrypt it
cargo run -- decrypt --input secret.txt.enc --load-metadata secret.meta --output decrypted.txt

# Verify they match
diff secret.txt decrypted.txt
```

### Using Explicit Keys

```bash
# Create key, nonce files (hex-encoded, 16 bytes each)
echo "0123456789abcdef0123456789abcdef" > my_key.txt
echo "fedcba9876543210fedcba9876543210" > my_nonce.txt

# Encrypt with explicit key and nonce
cargo run -- encrypt --input message.txt --key my_key.txt --nonce my_nonce.txt

# The tag will be printed to console
# Save it to a file for decryption
echo "tag_hex_from_output" > my_tag.txt

# Decrypt
cargo run -- decrypt --input message.txt.enc --key my_key.txt --nonce my_nonce.txt --tag my_tag.txt
```

## Testing

The implementation includes comprehensive unit tests:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test aead::tests
```

All tests verify correct encryption/decryption with various:
- Message lengths (empty, partial blocks, full blocks, multiple blocks)
- Authentication tag verification
- Associated data handling

## License

This is an educational implementation of the NIST-specified Ascon algorithm.
