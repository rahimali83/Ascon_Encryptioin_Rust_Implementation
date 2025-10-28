/// Ascon Encryption CLI
///
/// A command-line interface for the Ascon-AEAD128 encryption standard.
/// Supports file and string encryption/decryption with both CLI and interactive modes.

use anyhow::{Context, Result};
use ascon_encryption::{decrypt, encrypt, generate_key, generate_nonce};
use ascon_encryption::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ascon")]
#[command(author = "Ascon Encryption Implementation")]
#[command(version = "0.1.0")]
#[command(about = "Ascon-AEAD128 encryption/decryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt data using Ascon-AEAD128
    Encrypt {
        /// Input source (file path or string)
        #[arg(short, long)]
        input: String,

        /// Treat input as a string instead of file path
        #[arg(short, long)]
        string: bool,

        /// Output file path (defaults to input.enc for files, stdout for strings)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Key file (hex-encoded, 16 bytes). If not provided, a random key will be generated
        #[arg(short, long)]
        key: Option<PathBuf>,

        /// Nonce file (hex-encoded, 16 bytes). If not provided, a random nonce will be generated
        #[arg(short, long)]
        nonce: Option<PathBuf>,

        /// Additional authenticated data (not encrypted, but authenticated)
        #[arg(short, long, default_value = "")]
        associated_data: String,

        /// Save key, nonce, and tag to this file (for later decryption)
        #[arg(long)]
        save_metadata: Option<PathBuf>,
    },

    /// Decrypt data using Ascon-AEAD128
    Decrypt {
        /// Input source (file path or string)
        #[arg(short, long)]
        input: String,

        /// Treat input as a hex-encoded string instead of file path
        #[arg(short, long)]
        string: bool,

        /// Output file path (defaults to input without .enc, stdout for strings)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Key file (hex-encoded, 16 bytes). Not required if using --load-metadata
        #[arg(short, long, required_unless_present = "load_metadata")]
        key: Option<PathBuf>,

        /// Nonce file (hex-encoded, 16 bytes). Not required if using --load-metadata
        #[arg(short, long, required_unless_present = "load_metadata")]
        nonce: Option<PathBuf>,

        /// Tag file (hex-encoded, 16 bytes). Not required if using --load-metadata
        #[arg(short, long, required_unless_present = "load_metadata")]
        tag: Option<PathBuf>,

        /// Additional authenticated data (same as used during encryption)
        #[arg(short, long, default_value = "")]
        associated_data: String,

        /// Load key, nonce, and tag from metadata file
        #[arg(long)]
        load_metadata: Option<PathBuf>,
    },

    /// Interactive mode with menu-driven interface
    Interactive,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            string,
            output,
            key,
            nonce,
            associated_data,
            save_metadata,
        } => {
            encrypt_command(input, string, output, key, nonce, associated_data, save_metadata)?;
        }
        Commands::Decrypt {
            input,
            string,
            output,
            key,
            nonce,
            tag,
            associated_data,
            load_metadata,
        } => {
            decrypt_command(
                input,
                string,
                output,
                key,
                nonce,
                tag,
                associated_data,
                load_metadata,
            )?;
        }
        Commands::Interactive => {
            interactive_mode()?;
        }
    }

    Ok(())
}

/// Handle encryption command
fn encrypt_command(
    input: String,
    is_string: bool,
    output: Option<PathBuf>,
    key_file: Option<PathBuf>,
    nonce_file: Option<PathBuf>,
    associated_data: String,
    save_metadata: Option<PathBuf>,
) -> Result<()> {
    // Read or generate key
    let key = if let Some(key_path) = key_file {
        read_hex_file(&key_path, KEY_SIZE).context("Failed to read key file")?
    } else {
        let k = generate_key();
        println!("Generated random key: {}", hex::encode(&k));
        k.to_vec()
    };

    // Read or generate nonce
    let nonce = if let Some(nonce_path) = nonce_file {
        read_hex_file(&nonce_path, NONCE_SIZE).context("Failed to read nonce file")?
    } else {
        let n = generate_nonce();
        println!("Generated random nonce: {}", hex::encode(&n));
        n.to_vec()
    };

    // Read input data
    let plaintext = if is_string {
        input.as_bytes().to_vec()
    } else {
        fs::read(&input).context(format!("Failed to read input file: {}", input))?
    };

    // Encrypt
    let (ciphertext, tag) = encrypt(&key, &nonce, associated_data.as_bytes(), &plaintext)
        .context("Encryption failed")?;

    // Write output
    if is_string {
        if let Some(out_path) = output {
            fs::write(&out_path, hex::encode(&ciphertext))
                .context("Failed to write output file")?;
            println!("Encrypted data written to: {}", out_path.display());
        } else {
            println!("Ciphertext (hex): {}", hex::encode(&ciphertext));
        }
        println!("Tag (hex): {}", hex::encode(&tag));
    } else {
        let output_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.enc", input)));
        fs::write(&output_path, &ciphertext).context("Failed to write output file")?;
        println!("Encrypted file written to: {}", output_path.display());
        println!("Tag (hex): {}", hex::encode(&tag));
    }

    // Save metadata if requested
    if let Some(metadata_path) = save_metadata {
        let metadata = format!(
            "key={}\nnonce={}\ntag={}\n",
            hex::encode(&key),
            hex::encode(&nonce),
            hex::encode(&tag)
        );
        fs::write(&metadata_path, metadata).context("Failed to write metadata file")?;
        println!("Metadata saved to: {}", metadata_path.display());
    }

    println!("Encryption successful!");
    Ok(())
}

/// Handle decryption command
fn decrypt_command(
    input: String,
    is_string: bool,
    output: Option<PathBuf>,
    key_file: Option<PathBuf>,
    nonce_file: Option<PathBuf>,
    tag_file: Option<PathBuf>,
    associated_data: String,
    load_metadata: Option<PathBuf>,
) -> Result<()> {
    // Load key, nonce, tag
    let (key, nonce, tag) = if let Some(metadata_path) = load_metadata {
        load_metadata_file(&metadata_path)?
    } else {
        let k = read_hex_file(&key_file.unwrap(), KEY_SIZE).context("Failed to read key file")?;
        let n = read_hex_file(&nonce_file.unwrap(), NONCE_SIZE).context("Failed to read nonce file")?;
        let t = read_hex_file(&tag_file.unwrap(), TAG_SIZE).context("Failed to read tag file")?;
        (k, n, t)
    };

    // Read input data
    let ciphertext = if is_string {
        hex::decode(&input).context("Failed to decode hex string")?
    } else {
        fs::read(&input).context(format!("Failed to read input file: {}", input))?
    };

    // Decrypt
    let plaintext = decrypt(&key, &nonce, associated_data.as_bytes(), &ciphertext, &tag)
        .context("Decryption failed (authentication may have failed)")?;

    // Write output
    if is_string {
        if let Some(out_path) = output {
            fs::write(&out_path, &plaintext).context("Failed to write output file")?;
            println!("Decrypted data written to: {}", out_path.display());
        } else {
            let text = String::from_utf8_lossy(&plaintext);
            println!("Plaintext: {}", text);
        }
    } else {
        let output_path = output.unwrap_or_else(|| {
            PathBuf::from(input.trim_end_matches(".enc"))
        });
        fs::write(&output_path, &plaintext).context("Failed to write output file")?;
        println!("Decrypted file written to: {}", output_path.display());
    }

    println!("Decryption successful!");
    Ok(())
}

/// Interactive mode with menu-driven interface
fn interactive_mode() -> Result<()> {
    println!("\n=== Ascon-AEAD128 Interactive Mode ===\n");

    loop {
        println!("\nSelect an operation:");
        println!("1. Encrypt a string");
        println!("2. Decrypt a string");
        println!("3. Encrypt a file");
        println!("4. Decrypt a file");
        println!("5. Generate random key");
        println!("6. Generate random nonce");
        println!("7. Exit");
        print!("\nChoice: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim();

        match choice {
            "1" => encrypt_string_interactive()?,
            "2" => decrypt_string_interactive()?,
            "3" => encrypt_file_interactive()?,
            "4" => decrypt_file_interactive()?,
            "5" => {
                let key = generate_key();
                println!("\nGenerated key (hex): {}", hex::encode(&key));
            }
            "6" => {
                let nonce = generate_nonce();
                println!("\nGenerated nonce (hex): {}", hex::encode(&nonce));
            }
            "7" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid choice. Please try again."),
        }
    }

    Ok(())
}

fn encrypt_string_interactive() -> Result<()> {
    println!("\n--- Encrypt String ---");

    let plaintext = prompt_input("Enter plaintext string")?;
    let key = prompt_hex_or_generate("Enter key (hex, 16 bytes) or press Enter to generate", KEY_SIZE)?;
    let nonce = prompt_hex_or_generate("Enter nonce (hex, 16 bytes) or press Enter to generate", NONCE_SIZE)?;
    let ad = prompt_input("Enter associated data (optional)")?;

    let (ciphertext, tag) = encrypt(&key, &nonce, ad.as_bytes(), plaintext.as_bytes())
        .context("Encryption failed")?;

    println!("\n=== Results ===");
    println!("Key (hex):        {}", hex::encode(&key));
    println!("Nonce (hex):      {}", hex::encode(&nonce));
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("Tag (hex):        {}", hex::encode(&tag));

    Ok(())
}

fn decrypt_string_interactive() -> Result<()> {
    println!("\n--- Decrypt String ---");

    let ciphertext_hex = prompt_input("Enter ciphertext (hex)")?;
    let ciphertext = hex::decode(&ciphertext_hex).context("Invalid hex string")?;

    let key = prompt_hex("Enter key (hex, 16 bytes)", KEY_SIZE)?;
    let nonce = prompt_hex("Enter nonce (hex, 16 bytes)", NONCE_SIZE)?;
    let tag = prompt_hex("Enter tag (hex, 16 bytes)", TAG_SIZE)?;
    let ad = prompt_input("Enter associated data (optional)")?;

    let plaintext = decrypt(&key, &nonce, ad.as_bytes(), &ciphertext, &tag)
        .context("Decryption failed (authentication may have failed)")?;

    let text = String::from_utf8_lossy(&plaintext);
    println!("\n=== Results ===");
    println!("Plaintext: {}", text);

    Ok(())
}

fn encrypt_file_interactive() -> Result<()> {
    println!("\n--- Encrypt File ---");

    let input_path = prompt_input("Enter input file path")?;
    let output_path = prompt_input("Enter output file path (or press Enter for default)")?;
    let output_path = if output_path.is_empty() {
        format!("{}.enc", input_path)
    } else {
        output_path
    };

    let key = prompt_hex_or_generate("Enter key (hex, 16 bytes) or press Enter to generate", KEY_SIZE)?;
    let nonce = prompt_hex_or_generate("Enter nonce (hex, 16 bytes) or press Enter to generate", NONCE_SIZE)?;
    let ad = prompt_input("Enter associated data (optional)")?;

    let plaintext = fs::read(&input_path).context("Failed to read input file")?;
    let (ciphertext, tag) = encrypt(&key, &nonce, ad.as_bytes(), &plaintext)
        .context("Encryption failed")?;

    fs::write(&output_path, &ciphertext).context("Failed to write output file")?;

    println!("\n=== Results ===");
    println!("Key (hex):   {}", hex::encode(&key));
    println!("Nonce (hex): {}", hex::encode(&nonce));
    println!("Tag (hex):   {}", hex::encode(&tag));
    println!("Output file: {}", output_path);

    Ok(())
}

fn decrypt_file_interactive() -> Result<()> {
    println!("\n--- Decrypt File ---");

    let input_path = prompt_input("Enter input file path")?;
    let output_path = prompt_input("Enter output file path (or press Enter for default)")?;
    let output_path = if output_path.is_empty() {
        input_path.trim_end_matches(".enc").to_string()
    } else {
        output_path
    };

    let key = prompt_hex("Enter key (hex, 16 bytes)", KEY_SIZE)?;
    let nonce = prompt_hex("Enter nonce (hex, 16 bytes)", NONCE_SIZE)?;
    let tag = prompt_hex("Enter tag (hex, 16 bytes)", TAG_SIZE)?;
    let ad = prompt_input("Enter associated data (optional)")?;

    let ciphertext = fs::read(&input_path).context("Failed to read input file")?;
    let plaintext = decrypt(&key, &nonce, ad.as_bytes(), &ciphertext, &tag)
        .context("Decryption failed (authentication may have failed)")?;

    fs::write(&output_path, &plaintext).context("Failed to write output file")?;

    println!("\n=== Results ===");
    println!("Output file: {}", output_path);

    Ok(())
}

// Helper functions

fn prompt_input(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_hex(prompt: &str, expected_size: usize) -> Result<Vec<u8>> {
    let input = prompt_input(prompt)?;
    let bytes = hex::decode(&input).context("Invalid hex string")?;
    if bytes.len() != expected_size {
        anyhow::bail!(
            "Invalid size: expected {} bytes, got {}",
            expected_size,
            bytes.len()
        );
    }
    Ok(bytes)
}

fn prompt_hex_or_generate(prompt: &str, size: usize) -> Result<Vec<u8>> {
    let input = prompt_input(prompt)?;
    if input.is_empty() {
        let generated = if size == KEY_SIZE {
            generate_key().to_vec()
        } else {
            generate_nonce().to_vec()
        };
        println!("Generated: {}", hex::encode(&generated));
        Ok(generated)
    } else {
        let bytes = hex::decode(&input).context("Invalid hex string")?;
        if bytes.len() != size {
            anyhow::bail!("Invalid size: expected {} bytes, got {}", size, bytes.len());
        }
        Ok(bytes)
    }
}

fn read_hex_file(path: &PathBuf, expected_size: usize) -> Result<Vec<u8>> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read file: {}", path.display()))?;
    let bytes = hex::decode(content.trim()).context("Invalid hex content in file")?;
    if bytes.len() != expected_size {
        anyhow::bail!(
            "Invalid size in {}: expected {} bytes, got {}",
            path.display(),
            expected_size,
            bytes.len()
        );
    }
    Ok(bytes)
}

fn load_metadata_file(path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read metadata file: {}", path.display()))?;

    let mut key = None;
    let mut nonce = None;
    let mut tag = None;

    for line in content.lines() {
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() != 2 {
            continue;
        }
        match parts[0] {
            "key" => key = Some(hex::decode(parts[1]).context("Invalid key in metadata")?),
            "nonce" => nonce = Some(hex::decode(parts[1]).context("Invalid nonce in metadata")?),
            "tag" => tag = Some(hex::decode(parts[1]).context("Invalid tag in metadata")?),
            _ => {}
        }
    }

    let key = key.context("Missing key in metadata file")?;
    let nonce = nonce.context("Missing nonce in metadata file")?;
    let tag = tag.context("Missing tag in metadata file")?;

    if key.len() != KEY_SIZE {
        anyhow::bail!("Invalid key size in metadata");
    }
    if nonce.len() != NONCE_SIZE {
        anyhow::bail!("Invalid nonce size in metadata");
    }
    if tag.len() != TAG_SIZE {
        anyhow::bail!("Invalid tag size in metadata");
    }

    Ok((key, nonce, tag))
}
