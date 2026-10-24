// examples/FileEncrypt.rs

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use rand::Rng;
use serde::{Deserialize, Serialize};

use chacha20_blake3::{
    blake3_mac,
    xchacha20_decrypt,
    xchacha20_encrypt,
    Session20b3,
};

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedFile {
    nonce: [u32; 3],
    tag: [u8; 32],
    ciphertext: Vec<u8>,
    version: u8,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyFile {
    key: [u32; 8],
    version: u8,
    created_at: u64,
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <encrypt|decrypt> <input_file> <output_file> <key_file>", args[0]);
        eprintln!("[!] Key file will be created if it doesn't exist during encryption");
        eprintln!("[!] Key file must exist during decryption");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  [+] {} encrypt secret.txt secret.enc key.bin", args[0]);
        eprintln!("  [+] {} decrypt secret.enc secret_decrypted.txt key.bin", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let input_file = PathBuf::from(&args[2]);
    let output_file = PathBuf::from(&args[3]);
    let key_file = PathBuf::from(&args[4]);

    if !input_file.exists() {
        eprintln!("[-] Input file not found: {}", input_file.display());
        std::process::exit(1);
    }

    match mode.as_str() {
        "encrypt" => encrypt_file(&input_file, &output_file, &key_file)?,
        "decrypt" => decrypt_file(&input_file, &output_file, &key_file)?,
        _ => {
            eprintln!("[-] Invalid mode. Use 'encrypt' or 'decrypt'");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn encrypt_file(input_path: &PathBuf, output_path: &PathBuf, key_path: &PathBuf) -> std::io::Result<()> {
    println!("[+] Starting file encryption...");
    let start_time = Instant::now();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut input_file = File::open(input_path)?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)?;
    let file_size = plaintext.len();
    println!("[?] File size: {} bytes", file_size);

    let key_file = if key_path.exists() {
        println!("[+] Loading existing key from: {}", key_path.display());
        load_key_serialized(key_path)?
    } else {
        println!("[+] Generating new key...");
        let new_key = generate_key();
        let key_file = KeyFile {
            key: new_key,
            version: 1,
            created_at: timestamp,
        };
        println!("[+] Saving key to: {}", key_path.display());
        save_key_serialized(key_path, &key_file)?;
        key_file
    };

    let info = Session20b3 {
        key: key_file.key,
        nonce: [0, 0, 0],
        counter: 1,
    };

    println!("[+] Encrypting data...");
    let (ciphertext, nonce) = xchacha20_encrypt(&info, &plaintext);

    let blake3_key = blake3_mac::derive_key(&info.key);
    let tag = blake3_mac::keyed_hash_nonce_ct(&nonce, &ciphertext, &blake3_key);

    let encrypted_file = EncryptedFile {
        nonce,
        tag,
        ciphertext,
        version: 1,
        timestamp,
    };

    println!("[+] Serializing encrypted data...");
    let serialized_data = bincode::serialize(&encrypted_file)
        .expect("Failed to serialize encrypted data");

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&serialized_data)?;

    let elapsed = start_time.elapsed();
    println!("[+] Encryption completed in {:?}", elapsed);
    println!("[?] Original size: {} bytes", file_size);
    println!("[?] Encrypted size: {} bytes", encrypted_file.ciphertext.len());
    println!("[?] Total file size: {} bytes", serialized_data.len());
    println!(
        "[?] Serialization overhead: {} bytes",
        serialized_data.len() - encrypted_file.ciphertext.len()
    );
    println!("[+] Output file: {}", output_path.display());
    println!("[+] Key file: {}", key_path.display());

    Ok(())
}

fn decrypt_file(input_path: &PathBuf, output_path: &PathBuf, key_path: &PathBuf) -> std::io::Result<()> {
    println!("[+] Starting file decryption...");
    let start_time = Instant::now();

    if !key_path.exists() {
        eprintln!("[-] Key file not found: {}", key_path.display());
        eprintln!("[!] Key file must exist for decryption");
        std::process::exit(1);
    }

    let mut input_file = File::open(input_path)?;
    let mut file_data = Vec::new();
    input_file.read_to_end(&mut file_data)?;

    if file_data.is_empty() {
        eprintln!("[-] Invalid encrypted file: empty");
        std::process::exit(1);
    }

    println!("[+] Deserializing encrypted data...");
    let encrypted_file: EncryptedFile = match bincode::deserialize(&file_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[-] Failed to deserialize encrypted data: {}", e);
            eprintln!("[!] File may be corrupted or in an old format");
            std::process::exit(1);
        }
    };

    println!("[?] File version: {}", encrypted_file.version);
    println!("[?] Created at: {}", encrypted_file.timestamp);
    println!("[?] Encrypted data size: {} bytes", encrypted_file.ciphertext.len());

    println!("[+] Loading key from: {}", key_path.display());
    let key_file = load_key_serialized(key_path)?;
    println!("[?] Key version: {}", key_file.version);

    if key_file.version != encrypted_file.version {
        println!(
            "[!] Warning: Key version ({}) differs from file version ({})",
            key_file.version, encrypted_file.version
        );
    }

    let info = Session20b3 {
        key: key_file.key,
        nonce: [0, 0, 0],
        counter: 1,
    };

    let blake3_key = blake3_mac::derive_key(&info.key);
    println!("[+] Verifying authentication...");

    if !blake3_mac::verify_nonce_ct(
        &encrypted_file.nonce,
        &encrypted_file.ciphertext,
        &encrypted_file.tag,
        &blake3_key,
    ) {
        eprintln!("[-] Authentication failed! File may have been tampered with.");
        std::process::exit(1);
    }
    println!("[+] Authentication successful!");

    println!("[+] Decrypting data...");

    let mut ciphertext_with_nonce = encrypted_file.ciphertext.clone();
    for word in encrypted_file.nonce.iter() {
        ciphertext_with_nonce.extend_from_slice(&word.to_le_bytes());
    }

    let plaintext = xchacha20_decrypt(&info, &ciphertext_with_nonce);

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&plaintext)?;

    let elapsed = start_time.elapsed();
    println!("[+] Decryption completed in {:?}", elapsed);
    println!("[?] Decrypted size: {} bytes", plaintext.len());
    println!("[+] Output file: {}", output_path.display());

    Ok(())
}

fn generate_key() -> [u32; 8] {
    let mut key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut key_bytes);

    let mut key = [0u32; 8];
    for (i, chunk) in key_bytes.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        key[i] = u32::from_le_bytes(b);
    }
    key
}

fn save_key_serialized(path: &PathBuf, key_file: &KeyFile) -> std::io::Result<()> {
    let serialized = bincode::serialize(key_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let mut file = File::create(path)?;
    file.write_all(&serialized)?;
    Ok(())
}

fn load_key_serialized(path: &PathBuf) -> std::io::Result<KeyFile> {
    let mut file = File::open(path)?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;

    let key_file: KeyFile = bincode::deserialize(&file_data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(key_file)
}
