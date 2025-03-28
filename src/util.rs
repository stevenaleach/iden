/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    util.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.
-----------------------------------------------------------------------------*/
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use rand::Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::UNIX_EPOCH;

// File paths for private and public keys
const PRIVATE_KEY_PATH: &str = ".iden/private_key.bin";
const PUBLIC_KEY_PATH: &str = ".iden/public_key.bin";

/// Stores IP tracking data: (last_seen_time, optional dedicated iden)
type IpThrottleStore = HashMap<[u8; 4], (f64, Option<[u8; 32]>)>;

use crate::id::State;
use sha2::{Digest, Sha256};

/// Reads a pad file, finds the lowest checkpoint above target_idx, steps to idx,
/// asks for password and confirmation, and writes two encrypted 36-byte states to output.
pub fn store_pad(pad_path: &str, target_idx: u32, out_path: &str) {
    println!("Reading pad file: {}", pad_path);
    let file = match File::open(pad_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open pad file: {}", e);
            return;
        }
    };
    let reader = BufReader::new(file);

    let mut checkpoint: Option<(u32, State)> = None;

    for line in reader.lines().flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            continue;
        }

        let idx = match parts[0].parse::<u32>() {
            Ok(i) => i,
            Err(_) => continue,
        };

        if idx <= target_idx {
            continue;
        }

        let state = match State::from_str(parts[1]) {
            Some(s) => s,
            None => continue,
        };

        // Always store the latest match that is still above target
        checkpoint = Some((idx, state));
    }

    let (start_idx, mut state) = match checkpoint {
        Some(c) => c,
        None => {
            eprintln!("No suitable checkpoint found above idx {}", target_idx);
            return;
        }
    };

    let steps = start_idx - target_idx;
    println!(
        "Checkpoint found at idx {}. Stepping down {} steps to target idx {}...",
        start_idx, steps, target_idx
    );

    if steps > 1_000_000 {
        println!("Warning: This will take a while...");
    }

    for i in 0..steps {
        state = state.step();
        if i % 1_000_000 == 0 && i > 0 {
            print!(".");
            let _ = io::stdout().flush();
        }
    }
    println!("\nStep-down complete.");

    let next_state = state.step();

    let password = prompt_password("Enter password: ");
    let verify = prompt_password("Verify password: ");

    if password != verify {
        eprintln!("Passwords do not match.");
        return;
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let key: Vec<u8> = hash[..32].to_vec();

    fn xor_partial(state: &State, key: &[u8]) -> Vec<u8> {
        let mut result = state.to_bytes();
        for i in 0..32 {
            result[i] ^= key[i % key.len()];
        }
        result.to_vec()
    }

    let encrypted_state = xor_partial(&state, &key);
    let encrypted_next = xor_partial(&next_state, &key);

    let mut out_file = match File::create(out_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create output file: {}", e);
            return;
        }
    };

    if out_file.write_all(&encrypted_state).is_err() || out_file.write_all(&encrypted_next).is_err()
    {
        eprintln!("Failed to write output file");
    } else {
        println!("Encrypted state written to {}", out_path);
    }
}

fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut password = String::new();
    if io::stdin().read_line(&mut password).is_ok() {
        password.trim().to_string()
    } else {
        String::new()
    }
}

/// Starts the single-threaded throttling service.
pub fn throttling_service() {
    let socket_path = ".iden/throttle";

    // Ensure no stale socket file exists
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path).unwrap();
    }

    // Load config values
    let throttle_delta = config("throttle_delta")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(2.0);
    let throttle_forget = config("throttle_forget")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(900.0);

    println!(
        "Throttling Service started. Delta: {:.2}s, Forget: {:.0}s",
        throttle_delta, throttle_forget
    );

    // Bind to the Unix socket
    let listener =
        UnixListener::bind(socket_path).expect("Failed to bind Unix socket for throttling");

    // Store IP records
    let mut ip_store: IpThrottleStore = HashMap::new();

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut buffer = [0; 38]; // '??' or 'de' + 4-byte IP + 32-byte iden

            if let Ok(n) = stream.read(&mut buffer) {
                if n >= 2 {
                    let opcode = &buffer[..2];

                    // Shutdown request
                    if opcode == b"qu" {
                        let _ = stream.write(b"Shutting Down Throttling Service.");
                        println!("Received shutdown signal. Stopping throttling service.");
                        break;
                    }

                    // Ensure valid message length
                    if n != 38 {
                        eprintln!("Invalid request size: {}", n);
                        continue;
                    }

                    let ip: [u8; 4] = buffer[2..6].try_into().unwrap();
                    let iden: [u8; 32] = buffer[6..38].try_into().unwrap();
                    let now = current_time();

                    // Remove old entries that exceed `throttle_forget` duration
                    ip_store.retain(|_, (last_seen, _)| now - *last_seen < throttle_forget);

                    let wait_time = match opcode {
                        b"??" => {
                            match ip_store.get(&ip) {
                                Some((_last_seen, Some(dedicated_iden))) => {
                                    if *dedicated_iden == iden {
                                        0.0 // Dedicated, no delay
                                    } else {
                                        throttle_delta // Different iden, apply normal delay
                                    }
                                }
                                Some((last_seen, None)) => {
                                    let since_last = now - *last_seen;
                                    if since_last >= throttle_delta {
                                        0.0
                                    } else {
                                        throttle_delta - since_last
                                    }
                                }
                                None => {
                                    // First time seeing this IP, store it now
                                    ip_store.insert(ip, (now, None));
                                    0.0
                                }
                            }
                        }

                        b"de" => {
                            // Dedicate IP to this iden **after** applying normal delay
                            let delay = match ip_store.get(&ip) {
                                Some((last_seen, _)) => {
                                    let since_last = now - *last_seen;
                                    if since_last >= throttle_delta {
                                        0.0
                                    } else {
                                        throttle_delta - since_last
                                    }
                                }
                                None => {
                                    // First time seeing this IP, store it now
                                    ip_store.insert(ip, (now, None));
                                    0.0
                                }
                            };

                            // Dedicate this IP to the given iden
                            //println!(
                            //    "IP {:?} dedicated to iden {:?}",
                            //    ip,
                            //    hex::encode(iden) // Display the iden as hex for logging
                            //);
                            ip_store.insert(ip, (now, Some(iden)));

                            delay // Still enforce delay on first dedication
                        }

                        _ => {
                            eprintln!("Unknown opcode received.");
                            continue;
                        }
                    };

                    // Update last seen timestamp
                    ip_store
                        .entry(ip)
                        .and_modify(|e| e.0 = now)
                        .or_insert((now, None));

                    // Send back how long TCP should sleep
                    let _ = stream.write(&wait_time.to_le_bytes());
                }
            }
        }
    }

    println!("Throttling service shutting down.");
}

//-----------------------------------------------------------------------------
/// Returns current time as f64 seconds since the Unix epoch.
pub fn current_time() -> f64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time is broken.")
        .as_secs_f64()
}

//-----------------------------------------------------------------------------
/// Reads a configuration key from `.iden/iden.cfg`.
pub fn config(key: &str) -> Option<String> {
    let config_path = Path::new(".iden/iden.cfg");
    if !config_path.exists() {
        return None;
    }

    let file = fs::File::open(config_path).ok()?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0].ends_with(':') {
                let key_name = &parts[0][..parts[0].len() - 1];
                if key_name == key {
                    return Some(parts[1].to_string());
                }
            }
        }
    }
    None
}

//-----------------------------------------------------------------------------
/// Generates a new Ed25519 key-pair and saves it to disk.
pub fn generate_keys() {
    //let mut rng = rand::rng();
    let mut private_key_bytes = [0u8; 32];
    for i in 0..32 {
        private_key_bytes[i] = random_byte();
    }

    //    for i in 0..32 {
    //        private_key_bytes[i] = rng.next_u32() as u8; // Use a range-safe random number
    //    }

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Ensure `.iden/` directory exists
    fs::create_dir_all(".iden").expect("Failed to create .iden directory");

    // Save private key (signing key)
    let mut private_file =
        File::create(PRIVATE_KEY_PATH).expect("Failed to create private key file");
    private_file
        .write_all(&private_key_bytes)
        .expect("Failed to write private key");

    // Save public key (verifying key)
    let mut public_file = File::create(PUBLIC_KEY_PATH).expect("Failed to create public key file");
    public_file
        .write_all(verifying_key.as_bytes())
        .expect("Failed to write public key");
}

//-----------------------------------------------------------------------------
/// Loads the Ed25519 signing key (private key) from disk.
pub fn load_signing_key() -> Option<SigningKey> {
    let private_key_bytes: [u8; 32] = fs::read(PRIVATE_KEY_PATH).ok()?.try_into().ok()?;
    Some(SigningKey::from_bytes(&private_key_bytes))
}

//-----------------------------------------------------------------------------
/// Loads the Ed25519 verifying key (public key) from disk.
pub fn load_verifying_key() -> Option<VerifyingKey> {
    let public_key_bytes: [u8; 32] = fs::read(PUBLIC_KEY_PATH).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&public_key_bytes).ok()
}

//-----------------------------------------------------------------------------
/// Constructs an Ed25519 verifying key from a 32-byte array.
/// Returns `None` if the bytes are invalid.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).ok()
}

//-----------------------------------------------------------------------------
/// Signs a byte sequence with the node's private key.
pub fn sign_data(data: &[u8]) -> Option<Signature> {
    let signing_key = load_signing_key()?;
    Some(signing_key.sign(data))
}

//-----------------------------------------------------------------------------
/// Verifies a signed byte sequence using the sender's public key.
pub fn verify_signature(public_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
    public_key.verify(data, signature).is_ok()
}

//-----------------------------------------------------------------------------
/// Performs a sanity check by signing and verifying the string "key test".
/// This ensures the stored signing and verifying keys are working correctly.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn sanity_check_keys() -> bool {
    let test_message = b"key test";

    // Load the signing key
    let signing_key = match load_signing_key() {
        Some(key) => key,
        None => {
            eprintln!("Sanity Check Failed: Unable to load signing key.");
            return false;
        }
    };

    // Load the verifying key
    let verifying_key = match load_verifying_key() {
        Some(key) => key,
        None => {
            eprintln!("Sanity Check Failed: Unable to load verifying key.");
            return false;
        }
    };

    // Sign the test message
    let signature = signing_key.sign(test_message);

    // Verify the signature
    if verifying_key.verify(test_message, &signature).is_ok() {
        println!("Signing Key Sanity Check Passed.");
        true
    } else {
        eprintln!("Sanity Check Failed: Signature verification failed.");
        false
    }
}

//-----------------------------------------------------------------------------
pub fn shard(iden: &[u8; 32]) -> Option<String> {
    let iden_hex = hex::encode(iden); // Convert to 64-character hex string
    let prefix = &iden_hex[..4]; // Extract first four hex characters

    let prefix_value = u16::from_str_radix(prefix, 16).ok()?;
    let path = Path::new(".iden/shard.map");

    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 {
                continue;
            }

            let (shard_name, start_hex, end_hex) = (parts[0], parts[1], parts[2]);
            if let (Ok(start), Ok(end)) = (
                u16::from_str_radix(start_hex, 16),
                u16::from_str_radix(end_hex, 16),
            ) {
                if (start..=end).contains(&prefix_value) {
                    return Some(shard_name.to_string());
                }
            }
        }
    }
    None
}

//-----------------------------------------------------------------------------
/// Returns a single random byte (u8) using `rng.random_range(..=255)`.
pub fn random_byte() -> u8 {
    let mut rng = rand::rng();
    rng.random_range(..=255)
}

//-----------------------------------------------------------------------------
/// Returns a vector of `n` random bytes, calling `random_byte()` for each.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(n);
    for _ in 0..n {
        bytes.push(random_byte());
    }
    bytes
}
