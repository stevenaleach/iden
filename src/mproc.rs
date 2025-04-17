/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    mproc.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.

Message Processor Unix socket service:

    Opcodes:
        - "cc"  → Claim count (debug)
        - "ck"  → Check claim presence (debug)
        - "cl"  → Claim
        - "co"  → Message count (debug)
        - "ct"  → Message count newer than t seconds
        - "gt"  → Get messages newer than t seconds
        - "ix"  → Retrieve current idx
        - "pr"  → Proof
        - "qu"  → Quit service
        - "re"  → Report
        - "si"  → Retrieve a signal by idx
        - "st"  → Retrieve highest known state
        - "ve"  → Version

-----------------------------------------------------------------------------*/
use crate::id::{Iden, State};
use crate::util::{config, current_time};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_RESPONSE_SIZE: usize = 4 * 1024 * 1024; // 4MB limit
//
//-----------------------------------------------------------------------------
/// Response codes for mproc.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RE {
    OK = 0,
    BadSize = 1,
    TooLow = 2,
    TooFar = 3,
    False = 4,
}

impl RE {
    pub fn to_byte(self) -> [u8; 1] {
        [self as u8]
    }
}
//-----------------------------------------------------------------------------
/// message processor instance and configuration values to be passed as
/// command-line arguments when launching.
pub struct MProc {
    command: String,
    socket_path: String,
}

/// Creates a new `MProc` instance with the specified command and socket path.
impl MProc {
    pub fn new(command: String, socket_path: String) -> Self {
        Self {
            command,
            socket_path,
        }
    }
    /// Start a background mproc service.
    pub fn start(&self) {
        let _child = Command::new(&self.command)
            .arg("mproc")
            .arg(&self.socket_path) //.arg(&self.step_limit)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start mproc instance");
    }
}

//-----------------------------------------------------------------------------
/// Report Message: "re"+Iden+State.
#[derive(Debug, Clone)]
pub struct Report {
    pub iden: Iden,
    pub state: State,
}

impl Report {
    pub fn encode(&self) -> [u8; 70] {
        let mut buf = [0u8; 70];
        buf[..2].copy_from_slice(b"re"); // Opcode "re" as two bytes
        buf[2..34].copy_from_slice(&self.iden.to_bytes());
        buf[34..].copy_from_slice(&self.state.to_bytes());
        buf
    }
}

//-----------------------------------------------------------------------------
/// Listener for mproc service on local unix socket.
pub fn listener(args: &[String]) {
    println!("\nmproc udp listener started.");
    if args.is_empty() {
        eprintln!("No socket path provided.");
        return;
    }
    let split_chars = config("ss_split_chars")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4);
    println!("ss_split_chars: {}", split_chars);

    let split_count = config("ss_split_count")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4);
    println!("ss_split_count: {}", split_count);

    let signal_cache_size = config("signal_cache_size")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4096);
    println!("signal_cache_size: {}\n", signal_cache_size);

    let step_limit = config("mproc_step_limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10_000);
    println!("mproc_step_limit: {}\n", step_limit);

    let claim_cache_limit = config("claim_cache_limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(512);
    println!("claim_cache_limit: {}", claim_cache_limit);

    let claim_cache_time = config("claim_cache_time")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(900.0); // Default: 900 seconds (15 minutes)
    println!("claim_cache_time: {} seconds", claim_cache_time);

    let claim_cache_total = config("claim_cache_total")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10000000); // Default: 10000000
    println!("claim_cache_total: {}", claim_cache_total);

    let mut message_cache = MessageCache::new();

    let signal_store = SignalStore::new(split_chars, split_count, signal_cache_size);
    let mut claim_cache = ClaimCache::new(claim_cache_time, claim_cache_limit, claim_cache_total);

    let sock_path = &args[0];
    let socket = Path::new(sock_path);
    if socket.exists() {
        std::fs::remove_file(socket).unwrap();
    }
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();

    println!("\nListening on socket {:?}", socket);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => mproc_handler(
                stream,
                step_limit,
                &signal_store,
                &mut claim_cache,
                &mut message_cache,
            ),
            Err(err) => println!("mproc Unix Stream error: {:?}", err),
        }
    }
}

//-----------------------------------------------------------------------------
/// Connection handler for mproc service on local Unix socket.
fn mproc_handler(
    mut stream: std::os::unix::net::UnixStream,
    step_limit: u32,
    signal_store: &SignalStore,
    claim_cache: &mut ClaimCache,
    message_cache: &mut MessageCache,
) {
    let mut buf = [0; 65536];

    if let Ok(n) = stream.read(&mut buf) {
        if n >= 2 {
            match &buf[..2] {
                //-------------------------------------------------------------
                // This is basically useless for any purpose other than
                // debugging.  It can be called from the REPL.
                b"cc" => {
                    // CLAIM COUNT
                    if n != 34 {
                        let _ = stream.write(&(-1i32).to_le_bytes()); // Return -1 on bad size
                        return;
                    }

                    // Parse iden
                    let iden = match Iden::try_from(&buf[2..34]) {
                        Ok(iden) => iden,
                        Err(_) => {
                            let _ = stream.write(&(-1i32).to_le_bytes()); // Return -1 on parsing error
                            return;
                        }
                    };

                    // Get claim count
                    let count = claim_cache.claim_count(&iden);

                    // Send response as little-endian 4-byte integer
                    let _ = stream.write(&count.to_le_bytes());
                }

                //-------------------------------------------------------------
                b"ck" => {
                    //  CLAIM CHECK
                    if n != 70 {
                        let _ = stream.write(&RE::BadSize.to_byte());
                        return;
                    }

                    // Parse iden, mix, and n
                    let iden = match Iden::try_from(&buf[2..34]) {
                        Ok(iden) => iden,
                        Err(_) => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    let mut mix = [0u8; 32];
                    mix.copy_from_slice(&buf[34..66]);

                    let n = u32::from_le_bytes(buf[66..70].try_into().unwrap());

                    // Check if claim exists
                    if claim_cache.claim_check(&iden, &mix, n) {
                        let _ = stream.write(&RE::OK.to_byte()); // Claim exists
                    } else {
                        let _ = stream.write(&RE::False.to_byte()); // No match found
                    }
                }

                //-------------------------------------------------------------
                b"cl" => {
                    // CLAIM MESSAGE
                    // "cl" (2 bytes) + iden (32 bytes) + mix (32 bytes) + idx (4 bytes)
                    if n != 70 {
                        let _ = stream.write(&RE::BadSize.to_byte());
                        return;
                    }

                    // Parse iden, mix, and n
                    let iden = match Iden::try_from(&buf[2..34]) {
                        Ok(iden) => iden,
                        Err(_) => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    let mut mix = [0u8; 32];
                    mix.copy_from_slice(&buf[34..66]);

                    let n = u32::from_le_bytes(buf[66..70].try_into().unwrap());

                    // Store the claim
                    claim_cache.add_claim(iden, mix, n, signal_store);

                    // Send success response
                    let _ = stream.write(&RE::OK.to_byte());
                }
                //-------------------------------------------------------------
                // This too exists only for debugging.  Call it from REPL
                // if it interests you.
                b"co" => {
                    // COUNT total cache size (MessageCache)
                    let count = message_cache.count() as u32; // convert usize to u32
                    let _ = stream.write(&count.to_le_bytes()); // Send as 4-byte LE
                }

                //-------------------------------------------------------------
                b"ct" => {
                    // COUNT_T: entries newer than provided t seconds (MessageCache)
                    if n != 10 {
                        let _ = stream.write(&0u32.to_le_bytes()); // Invalid request size returns 0
                        return;
                    }

                    // Parse t (f64, little-endian bytes)
                    let t = f64::from_le_bytes(buf[2..10].try_into().unwrap());

                    let count = message_cache.count_t(t) as u32; // convert usize to u32
                    let _ = stream.write(&count.to_le_bytes()); // Send as 4-byte LE
                }

                //-------------------------------------------------------------
                b"gt" => {
                    if n != 10 {
                        let _ = stream.write(&0u32.to_le_bytes()); // Return 0 messages if the request is malformed
                        return;
                    }

                    // Parse t (f64, little-endian bytes)
                    let t = f64::from_le_bytes(buf[2..10].try_into().unwrap());

                    // Retrieve messages
                    let messages = message_cache.get_t(t, claim_cache, signal_store);

                    // If no messages, return immediately without writing anything
                    if messages.is_empty() {
                        return;
                    }

                    // Convert messages to a byte stream
                    let mut response = Vec::new();
                    let mut total_size = 0;

                    for msg in messages {
                        let msg_size = msg.len();
                        if total_size + msg_size > MAX_RESPONSE_SIZE {
                            break; // Stop adding messages once we hit the 4MB limit
                        }
                        response.extend_from_slice(&msg); // Append message bytes
                        total_size += msg_size;
                    }

                    // Send the response
                    let _ = stream.write(&response);
                }

                //-------------------------------------------------------------
                b"ix" => {
                    // IDX
                    if n == 34 {
                        if let Ok(iden) = Iden::try_from(&buf[2..34]) {
                            if let Some(idx) = signal_store.get_idx(&iden) {
                                let _ = stream.write(&idx.to_le_bytes());
                            } else {
                                let _ = stream.write(&[0]); // Single byte response for "not found"
                            }
                        }
                    }
                }

                //-------------------------------------------------------------
                b"pr" => {
                    // PROOF
                    if n != 134 {
                        let _ = stream.write(&RE::BadSize.to_byte());
                        return;
                    }

                    // Parse iden, state, and signal
                    let iden = match Iden::try_from(&buf[2..34]) {
                        Ok(iden) => iden,
                        Err(_) => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    let state = match State::try_from(&buf[34..70]) {
                        Ok(state) => state,
                        Err(_) => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    let signal = match Signal::from_bytes(&buf[70..134]) {
                        Some(signal) => signal,
                        None => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    // Get highest known state from storage
                    let base_state = signal_store
                        .get_state(&iden)
                        .unwrap_or_else(|| iden.to_state());

                    let step_count = state.idx().saturating_sub(base_state.idx());

                    // Validate state
                    if state.idx() <= base_state.idx() {
                        let _ = stream.write(&RE::TooLow.to_byte());
                        message_cache.include(iden);
                        return;
                    } else if step_count > step_limit {
                        let _ = stream.write(&RE::TooFar.to_byte());
                        message_cache.include(iden);
                        return;
                    } else if !base_state.step_check(&state) {
                        let _ = stream.write(&RE::False.to_byte());
                        message_cache.include(iden);
                        return;
                    }

                    // Compute mix
                    let mix_value = mix(&state, &signal);

                    // Check if claim exists in cache
                    if claim_cache.claim_check(&iden, &mix_value, state.idx()) {
                        // Claim found: Store state and signal
                        signal_store.write(&iden, &state, Some(&signal));
                        // DROP FROM N ON CLAIM CACHE HERE.
                        claim_cache.drop_from(&iden, state.idx());
                    } else {
                        // No claim found: Store state only
                        signal_store.write(&iden, &state, None);
                        // DROP FROM N ON CLAIM CACHE HERE.
                        claim_cache.drop_from(&iden, state.idx());
                    }

                    // Acknowledge success
                    let _ = stream.write(&RE::OK.to_byte());
                    message_cache.add(iden);
                }

                //-------------------------------------------------------------
                b"qu" => {
                    // QUIT
                    println!("mproc exiting.");
                    let _ = stream.write(b"Shutting Down.");
                    std::process::exit(0);
                }

                //-------------------------------------------------------------
                b"re" => {
                    // REPORT
                    if n == 70 {
                        let iden = Iden::try_from(&buf[2..34]);
                        let state = State::try_from(&buf[34..70]);

                        if let (Ok(iden), Ok(state)) = (iden, state) {
                            // Get highest known state from storage
                            let base_state = signal_store
                                .get_state(&iden)
                                .unwrap_or_else(|| iden.to_state());

                            let step_count = state.idx().saturating_sub(base_state.idx());

                            // Check if reported state is too low
                            if state.idx() <= base_state.idx() {
                                let _ = stream.write(&RE::TooLow.to_byte());
                                message_cache.include(iden);
                            }
                            // Check if the state steps too far
                            else if step_count > step_limit {
                                let _ = stream.write(&RE::TooFar.to_byte());
                                message_cache.include(iden);
                            }
                            // Step down only to `base_state`, not idx=0
                            else if base_state.step_check(&state) {
                                let _ = stream.write(&RE::OK.to_byte());
                                message_cache.add(iden);

                                // Write the state into the signal store
                                signal_store.write(&iden, &state, None);
                                // DROP FROM N ON CLAIM CACHE HERE.
                                claim_cache.drop_from(&iden, state.idx());
                            } else {
                                let _ = stream.write(&RE::False.to_byte());
                                message_cache.include(iden);
                            }
                        } else {
                            let _ = stream.write(&RE::BadSize.to_byte());
                        }
                    } else {
                        let _ = stream.write(&RE::BadSize.to_byte());
                    }
                }

                //-------------------------------------------------------------
                b"si" => {
                    // SIGNAL
                    if n != 38 {
                        let _ = stream.write(&RE::BadSize.to_byte());
                        return;
                    }

                    // Parse iden
                    let iden = match Iden::try_from(&buf[2..34]) {
                        Ok(iden) => iden,
                        Err(_) => {
                            let _ = stream.write(&RE::BadSize.to_byte());
                            return;
                        }
                    };

                    // Parse index (last 4 bytes, little-endian)
                    let idx = u32::from_le_bytes(buf[34..38].try_into().unwrap());

                    // Retrieve the signal from the SignalStore
                    if let Some(signal) = signal_store.signal(&iden, idx) {
                        let _ = stream.write(&signal.to_bytes()); // Send 64-byte signal
                    } else {
                        let _ = stream.write(&[0]); // No signal found, send single byte 0
                    }
                }

                //-------------------------------------------------------------
                b"st" => {
                    // STATE
                    if n == 34 {
                        if let Ok(iden) = Iden::try_from(&buf[2..34]) {
                            if let Some(state) = signal_store.get_state(&iden) {
                                let _ = stream.write(&state.to_bytes());
                            } else {
                                let _ = stream.write(&[0]); // Single byte response for "not found"
                            }
                        }
                    }
                }

                //-------------------------------------------------------------
                b"ve" => {
                    // VERSION
                    // Retrieve the version from Cargo.toml via environment variable
                    let version = env!("CARGO_PKG_VERSION").as_bytes();
                    let _ = stream.write(version);
                }

                //-------------------------------------------------------------
                _ => {
                    return;
                } //-------------------------------------------------------------
            }
        }
    }
}

/// Represents a Signal as a 64-byte array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(pub [u8; 64]);

impl Signal {
    /// Creates a `Signal` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 64 {
            let mut signal = [0u8; 64];
            signal.copy_from_slice(bytes);
            Some(Self(signal))
        } else {
            None
        }
    }

    /// Converts the `Signal` to a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

/// Mix function: Computes SHA-256(State + Signal)
pub fn mix(state: &State, signal: &Signal) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&state.to_bytes());
    hasher.update(&signal.to_bytes());
    let result = hasher.finalize();

    let mut mix = [0u8; 32];
    mix.copy_from_slice(&result[..32]); // Take the first 32 bytes
    mix
}

//-----------------------------------------------------------------------------
/// Disk storage for iden:state:signal records.
///
/// Byte 0 flag marks the first entry as state only or state+signal.  Any
/// records past the first are always state+signal. The file is kept trimmed
/// to config(signal_cache_size)
pub struct SignalStore {
    split_chars: usize,
    split_count: usize,
    signal_cache_size: usize,
}

impl SignalStore {
    /// Initializes a `SignalStore` with passed configuration values
    pub fn new(split_chars: usize, split_count: usize, signal_cache_size: usize) -> Self {
        Self {
            split_chars,
            split_count,
            signal_cache_size,
        }
    }

    /// Generates the path for the given `Iden`
    /// iden.path + ss.bin
    fn iden_path(&self, iden: &Iden) -> String {
        format!("{}ss.bin", iden.to_path(self.split_chars, self.split_count))
    }

    pub fn write(&self, iden: &Iden, state: &State, signal: Option<&Signal>) {
        let path = PathBuf::from(self.iden_path(iden));
        let dir = path.parent().unwrap();

        // Ensure the directory exists
        if !dir.exists() {
            if let Err(e) = fs::create_dir_all(dir) {
                eprintln!("Failed to create directory {:?}: {:?}", dir, e);
                return;
            }
        }

        // Read old file (if exists)
        let mut buffer = Vec::new();
        if let Ok(mut file) = OpenOptions::new().read(true).open(&path) {
            if let Err(e) = file.read_to_end(&mut buffer) {
                eprintln!("Failed to read existing file {:?}: {:?}", path, e);
            }
        }

        // If buffer is empty, this is a new file—no need to trim anything.
        if buffer.is_empty() {
            buffer.clear(); // Explicitly reset just in case
        } else {
            // Safely check the first byte only if the buffer isn't empty
            let is_state_signal = buffer.first().copied().unwrap_or(0) == 1;

            // If old file starts with 0, trim first 37 bytes; if it starts
            // with 1, trim first byte
            if !is_state_signal && buffer.len() >= 37 {
                buffer.drain(0..37); // Remove first state-only record
            } else if is_state_signal {
                // Remove only the first byte for state+signal
                buffer.drain(0..1);
            }
        }

        // Construct new file content
        let mut new_file_content = vec![if signal.is_some() { 1 } else { 0 }];
        new_file_content.extend_from_slice(&state.to_bytes());

        if let Some(sig) = signal {
            new_file_content.extend_from_slice(&sig.to_bytes());
        }

        // Append remaining old content
        new_file_content.extend_from_slice(&buffer);

        // Write to file
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // Ensure we overwrite old content
            .open(&path)
        {
            if let Err(e) = file.write_all(&new_file_content) {
                eprintln!("Failed to write to file {:?}: {:?}", path, e);
            }
        }

        self.trim(&iden);
    }

    ///------------------------------------------------------------------------
    /// Trims `ss.bin` if it exceeds `signal_cache_size`
    pub fn trim(&self, iden: &Iden) {
        let iden_path = self.iden_path(iden);
        let path = Path::new(&iden_path);

        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file for trimming: {:?}", err);
                return;
            }
        };

        let mut buffer = Vec::new();
        if let Err(err) = file.read_to_end(&mut buffer) {
            eprintln!("Failed to read file for trimming: {:?}", err);
            return;
        }

        // Ensure we always remove full records, avoiding partial corruption
        while buffer.len() > self.signal_cache_size {
            if buffer.len() >= 101 {
                buffer.drain(0..100); // Remove an entire state:signal record
            } else {
                break;
            }
        }

        // Directly write the trimmed content back without truncating first
        if let Err(err) = file.write_all(&buffer) {
            eprintln!("Failed to write trimmed data: {:?}", err);
        }

        // Ensure the file length matches the new buffer size
        if let Err(err) = file.set_len(buffer.len() as u64) {
            eprintln!("Failed to set trimmed file length: {:?}", err);
        }
    }

    ///------------------------------------------------------------------------
    /// Get Option<State> with current high state, if any, for an Iden.
    pub fn get_state(&self, iden: &Iden) -> Option<State> {
        let path = PathBuf::from(self.iden_path(iden));

        // Open the file and read the first 37 bytes
        // (1-byte header + 36-byte state)
        let mut file = fs::File::open(&path).ok()?;
        let mut buffer = [0u8; 37];

        // Ensure we can read at least 37 bytes
        if file.read_exact(&mut buffer).is_err() {
            return None;
        }

        // Extract the state from bytes 1-37 (ignoring the first byte)
        State::try_from(&buffer[1..]).ok() // Convert `Result` to `Option`
    }
    /// Retrieves `idx` value of the most recent `State` in the signal store.
    /// Returns `None` if the file does not exist or is too small.
    pub fn get_idx(&self, iden: &Iden) -> Option<u32> {
        self.get_state(iden).map(|state| state.idx())
    }

    pub fn get_message(&self, iden: &Iden) -> Option<Vec<u8>> {
        let path = PathBuf::from(self.iden_path(iden));

        // Open the file, return None if it doesn't exist
        let mut file = fs::File::open(&path).ok()?;

        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_err() {
            return None;
        }

        if buffer.is_empty() {
            return None;
        }

        // The first byte determines the type of stored data
        match buffer[0] {
            0 => {
                // State-only record, construct a report message
                if buffer.len() < 37 {
                    return None; // Invalid record
                }
                let state_bytes = &buffer[1..37];

                let mut msg = vec![b'r', b'e']; // "re"
                msg.extend_from_slice(&iden.to_bytes());
                msg.extend_from_slice(state_bytes);

                Some(msg)
            }
            1 => {
                // State+signal record, construct a proof message
                if buffer.len() < 101 {
                    return None; // Invalid record
                }
                let state_bytes = &buffer[1..37];
                let signal_bytes = &buffer[37..101];

                let mut msg = vec![b'p', b'r']; // "pr"
                msg.extend_from_slice(&iden.to_bytes());
                msg.extend_from_slice(state_bytes);
                msg.extend_from_slice(signal_bytes);

                Some(msg)
            }
            _ => None, // Invalid first byte
        }
    }

    /// Retrieves signal n for iden if present in store.
    pub fn signal(&self, iden: &Iden, n: u32) -> Option<Signal> {
        let path = PathBuf::from(self.iden_path(iden));
        let mut file = fs::File::open(&path).ok()?; // Return None if file does not exist

        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_err() {
            return None; // Return None on read failure
        }

        if buffer.is_empty() {
            return None; // Empty file, return None
        }

        let mut offset = 1; // Default start position

        // Check if the first byte is 0, meaning the first record is state-only
        if buffer[0] == 0 {
            if buffer.len() < 38 {
                return None; // Not enough data to have a valid state
            }
            offset = 37; // Skip the first 37-byte state-only record
        }

        // Iterate through remaining state+signal records (100 bytes each)
        while offset + 100 <= buffer.len() {
            let state_bytes = &buffer[offset..offset + 36];
            let signal_bytes = &buffer[offset + 36..offset + 100];

            // Extract the index from the last 4 bytes of the state (little-endian)
            let state_idx = u32::from_le_bytes(state_bytes[32..36].try_into().unwrap());

            if state_idx == n {
                return Signal::from_bytes(signal_bytes); // Found the matching idx, return the signal
            }

            offset += 100; // Move to the next state+signal pair
        }

        None // No matching idx found
    }
}

//-----------------------------------------------------------------------------
//  CLAIM CACHE
//-----------------------------------------------------------------------------
// In memory claim-cache.
/// A single claim entry with mix, promised index, and timestamp.
#[derive(Debug, Clone)]
pub struct ClaimEntry {
    mix: [u8; 32],  // 32-byte mix
    n: u32,         // Promised index
    timestamp: f64, // Time first seen
}

//-----------------------------------------------------------------------------
/// Stores claims grouped by `Iden`, with last access timestamps.
pub struct ClaimCache {
    claims: HashMap<Iden, (f64, Vec<ClaimEntry>)>, // (last_access_time, claims)
    max_age: f64,                                  // Max claim retention time (seconds)
    max_size: usize,                               // Max number of claims per iden
    total_max: usize,                              // Maximum total entries in cache
}

//-----------------------------------------------------------------------------
impl ClaimCache {
    /// Create a new ClaimCache with a given expiration time and max size.
    pub fn new(max_age: f64, max_size: usize, total_max: usize) -> Self {
        Self {
            claims: HashMap::new(),
            max_age,
            max_size,
            total_max,
        }
    }

    //-------------------------------------------------------------------------
    /// Returns the number of claims stored for a given `Iden`.
    pub fn claim_count(&self, iden: &Iden) -> i32 {
        self.claims
            .get(iden)
            .map_or(0, |(_, claims)| claims.len() as i32)
    }

    pub fn add_claim(&mut self, iden: Iden, mix: [u8; 32], n: u32, signal_store: &SignalStore) {
        // Retrieve the current highest known index for the iden
        let Some(current_idx) = signal_store.get_idx(&iden) else {
            return; // Ignore claims for unknown idens
        };

        // Only accept claims where n > current_idx
        if n <= current_idx {
            return; // Reject claims that promise an idx lower than or equal to current_idx
        }

        let now = current_time();
        let entry = self.claims.entry(iden).or_insert_with(|| (now, Vec::new()));

        // Update last access time
        entry.0 = now;
        let claims = &mut entry.1;

        // Remove expired claims and those with lower `n`
        claims.retain(|c| now - c.timestamp < self.max_age && c.n >= n);

        // Check if claim already exists
        if !claims.iter().any(|c| c.mix == mix && c.n == n) {
            claims.push(ClaimEntry {
                mix,
                n,
                timestamp: now,
            });
        }

        self.clean_iden(&iden);
        self.clean_cache();
    }

    //-------------------------------------------------------------------------
    /// Returns True/False if claim is present, runs clean_iden(), resets
    /// iden's last access time.
    pub fn claim_check(&mut self, iden: &Iden, mix: &[u8; 32], proof_n: u32) -> bool {
        let now = current_time();
        let mut result = false;

        if let Some(entry) = self.claims.get_mut(iden) {
            entry.0 = now; // Update last access time

            // Check if a matching claim exists
            result = entry.1.iter().any(|c| c.mix == *mix && c.n <= proof_n);
        }

        // Clean up old claims for this iden after checking
        self.clean_iden(iden);

        result
    }

    //-------------------------------------------------------------------------
    pub fn clean_iden(&mut self, iden: &Iden) {
        if let Some((_, claims)) = self.claims.get_mut(iden) {
            let now = current_time();

            // Remove expired claims
            claims.retain(|c| now - c.timestamp < self.max_age);

            // If claims exceed max_size, remove oldest first
            while claims.len() > self.max_size {
                if let Some(pos) = claims
                    .iter()
                    .enumerate()
                    .min_by(|a, b| a.1.timestamp.partial_cmp(&b.1.timestamp).unwrap())
                    .map(|(idx, _)| idx)
                {
                    claims.remove(pos);
                }
            }
        }

        // If no claims remain, remove the entire `Iden` from the cache
        if let Some((_, claims)) = self.claims.get(iden) {
            if claims.is_empty() {
                self.claims.remove(iden);
            }
        }
    }

    //-------------------------------------------------------------------------
    // Cleans the entire cache (if oversized) beginning with clean_iden() on
    // all idens and then dumping oldest iden records entirely.
    pub fn clean_cache(&mut self) {
        // TODO: Test exceeding total max size.  clean_iden() has been tested by
        // adding claims over a period of time, checking with claim_count, count
        // builds then starts to degrade as claims get too old.  Check. Yay.
        if self.total_claims() > self.total_max {
            // Collect the idens first, then iterate over them
            let idens: Vec<Iden> = self.claims.keys().copied().collect();
            for iden in idens {
                self.clean_iden(&iden);

                // If empty after cleanup, remove it
                if let Some((_, claims)) = self.claims.get(&iden) {
                    if claims.is_empty() {
                        self.claims.remove(&iden);
                    }
                }
            }
        }

        while self.total_claims() > self.total_max {
            if let Some((oldest_iden, _)) = self
                .claims
                .iter()
                .min_by(|a, b| a.1.0.partial_cmp(&b.1.0).unwrap()) // Find the oldest last_access_time
                .map(|(iden, _)| (*iden, ()))
            {
                self.claims.remove(&oldest_iden);
            }
        }
    }

    //-------------------------------------------------------------------------
    /// Returns the total number of claims across all `Iden`s.
    pub fn total_claims(&self) -> usize {
        self.claims.values().map(|(_, claims)| claims.len()).sum()
    }

    //-------------------------------------------------------------------------
    /// Removes all claims for the given `Iden` without promised idx values
    /// higher than n.
    pub fn drop_from(&mut self, iden: &Iden, n: u32) {
        if let Some((_, claims)) = self.claims.get_mut(iden) {
            claims.retain(|c| c.n > n);

            // If no claims remain after filtering, remove the entire entry
            if claims.is_empty() {
                self.claims.remove(iden);
            }
        }
    }
    /// Returns a vector of claim messages for a given `Iden`, or None if no claims exist.
    pub fn messages(&self, iden: &Iden) -> Option<Vec<Vec<u8>>> {
        if let Some((_, claims)) = self.claims.get(iden) {
            if claims.is_empty() {
                return None;
            }

            let mut messages = Vec::new();
            for claim in claims {
                let mut msg = Vec::with_capacity(70);
                msg.extend_from_slice(b"cl"); // Opcode
                msg.extend_from_slice(&iden.to_bytes());
                msg.extend_from_slice(&claim.mix);
                msg.extend_from_slice(&claim.n.to_le_bytes());
                messages.push(msg);
            }

            Some(messages)
        } else {
            None
        }
    }
}

/// A cache to track recently seen messages using timestamps.
pub struct MessageCache {
    cache: HashMap<Iden, f64>, // Maps `Iden` to the last-seen timestamp
    max_size: usize,           // Maximum cache size
    max_age: f64,              // Maximum retention time in seconds
}

impl MessageCache {
    /// Creates a new `MessageCache` with parameters from config.
    pub fn new() -> Self {
        let max_size = config("message_cache_size")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(10000);
        println!("\tmessage_cache_size: {}", max_size);

        let max_age = config("message_cache_time")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(900.0); // Default to 15 minutes
        println!("\tmessage_cache_time: {} seconds", max_age);

        Self {
            cache: HashMap::new(),
            max_size,
            max_age,
        }
    }

    /// Adds an `Iden` to the cache, updating its timestamp if it already exists.
    pub fn add(&mut self, iden: Iden) {
        let now = current_time();
        self.cache.insert(iden, now);
        self.cleanup();
    }

    /// Includes an `Iden` in the cache without updating its timestamp if it already exists.
    pub fn include(&mut self, iden: Iden) {
        if !self.cache.contains_key(&iden) {
            self.add(iden);
            self.cleanup();
        }
    }

    /// Removes expired entries and trims to `max_size` if necessary.
    pub fn cleanup(&mut self) {
        let now = current_time();

        // Remove expired entries
        self.cache
            .retain(|_, &mut timestamp| now - timestamp < self.max_age);

        // If the cache exceeds max size, remove the oldest entries
        if self.cache.len() > self.max_size {
            let mut entries: Vec<_> = self.cache.iter().collect();
            entries.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap()); // Sort by timestamp
            self.cache = entries
                .into_iter()
                .rev()
                .take(self.max_size)
                .map(|(&iden, &timestamp)| (iden, timestamp))
                .collect();
        }
    }

    pub fn get_t(
        &self,
        t: f64,
        claim_cache: &ClaimCache,
        signal_store: &SignalStore,
    ) -> Vec<Vec<u8>> {
        let now = current_time();

        // Step 1: Filter only relevant entries (skip old ones)
        let mut recent_entries: Vec<_> = self
            .cache
            .iter()
            .filter(|&(_, timestamp)| now - *timestamp <= t) // Explicitly dereference timestamp
            .collect();

        // Step 2: Sort the filtered entries (oldest first)
        recent_entries.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap());

        let mut messages = Vec::new();

        // Step 3: Iterate only over relevant entries
        for (&iden, _) in recent_entries {
            if let Some(claims) = claim_cache.messages(&iden) {
                messages.extend(claims);
            }
            if let Some(message) = signal_store.get_message(&iden) {
                messages.push(message);
            }
        }

        messages
    }

    pub fn count(&self) -> usize {
        self.cache.len()
    }

    /// Returns the number of entries added within the last `t` seconds.
    pub fn count_t(&self, t: f64) -> usize {
        let now = current_time();
        self.cache
            .values()
            .filter(|&&timestamp| now - timestamp <= t)
            .count()
    }
}
