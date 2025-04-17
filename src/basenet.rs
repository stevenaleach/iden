/*-----------------------------------------------------------------------------
    IDEN 0.1.0
    basenet.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.

    This module implements the Basenet service which:
    - Listens on a Unix socket .iden/bn<name>.

basenet Unix socket and TCP services:

    Supported Opcodes:
    - "of" → Offer: submit a new payload for a given iden + index + hashkey.
    - "ck" → Check: verify if a record already exists.
    - "id"* → Resolve: resolve a content request from a URI.
        * iden://<iden string>(.n)
    - "qu" → Quit: stop the service.

    Payload Types (determined by YAML header key '_'):
    - _ = 0 → Single overwriteable record stored in 0.bin.
    - _ = 1 → Rolling log of records, size-bound by pin.txt or 128KB (1.bin).
-----------------------------------------------------------------------------*/
use crate::id::Iden;
use crate::util;
use hex;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use threadpool::ThreadPool;

/// Starts the basenet service, listening on a Unix socket passed as a command-line argument.
pub fn listener(args: &[String]) {
    println!("\nbasenet service starting...");

    if args.is_empty() {
        eprintln!("No socket path provided.");
        return;
    }

    let sock_path = &args[0];
    let socket = Path::new(sock_path);

    if socket.exists() {
        fs::remove_file(socket).unwrap();
    }

    let listener = UnixListener::bind(socket).expect("Failed to bind Unix socket for basenet");
    println!("Listening on {:?}", socket);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buffer = [0; 1024];
                if let Ok(n) = stream.read(&mut buffer) {
                    if n < 2 {
                        continue;
                    }

                    match &buffer[..2] {
                        // Check for record in store.
                        // [2..34]: 32-byte iden, [34..38]: u32_le idx
                        b"ck" => {
                            if n != 38 {
                                eprintln!("Invalid 'check' message length: {}", n);
                                continue;
                            }

                            let iden = match Iden::try_from(&buffer[2..34]) {
                                Ok(i) => i,
                                Err(_) => {
                                    eprintln!("Invalid iden format in 'check' message.");
                                    continue;
                                }
                            };

                            let idx = u32::from_le_bytes(buffer[34..38].try_into().unwrap());
                            println!("Received CHECK request:");
                            println!("  iden : {}", hex::encode(iden.to_bytes()));
                            println!("  idx  : {}", idx);

                            let split_chars = util::config("ss_split_chars")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);
                            let split_count = util::config("ss_split_count")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);

                            let content_path = iden.to_path(split_chars, split_count);
                            let path = format!("{}/1.bin", content_path);

                            if !Path::new(&path).exists() {
                                let _ = stream.write_all(b"NO");
                                println!("  → 1.bin not found.");
                                continue;
                            }

                            let file = match File::open(&path) {
                                Ok(f) => f,
                                Err(e) => {
                                    eprintln!("  → Failed to open 1.bin: {}", e);
                                    let _ = stream.write_all(b"NO");
                                    continue;
                                }
                            };

                            let mut reader = BufReader::new(file);
                            let mut found = false;

                            loop {
                                let mut header = [0u8; 6];
                                match reader.read_exact(&mut header) {
                                    Ok(_) => {
                                        let rec_idx = u32::from_le_bytes([
                                            header[0], header[1], header[2], header[3],
                                        ]);
                                        let rec_len =
                                            u16::from_le_bytes([header[4], header[5]]) as usize;

                                        if rec_idx == idx {
                                            found = true;
                                            break;
                                        }

                                        if reader.seek_relative(rec_len as i64).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            if found {
                                let _ = stream.write_all(b"YE");
                                println!("  → Match found for idx");
                            } else {
                                let _ = stream.write_all(b"NO");
                                println!("  → No matching idx found");
                            }
                        }
                        // Shut-down.
                        b"qu" => {
                            let _ = stream.write(b"Shutting Down basenet service.\n");
                            println!("Received shutdown signal. Exiting basenet service.");
                            break;
                        }

                        b"of" => {
                            if n < 70 {
                                eprintln!("Invalid 'of' message length: {n}");
                                return;
                            }

                            let iden = match Iden::try_from(&buffer[2..34]) {
                                Ok(i) => i,
                                Err(_) => {
                                    eprintln!("Invalid iden in 'of' message.");
                                    return;
                                }
                            };

                            let shard = match util::shard(&iden.to_bytes()) {
                                Some(name) => name,
                                None => {
                                    eprintln!("No shard match for iden in 'of'.");
                                    return;
                                }
                            };

                            let socket_path = format!(".iden/bn{}", shard);
                            let mut ck_msg = vec![b'c', b'k'];
                            ck_msg.extend_from_slice(&buffer[2..38]);

                            match UnixStream::connect(&socket_path) {
                                Ok(mut unix_stream) => {
                                    if let Err(e) = unix_stream.write_all(&ck_msg) {
                                        eprintln!("Failed to send 'ck' message to shard: {e:?}");
                                        return;
                                    }

                                    let mut response = [0u8; 2];
                                    match unix_stream.read_exact(&mut response) {
                                        Ok(_) => {
                                            if &response == b"YE" {
                                                println!("Duplicate offer detected. Skipping.");
                                                return;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Error reading 'ck' response: {e:?}");
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Failed to connect to shard socket {}: {e:?}",
                                        socket_path
                                    );
                                    return;
                                }
                            }

                            // extract idx and hashkey
                            let idx = u32::from_le_bytes(buffer[34..38].try_into().unwrap());
                            let hashkey = &buffer[38..70];

                            let split_chars = util::config("ss_split_chars")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);
                            let split_count = util::config("ss_split_count")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);

                            let content_path = match Iden::try_from(&buffer[2..34]) {
                                Ok(i) => i.to_path(split_chars, split_count),
                                Err(_) => {
                                    eprintln!("Failed to convert iden to path.");
                                    return;
                                }
                            };

                            // Length comes immediately after offer (70..72), then payload
                            if n < 72 {
                                eprintln!("Incomplete message — missing length bytes.");
                                return;
                            }

                            let expected_len =
                                u16::from_le_bytes(buffer[70..72].try_into().unwrap()) as usize;
                            if n < 72 + expected_len {
                                eprintln!(
                                    "Incomplete message — missing full payload (have {}, need {}).",
                                    n - 72,
                                    expected_len
                                );
                                return;
                            }

                            let payload = &buffer[72..72 + expected_len];

                            // Check hash
                            let hash = Sha256::digest(payload);

                            if hash.as_slice() != hashkey {
                                eprintln!(
                                    "  → Error: Payload hash does not match the provided hashkey."
                                );
                                return;
                            }

                            println!("→ Attempting to store payload");
                            println!("  Length declared: {}", expected_len);
                            println!("  Actual slice size: {}", payload.len());
                            println!("  SHA256: {}", hex::encode(Sha256::digest(payload)));
                            println!("  Expected hashkey: {}", hex::encode(hashkey));

                            store_payload(&content_path, payload, idx);
                            return;
                        }

                        b"id" => {
                            let text = match std::str::from_utf8(&buffer[2..n]) {
                                Ok(s) => s,
                                Err(_) => {
                                    eprintln!("Invalid UTF-8 in resolver request.");
                                    continue;
                                }
                            };

                            println!("Received RESOLVER request:");

                            let url = match text.find("en://") {
                                Some(pos) => &text[pos + 5..],
                                None => {
                                    eprintln!("Missing 'iden://' in resolver request.");
                                    continue;
                                }
                            };

                            let iden_part = url.split('.').next().unwrap_or("");

                            println!("  iden string: {}", iden_part);

                            let split_chars = util::config("ss_split_chars")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);
                            let split_count = util::config("ss_split_count")
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(4);

                            println!("  ss_split_chars: {}", split_chars);
                            println!("  ss_split_count: {}", split_count);

                            let Some(iden_obj) = Iden::from_str(iden_part) else {
                                eprintln!("  → Error: Invalid iden format");
                                continue;
                            };

                            let content_path = iden_obj.to_path(split_chars, split_count);
                            println!("  → Content path: {}", content_path);

                            // Extract optional idx from the URL
                            let idx_opt = url.split('.').nth(1).and_then(|s| s.parse::<u32>().ok());

                            match idx_opt {
                                Some(idx) => {
                                    println!("  → Index specified: {}", idx);

                                    if idx == 0 {
                                        let path = format!("{}/0.bin", content_path);
                                        if Path::new(&path).exists() {
                                            match fs::read(&path) {
                                                Ok(data) => {
                                                    if data.len() >= 6 {
                                                        // Skip first 6 bytes (idx + len) and send just the payload
                                                        let payload = &data[6..];
                                                        let _ = stream.write_all(payload);
                                                    } else {
                                                        let _ = stream.write_all(b"!Corrupt file.");
                                                        eprintln!(
                                                            "  → 0.bin is too short (less than 6 bytes)."
                                                        );
                                                    }
                                                }
                                                Err(e) => {
                                                    let _ =
                                                        stream.write_all(b"!Error reading file.");
                                                    eprintln!("  → Error reading 0.bin: {}", e);
                                                }
                                            }
                                        } else {
                                            let _ = stream.write_all(b"!Not Found.");
                                            println!("  → 0.bin not found.");
                                        }
                                    } else {
                                        // Begin step-by-step resolution for non-zero idx values
                                        println!("  → Resolving specific index: {}", idx);

                                        let path = format!("{}/1.bin", content_path);
                                        if !Path::new(&path).exists() {
                                            let _ = stream.write_all(b"!Not Found.");
                                            println!("  → 1.bin not found.");
                                            continue;
                                        }

                                        let file = match File::open(&path) {
                                            Ok(f) => f,
                                            Err(e) => {
                                                let _ = stream.write_all(b"!Error opening file.");
                                                eprintln!("  → Failed to open 1.bin: {}", e);
                                                return;
                                            }
                                        };

                                        let mut reader = BufReader::new(file);
                                        let mut record_index = 0;
                                        let _ = record_index;

                                        loop {
                                            let mut header = [0u8; 6];

                                            match reader.read_exact(&mut header) {
                                                Ok(_) => {
                                                    let rec_idx = u32::from_le_bytes([
                                                        header[0], header[1], header[2], header[3],
                                                    ]);
                                                    let rec_len =
                                                        u16::from_le_bytes([header[4], header[5]])
                                                            as usize;

                                                    let mut data = vec![0u8; rec_len];
                                                    if let Err(e) = reader.read_exact(&mut data) {
                                                        eprintln!(
                                                            "  → Error reading record data: {}",
                                                            e
                                                        );
                                                        let _ = stream
                                                            .write_all(b"!Error reading record.");
                                                        return;
                                                    }

                                                    if rec_idx == idx {
                                                        println!("  → Match found for idx {}", idx);
                                                        let _ = stream.write_all(&data);
                                                        break;
                                                    }

                                                    record_index += 1;
                                                }
                                                Err(e) => {
                                                    println!(
                                                        "  → End of file or read error: {}",
                                                        e
                                                    );
                                                    let _ = stream.write_all(b"!Not Found.");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                None => {
                                    println!("  → No index specified");

                                    let path = format!("{}/1.bin", content_path);
                                    if Path::new(&path).exists() {
                                        if let Ok(mut file) = File::open(&path) {
                                            let mut header = [0u8; 6];
                                            if file.read_exact(&mut header).is_ok() {
                                                let len = u16::from_le_bytes([header[4], header[5]])
                                                    as usize;
                                                let mut result = vec![0u8; len];
                                                if file.read_exact(&mut result).is_ok() {
                                                    let _ = stream.write_all(&result);
                                                } else {
                                                    let _ = stream
                                                        .write_all(b"!Error reading record body.");
                                                    eprintln!(
                                                        "  → Error reading record data from 1.bin"
                                                    );
                                                }
                                            } else {
                                                let _ = stream.write_all(b"!Error reading header.");
                                                eprintln!("  → Error reading header from 1.bin");
                                            }
                                        } else {
                                            let _ = stream.write_all(b"!Error opening file.");
                                            eprintln!("  → Error opening 1.bin");
                                        }
                                    } else {
                                        let _ = stream.write_all(b"!Not Found.");
                                        println!("  → 1.bin not found.");
                                    }
                                }
                            }
                        }

                        _ => {
                            eprintln!("Unknown opcode: {:?}", &buffer[..2]);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Connection error: {:?}", e);
            }
        }
    }

    println!("basenet service has exited.");
}

fn store_payload(content_path: &str, data: &[u8], idx: u32) {
    println!(
        "  → Storing payload of {} bytes to {} (idx={})",
        data.len(),
        content_path,
        idx
    );

    let Ok(text) = std::str::from_utf8(data) else {
        eprintln!("  → Error: Payload is not valid UTF-8.");
        return;
    };

    println!("  → Payload is valid UTF-8.");

    if !text.contains("---") {
        eprintln!("  → Error: Payload is missing YAML divider (---). Aborting.");
        return;
    }

    let parts: Vec<&str> = text.splitn(2, "---").collect();
    let header = parts[0];

    let mut underscore_value: Option<String> = None;

    for line in header.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(":") {
            let key = key.trim();
            let value = value.trim();
            if key == "_" {
                underscore_value = Some(value.to_string());
            }
        }
    }

    let Some(value) = underscore_value else {
        eprintln!("  → Error: Missing required '_' key in header.");
        return;
    };

    match value.as_str() {
        "0" => {
            println!("  → Header value _ = 0");
            let file_path = format!("{}/0.bin", content_path);
            let mut file_data = idx.to_le_bytes().to_vec();
            let len = data.len() as u16;
            file_data.extend_from_slice(&len.to_le_bytes());
            file_data.extend_from_slice(data);
            match fs::write(&file_path, &file_data) {
                Ok(_) => println!("  → Type 0 payload saved to {}", file_path),
                Err(e) => eprintln!("  → Error writing to {}: {}", file_path, e),
            }
        }
        "1" => {
            println!("  → Header value _ = 1");
            let pin_path = format!("{}/pin.txt", content_path);
            let mut max_size = 131072; // default 128KB

            if let Ok(file) = File::open(&pin_path) {
                let mut reader = BufReader::new(file);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    if let Ok(limit) = line.trim().parse::<usize>() {
                        if limit >= 131072 {
                            max_size = limit;
                        }
                    }
                }
            }

            let new_path = format!("{}/1.bin.new", content_path);
            let len = data.len() as u16;
            let mut new_data = idx.to_le_bytes().to_vec();
            new_data.extend_from_slice(&len.to_le_bytes());
            new_data.extend_from_slice(data);

            if let Err(e) = fs::write(&new_path, &new_data) {
                eprintln!("  → Error writing to new file: {}", e);
                return;
            }

            let old_path = format!("{}/1.bin", content_path);
            if let Ok(old_file) = File::open(&old_path) {
                let mut reader = BufReader::new(old_file);
                let mut total_size = new_data.len();

                loop {
                    let mut header = [0u8; 6];
                    if reader.read_exact(&mut header).is_err() {
                        break;
                    }
                    let len_value = u16::from_le_bytes(header[4..6].try_into().unwrap()) as usize;

                    let mut record = vec![0u8; len_value];
                    if reader.read_exact(&mut record).is_err() {
                        break;
                    }

                    let record_size = 6 + len_value;
                    if total_size + record_size > max_size {
                        break;
                    }

                    let mut combined = header.to_vec();
                    combined.extend_from_slice(&record);

                    if let Err(e) = fs::OpenOptions::new()
                        .append(true)
                        .open(&new_path)
                        .and_then(|mut f| f.write_all(&combined))
                    {
                        eprintln!("  → Error appending record: {}", e);
                        return;
                    }

                    total_size += record_size;
                }
            }

            let final_path = format!("{}/1.bin", content_path);
            if let Err(e) = fs::rename(&new_path, &final_path) {
                eprintln!("  → Error finalizing 1.bin file: {}", e);
                return;
            }
            println!(
                "  → Type 1 payload stored and pruned to limit {} bytes",
                max_size
            );
        }

        _ => {
            eprintln!("  → Error: Invalid value for '_' key. Expected '0' or '1'.");
            return;
        }
    }
}

const DEFAULT_THREAD_LIMIT: usize = 8;
static RUNNING: AtomicBool = AtomicBool::new(true);

fn handle_connection(mut stream: TcpStream) {
    println!("Accepted new basenet TCP connection.");

    let mut buffer = [0u8; 65536];
    let Ok(n) = stream.read(&mut buffer) else {
        eprintln!("Failed to read from TCP stream.");
        return;
    };

    if n < 2 {
        eprintln!("Message too short.");
        return;
    }

    let (iden_bytes, shard_name, is_offer) = match &buffer[..2] {
        b"of" => {
            let mut full_buffer = buffer[..n].to_vec();

            // Check if we have enough to read expected length
            if full_buffer.len() < 72 {
                eprintln!("Initial 'of' message too short: {}", full_buffer.len());
                return;
            }

            let expected_len = u16::from_le_bytes(full_buffer[70..72].try_into().unwrap()) as usize;
            let total_len = 72 + expected_len;

            while full_buffer.len() < total_len {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => break,
                    Ok(read_n) => full_buffer.extend_from_slice(&temp[..read_n]),
                    Err(e) => {
                        eprintln!("Error reading additional payload: {e:?}");
                        return;
                    }
                }
            }

            if full_buffer.len() < total_len {
                eprintln!(
                    "Still missing payload: got {}, need {}",
                    full_buffer.len(),
                    total_len
                );
                return;
            }

            let iden = match Iden::try_from(&full_buffer[2..34]) {
                Ok(i) => i,
                Err(_) => {
                    eprintln!("Invalid iden in 'of' message.");
                    return;
                }
            };

            let shard = match util::shard(&iden.to_bytes()) {
                Some(name) => name,
                None => {
                    eprintln!("No shard match for iden in 'of'.");
                    return;
                }
            };
            let mproc_socket = format!(".iden/{}", shard); // mproc socket (si)
            let socket_path = format!(".iden/bn{}", shard);
            let mut ck_msg = vec![b'c', b'k'];
            ck_msg.extend_from_slice(&full_buffer[2..38]);

            match UnixStream::connect(&socket_path) {
                Ok(mut unix_stream) => {
                    if let Err(e) = unix_stream.write_all(&ck_msg) {
                        eprintln!("Failed to send 'ck' message to shard: {e:?}");
                        return;
                    }

                    let mut response = [0u8; 2];
                    match unix_stream.read_exact(&mut response) {
                        Ok(_) => {
                            if &response == b"YE" {
                                println!("Duplicate offer detected. Skipping.");
                                return;
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading 'ck' response: {e:?}");
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to shard socket {}: {e:?}", socket_path);
                    return;
                }
            }

            let idx = u32::from_le_bytes(full_buffer[34..38].try_into().unwrap());
            let hashkey = &full_buffer[38..70];
            let payload = &full_buffer[72..72 + expected_len];

            let hash = Sha256::digest(payload);
            if hash.as_slice() != hashkey {
                eprintln!("Payload hash mismatch.");
                return;
            }

            // SIGNAL CHECK

            let mut si_msg = vec![b's', b'i'];
            si_msg.extend_from_slice(&buffer[2..34]); // iden
            si_msg.extend_from_slice(&buffer[34..38]); // idx

            match UnixStream::connect(&mproc_socket) {
                Ok(mut unix_stream) => {
                    println!("→ Requesting signal from {}", mproc_socket);
                    if unix_stream.write_all(&si_msg).is_err() {
                        eprintln!("Failed to send 'si' request to mproc.");
                        return;
                    }

                    let mut signal_buf = [0u8; 64];
                    match unix_stream.read_exact(&mut signal_buf) {
                        Ok(_) => {
                            if signal_buf[0] == 0 {
                                eprintln!("→ No signal returned for idx {idx}. Rejecting.");
                                return;
                            }

                            let mut doubled = [0u8; 128];
                            doubled[..64].copy_from_slice(&signal_buf);
                            doubled[64..].copy_from_slice(&signal_buf);

                            let hashkey = &buffer[38..70];
                            if !doubled.windows(32).any(|w| w == hashkey) {
                                eprintln!("→ Hashkey not found in doubled signal. Rejecting.");
                                return;
                            } else {
                                println!("Good Signal Match Found!");
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read signal: {e:?}");
                            return;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Could not connect to mproc at {}: {e:?}", mproc_socket);
                    return;
                }
            }

            let split_chars = util::config("ss_split_chars")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(4);
            let split_count = util::config("ss_split_count")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(4);
            let content_path = iden.to_path(split_chars, split_count);

            store_payload(&content_path, payload, idx);
            return;
        }

        b"id" => {
            let text = match std::str::from_utf8(&buffer[2..n]) {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("Invalid UTF-8 in 'id' message.");
                    return;
                }
            };
            let Some(start) = text.find("en://") else {
                eprintln!("Missing 'iden://' prefix.");
                return;
            };
            let url = &text[start + 5..];
            let iden_part = url.split('.').next().unwrap_or("");
            let Some(iden) = Iden::from_str(iden_part) else {
                eprintln!("Invalid iden string.");
                return;
            };
            let iden_bytes = buffer[..n].to_vec();
            let shard = match util::shard(&iden.to_bytes()) {
                Some(name) => name,
                None => {
                    eprintln!("No shard match for iden in 'id'.");
                    return;
                }
            };
            (iden_bytes, format!("bn{}", shard), false)
        }
        _ => {
            eprintln!("Unknown opcode: {:?}", &buffer[..2]);
            return;
        }
    };

    let socket_path = format!(".iden/{}", shard_name);

    match UnixStream::connect(&socket_path) {
        Ok(mut unix_stream) => {
            if let Err(e) = unix_stream.write_all(&iden_bytes) {
                eprintln!("Failed to send to shard socket: {e:?}");
                return;
            }

            if is_offer {
                let mut response = [0u8; 2];
                match unix_stream.read_exact(&mut response) {
                    Ok(_) => {
                        if let Err(e) = stream.write_all(&response) {
                            eprintln!("Failed to send initial response to TCP caller: {e:?}");
                            return;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading initial response from shard: {e:?}");
                        return;
                    }
                }

                if &response == b"ok" {
                    let mut remaining = vec![0u8; 65536];
                    let Ok(n_read) = stream.read(&mut remaining) else {
                        eprintln!("Failed to read remaining payload from peer.");
                        return;
                    };
                    if let Err(e) = unix_stream.write_all(&remaining[..n_read]) {
                        eprintln!("Failed to forward data to shard: {e:?}");
                    }
                }
            } else {
                // 'id' resolver: read full response and send back to TCP
                let mut response = vec![0u8; 65536];
                match unix_stream.read(&mut response) {
                    Ok(rn) if rn > 0 => {
                        if let Err(e) = stream.write_all(&response[..rn]) {
                            eprintln!("Failed to send resolver response to TCP: {e:?}");
                        }
                    }
                    Ok(_) => eprintln!("Empty resolver response."),
                    Err(e) => eprintln!("Error reading resolver response: {e:?}"),
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to shard socket {}: {e:?}", socket_path);
        }
    }
}

/// Starts the basenet TCP service
pub fn start_basenet_tcp_service() {
    let thread_limit = util::config("thread_limit_in")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_THREAD_LIMIT);

    let tcp_port = util::config("basenet_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(4040); // Choose a reasonable default
    //
    let bind_addr = util::config("tcp_bind_addr").unwrap_or_else(|| "0.0.0.0".to_string());

    //let listener = TcpListener::bind(("0.0.0.0", tcp_port))
    //    .expect(&format!("Failed to bind to port {}", tcp_port));

    let listener = TcpListener::bind((bind_addr.as_str(), tcp_port))
        .expect(&format!("Failed to bind to {}:{}", bind_addr, tcp_port));

    let pool = ThreadPool::new(thread_limit);
    let listener = Arc::new(listener);

    let socket_path = ".iden/basenet_tcp";
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path).unwrap();
    }
    let shutdown_listener =
        UnixListener::bind(socket_path).expect("Failed to bind Unix socket for shutdown");

    println!(
        "Basenet TCP service listening on port {} with {} threads.",
        tcp_port, thread_limit
    );

    // Spawn shutdown thread
    thread::spawn(move || {
        for stream in shutdown_listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 10];
                if let Ok(n) = stream.read(&mut buffer) {
                    if n > 0 && buffer.starts_with(b"qu") {
                        let _ = stream.write(b"Shutting Down Basenet TCP.");
                        println!("Received shutdown signal. Stopping basenet_tcp service.");
                        std::process::exit(0);
                    }
                }
            }
        }
    });

    // Accept loop
    for stream in listener.incoming() {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                pool.execute(move || handle_connection(stream));
            }
            Err(e) => eprintln!("Basenet TCP connection failed: {:?}", e),
        }
    }

    println!("Basenet TCP service shutting down.");
}
