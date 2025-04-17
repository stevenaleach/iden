/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    tcp.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.
-----------------------------------------------------------------------------*/

use crate::util;
use ed25519_dalek::Signature;
use std::fs;
use std::io::{Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;
use threadpool::ThreadPool;

use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::id::Iden;

/// Returns true if the iden is listed in `.iden/idens.txt`,
/// or if the file is missing. False if the iden is not listed.
/// To allow for private nodes.
fn is_iden_allowed(iden_bytes: &[u8]) -> bool {
    let iden = match Iden::try_from(iden_bytes) {
        Ok(i) => i,
        Err(_) => return false, // Malformed iden
    };

    let iden_str = iden.to_string();

    let file = match File::open(".iden/idens.txt") {
        Ok(f) => f,
        Err(_) => return true, // No file = allow all
    };

    let reader = BufReader::new(file);

    for line in reader.lines().flatten() {
        let parts: Vec<_> = line
            .split_whitespace()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if let Some(first) = parts.first() {
            if *first == iden_str {
                return true;
            }
        }
    }

    false
}

const DEFAULT_THREAD_LIMIT: usize = 8;
static RUNNING: AtomicBool = AtomicBool::new(true);

/// Handles an incoming TCP connection.
fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 512];
    match stream.read(&mut buffer) {
        Ok(n) if n >= 2 => {
            let opcode = &buffer[..2];
            // branch for version, too short for normal rules.
            if opcode == b"ve" {
                let shard_name = util::shard(&[0u8; 32]);
                let Some(shard_name) = shard_name else {
                    eprintln!("No matching shard found for 've'.");
                    return;
                };
                let socket_path = format!(".iden/{}", shard_name);

                match UnixStream::connect(&socket_path) {
                    Ok(mut unix_stream) => {
                        if let Err(e) = unix_stream.write_all(&buffer[..n]) {
                            eprintln!("Failed to forward 've' to {}: {:?}", socket_path, e);
                            return;
                        }

                        let mut response_buffer = [0; 256];
                        match unix_stream.read(&mut response_buffer) {
                            Ok(resp_len) if resp_len > 0 => {
                                let _ = stream.write_all(&response_buffer[..resp_len]);
                            }
                            Ok(_) => eprintln!("Empty response from {}", socket_path),
                            Err(e) => eprintln!("Failed to read version response: {:?}", e),
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to mproc {}: {:?}", socket_path, e);
                    }
                }
                return;
            }

            // First, check if opcode is throttled
            if matches!(&buffer[..2], b"cl" | b"pr" | b"re" | b"de") {
                if n < 34 {
                    // minimum length to safely extract iden
                    eprintln!("Invalid message length: cannot extract iden");
                    return;
                }

                let iden_bytes = &buffer[2..34];

                if !is_iden_allowed(iden_bytes) {
                    eprintln!("Blocked iden not listed in idens.txt");
                    return;
                }

                let ipv4 = match stream.peer_addr() {
                    Ok(addr) => match addr.ip() {
                        std::net::IpAddr::V4(ip) => ip.octets(),
                        _ => {
                            eprintln!("IPv6 not supported for throttling.");
                            return;
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to get peer IP address: {:?}", e);
                        return;
                    }
                };

                let mut throttle_message = vec![b'?', b'?'];
                throttle_message.extend_from_slice(&ipv4);
                throttle_message.extend_from_slice(iden_bytes);

                // Connect to throttling service
                if let Ok(mut throttle_stream) = UnixStream::connect(".iden/throttle") {
                    if let Err(e) = throttle_stream.write_all(&throttle_message) {
                        eprintln!("Error writing to throttling service: {:?}", e);
                    } else {
                        let mut delay_buffer = [0u8; 8]; // f64 = 8 bytes
                        if let Err(e) = throttle_stream.read_exact(&mut delay_buffer) {
                            eprintln!("Error reading from throttling service: {:?}", e);
                        } else {
                            let delay_secs = f64::from_le_bytes(delay_buffer);

                            if delay_secs > 0.0 {
                                println!(
                                    "Throttling: delaying request from {} for {:.3} seconds.",
                                    std::net::Ipv4Addr::from(ipv4),
                                    delay_secs
                                );
                                std::thread::sleep(std::time::Duration::from_secs_f64(delay_secs));
                            }
                        }
                    }
                } else {
                    //eprintln!("Failed to connect to throttling service. Proceeding without throttling.");
                }
            }

            let opcode = &buffer[..2];

            //-----------------------------------------------------------------
            //  HANDLE 'de' OPCODE (Dedication)
            //-----------------------------------------------------------------
            if opcode == b"de" {
                if n != 70 {
                    eprintln!("Invalid 'de' message length: {}", n);
                    return;
                }

                let iden_bytes = &buffer[2..34];
                let state_bytes = &buffer[34..70];

                // Modify "de" -> "re" // TODO: re-name proof_message.. should be report_message.
                let mut proof_message = vec![b'r', b'e']; // Fix: Correct opcode
                proof_message.extend_from_slice(iden_bytes);
                proof_message.extend_from_slice(state_bytes);

                // Determine shard
                let iden_array: &[u8; 32] = match iden_bytes.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("Invalid iden length");
                        return;
                    }
                };
                let shard_name = util::shard(iden_array);

                let Some(shard_name) = shard_name else {
                    eprintln!("No matching shard found for 'de'.");
                    return;
                };
                let socket_path = format!(".iden/{}", shard_name);

                // DEBUG: Print the outgoing message
                //println!(
                //    "Forwarding 'de' (as 'pr') to shard {}: {:?} ({} bytes)",
                //    shard_name,
                //    hex::encode(&proof_message),
                //    proof_message.len()
                //);

                match UnixStream::connect(&socket_path) {
                    Ok(mut unix_stream) => {
                        if let Err(e) = unix_stream.write_all(&proof_message) {
                            eprintln!("Failed to send proof to {}: {:?}", socket_path, e);
                            return;
                        }

                        let mut response_buffer = [0; 1];
                        match unix_stream.read(&mut response_buffer) {
                            Ok(1) => {
                                // DEBUG: Print mproc's response
                                //println!(
                                //    "Response from {}: {} ({} bytes)",
                                //    socket_path, response_buffer[0], 1
                                //);

                                if response_buffer[0] == 0 {
                                    // OK response
                                    if let Ok(peer_addr) = stream.peer_addr() {
                                        let ipv4 = match peer_addr.ip() {
                                            std::net::IpAddr::V4(ip) => ip.octets(),
                                            _ => {
                                                eprintln!("Non-IPv4 address detected.");
                                                return;
                                            }
                                        };

                                        // Format the message for the throttler
                                        let mut throttle_message = vec![b'd', b'e'];
                                        throttle_message.extend_from_slice(&ipv4);
                                        throttle_message.extend_from_slice(iden_bytes);

                                        // DEBUG: Print dedication message for throttle
                                        //println!(
                                        //    "Sending dedication to throttle: {:?} ({} bytes)",
                                        //    hex::encode(&throttle_message),
                                        //    throttle_message.len()
                                        //);

                                        // Send to .iden/throttle
                                        if let Ok(mut throttle_stream) =
                                            UnixStream::connect(".iden/throttle")
                                        {
                                            if let Err(e) =
                                                throttle_stream.write_all(&throttle_message)
                                            {
                                                eprintln!("Failed to write to throttle: {:?}", e);
                                            }
                                        } else {
                                            //eprintln!("Failed to connect to throttle service.");
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "mproc rejected dedication: {:?}",
                                        response_buffer[0]
                                    );
                                }
                            }
                            Ok(_) => eprintln!("Unexpected response size from {}", socket_path),
                            Err(e) => {
                                eprintln!("Failed to read response from {}: {:?}", socket_path, e)
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to mproc {}: {:?}", socket_path, e);
                    }
                }
                return;
            }

            //-------------------------------------------------------------------------
            // PEER REQUEST: 'pe' + u16 (number of peers requested)
            //-------------------------------------------------------------------------
            if opcode == b"pe" {
                if n < 4 {
                    eprintln!("Invalid peer request length: {}", n);
                    return;
                }

                let requested_count = u16::from_le_bytes(buffer[2..4].try_into().unwrap());
                println!("Someone asked for {} peers", requested_count);

                // Construct "gn" message (replace 'pe' with 'gn')
                let mut peerstat_request = vec![b'g', b'n'];
                peerstat_request.extend_from_slice(&buffer[2..4]); // Append the requested count

                // Connect to peerstat
                if let Ok(mut peerstat_stream) = UnixStream::connect(".iden/peerstat") {
                    if let Err(e) = peerstat_stream.write_all(&peerstat_request) {
                        eprintln!("Failed to send peer request to peerstat: {:?}", e);
                        return;
                    }

                    // Read peerstat's response
                    let mut response_buffer = vec![0u8; 65536];
                    match peerstat_stream.read(&mut response_buffer) {
                        Ok(bytes_read) => {
                            println!("Peerstat returned {} bytes", bytes_read);

                            // Send the received data back to the TCP client
                            match stream.write_all(&response_buffer[..bytes_read]) {
                                Ok(_) => {
                                    println!("Sent {} bytes of peer data to client.", bytes_read)
                                }
                                Err(e) => eprintln!("Failed to send peer data to client: {:?}", e),
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read from peerstat: {:?}", e);
                        }
                    }
                } else {
                    eprintln!("Failed to connect to peerstat.");
                }

                return;
            }

            //-------------------------------------------------------------------------
            // HANDSHAKE.  Handle incoming caller.
            //-------------------------------------------------------------------------
            if opcode == b"hi" {
                if n != 66 {
                    eprintln!("Invalid handshake message length: {}", n);
                    return;
                }

                let challenge_bytes = &buffer[2..66]; // Extract the 64-byte challenge

                // Sign the challenge using our existing function
                let Some(signature) = util::sign_data(challenge_bytes) else {
                    eprintln!("Failed to sign handshake challenge.");
                    return;
                };

                // Load our public key
                let Some(public_key) = util::load_verifying_key() else {
                    eprintln!("Failed to load public key.");
                    return;
                };

                let public_key_bytes = public_key.as_bytes();
                let signature_bytes = signature.to_bytes();

                // Generate a new 64-byte challenge for the peer
                let new_challenge = util::random_bytes(64);

                // Construct response: [our 32-byte public key] + [our 64-byte signature] + [64-byte challenge]
                let mut response = Vec::new();
                response.extend_from_slice(public_key_bytes);
                response.extend_from_slice(&signature_bytes);
                response.extend_from_slice(&new_challenge);

                // Send response back to peer
                if let Err(e) = stream.write_all(&response) {
                    eprintln!("Failed to send handshake response: {:?}", e);
                    return;
                }

                let mut peer_response = [0; 512]; // 32-byte pubkey + 64-byte signature

                let size = match stream.read(&mut peer_response) {
                    Ok(n) if n >= 96 => n, // Ensure we got at least 96 bytes (pubkey + signature)
                    Ok(_) => {
                        eprintln!("Peer response too short.");
                        return;
                    }
                    Err(e) => {
                        eprintln!("Failed to read peer response: {:?}", e);
                        return;
                    }
                };

                // Extract the peer's public key bytes (first 32 bytes)
                let peer_pubkey_bytes: [u8; 32] = peer_response[..32].try_into().unwrap();
                // Use `verifying_key_from_bytes()` from util.rs
                let peer_public_key = match util::verifying_key_from_bytes(&peer_pubkey_bytes) {
                    Some(key) => key,
                    None => {
                        eprintln!("Invalid peer public key.");
                        return;
                    }
                };

                // Extract peer's signature (bytes 32-96)
                let signature_bytes: [u8; 64] = peer_response[32..96].try_into().unwrap();
                let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
                // Verify the peer's signature against the challenge we sent them
                if peer_public_key
                    .verify_strict(&new_challenge, &signature)
                    .is_err()
                {
                    eprintln!("Peer signature verification failed.");
                    return;
                }
                // === Peer is now authenticated! ===

                let ad_message = if size > 96 {
                    let mut str_buff = peer_response[96..size].to_vec(); // Copy everything after byte 96

                    // Remove trailing null (if it exists)
                    if let Some(&last) = str_buff.last() {
                        if last == 0 {
                            str_buff.pop();
                        }
                    }

                    match String::from_utf8(str_buff) {
                        Ok(msg) => msg,
                        Err(_) => "[Invalid UTF-8]".to_string(),
                    }
                } else {
                    "".to_string() // No advertisement sent
                };

                // Get the peer's IP and port
                let connection_info = match stream.peer_addr() {
                    Ok(addr) => format!("{}:{}:", addr.ip(), addr.port()),
                    Err(_) => "[Unknown Address]:".to_string(),
                };

                // Construct the full peer info string
                let peer_info = format!("{}{}", connection_info, ad_message);

                println!("Peer Info: {}", peer_info);

                if !ad_message.is_empty() {
                    if let Err(e) = send_to_peerstat(&peer_pubkey_bytes, &peer_info) {
                        eprintln!("Failed to send to peerstat: {:?}", e);
                    }
                }

                match stream.peer_addr() {
                    Ok(addr) => {
                        let ip_info = format!("{}", addr);
                        if let Err(e) = stream.write_all(ip_info.as_bytes()) {
                            eprintln!("Failed to send IP info: {:?}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to retrieve peer address: {:?}", e);
                    }
                }
                return;
            }

            //-------------------------------------------------------------------------
            // Message Count
            //-------------------------------------------------------------------------
            // "ct" count since t - queries all shards
            if opcode == b"ct" {
                let mut total_count = 0u32;
                if let Ok(map_content) = fs::read_to_string(".iden/shard.map") {
                    for line in map_content.lines() {
                        if let Some(shard_name) = line.split_whitespace().next() {
                            let socket_path = format!(".iden/{}", shard_name);
                            if let Ok(mut unix_stream) = UnixStream::connect(&socket_path) {
                                if let Err(e) = unix_stream.write_all(&buffer[..n]) {
                                    eprintln!("Failed to send 'ct' to {}: {:?}", socket_path, e);
                                    continue;
                                }
                                let mut response_buffer = [0u8; 4];
                                match unix_stream.read_exact(&mut response_buffer) {
                                    Ok(_) => {
                                        let count = u32::from_le_bytes(response_buffer);
                                        total_count = total_count.saturating_add(count);
                                    }
                                    Err(e) => eprintln!(
                                        "Failed to read 'ct' response from {}: {:?}",
                                        socket_path, e
                                    ),
                                }
                            } else {
                                eprintln!("Failed to connect to mproc at {}", socket_path);
                            }
                        }
                    }
                } else {
                    eprintln!("Failed to read .iden/shard.map");
                }
                if let Err(e) = stream.write_all(&total_count.to_le_bytes()) {
                    eprintln!("Failed to send aggregated 'ct' response: {:?}", e);
                }
                return;
            }

            //-------------------------------------------------------------------------
            //  Collect Messages
            //-------------------------------------------------------------------------
            // "gt" collects messages since t from all shards
            if opcode == b"gt" {
                let mut all_messages = Vec::new();

                if let Ok(map_content) = fs::read_to_string(".iden/shard.map") {
                    for line in map_content.lines() {
                        if let Some(shard_name) = line.split_whitespace().next() {
                            let socket_path = format!(".iden/{}", shard_name);

                            if let Ok(mut unix_stream) = UnixStream::connect(&socket_path) {
                                if let Err(e) = unix_stream.write_all(&buffer[..n]) {
                                    eprintln!("Failed to send 'gt' to {}: {:?}", socket_path, e);
                                    continue;
                                }

                                let mut response_buffer = vec![0; 4194304]; //  65536];
                                match unix_stream.read(&mut response_buffer) {
                                    Ok(resp_len) if resp_len > 0 => {
                                        // Ensure we actually got data
                                        all_messages.push(response_buffer[..resp_len].to_vec()); // Read everything directly
                                    }
                                    Err(e) => eprintln!(
                                        "Failed to read 'gt' response from {}: {:?}",
                                        socket_path, e
                                    ),
                                    _ => {}
                                }
                            } else {
                                eprintln!("Failed to connect to mproc at {}", socket_path);
                            }
                        }
                    }
                }

                // If there are messages, send them, otherwise return nothing
                if !all_messages.is_empty() {
                    let mut response = Vec::new();
                    for msg in &all_messages {
                        response.extend_from_slice(msg);
                    }
                    send_data(&mut stream, &response);
                }
                return;
            }
            //-----------------------------------------------------------------

            let iden_bytes = &buffer[2..34];
            let iden_array: &[u8; 32] = match iden_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    eprintln!("Invalid iden length");
                    return;
                }
            };
            //-------------------------------------------------------------------------
            //  MESSAGES THAT ARE FORWARDED TO MPROC SHARD.
            //-------------------------------------------------------------------------
            let shard_name = match opcode {
                b"ix" | b"si" | b"st" | b"cl" | b"pr" | b"re" => util::shard(iden_array),
                //b"ve" => util::shard(&[0u8; 32]),
                _ => None,
            };

            let Some(shard_name) = shard_name else {
                eprintln!("No matching shard found.");
                return;
            };
            let socket_path = format!(".iden/{}", shard_name);

            match UnixStream::connect(&socket_path) {
                Ok(mut unix_stream) => {
                    if let Err(e) = unix_stream.write_all(&buffer[..n]) {
                        eprintln!("Failed to forward message to {}: {:?}", socket_path, e);
                        return;
                    }
                    let mut response_buffer = [0; 65536];
                    match unix_stream.read(&mut response_buffer) {
                        Ok(resp_len) if resp_len > 0 => {
                            if let Err(e) = stream.write_all(&response_buffer[..resp_len]) {
                                eprintln!("Failed to send response to client: {:?}", e);
                            }
                        }
                        Ok(_) => eprintln!("Empty response received from {}", socket_path),
                        Err(e) => {
                            eprintln!("Failed to read response from {}: {:?}", socket_path, e)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to mproc {}: {:?}", socket_path, e);
                }
            }
        }
        Ok(_) => println!("Client closed connection."),
        Err(e) => eprintln!("Error reading from client: {:?}", e),
    }
}

const CHUNK_SIZE: usize = 1380;

//-----------------------------------------------------------------------------
// General Purpose Chunked Sender.
//-----------------------------------------------------------------------------
/// Sends data in chunks with an initial size prefix.
fn send_data(stream: &mut TcpStream, data: &[u8]) {
    let total_size = data.len() as u32;
    //let mut offset = 0;

    // First chunk: includes 4-byte length prefix + up to (CHUNK_SIZE - 4) bytes of data
    let mut first_chunk = Vec::new();
    first_chunk.extend_from_slice(&total_size.to_le_bytes());
    let first_chunk_size = CHUNK_SIZE - 4;
    let end_first_chunk = std::cmp::min(first_chunk_size, data.len());
    first_chunk.extend_from_slice(&data[..end_first_chunk]);

    if let Err(e) = stream.write_all(&first_chunk) {
        eprintln!("Failed to send first chunk: {:?}", e);
        return;
    }

    let mut offset = end_first_chunk;
    while offset < data.len() {
        let end = std::cmp::min(offset + CHUNK_SIZE, data.len());
        if let Err(e) = stream.write_all(&data[offset..end]) {
            eprintln!("Failed to send data chunk: {:?}", e);
            return;
        }
        offset = end;
    }
}

//-----------------------------------------------------------------------------
/// Starts the TCP service with a thread pool and a Unix socket for shutdown.
//-----------------------------------------------------------------------------
pub fn start_tcp_service() {
    let thread_limit = util::config("thread_limit_in")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_THREAD_LIMIT);

    let tcp_port = util::config("tcp_in_port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(4004);

    //    let listener = TcpListener::bind(("0.0.0.0", tcp_port))
    //        .expect(&format!("Failed to bind to port {}", tcp_port));

    let bind_addr = util::config("tcp_bind_addr").unwrap_or_else(|| "0.0.0.0".to_string());
    let listener = TcpListener::bind((bind_addr.as_str(), tcp_port))
        .expect(&format!("Failed to bind to {}:{}", bind_addr, tcp_port));

    let pool = ThreadPool::new(thread_limit);
    let listener = Arc::new(listener);

    let socket_path = ".iden/tcp_in";
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path).unwrap();
    }
    let shutdown_listener =
        UnixListener::bind(socket_path).expect("Failed to bind Unix socket for shutdown");

    println!(
        "TCP Service listening on port {} with {} threads",
        tcp_port, thread_limit
    );

    let listener_clone = Arc::clone(&listener);
    thread::spawn(move || {
        for stream in shutdown_listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 10];
                if let Ok(n) = stream.read(&mut buffer) {
                    if n > 0 && buffer.starts_with(b"qu") {
                        let _ = stream.write(b"Shutting Down.");
                        println!("Received shutdown signal. Stopping TCP service.");
                        std::process::exit(0);
                    }
                }
            }
        }
    });

    for stream in listener_clone.incoming() {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                pool.execute(move || handle_client(stream));
            }
            Err(e) => eprintln!("Connection failed: {:?}", e),
        }
    }
    println!("TCP Service shutting down.");
}

//-----------------------------------------------------------------------------
// Connect To Peer
//-----------------------------------------------------------------------------
pub fn connect(full_address: &str) {
    println!("Attempting to connect to {}", full_address);

    match std::net::TcpStream::connect(full_address) {
        Ok(mut stream) => {
            println!("Connected to {}", full_address);

            // Generate 64 random bytes as challenge
            let challenge = util::random_bytes(64);

            // Construct handshake message: "hi" + 64 random bytes
            let mut handshake_msg = vec![b'h', b'i'];
            handshake_msg.extend_from_slice(&challenge);

            // Send the handshake message
            if let Err(e) = stream.write_all(&handshake_msg) {
                eprintln!("Failed to send handshake: {:?}", e);
                return;
            }

            println!("Sent handshake: hi + [64 random bytes]");

            // Try to read any response
            let mut buffer = [0u8; 512]; // Arbitrary size
            match stream.read(&mut buffer) {
                Ok(n) if n >= 160 => {
                    // Expecting at least 32 + 64 + 64 bytes
                    let alleged_pubkey = &buffer[..32];
                    let alleged_signature = &buffer[32..96];
                    let returned_challenge = &buffer[96..160];

                    // Convert alleged public key
                    let verifying_key = match util::verifying_key_from_bytes(
                        &alleged_pubkey.try_into().expect("Invalid key length"),
                    ) {
                        Some(key) => key,
                        None => {
                            eprintln!("Invalid public key received.");
                            return;
                        }
                    };

                    let signature = Signature::from_bytes(
                        &alleged_signature
                            .try_into()
                            .expect("Invalid signature length"),
                    );

                    // Verify the signature
                    if !util::verify_signature(&verifying_key, &challenge, &signature) {
                        eprintln!("Signature verification failed. Disconnecting.");
                        return;
                    }

                    println!(
                        "Signature verified! Returned challenge: {:?}",
                        returned_challenge
                    );

                    let peer_port = full_address.split(':').last().unwrap_or("4004");
                    let peer_ip = full_address.split(':').next().unwrap_or("unknown_ip");
                    let peer_info = format!(
                        "{}:{}:Ed25519_IPv4_TCP_0.1.0:{}",
                        peer_ip, peer_port, peer_port
                    );

                    println!("Peer Info String: {}", peer_info);

                    let mut peerstat_message = vec![b'a', b'd'];
                    peerstat_message.extend_from_slice(alleged_pubkey);
                    peerstat_message.extend_from_slice(peer_info.as_bytes());

                    if let Ok(mut peerstat_stream) = UnixStream::connect(".iden/peerstat") {
                        let _ = peerstat_stream.write_all(&peerstat_message);
                    } else {
                        eprintln!("Failed to send peer info to peerstat.");
                    }

                    // Now sign the returned challenge
                    let Some(response_signature) = util::sign_data(returned_challenge) else {
                        eprintln!("Failed to sign returned challenge.");
                        return;
                    };

                    // Load our own public key
                    let Some(our_pubkey) = util::load_verifying_key() else {
                        eprintln!("Failed to load our public key.");
                        return;
                    };

                    // Prepare response: [our 32-byte public key] + [our 64-byte signature] + ["Good to meet you.\0"]
                    let mut response = Vec::new();
                    response.extend_from_slice(our_pubkey.as_bytes());
                    response.extend_from_slice(&response_signature.to_bytes());
                    //response.extend_from_slice(b"Good to meet you.\0");
                    response.extend_from_slice(advertise().as_bytes());

                    // Print the raw bytes we are sending
                    println!("Sending Response Bytes: {:?}", response);

                    // Send response back to peer
                    if let Err(e) = stream.write_all(&response) {
                        eprintln!("Failed to send handshake confirmation: {:?}", e);
                        return;
                    }

                    // Try to read the server's response containing our observed public IP/port
                    let mut ip_buffer = [0u8; 128]; // Arbitrary size, should be enough
                    match stream.read(&mut ip_buffer) {
                        Ok(n) if n > 0 => {
                            // Convert the received bytes into a UTF-8 string
                            let ip_message = match std::str::from_utf8(&ip_buffer[..n]) {
                                Ok(msg) => msg.trim_end_matches('\0'), // Trim any null terminators if present
                                Err(_) => "[Invalid UTF-8]",
                            };
                            println!("Server Observed: {}", ip_message);
                        }
                        Ok(_) => {
                            println!("No IP info received from the server.");
                        }
                        Err(e) => {
                            eprintln!("Failed to read public IP info: {:?}", e);
                        }
                    }
                }
                Ok(_) => {
                    println!("Unexpected response size. Disconnecting.");
                }
                Err(e) => {
                    eprintln!("Failed to read response: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {:?}", full_address, e);
        }
    }
}

//-----------------------------------------------------------------------------
// Generate Advertisement String For All Services
//-----------------------------------------------------------------------------
fn advertise() -> String {
    let mut services = Vec::new();

    // 4004 Iden Signaling
    if let Some(port_str) = util::config("tcp_in_port") {
        if let Ok(port) = port_str.parse::<u16>() {
            services.push(format!("Ed25519_IPv4_TCP_0.1.0:{}", port));
        }
    }

    // 4040 Basenet Raw Retrieval
    if let Some(port_str) = util::config("basenet_port") {
        if let Ok(port) = port_str.parse::<u16>() {
            services.push(format!("basenet_0.1.0:{}", port));
        }
    }

    // 8008 Basenet Web Service With YAML Resolution & PeerPub.
    if let Some(port_str) = util::config("pubnet_port") {
        if let Ok(port) = port_str.parse::<u16>() {
            services.push(format!("peerpub_0.1.0:{}", port));
        }
    }

    services.join(",") // Return as a single comma-separated string
}

fn send_to_peerstat(peer_id: &[u8; 32], peer_info: &str) -> Result<(), Error> {
    // Connect to the peerstat Unix socket
    let mut stream = UnixStream::connect(".iden/peerstat")?;

    // Build the message: "ad" + [32-byte peer_id] + peer_info
    let mut message = Vec::with_capacity(2 + 32 + peer_info.len());
    message.extend_from_slice(b"ad");
    message.extend_from_slice(peer_id);
    message.extend_from_slice(peer_info.as_bytes());

    // Send message to peerstat
    stream.write_all(&message)?;

    Ok(())
}

//-----------------------------------------------------------------------------
/// Starts the sender service
//-----------------------------------------------------------------------------
pub fn sender_service() {
    let thread_limit = util::config("sender_thread_limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_THREAD_LIMIT);

    let pool = ThreadPool::new(thread_limit);
    let socket_path = ".iden/sender";

    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path).unwrap();
    }
    let shutdown_listener =
        UnixListener::bind(socket_path).expect("Failed to bind Unix socket for shutdown");

    println!("Sender Service started with {} threads.", thread_limit);

    thread::spawn(move || {
        for stream in shutdown_listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 10];
                if let Ok(n) = stream.read(&mut buffer) {
                    if n > 0 && buffer.starts_with(b"qu") {
                        let _ = stream.write(b"Shutting Down Sender.");
                        println!("Received shutdown signal. Stopping sender service.");
                        std::process::exit(0);
                    }
                }
            }
        }
    });
    let mut last_time = util::current_time(); // Initialize the last timestamp
    loop {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        let current_time = util::current_time();
        let delta_t = current_time - last_time;
        last_time = current_time; // Update last_time for the next loop

        // Read .iden/shard.map and collect mproc names
        let mut mproc_names = Vec::new();

        if let Ok(contents) = fs::read_to_string(".iden/shard.map") {
            for line in contents.lines() {
                if let Some(name) = line.split_whitespace().next() {
                    mproc_names.push(name.to_string());
                }
            }
        } else {
            eprintln!("Failed to read .iden/shard.map");
        }

        // Prepare 'gt' request message with current delta_t
        let mut gt_request = vec![b'g', b't'];
        gt_request.extend_from_slice(&delta_t.to_le_bytes()); // Append f64 as little-endian

        // Collect messages from all mprocs
        let mut collected_messages = Vec::new();

        for mproc in &mproc_names {
            let socket_path = format!(".iden/{}", mproc);

            if let Ok(mut unix_stream) = UnixStream::connect(&socket_path) {
                if let Err(e) = unix_stream.write_all(&gt_request) {
                    eprintln!("Failed to send 'gt' to {}: {:?}", socket_path, e);
                    continue;
                }

                let mut response_buffer = vec![0; 65536]; // Buffer to read response
                match unix_stream.read(&mut response_buffer) {
                    Ok(resp_len) if resp_len > 0 => {
                        collected_messages.push(response_buffer[..resp_len].to_vec());
                    }
                    Err(e) => {
                        eprintln!("Failed to read 'gt' response from {}: {:?}", socket_path, e)
                    }
                    _ => {} // No data returned, skip
                }
            } else {
                eprintln!("Failed to connect to mproc at {}", socket_path);
            }
        }

        // Now, extract individual messages from collected mproc responses
        let mut messages_to_send = Vec::new();

        for msg_vec in collected_messages {
            let mut offset = 0;
            while offset < msg_vec.len() {
                if offset + 2 > msg_vec.len() {
                    break; // Not enough bytes left for an opcode
                }
                let opcode = &msg_vec[offset..offset + 2];

                let message_size = match opcode {
                    b"cl" | b"re" => 70,
                    b"pr" => 134,
                    _ => {
                        eprintln!("Unknown opcode in message, skipping.");
                        break;
                    }
                };

                if offset + message_size > msg_vec.len() {
                    eprintln!("Truncated message, skipping.");
                    break;
                }

                messages_to_send.push(msg_vec[offset..offset + message_size].to_vec());
                offset += message_size;
            }
        }

        // Request up to 100 peers from Peerstat
        let mut peer_request = vec![b'g', b'n'];
        peer_request.extend_from_slice(&100u16.to_le_bytes()); // Request 100 peers

        let mut peer_addresses = Vec::new(); // Store parsed peer connection info
        if let Ok(mut peerstat_stream) = UnixStream::connect(".iden/peerstat") {
            if let Err(e) = peerstat_stream.write_all(&peer_request) {
                eprintln!("Failed to request peers from peerstat: {:?}", e);
            } else {
                let mut response_buffer = vec![0; 65536]; // Large buffer to capture peers
                match peerstat_stream.read(&mut response_buffer) {
                    Ok(resp_len) if resp_len > 2 => {
                        let mut offset = 2; // Skip the first two bytes (peer count)

                        while offset + 2 <= resp_len {
                            // Read next 2 bytes for record length
                            let record_len = u16::from_le_bytes(
                                response_buffer[offset..offset + 2].try_into().unwrap(),
                            );
                            offset += 2;

                            if offset + record_len as usize > resp_len {
                                break; // Avoid out-of-bounds read
                            }

                            // Discard the first 32 bytes (public key)
                            let connection_info_start = offset + 32;
                            let connection_info_end = offset + record_len as usize;

                            if connection_info_end > resp_len {
                                break; // Ensure we don't read out of bounds
                            }

                            // Extract the connection string
                            let connection_info = String::from_utf8_lossy(
                                &response_buffer[connection_info_start..connection_info_end],
                            )
                            .to_string();
                            peer_addresses.push(connection_info);

                            // Move offset to the next record
                            offset = connection_info_end;
                        }
                    }
                    Err(e) => eprintln!("Failed to read peer response from peerstat: {:?}", e),
                    _ => {}
                }
            }
        }

        let mut selected_peers = Vec::new();

        for peer in &peer_addresses {
            if let Some(start) = peer.find("Ed25519_IPv4_TCP_0") {
                // Find the first colon AFTER the protocol name
                let after_protocol = &peer[start..];
                if let Some(colon_index) = after_protocol.find(':') {
                    let after_colon = &after_protocol[colon_index + 1..];

                    // Extract the port by splitting on the next colon
                    if let Some(port_str) = after_colon.split(':').next() {
                        let port_str_trimmed = port_str.trim_matches('\0'); // <== REMOVE NULL BYTES
                        if let Ok(port) = port_str_trimmed.parse::<u16>() {
                            let hostname = peer.split(':').next().unwrap_or("").to_string();
                            selected_peers.push((hostname, port));
                        } else {
                            println!("Failed to parse port from: {}", port_str); // Debugging step
                        }
                    } else {
                        println!("No port found after protocol match in: {}", peer); // Debugging step
                    }
                } else {
                    println!("No colon found after protocol match in: {}", peer); // Debugging step
                }
            }
        }

        for (host, port) in selected_peers {
            let messages_clone = messages_to_send.clone(); // Clone messages for the new thread
            let host_clone = host.clone(); // Clone the host for the new thread

            pool.execute(move || {
                send_messages_to_peer(messages_clone, host_clone, port);
            });
        }

        thread::sleep(Duration::from_secs(5)); // Temporary loop to simulate processing
    }

    println!("Sender service shutting down.");
}

fn send_messages_to_peer(messages: Vec<Vec<u8>>, host: String, port: u16) {
    for message in messages {
        let address = format!("{}:{}", host, port);
        match TcpStream::connect(&address) {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(&message) {
                    eprintln!("Failed to send message to {}: {:?}.", address, e);
                } else {
                    //println!("Sent message to {}", address);
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to {}: {:?}", address, e);
            }
        }
    }
}
