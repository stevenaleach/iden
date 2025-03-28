/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    padman.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.

    Pad Manager:  Listens on .iden/padman
    Optional flag: --no-gui (disables Zenity prompts)
-----------------------------------------------------------------------------*/

use std::fs;
use std::io::{self};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;

use crate::id::State;
use sha2::{Digest, Sha256};
use std::process::Command;

/// Starts the padman service. Loads a pad file, checks whether it is
/// encrypted or decrypted, and listens on the .iden/padman socket.
pub fn listener(args: &[String]) {
    println!("\npadman service starting...");

    let pad_name = match args.get(0) {
        Some(p) => p,
        None => {
            eprintln!("No pad name provided.");
            return;
        }
    };

    let use_gui = !args.iter().any(|a| a == "--no-gui");

    let pad_path = format!(".iden/{}.pad", pad_name);
    let idx_path = format!(".iden/{}.idx", pad_name);

    // Analyze the pad file to determine if it's encrypted or decrypted
    let high_state = match analyze_pad_file(&pad_path, use_gui) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Pad file analysis failed: {}", e);
            return;
        }
    };

    // Check or initialize .idx file
    if !Path::new(&idx_path).exists() {
        if let Err(e) = fs::write(&idx_path, "0\n") {
            eprintln!("Failed to create idx file: {}", e);
            return;
        }
    }

    println!("Current index loaded from {}", idx_path);

    // Derive iden from highest state by stepping it down to idx=0
    let iden = high_state.nstep(high_state.idx()).to_iden();

    if let Some(id) = iden {
        println!("Managing Iden: {}", id.to_string());
        if use_gui {
            let _ = Command::new("zenity")
                .arg("--info")
                .arg("--title=Padman Ready")
                .arg("--text")
                .arg(&format!("Managing pad for: {}", id.to_string()))
                .status();
        }
    } else {
        eprintln!("Failed to extract Iden from pad state.");
    }

    // Listen on hardcoded socket path
    let socket_path = ".iden/padman";
    let socket = Path::new(socket_path);

    if socket.exists() {
        fs::remove_file(socket).unwrap();
    }

    let listener = UnixListener::bind(socket).expect("Failed to bind Unix socket for padman");
    println!("Listening on {:?}", socket);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buffer = [0; 2];
                if let Ok(n) = stream.read(&mut buffer) {
                    if n < 2 {
                        continue;
                    }

                    match &buffer[..2] {
                        b"ix" => {
                            let idx_contents = match fs::read_to_string(&idx_path) {
                                Ok(s) => s,
                                Err(e) => {
                                    eprintln!("Failed to read idx file: {}", e);
                                    continue;
                                }
                            };

                            let current_idx = idx_contents.trim().parse::<u32>().unwrap_or(0);
                            let idx_bytes = current_idx.to_le_bytes();
                            if let Err(e) = stream.write_all(&idx_bytes) {
                                eprintln!("Failed to send index: {}", e);
                            }
                        }

                        b"id" => {
                            if let Some(id) = &iden {
                                let id_str = id.to_string();
                                let _ = stream.write(id_str.as_bytes());
                            } else {
                                let _ = stream.write(b"No iden available.\n");
                            }
                        }

                        b"qu" => {
                            let _ = stream.write(b"Shutting Down padman service.\n");
                            println!("Received shutdown signal. Exiting padman service.");
                            break;
                        }
                        b"st" => {
                            let idx_contents = match fs::read_to_string(&idx_path) {
                                Ok(s) => s,
                                Err(e) => {
                                    eprintln!("Failed to read idx file: {}", e);
                                    continue;
                                }
                            };

                            let current_idx = idx_contents.trim().parse::<u32>().unwrap_or(0);
                            let new_idx = current_idx + 1;

                            let stepped_state = high_state.nstep(high_state.idx() - new_idx);

                            if let Err(e) = fs::write(&idx_path, format!("{}\n", new_idx)) {
                                eprintln!("Failed to update idx file: {}", e);
                                continue;
                            }

                            if let Err(e) = stream.write_all(&stepped_state.to_bytes()) {
                                eprintln!("Failed to send stepped state: {}", e);
                            } else {
                                println!("Sent state at idx {}", new_idx);
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

    println!("padman service has exited.");
}

/// Analyze the pad file to determine if it's encrypted or not.
/// If encrypted, prompts for password via zenity or terminal input.
fn analyze_pad_file(path: &str, use_gui: bool) -> Result<State, String> {
    let content = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    if content.len() != 72 {
        return Err(format!(
            "Invalid pad file size: expected 72 bytes, found {}",
            content.len()
        ));
    }

    let mut state_a_buf = content[..36].to_vec();
    let mut state_b_buf = content[36..].to_vec();

    let state_a = State::try_from(&state_a_buf[..]);
    let state_b = State::try_from(&state_b_buf[..]);

    if let (Ok(a), Ok(b)) = (state_a, state_b) {
        if b.step_check(&a) {
            println!("Pad file is decrypted.");
            return Ok(a);
        } else {
            println!("Pad file is encrypted.");

            let password = if use_gui {
                let output = Command::new("zenity")
                    .arg("--password")
                    .arg("--title=Unlock Pad")
                    .output()
                    .map_err(|e| format!("Failed to execute zenity: {}", e))?;

                if !output.status.success() {
                    return Err("Zenity was cancelled or failed".into());
                }

                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                use rpassword::read_password;
                print!("Enter password to unlock pad: ");
                io::stdout().flush().unwrap();
                let password = read_password().unwrap_or_default();
                password.trim().to_string()
            };

            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();

            for i in 0..32 {
                state_a_buf[i] ^= hash[i];
                state_b_buf[i] ^= hash[i];
            }

            let dec_a = State::try_from(&state_a_buf[..]).map_err(|_| "Decryption failed on A")?;
            let dec_b = State::try_from(&state_b_buf[..]).map_err(|_| "Decryption failed on B")?;

            if dec_b.step_check(&dec_a) {
                println!("Pad file successfully decrypted.");
                return Ok(dec_a);
            } else {
                return Err("Password incorrect, failed to decrypt pad file.".into());
            }
        }
    }

    Err("Failed to parse pad states".into())
}
