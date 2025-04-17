/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    main.rs

    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.
-----------------------------------------------------------------------------*/
//#![allow(unused_imports)]
//#![allow(dead_code)]
//#![allow(unused_variables)]

static INIT_CONFIG: &str = "
basenet_port:         4040  Offers+full-frame resolution and retrieval.
claim_cache_limit:    512   Per-iden limit for claim-cache size.
claim_cache_time:     900   Number of seconds after which a claim is discarded.
claim_cache_total:    10000000  Per-shard limit for claim-cache size.
message_cache_size:   60000     Per shard max message cache size.
message_cache_time:   1800  Time in seconds after which old messages are discarded.
mproc_step_limit:     50000
peercache_size:       500
pubnet_port:          8008
sender_thread_limit:  128
signal_cache_size:    4096  Filesize limit for ss.bin
ss_split_chars:       4 /nnnn/... chars per division.
ss_split_count:       2 /nnnn/nnnn/aaaaaaaaaaaaaaaaaaaaaaaaa.../ N divisions.
tcp_in_port:          4004
thread_limit_in:      8
throttle_delta:       2.0  <-- An overly safe extreme default.
throttle_forget:      900  Time hosts/dedications will be remembered for.
";

pub mod basenet;
pub mod id;
pub mod mproc;
pub mod padman;
pub mod tcp;
pub mod util;
use crate::util::generate_keys;
use id::{Iden, State};
use indicatif::{ProgressBar, ProgressStyle};
use mproc::MProc;
use rand::Rng;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::str;

// ------------------------------------------------------------------------------
fn main() {
    println!("{}", GREETING);
    let args: Vec<String> = env::args().collect();
    let executable = &args[0];
    let executable = executable.to_string();

    if args.len() > 1 {
        let command = &args[1];

        match command.as_str() {
            "connect" => {
                if let Some(addr) = args.get(2) {
                    let port = args
                        .get(3)
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(4004);
                    let full_address = format!("{}:{}", addr, port);
                    tcp::connect(&full_address);
                } else {
                    println!("Usage: iden connect <ip/domain> [port]");
                }
            }

            "help" | "-help" | "--help" | "-h" | "--h" => {
                println!("{}", CLI_HELP);
                return;
            }
            "init" => init(),
            "mproc" => mproc::listener(&args[2..]),
            "basenet" => {
                basenet::listener(&args[2..]);
            }
            "basenet_in" => {
                basenet::start_basenet_tcp_service();
            }
            "padman" => {
                padman::listener(&args[2..]);
            }
            "peerstat" => {
                start_peerstat();
            }
            "run" => {
                if let Some(script_path) = args.get(2) {
                    run(script_path, &executable);
                } else {
                    println!("Usage: run <startup_file>");
                }
                repl(executable);
            }

            "shard" => {
                if let Some(n_str) = args.get(2) {
                    match n_str.parse::<usize>() {
                        Ok(n) if n > 0 => shardmap(n),
                        _ => println!("Error: Invalid shard count. Must be a positive integer."),
                    }
                } else {
                    println!("Usage: iden shard <N>");
                }
            }

            "sender" => {
                tcp::sender_service();
            }

            "tcp_in" => {
                tcp::start_tcp_service();
            }

            "store" | "Store" => {
                if args.len() == 5 {
                    let pad_file = &args[2];
                    let output_name = &args[3];
                    if let Ok(idx) = args[4].parse::<u32>() {
                        util::store_pad(pad_file, idx, output_name);
                    } else {
                        println!("Invalid index. Please provide a valid u32 number.");
                    }
                } else {
                    println!("Usage: iden store <input-pad> <name> <idx>");
                }
            }

            "throttle" => {
                util::throttling_service();
            }
            "generate" => {
                if let Some(filename) = args.get(2) {
                    generate_iden(filename);
                } else {
                    println!("Usage: generate <filename>");
                }
            }
            _ => println!("Unknown Command: \"{command}\""),
        }
    } else {
        repl(executable);
    }
}

// ----------------------------------------------------------------------------
// Executes REPL commands from a file.
// #'s = comment,
// !   = shell command
fn run(script_path: &str, executable: &str) {
    // Try opening from current directory first
    let path = Path::new(script_path);

    // If not found, try in .iden/
    let file = if path.exists() {
        File::open(path)
    } else {
        let fallback_path = Path::new(".iden").join(script_path);
        File::open(fallback_path)
    };

    match file {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(command) = line {
                    let trimmed = command.trim();

                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue; // Ignore empty lines and comments
                    }

                    if trimmed.starts_with('!') {
                        // Execute shell command
                        let shell_cmd = &trimmed[1..]; // Strip the '!'
                        let status = Command::new("sh").arg("-c").arg(shell_cmd).status();

                        match status {
                            Ok(exit_status) if exit_status.success() => (),
                            Ok(exit_status) => eprintln!("Command failed: {:?}", exit_status),
                            Err(e) => eprintln!("Error running command: {:?}", e),
                        }
                    } else {
                        // Normal REPL command
                        println!("▶ {command}");
                        do_command(trimmed, executable);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open script file '{}': {}", script_path, e);
        }
    }
}

// ----------------------------------------------------------------------------
static HELP: &str = "
Available Commands:
────────────────────────────────────────────────────────────────────
basenet_in start <name>:
    Start the basenet service on the given socket name.

basenet_in stop <name>:
    Stop the basenet service on the given socket name.

connect <host> [port]:
    Establish a connection to a remote peer.

exit | quit | q:
    Exit the REPL.

help | ?:
    Display this help text.

listener start:
    Start the TCP listener service.

listener stop:
    Stop the TCP listener service.

mproc start <name>:
    Start an mproc instance listening on the specified socket.

mproc stop <name>:
    Shut down a running mproc instance.

peerstat start:
    Start the peerstat service.

peerstat stop:
    Stop the peerstat service.

sender start:
    Start the sender service.

sender stop:
    Stop the sender service.

shard <iden>:
    Determine which shard an iden belongs to.

start_mprocs:
    Start all mproc instances defined in .iden/shard.map.

stop_mprocs:
    Stop all mproc instances defined in .iden/shard.map.

throttle start:
    Start the throttling service.

throttle stop:
    Stop the throttling service.

padman stop:
    Shut down the padman service.

start_basenets:
    Start all basenet instances defined in .iden/shard.map.

stop_basenets:
    Stop all basenet instances defined in .iden/shard.map.

version <mproc_socket> | ve:
    Display the current version number.
────────────────────────────────────────────────────────────────────
";

static GREETING: &str = concat!("Iden 🐧🦀 ", env!("CARGO_PKG_VERSION"));

static CLI_HELP: &str = concat!(
    "IDEN ",
    env!("CARGO_PKG_VERSION"),
    " - Spring 2025\n\n",
    "Usage:\n",
    "    iden <command> [options]\n\n",
    "Commands:\n",
    "    connect <host> [port]  Connect to a remote peer at <host> on optional [port] (default 4004).\n",
    "    generate <file>        Generate a new IDEN pad, saving to <file>.\n",
    "    init                   Initialize the IDEN storage directory and config file.\n",
    "    mproc <name>           Run an mproc message processor on .iden/<name>.\n",
    "    basenet <name>         Run a basenet message processor on .iden/bn<name>.\n",
    "    basenet_in             Start the basenet TCP listener service.\n",
    "    peerstat               Start the peer statistics tracking service.\n",
    "    run <startup_file>     Execute commands from a file before entering the REPL.\n",
    "    sender                 Start the sender service.\n",
    "    shard <N>              Generate a new shard map with N shards.\n",
    "    tcp_in                 Start the TCP listener service.\n",
    "    store <pad> <name> <idx> Store an encrypted checkpoint for padman",
    "    throttle               Start the throttling service.\n",
    "    version | ve           Display the current version number.\n",
    "    help | -h | --help     Display this help message.\n\n",
    "Examples:\n",
    "    iden init\n",
    "    iden mproc .iden/0\n",
    "    iden peerstat\n",
    "    iden tcp_in\n",
    "    iden sender\n",
    "    iden throttle\n",
    "    iden run start.txt\n",
    "    iden shard 8\n",
    "    iden generate newpad.txt\n",
    "    iden connect example.com 4004\n\n",
    "For interactive mode, run without arguments.\n",
);

// ----------------------------------------------------------------------------
fn repl(executable: String) {
    loop {
        print!("▶ ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("stdin error.");
        if !do_command(input.trim(), &executable) {
            break;
        }
    }
}

// ----------------------------------------------------------------------------
// Handle a REPL command
fn do_command(line: &str, executable: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();

    if let Some(command) = words.first() {
        match *command {
            //-----------------------------------------------------------------
            "basenet" => {
                match words.get(1) {
                    // start basenet --------------------------------------------
                    Some(&"start") => {
                        if let Some(name) = words.get(2) {
                            let mut socket = String::from(".iden/");
                            socket.push_str(name);
                            let proc = mproc::MProc::new(executable.to_string(), socket.clone());
                            proc.start(); // This works as-is, since MProc just starts a binary with args
                            println!("Started basenet on {}", socket);
                        } else {
                            println!("Usage: basenet start <name>");
                        }
                    }
                    // stop basenet ---------------------------------------------
                    Some(&"stop") => {
                        if let Some(name) = words.get(2) {
                            if let Some(response) = send_to_mproc(name, b"qu") {
                                let s = String::from_utf8(response).expect("bad utf8");
                                println!("Response: {:?}", s);
                            } else {
                                println!("No response.");
                            }
                        } else {
                            println!("Usage: basenet stop <name>");
                        }
                    }
                    _ => println!("Usage: basenet <start|stop> <name>"),
                }
            }
            //-----------------------------------------------------------------
            "basenet_in" => match words.get(1) {
                Some(&"start") => match Command::new(executable).arg("basenet_in").spawn() {
                    Ok(_) => println!("Started basenet TCP service."),
                    Err(e) => println!("Failed to start basenet TCP service: {:?}", e),
                },
                Some(&"stop") => {
                    if let Ok(mut stream) =
                        std::os::unix::net::UnixStream::connect(".iden/basenet_tcp")
                    {
                        if let Err(e) = stream.write_all(b"qu") {
                            println!("Failed to send shutdown signal: {:?}", e);
                        } else {
                            let mut response = [0u8; 256];
                            if let Ok(n) = stream.read(&mut response) {
                                let response_str = String::from_utf8_lossy(&response[..n]);
                                println!("Basenet TCP shutdown response: {}", response_str.trim());
                            }
                        }
                    } else {
                        println!("Failed to connect to basenet TCP shutdown socket.");
                    }
                }
                _ => println!("Usage: basenet_in <start|stop>"),
            },

            //-----------------------------------------------------------------
            "connect" | "Connect" => {
                if words.len() < 2 {
                    println!("Usage: connect <host> [port]");
                    return true;
                }

                let host = words[1];
                let port = words.get(2).unwrap_or(&"4004"); // Default to 4004
                let full_address = format!("{}:{}", host, port);

                tcp::connect(&full_address);
            }

            //-----------------------------------------------------------------
            "exit" | "q" | "quit" => std::process::exit(0), //return false, // Exit REPL
            //-----------------------------------------------------------------
            "help" | "?" | "Help" => {
                print!("{HELP}");
            }

            //-----------------------------------------------------------------
            "listener" => match words.get(1) {
                Some(&"start") => match Command::new(executable).arg("tcp_in").spawn() {
                    Ok(_) => println!("Started TCP listener."),
                    Err(e) => println!("Failed to start TCP listener: {:?}", e),
                },

                Some(&"stop") => {
                    let socket_name = "tcp_in".to_string();

                    if let Some(response) = send_to_mproc(&socket_name, b"qu") {
                        let s = String::from_utf8(response).expect("bad utf8");
                        println!("TCP listener shutdown response: {:?}", s);
                    } else {
                        println!("Failed to stop TCP listener.");
                    }
                }

                _ => println!("Usage: listener <start|stop>"),
            },
            //-----------------------------------------------------------------
            "mproc" => {
                match words.get(1) {
                    // start mproc --------------------------------------------
                    Some(&"start") => {
                        if let Some(name) = words.get(2) {
                            let mut socket = String::from(".iden/");
                            socket.push_str(name);
                            let proc = MProc::new(executable.to_string(), socket.clone());
                            proc.start();
                            println!("Started mproc on {}", socket);
                        } else {
                            println!("Usage: mproc start <name>");
                        }
                    }
                    // stop mproc -0-------------------------------------------
                    Some(&"stop") => {
                        if let Some(name) = words.get(2) {
                            if let Some(response) = send_to_mproc(name, b"qu") {
                                let s = String::from_utf8(response).expect("bad utf8");
                                println!("Response: {:?}", s);
                            } else {
                                println!("No response.");
                            }
                        } else {
                            println!("Usage: mproc stop <name>");
                        }
                    }
                    _ => println!("Usage: mproc <start|stop> <name>"),
                }
            }

            //-----------------------------------------------------------------
            "padman" => match words.get(1) {
                Some(&"stop") => {
                    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(".iden/padman")
                    {
                        if let Err(e) = stream.write_all(b"qu") {
                            println!("Failed to send shutdown signal: {:?}", e);
                        } else {
                            let mut response = [0u8; 256];
                            if let Ok(n) = stream.read(&mut response) {
                                let response_str = String::from_utf8_lossy(&response[..n]);
                                println!("Padman shutdown response: {}", response_str.trim());
                            }
                        }
                    } else {
                        println!("Could not connect to padman socket.");
                    }
                }
                _ => println!("Usage: padman stop"),
            },

            //-----------------------------------------------------------------
            "peerstat" => match words.get(1) {
                Some(&"start") => match Command::new(executable).arg("peerstat").spawn() {
                    Ok(_) => println!("Started peerstat service."),
                    Err(e) => println!("Failed to start peerstat: {:?}", e),
                },
                Some(&"stop") => {
                    if let Some(response) = send_to_mproc("peerstat", b"qu") {
                        let s = String::from_utf8(response).expect("bad utf8");
                        println!("Peerstat shutdown response: {:?}", s);
                    } else {
                        println!("Failed to stop peerstat.");
                    }
                }
                _ => println!("Usage: peerstat <start|stop>"),
            },

            //-----------------------------------------------------------------
            "sender" => match words.get(1) {
                Some(&"start") => {
                    match std::process::Command::new(executable).arg("sender").spawn() {
                        Ok(_) => println!("Started sender service."),
                        Err(e) => println!("Failed to start sender service: {:?}", e),
                    }
                }
                Some(&"stop") => {
                    if let Some(response) = send_to_mproc("sender", b"qu") {
                        let s = String::from_utf8(response).expect("bad utf8");
                        println!("Sender service shutdown response: {:?}", s);
                    } else {
                        println!("Failed to stop sender service.");
                    }
                }
                _ => println!("Usage: sender <start|stop>"),
            },

            //-----------------------------------------------------------------
            "shard" | "Shard" => {
                if words.len() != 2 {
                    println!("Usage: shard <iden>");
                    return true;
                }

                let iden_str = words[1];

                if let Some(iden) = Iden::from_str(iden_str) {
                    match util::shard(&iden.to_bytes()) {
                        // <-- FIXED: Convert Iden to byte array
                        Some(shard_name) => println!("Shard: {}", shard_name),
                        None => println!("No matching shard found."),
                    }
                } else {
                    println!("Invalid iden.");
                }
            }

            //-----------------------------------------------------------------
            "start_mprocs" => {
                if let Ok(file) = std::fs::read_to_string(".iden/shard.map") {
                    for line in file.lines() {
                        if let Some(name) = line.split_whitespace().next() {
                            let command = format!("mproc start {}", name);
                            do_command(&command, executable);
                        }
                    }
                    println!("Started all mproc instances.");
                } else {
                    println!("Error: Could not read .iden/shard.map.");
                }
            }

            //-----------------------------------------------------------------
            "start_basenets" => {
                if let Ok(file) = std::fs::read_to_string(".iden/shard.map") {
                    for line in file.lines() {
                        if let Some(name) = line.split_whitespace().next() {
                            let socket_name = format!(".iden/bn{}", name);
                            match Command::new(&executable)
                                .arg("basenet")
                                .arg(&socket_name)
                                .spawn()
                            {
                                Ok(_) => println!("Started basenet on {}", socket_name),
                                Err(e) => {
                                    eprintln!("Failed to start basenet {}: {:?}", socket_name, e)
                                }
                            }
                        }
                    }
                    println!("Started all basenet instances.");
                } else {
                    println!("Error: Could not read .iden/shard.map.");
                }
            }

            //-----------------------------------------------------------------
            "stop_basenets" => {
                if let Ok(file) = std::fs::read_to_string(".iden/shard.map") {
                    for line in file.lines() {
                        if let Some(name) = line.split_whitespace().next() {
                            let socket_name = format!("bn{}", name);
                            if let Some(response) = send_to_mproc(&socket_name, b"qu") {
                                let s = String::from_utf8_lossy(&response);
                                println!("Stopped basenet {}: {}", socket_name, s.trim());
                            } else {
                                println!("Failed to stop basenet {}.", socket_name);
                            }
                        }
                    }
                    println!("Sent shutdown signal to all basenet instances.");
                } else {
                    println!("Error: Could not read .iden/shard.map.");
                }
            }

            //-----------------------------------------------------------------
            "stop_mprocs" => {
                if let Ok(file) = std::fs::read_to_string(".iden/shard.map") {
                    for line in file.lines() {
                        if let Some(name) = line.split_whitespace().next() {
                            if let Some(response) = send_to_mproc(name, b"qu") {
                                // Just name, no extra ".iden/"
                                let s = String::from_utf8_lossy(&response);
                                println!("Stopped mproc {}: {}", name, s.trim());
                            } else {
                                println!("Failed to stop mproc {}.", name);
                            }
                        }
                    }
                    println!("Sent shutdown signal to all mproc instances.");
                } else {
                    println!("Error: Could not read .iden/shard.map.");
                }
            }

            //-----------------------------------------------------------------
            "throttle" => match words.get(1) {
                Some(&"start") => {
                    match std::process::Command::new(executable)
                        .arg("throttle")
                        .spawn()
                    {
                        Ok(_) => println!("Started throttling service."),
                        Err(e) => println!("Failed to start throttling service: {:?}", e),
                    }
                }
                Some(&"stop") => {
                    if let Ok(mut stream) =
                        std::os::unix::net::UnixStream::connect(".iden/throttle")
                    {
                        if let Err(e) = stream.write_all(b"qu") {
                            println!("Failed to send shutdown signal: {:?}", e);
                        } else {
                            let mut response = [0u8; 256];
                            if let Ok(n) = stream.read(&mut response) {
                                let response_str = String::from_utf8_lossy(&response[..n]);
                                println!(
                                    "Throttling service shutdown response: {}",
                                    response_str.trim()
                                );
                            }
                        }
                    } else {
                        println!("Failed to connect to throttling service.");
                    }
                }
                _ => println!("Usage: throttle <start|stop>"),
            },

            //-----------------------------------------------------------------
            "version" | "ve" | "Version" | "VE" => {
                if words.len() != 2 {
                    println!("Usage: version <mproc_socket>");
                    return true;
                }

                let socket_name = words[1];

                if let Some(response) = send_to_mproc(socket_name, b"ve") {
                    if let Ok(version) = String::from_utf8(response) {
                        println!("Iden mproc version: {}", version.trim());
                    } else {
                        println!("Received invalid UTF-8 in version response.");
                    }
                } else {
                    println!("Failed to retrieve version from mproc.");
                }
            }
            //-----------------------------------------------------------------
            _ => println!("{}?", command),
            //-----------------------------------------------------------------
        }
    }
    true
}

// ----------------------------------------------------------------------------
// Sends byte data to a named mproc instance, returns Option<Vec<u8>>
// response.
fn send_to_mproc(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    let socket_path = format!(".iden/{}", name);

    if !fs::metadata(&socket_path).is_ok() {
        eprintln!("Socket {} does not exist.", socket_path);
        return None;
    }

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            if let Err(err) = stream.write_all(data) {
                eprintln!("Failed to send data: {:?}", err);
                return None;
            }

            let mut buf = [0; 65536];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => Some(buf[..n].to_vec()),
                _ => None,
            }
        }
        Err(err) => {
            eprintln!("Failed to connect to {}: {:?}", socket_path, err);
            None
        }
    }
}

// ----------------------------------------------------------------------------
/// create storage paths and initial configuration file in ./iden in the
/// current directory.
fn init() {
    let config = INIT_CONFIG.as_bytes();
    let mut dir_path = env::current_dir().unwrap().display().to_string();
    dir_path.push_str("/.iden");

    println!("Initialize in {}/\ny/n?", dir_path);
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("stdin error.");

    if matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
        fs::create_dir_all(&dir_path).unwrap();
        dir_path.push('/');
    } else {
        println!("Exiting");
        return;
    }

    let ss_dir = format!("{}ss", dir_path);
    fs::create_dir_all(&ss_dir).unwrap();

    let config_path = format!("{}iden.cfg", dir_path);
    println!("{}", config_path);

    let _ = fs::write(config_path, config);
    // Write default start and stop scripts
    let start_script = "\
!echo default startup script.
throttle start
start_mprocs
start_basenets
listener start
peerstat start
basenet_in start
sender start
#!cargo run padman foo&
quit
";

    let stop_script = "\
!echo default shutdown script.
sender stop
stop_mprocs
stop_basenets
listener stop
peerstat stop
basenet_in stop
padman stop
throttle stop
quit
";

    let start_path = format!("{}start", dir_path);
    let stop_path = format!("{}stop", dir_path);

    if let Err(e) = fs::write(&start_path, start_script) {
        eprintln!("Failed to write start script: {:?}", e);
    }

    if let Err(e) = fs::write(&stop_path, stop_script) {
        eprintln!("Failed to write stop script: {:?}", e);
    }

    // Path to the shard map file
    let shard_map_path = format!("{}shard.map", dir_path);

    // Check if the file exists, create it if not
    if !Path::new(&shard_map_path).exists() {
        println!("Creating default shard.map...");
        if let Err(e) = fs::write(&shard_map_path, "0 0000 ffff\n") {
            eprintln!("Failed to create shard.map: {:?}", e);
        }
    }

    // Check if the private and public keys exist, generate if missing
    let private_key_path = Path::new(".iden/private_key.bin");
    let public_key_path = Path::new(".iden/public_key.bin");

    if !private_key_path.exists() || !public_key_path.exists() {
        println!("No existing keys found. Generating new Ed25519 keys...");
        generate_keys();
        println!("New keys generated and saved.");
    } else {
        println!("Existing node keys found.");
    }
    println!("Keys check?: {}", util::sanity_check_keys())
}

pub fn generate_iden(filename: &str) {
    // Check if the file exists
    let path = Path::new(filename);
    if path.exists() {
        eprintln!(
            "File '{}' already exists. Aborting to prevent overwrite.",
            filename
        );
        return;
    }

    let mut rng = rand::rng();
    let mut seed_bytes = [0u8; 36];
    for i in 0..32 {
        let n: u8 = rng.random_range(..=255);
        seed_bytes[i] = n;
    }
    seed_bytes[32..].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut state = State::try_from(&seed_bytes[..]).unwrap();

    // Create and open file
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error creating file '{}': {:?}", filename, e);
            return;
        }
    };

    // Write initial line: idx decimal + state
    writeln!(file, "{} {}", state.idx(), state.to_string()).unwrap();

    // Setup progress bar explicitly writing to stderr
    let steps: u32 = 500;
    let step_size = u32::MAX / steps;

    let bar = ProgressBar::new(steps as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    bar.inc(0);
    bar.tick();

    for _ in 0..steps {
        state = state.nstep(step_size);
        writeln!(file, "{} {}", state.idx(), state.to_string()).unwrap();
        bar.inc(1);
    }

    if state.idx() != 0 {
        state = state.nstep(state.idx()); // Ensure we reach exactly idx=0
        writeln!(file, "0 {}", state.to_string()).unwrap();
    }

    // Write final iden to file
    if let Some(iden) = state.to_iden() {
        writeln!(file, "{}", iden.to_string()).unwrap();
    }

    bar.finish_with_message("Pad generation complete.");
}

const DEFAULT_PEERCACHE_SIZE: usize = 1000;

//------------------------------------------------------------------------------
// PeerStat Service
//
/// Represents an entry in the peer cache.
struct PeerEntry {
    last_seen: f64,
    connection_info: String,
}

/// PeerStat service struct.
struct PeerStat {
    cache: HashMap<[u8; 32], PeerEntry>,
    max_size: usize,
}

//-----------------------------------------------------------------------------
impl PeerStat {
    //-------------------------------------------------------------------------
    /// Creates a new PeerStat service with cache size from config.
    fn new() -> Self {
        let max_size = util::config("peercache_size")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_PEERCACHE_SIZE);
        println!("peercache_size: {}", max_size);

        Self {
            cache: HashMap::new(),
            max_size,
        }
    }

    //-------------------------------------------------------------------------
    /// Adds or updates a peer in the cache.
    fn add_peer(&mut self, peer_id: [u8; 32], info: String) {
        let now = util::current_time();
        self.cache.insert(
            peer_id,
            PeerEntry {
                last_seen: now,
                connection_info: info,
            },
        );

        // If cache exceeds max size, remove the oldest entry
        if self.cache.len() > self.max_size {
            if let Some((&oldest_key, _)) = self
                .cache
                .iter()
                .min_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap())
            {
                self.cache.remove(&oldest_key);
            }
        }
    }

    //-------------------------------------------------------------------------
    /// Retrieves up to `n` peers from the cache.
    fn get_n_peers(&self, n: usize) -> Vec<u8> {
        let mut entries: Vec<_> = self.cache.iter().collect();
        entries.sort_by(|a, b| b.1.last_seen.partial_cmp(&a.1.last_seen).unwrap());
        let selected_entries = entries.into_iter().take(n);

        let mut response = Vec::new();
        response.extend_from_slice(&(selected_entries.len() as u16).to_le_bytes());
        for (peer_id, entry) in selected_entries {
            let record_bytes = format!("{}\0", entry.connection_info).into_bytes();

            response.extend_from_slice(&(record_bytes.len() as u16 + 32).to_le_bytes());
            response.extend_from_slice(peer_id);
            response.extend_from_slice(&record_bytes);
        }
        response
    }
}
//-----------------------------------------------------------------------------
/// Handles peerstat requests over the Unix socket.
fn handle_peerstat(mut stream: UnixStream, peerstat: &mut PeerStat) {
    let mut buffer = [0; 65536];

    if let Ok(n) = stream.read(&mut buffer) {
        if n < 2 {
            return;
        }
        match &buffer[..2] {
            //-----------------------------------------------------------------
            b"ad" => {
                if n > 34 {
                    let peer_id = buffer[2..34].try_into().unwrap();
                    if let Some(info) = std::str::from_utf8(&buffer[34..n]).ok() {
                        peerstat.add_peer(peer_id, info.to_string());
                    }
                }
            }
            //-----------------------------------------------------------------
            b"gn" => {
                if n == 4 {
                    let requested_count =
                        u16::from_le_bytes(buffer[2..4].try_into().unwrap()) as usize;
                    let response = peerstat.get_n_peers(requested_count);
                    let _ = stream.write_all(&response);
                }
            }
            //-----------------------------------------------------------------
            b"qu" => {
                println!("peerstat exiting.");
                let _ = stream.write(b"Shutting Down.");
                std::process::exit(0);
            }
            _ => {}
        }
    }
}
//-----------------------------------------------------------------------------
/// Starts the peerstat service.
pub fn start_peerstat() {
    let mut peerstat = PeerStat::new();
    let socket_path = ".iden/peerstat";

    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path).unwrap();
    }

    let listener = UnixListener::bind(socket_path).expect("Failed to bind peerstat socket");
    println!("peerstat service listening on {}", socket_path);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_peerstat(stream, &mut peerstat),
            Err(err) => println!("peerstat connection error: {:?}", err),
        }
    }
}

//-----------------------------------------------------------------------------
/// Generates a shard map with `n` shards and writes it to `.iden/shard.map`.
pub fn shardmap(n: usize) {
    if n == 0 {
        eprintln!("Error: Number of shards must be greater than 0.");
        return;
    }

    let step = 0x10000 / n; // 2**16 / n
    let mut output = String::new();

    for i in 0..n {
        let start = i * step;
        let end = if i == n - 1 {
            0xFFFF
        } else {
            (i + 1) * step - 1
        };
        output.push_str(&format!("{} {:04x} {:04x}\n", i, start, end));
    }

    // Write to .iden/shard.map
    if let Err(e) = fs::write(".iden/shard.map", output) {
        eprintln!("Failed to write shard map: {:?}", e);
    } else {
        println!("Shard map updated with {} shards.", n);
    }
}
