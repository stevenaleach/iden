/*-----------------------------------------------------------------------------
    IDEN 0.1.0,
    id.rs
    Copyright (C) 2025 Steven A. Leach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    See <https://www.gnu.org/licenses/> for details.
-----------------------------------------------------------------------------*/

use bs58;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Iden(pub [u8; 32]);

/// Represents a `State` as a 36-byte array. The last four bytes are
/// the `idx` value, stored in little-endian byte-order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State(pub [u8; 36]);

impl TryFrom<&[u8]> for Iden {
    type Error = &'static str;

    /// Creates an `Iden` from a 32-byte array.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 32 {
            let mut iden = [0u8; 32];
            iden.copy_from_slice(bytes);
            Ok(Self(iden))
        } else {
            Err("Invalid byte length for Iden")
        }
    }
}

impl TryFrom<&[u8]> for State {
    type Error = &'static str;

    /// Creates a `State` from a 36-byte array.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 36 {
            let mut state = [0u8; 36];
            state.copy_from_slice(bytes);
            Ok(Self(state))
        } else {
            Err("Invalid byte length for State")
        }
    }
}

impl Iden {
    /// Parses an `Iden` from a base58 string, expecting a 'z' prefix and a
    /// zero-byte version marker.
    ///
    /// Returns `None` if parsing fails.
    pub fn from_str(s: &str) -> Option<Self> {
        if !s.starts_with('z') {
            return None;
        }
        let decoded = bs58::decode(&s[1..]).into_vec().ok()?;
        if decoded.get(0) != Some(&0) || decoded.len() != 33 {
            return None;
        }
        let mut iden = [0u8; 32];
        iden.copy_from_slice(&decoded[1..]);
        Some(Self(iden))
    }

    /// Convert the `Iden` to a string.
    pub fn to_string(&self) -> String {
        let mut data = vec![0];
        data.extend_from_slice(&self.0);
        format!("z{}", bs58::encode(data).into_string())
    }
    /// Returns `Iden` as bytes [u8; 32]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert an `Iden` into a `State` at idx=0 by padding.
    pub fn to_state(&self) -> State {
        let mut state = [0u8; 36];
        state[..32].copy_from_slice(&self.0);
        State(state)
    }

    /// Convert the `Iden` to a 64-character uppercase hex string.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02X}", b)).collect()
    }

    /// Generate a path based on the hex representation of the `Iden`.
    /// hexadecimal string.
    /// - `split`: The number of characters per directory level.
    /// - `count`: The number of directory levels.
    pub fn to_path(&self, split: usize, count: usize) -> String {
        let hex = self.to_hex();
        let mut path_parts = Vec::new();

        let mut index = 0;
        for _ in 0..count {
            if index + split > hex.len() {
                break;
            }
            path_parts.push(&hex[index..index + split]);
            index += split;
        }

        path_parts.push(&hex[index..]);

        format!(".iden/ss/{}/", path_parts.join("/"))
    }
}

impl State {
    /// Parses a `State` from a base58 string, handling both full 36-byte states
    /// and 32-byte idens.
    pub fn from_str(s: &str) -> Option<Self> {
        if !s.starts_with('z') {
            return None;
        }
        let decoded = bs58::decode(&s[1..]).into_vec().ok()?;
        if decoded.get(0) != Some(&0) {
            return None;
        }
        match decoded[1..].len() {
            36 => Some(Self(decoded[1..].try_into().unwrap())),
            32 => {
                let mut padded = [0u8; 36];
                padded[..32].copy_from_slice(&decoded[1..]);
                Some(Self(padded))
            }
            _ => None,
        }
    }

    /// Convert the `State` to a string.
    pub fn to_string(&self) -> String {
        let mut data = vec![0];
        data.extend_from_slice(&self.0);
        format!("z{}", bs58::encode(data).into_string())
    }
    /// Convert the `State` to a 36-byte array.
    pub fn to_bytes(&self) -> [u8; 36] {
        self.0
    }

    /// Get the idx from a `State`.
    pub fn idx(&self) -> u32 {
        u32::from_le_bytes(self.0[32..].try_into().unwrap())
    }

    /// Advance `State`one step.
    pub fn step(&self) -> Self {
        if self.idx() == 0 {
            return *self; // If idx is 0, return the state unchanged.
        }

        let hash = Sha256::digest(&self.0);
        let new_idx = (self.idx() - 1).to_le_bytes();

        let mut new_state = [0u8; 36];
        new_state[..32].copy_from_slice(&hash[..32]);
        new_state[32..].copy_from_slice(&new_idx);
        Self(new_state)
    }

    /// Step `State` count times.
    pub fn nstep(&self, count: u32) -> Self {
        let mut new_state = *self;
        for _ in 0..count {
            if new_state.idx() == 0 {
                break;
            }
            new_state = new_state.step();
        }
        new_state
    }

    /// Checks if another `State` has a higher `idx`, and if so, steps it down
    /// to match.  Returns `true` if the states match after stepping,
    /// otherwise `false`.
    pub fn step_check(&self, other: &Self) -> bool {
        if self.idx() < other.idx() {
            let mut stepped_state = *other;
            while stepped_state.idx() > self.idx() {
                stepped_state = stepped_state.step();
            }
            return stepped_state == *self;
        }
        false
    }

    /// Convert a `State` (if idx=0) into an `Iden`.
    pub fn to_iden(&self) -> Option<Iden> {
        if self.0[32..].iter().all(|&b| b == 0) {
            Some(Iden(self.0[..32].try_into().unwrap()))
        } else {
            None
        }
    }
}
