//! Meshtastic key management utilities
//!
//! This module provides strongly-typed key management for Meshtastic encryption.
//! It uses Rust's type system to enforce correct key usage at compile time,
//! supporting 1-byte, 16-byte, and 32-byte keys with automatic expansion
//! for empty and 1-byte keys using the Meshtastic default key.

#[cfg(feature = "defmt")]
use defmt::Format;

use aes::Aes128;
use aes::Aes256;

use ctr::{Ctr128BE, cipher::{KeyIvInit, StreamCipher}};

type Aes128Ctr = Ctr128BE<Aes128>;
type Aes256Ctr = Ctr128BE<Aes256>;

/// The default Meshtastic encryption key
/// This is the standard key used by Meshtastic devices when no custom key is provided
pub const MESHTASTIC_DEFAULT_KEY: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

/// Errors that can occur during key operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(Format))]
pub enum KeyError {
    /// Invalid key size provided
    InvalidKeySize,
    EmptyData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(Format))]
pub enum MeshKey {
    MeshKeyEmpty([u8; 16]),
    MeshKey8bit([u8; 16]),
    MeshKey128bit([u8; 16]),
    MeshKey256bit([u8; 32]),
}

pub trait MeshKeyTrait {
    fn transform(&self, data: &mut [u8], nonce: [u8; 16]) -> Result<(), KeyError>;
}

impl MeshKeyTrait for MeshKey {
    fn transform(&self, data: &mut [u8], nonce: [u8; 16]) -> Result<(), KeyError> {
        if data.is_empty() {
            return Err(KeyError::EmptyData);
        }

        match self {
            MeshKey::MeshKeyEmpty(key) | 
            MeshKey::MeshKey8bit(key) | 
            MeshKey::MeshKey128bit(key) => {
                let mut cipher = Aes128Ctr::new(key.into(), &nonce.into());
                cipher.apply_keystream(data);
                Ok(())
            }
            MeshKey::MeshKey256bit(key) => {
                let mut cipher = Aes256Ctr::new(key.into(), &nonce.into());
                cipher.apply_keystream(data);
                Ok(())
            }
        }
    }
}

impl MeshKey {
    pub fn new(key: &[u8]) -> Result<Self, KeyError> {
        match key.len() {
            0 => Ok(MeshKey::MeshKeyEmpty(MESHTASTIC_DEFAULT_KEY)),
            1 => Ok(MeshKey::MeshKey8bit({
                let mut expanded_key = MESHTASTIC_DEFAULT_KEY;
                expanded_key[15] = key[0];
                expanded_key
            })),
            16 => {
                let mut array = [0u8; 16];
                array.copy_from_slice(key);
                Ok(MeshKey::MeshKey128bit(array))
            }
            32 => {
                let mut array = [0u8; 32];
                array.copy_from_slice(key);
                Ok(MeshKey::MeshKey256bit(array))
            }
            _ => Err(KeyError::InvalidKeySize),
        }
    }
    
    /// Get the key bytes for hashing purposes
    /// Returns a slice to the underlying key bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MeshKey::MeshKeyEmpty(key) | 
            MeshKey::MeshKey8bit(key) | 
            MeshKey::MeshKey128bit(key) => key,
            MeshKey::MeshKey256bit(key) => key,
        }
    }
}