#![cfg_attr(not(feature = "std"), no_std)]

use base64::engine::general_purpose;
use base64::Engine;
use key::{MeshKey, MeshKeyTrait};
use core::prelude::v1::*;

#[cfg(feature = "defmt")]
use defmt::Format;

// Channel hash generation utilities
pub mod channel;

// Meshtastic packet header utilities
pub mod header;
pub use header::MeshtasticHeader;

// Meshtastic key management utilities
pub mod key;

/// Errors that can occur during cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(Format))]
pub enum CryptoError {
    /// Invalid base64 encoding in key
    InvalidBase64,
    /// Decoded key is empty
    EmptyKey,
    /// Input data is empty
    EmptyData,
    /// Packet is too small or malformed
    InvalidPacket,
    /// Output buffer is too small
    BufferTooSmall,
}

/// Decodes a base64 key and zero-pads or truncates it to 32 bytes
pub fn parse_key(base64_key: &str) -> Result<[u8; 32], CryptoError> {
    let mut key_bytes: [u8; 32] = [0u8; 32];
    let mut decoded = [0u8; 64];

    match general_purpose::STANDARD.decode_slice(base64_key, &mut decoded) {
        Ok(decoded_len) => {
            if decoded_len == 0 {
                return Err(CryptoError::EmptyKey);
            }
            let len = decoded_len.min(32);
            key_bytes[..len].copy_from_slice(&decoded[..len]);
            Ok(key_bytes)
        }
        Err(_) => Err(CryptoError::InvalidBase64),
    }
}

/// Decrypt a Meshtastic packet
/// Returns the length of the decrypted payload on success, or None if the packet is invalid
/// 
/// Supports different key sizes:
/// - 1 byte: Uses default key with LSB replaced by the provided byte (AES-128)
/// - 16 bytes: Uses AES-128 with the provided key
/// - 32 bytes: Uses AES-256 with the provided key
pub fn decrypt_meshtastic_packet(
    packet_buffer: &[u8],
    packet_len: usize,
    output_buffer: &mut [u8],
    key: &[u8],
    key_len: usize,
) -> Option<usize> {
    // Validate minimum packet size (16-byte header)
    if packet_len < 16 || packet_buffer.len() < packet_len {
        return None;
    }

    let payload_len = packet_len - 16;
    if payload_len == 0 || payload_len > output_buffer.len() {
        return None;
    }
    
    // Validate key buffer has enough bytes for specified length
    if key.len() < key_len {
        return None;
    }
    
    // Split into header and encrypted payload
    let (header_bytes, encrypted_payload) = packet_buffer.split_at(16);

    // Parse the header
    let header = MeshtasticHeader::from_bytes(header_bytes)?;

    // Copy encrypted payload to output buffer
    output_buffer[..payload_len].copy_from_slice(&encrypted_payload[..payload_len]);

    // Build the 16-byte IV/nonce according to Meshtastic protocol:
    // Bytes 0-7: packet_id (native byte order u64)
    // Bytes 8-11: from_node (native byte order u32)
    // Bytes 12-15: extraNonce (always zero in current protocol)
    let iv = header.create_iv();

    // Handle different key sizes using the new MeshtasticKey system
    match MeshKey::new(&key[..key_len]) {
        Ok(k) => {
            // Use the new key's AES-CTR transform method
            match k.transform(&mut output_buffer[..payload_len], iv) {
                Ok(_) => Some(payload_len),
                Err(_) => None,
            }
        },
        Err(_) => return None,
    }
}

/// Compute a channel hash using the djb2 algorithm
/// This matches the Meshtastic channel hash implementation
pub fn channel_hash(channel_name: &str) -> u32 {
    let mut hash: u32 = 5381;

    for byte in channel_name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }

    hash
}

/// Encrypt a payload and create a complete Meshtastic packet
/// Returns the total packet length on success, or None if buffers are insufficient
pub fn encrypt_meshtastic_packet(
    header: &MeshtasticHeader,
    payload: &[u8],
    output_buffer: &mut [u8],
    key: &[u8],
    key_len: usize,
) -> Option<usize> {
    let packet_len = 16 + payload.len();

    if output_buffer.len() < packet_len || payload.is_empty() {
        return None;
    }
    
    // Validate key buffer has enough bytes for specified length
    if key.len() < key_len {
        return None;
    }

    // Write header to output buffer
    let header_bytes = header.to_bytes();
    output_buffer[..16].copy_from_slice(&header_bytes);

    // Copy payload to output buffer
    output_buffer[16..packet_len].copy_from_slice(payload);

    // Create IV and encrypt the payload portion
    let iv = header.create_iv();

    // Handle different key sizes using the new MeshtasticKey system
    match MeshKey::new(&key[..key_len]) {
        Ok(k) => {
            // Use the new key's AES-CTR transform method
            match k.transform(&mut output_buffer[16..packet_len], iv) {
                Ok(_) => Some(packet_len),
                Err(_) => None,
            }
        },
        Err(_) => return None,
    }
}

