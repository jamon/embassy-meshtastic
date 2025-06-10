#![cfg_attr(not(feature = "std"), no_std)]

use base64::engine::general_purpose;
use base64::Engine;
use core::prelude::v1::*;
use femtopb::Message as _;

#[cfg(feature = "defmt")]
use defmt::Format;

// Re-export commonly used types
pub use meshtastic_protobufs::meshtastic::PortNum;

// Channel hash generation utilities
pub mod channel;

// packet header types
pub mod header;
pub use header::Header;

// key management
pub mod key;
use crate::key::ChannelKey;

// Node database for storing device information
pub mod node_database;

/// Marker types to distinguish between encrypted and decrypted packet states
#[derive(Clone)]
pub struct Encrypted;

#[derive(Clone)]
pub struct Decrypted;

/// Marker type for a packet with decoded payload
#[derive(Clone)]
pub struct Decoded;

/// Owned Data payload that doesn't depend on zero-copy lifetimes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OwnedData {
    pub portnum: femtopb::EnumValue<meshtastic_protobufs::meshtastic::PortNum>,
    pub payload: [u8; 233],
    pub payload_len: usize,
    pub want_response: bool,
    pub dest: u32,
    pub source: u32,
    pub request_id: u32,
    pub reply_id: u32,
    pub emoji: u32,
}

impl OwnedData {
    /// Convert from protobuf Data to owned data
    pub fn from_protobuf(data: &meshtastic_protobufs::meshtastic::Data) -> Self {
        let mut payload = [0u8; 233];
        let payload_len = data.payload.len().min(233);
        payload[..payload_len].copy_from_slice(&data.payload[..payload_len]);
        
        Self {
            portnum: data.portnum,
            payload,
            payload_len,
            want_response: data.want_response,
            dest: data.dest,
            source: data.source,
            request_id: data.request_id,
            reply_id: data.reply_id,
            emoji: data.emoji,
        }
    }
}

/// A packet in various states of processing
#[derive(Clone)]
pub struct Packet<S> {
    pub header: Header,
    pub rssi: i8,
    pub snr: i8,
    pub payload: [u8; 240],
    pub payload_len: usize,
    pub _marker: core::marker::PhantomData<S>,
}

impl<S> Packet<S> {
    /// Create a new packet with the given data
    pub fn new(
        header: Header,
        rssi: i8,
        snr: i8,
        payload: [u8; 240],
        payload_len: usize,
    ) -> Self {
        Self {
            header,
            rssi,
            snr,
            payload,
            payload_len,
            _marker: core::marker::PhantomData,
        }
    }
}

impl Packet<Encrypted> {
    /// Create an encrypted packet from raw bytes
    /// The buffer should contain a 16-byte header followed by encrypted payload
    pub fn from_bytes(buffer: &[u8], rssi: i8, snr: i8) -> Option<Self> {
        if buffer.len() < 16 {
            return None;
        }

        let header = Header::from_bytes(&buffer[..16])?;
        let mut payload = [0u8; 240];
        let payload_len = (buffer.len() - 16).min(240);
        payload[..payload_len].copy_from_slice(&buffer[16..16 + payload_len]);

        Some(Self {
            header,
            rssi,
            snr,
            payload,
            payload_len,
            _marker: core::marker::PhantomData,
        })
    }

    /// Decrypts the packet payload using the provided key
    /// Returns a DecryptedPacket on success, or None if decryption fails
    /// Consumes the original encrypted packet
    pub fn decrypt(self, key: &ChannelKey) -> Result<Packet<Decrypted>, ()> {
        // Create IV from header
        let iv = self.header.generate_iv();

        // Copy payload for decryption
        let mut decrypted_payload = [0u8; 240];
        decrypted_payload[..self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);

        // Transform (decrypt) the payload in place
        match key.transform(&mut decrypted_payload[..self.payload_len], &iv) {
            Ok(()) => {
                Ok(Packet {
                    header: self.header,
                    rssi: self.rssi,
                    snr: self.snr,
                    payload: decrypted_payload,
                    payload_len: self.payload_len,
                    _marker: core::marker::PhantomData,
                })
            }
            Err(_) => Err(()),
        }
    }
}

impl Packet<Decrypted> {
    pub fn port_num(&self) -> femtopb::EnumValue<meshtastic_protobufs::meshtastic::PortNum> {
        if self.payload_len > 0 {
            let port_byte = self.payload[0];
            // For now, return unknown since PortNum doesn't implement TryFrom<i32>
            // We'll need to implement this conversion manually
            femtopb::EnumValue::Unknown(port_byte as i32)
        } else {
            femtopb::EnumValue::Unknown(0)
        }
    }

    pub fn payload_data(&self) -> &[u8] {
        if self.payload_len > 1 {
            &self.payload[1..self.payload_len] // Skip the port_num byte
        } else {
            &[]
        }
    }

    /// Decode the payload into structured data
    pub fn decode(self) -> Result<Packet<Decoded>, ()> {
        if self.payload_len == 0 {
            return Err(());
        }

        // Try to decode the payload as a Data protobuf message
        let payload_data = self.payload_data();
        match meshtastic_protobufs::meshtastic::Data::decode(payload_data) {
            Ok(data) => {
                // Convert protobuf data to owned data
                let owned_data = OwnedData::from_protobuf(&data);
                
                // Encode the owned data back into the payload format
                let mut new_payload = [0u8; 240];
                new_payload[0] = match owned_data.portnum {
                    femtopb::EnumValue::Known(p) => p as u8,
                    femtopb::EnumValue::Unknown(u) => u as u8,
                };
                
                // For now, just copy the original payload data
                let data_len = owned_data.payload_len.min(239);
                new_payload[1..1 + data_len].copy_from_slice(&owned_data.payload[..data_len]);

                Ok(Packet {
                    header: self.header,
                    rssi: self.rssi,
                    snr: self.snr,
                    payload: new_payload,
                    payload_len: 1 + data_len,
                    _marker: core::marker::PhantomData,
                })
            }
            Err(_) => Err(()),
        }
    }
}

impl Packet<Decoded> {
    pub fn port_num(&self) -> femtopb::EnumValue<meshtastic_protobufs::meshtastic::PortNum> {
        if self.payload_len > 0 {
            let port_byte = self.payload[0];
            femtopb::EnumValue::Unknown(port_byte as i32)
        } else {
            femtopb::EnumValue::Unknown(0)
        }
    }

    pub fn data(&self) -> Result<OwnedData, ()> {
        if self.payload_len == 0 {
            return Err(());
        }

        let payload_data = if self.payload_len > 1 {
            &self.payload[1..self.payload_len]
        } else {
            &[]
        };

        // Try to decode as protobuf Data and convert to owned
        match meshtastic_protobufs::meshtastic::Data::decode(payload_data) {
            Ok(data) => Ok(OwnedData::from_protobuf(&data)),
            Err(_) => Err(()),
        }
    }
}

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
        Ok(len) => {
            if len == 0 {
                return Err(CryptoError::EmptyKey);
            }
            let copy_len = len.min(32);
            key_bytes[..copy_len].copy_from_slice(&decoded[..copy_len]);
            Ok(key_bytes)
        }
        Err(_) => Err(CryptoError::InvalidBase64),
    }
}

/// Compute a channel hash using the djb2 algorithm
pub fn channel_hash(channel_name: &str) -> u32 {
    let mut hash: u32 = 5381;

    for byte in channel_name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }    hash
}
