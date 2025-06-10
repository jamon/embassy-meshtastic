#![cfg_attr(not(feature = "std"), no_std)]

use base64::engine::general_purpose;
use base64::Engine;
use core::prelude::v1::*;
use femtopb::Message as _;
use key::{MeshKey, MeshKeyTrait};

#[cfg(feature = "defmt")]
use defmt::Format;

// Re-export commonly used types
pub use meshtastic_protobufs::meshtastic::PortNum;
pub use meshtastic_protobufs::meshtastic::{
    NeighborInfo, Position, RouteDiscovery, Routing, Telemetry, User,
};

// Channel hash generation utilities
pub mod channel;

// packet header types
pub mod header;
pub use header::Header;

// key management
pub mod key;

// Node database for storing device information
pub mod node_database;

/// Marker types to distinguish between encrypted and decrypted packet states
#[derive(Clone)]
pub struct Encrypted;

#[derive(Clone)]
pub struct Decrypted;

#[derive(Clone)]
pub struct Decoded;

/// A generic packet that can be either encrypted or decrypted
#[derive(Clone)]
#[cfg_attr(feature = "defmt", derive(Format))]
pub struct Packet<T> {
    pub header: Header,
    pub rssi: i16,
    pub snr: i16,
    pub payload: [u8; 240],
    pub payload_len: usize,
    _marker: core::marker::PhantomData<T>,
}

impl<T> Packet<T> {
    /// Create a new packet with the given data
    pub fn new(
        header: Header,
        rssi: i16,
        snr: i16,
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
    pub fn from_bytes(packet_buffer: &[u8], rssi: i16, snr: i16) -> Option<Self> {
        // Validate minimum packet size (16-byte header)
        if packet_buffer.len() < 16 {
            return None;
        }

        // Parse the header from the first 16 bytes
        let header = Header::from_bytes(&packet_buffer[..16])?;

        // Calculate payload length
        let payload_len = packet_buffer.len() - 16;
        if payload_len > 240 {
            return None;
        }

        // Copy the encrypted payload
        let mut payload = [0u8; 240];
        payload[..payload_len].copy_from_slice(&packet_buffer[16..]);

        Some(Self::new(header, rssi, snr, payload, payload_len))
    }

    /// Decrypts the packet payload using the provided key
    /// Returns a DecryptedPacket on success, or None if decryption fails
    /// Consumes the original encrypted packet
    pub fn decrypt(self, key: &[u8], key_len: usize) -> Option<Packet<Decrypted>> {
        // Validate key buffer has enough bytes for specified length
        if key.len() < key_len {
            return None;
        }

        // Create a buffer for the decrypted payload
        let mut decrypted_payload = [0u8; 240];

        // Copy the encrypted payload to the decryption buffer
        decrypted_payload[..self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);

        // Build the 16-byte IV/nonce according to Meshtastic protocol:
        // Bytes 0-7: packet_id (native byte order u64)
        // Bytes 8-11: from_node (native byte order u32)
        // Bytes 12-15: extraNonce (always zero in current protocol)
        let iv = self.header.create_iv();

        // Handle different key sizes using the new MeshtasticKey system
        match MeshKey::new(&key[..key_len]) {
            Ok(k) => {
                // Use the new key's AES-CTR transform method
                match k.transform(&mut decrypted_payload[..self.payload_len], iv) {
                    Ok(_) => {
                        // Create and return the decrypted packet
                        Some(Packet::<Decrypted>::new(
                            self.header,
                            self.rssi,
                            self.snr,
                            decrypted_payload,
                            self.payload_len,
                        ))
                    }
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }
}

impl Packet<Decrypted> {
    pub fn decode(self) -> Option<Packet<Decoded>> {
        match meshtastic_protobufs::meshtastic::Data::decode(
            &self.payload[16..self.payload_len - 16],
        ) {
            Ok(mp) => {
                #[cfg(feature = "defmt")]
                defmt::trace!("Decoded packet {:?} ", mp);
                Some(Packet::<Decoded>::new(
                    self.header,
                    self.rssi,
                    self.snr,
                    self.payload,
                    self.payload_len,
                ))
            }
            Err(err) => {
                #[cfg(feature = "defmt")]
                defmt::info!("Failed to decode protobuf: {:?}", err);
                None
            }
        }
    }
    /// Encrypts the decrypted packet back to an encrypted packet
    /// Returns an encrypted Packet on success, or None if encryption fails
    pub fn encrypt(&self, key: &[u8], key_len: usize) -> Option<Packet<Encrypted>> {
        let mut encrypted_buffer = [0u8; 256];

        match encrypt_packet(
            &self.header,
            &self.payload[..self.payload_len],
            &mut encrypted_buffer,
            key,
            key_len,
        ) {
            Some(packet_len) => {
                let encrypted_payload_len = packet_len - 16;
                let mut encrypted_packet = Packet::<Encrypted>::new(
                    self.header.clone(),
                    self.rssi,
                    self.snr,
                    [0u8; 240],
                    encrypted_payload_len,
                );
                encrypted_packet.payload[..encrypted_payload_len]
                    .copy_from_slice(&encrypted_buffer[16..packet_len]);
                Some(encrypted_packet)
            }
            None => None,
        }
    }
}

impl Packet<Decoded> {
    /// Create a decoded packet from a decoded Meshtastic protobuf message
    pub fn from_decoded(
        header: Header,
        rssi: i16,
        snr: i16,
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
/// Represents a decoded Meshtastic packet with its specific payload type
#[derive(Clone)]
#[cfg_attr(feature = "defmt", derive(Format))]
pub enum DecodedPacket<'a> {
    Telemetry(Telemetry<'a>),
    NodeInfo(User<'a>),
    Position(Position<'a>),
    NeighborInfo(NeighborInfo<'a>),
    TextMessage(&'a str),
    Routing(Routing<'a>),
    RouteDiscovery(RouteDiscovery<'a>),
    Unknown(femtopb::EnumValue<PortNum>),
    Other(femtopb::EnumValue<PortNum>),
    TelemetryDecodeError,
    NodeInfoDecodeError,
    PositionDecodeError,
    NeighborInfoDecodeError,
    TextMessageDecodeError,
    RoutingDecodeError,
    RouteDiscoveryDecodeError,
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
pub fn decrypt_packet(
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
    let header = Header::from_bytes(header_bytes)?;

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
        }
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
pub fn encrypt_packet(
    header: &Header,
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
        }
        Err(_) => return None,
    }
}
