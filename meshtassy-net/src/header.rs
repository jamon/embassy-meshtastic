#[cfg(feature = "defmt")]
use defmt;

/// Represents a parsed packet header (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// Destination node ID (bytes 0-3)
    pub destination: u32,
    /// Source node ID (bytes 4-7)
    pub source: u32,
    /// Packet ID (bytes 8-11)
    pub packet_id: u32,
    /// Header flags (parsed from byte 12)
    pub flags: HeaderFlags,
    /// Channel hash (byte 13)
    pub channel_hash: u8,
    /// Next hop node ID (byte 14)
    pub next_hop: u8,
    /// Packet relay node ID (byte 15)
    pub relay_node: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeaderFlags {
    pub hop_limit: u8,  // 0..2
    pub want_ack: bool, // 3
    pub via_mqtt: bool, // 4
    pub hop_start: u8,  // 5..7
}

impl core::fmt::Display for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:08X} -> {:08X} [{}] {:08X} #{:02X} {:02X} {:02X}",
            self.source,
            self.destination,
            self.flags,
            self.packet_id,
            self.channel_hash,
            self.next_hop,
            self.relay_node
        )
    }
}
impl core::fmt::Display for HeaderFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}/{} {}{}",
            self.hop_limit,
            self.hop_start,
            if self.want_ack { "ACK " } else { "" },
            if self.via_mqtt { "MQTT " } else { "" }
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for HeaderFlags {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "{}/{} {}{}",
            self.hop_limit,
            self.hop_start,
            if self.want_ack { "ACK " } else { "" },
            if self.via_mqtt { "MQTT " } else { "" }
        );
    }
}
#[cfg(feature = "defmt")]
impl defmt::Format for Header {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "{:08X} -> {:08X} [{}] {:08X} #{:02X} {:02X} {:02X}",
            self.source,
            self.destination,
            self.flags,
            self.packet_id,
            self.channel_hash,
            self.next_hop,
            self.relay_node
        );
    }
}

impl Header {    /// Parse a 16-byte header from a byte slice
    /// Returns None if the slice is not exactly 16 bytes
    pub fn from_bytes(header_bytes: &[u8]) -> Option<Self> {
        #[cfg(feature = "defmt")]
        defmt::info!("Parsing header from {} bytes", header_bytes.len());
        
        if header_bytes.len() != 16 {
            #[cfg(feature = "defmt")]
            defmt::error!("Invalid header length: {} (expected 16)", header_bytes.len());
            return None;
        }

        let destination = u32::from_le_bytes(header_bytes[0..4].try_into().ok()?);
        let source = u32::from_le_bytes(header_bytes[4..8].try_into().ok()?);
        let packet_id = u32::from_le_bytes(header_bytes[8..12].try_into().ok()?);
        let flags = HeaderFlags::from_raw(header_bytes[12]);
        let channel_hash = header_bytes[13];
        let next_hop = header_bytes[14];
        let relay_node = header_bytes[15];

        #[cfg(feature = "defmt")]
        {
            defmt::info!("Parsed header fields:");
            defmt::info!("  destination: 0x{:08X}", destination);
            defmt::info!("  source: 0x{:08X}", source);
            defmt::info!("  packet_id: 0x{:08X}", packet_id);
            defmt::info!("  flags: hop_limit={}, hop_start={}, want_ack={}, via_mqtt={}", 
                        flags.hop_limit, flags.hop_start, flags.want_ack, flags.via_mqtt);
            defmt::info!("  channel_hash: 0x{:02X}", channel_hash);
            defmt::info!("  next_hop: 0x{:02X}", next_hop);
            defmt::info!("  relay_node: 0x{:02X}", relay_node);
        }

        Some(Header {
            destination,
            source,
            packet_id,
            flags,
            channel_hash,
            next_hop,
            relay_node,
        })
    }

    /// Convert the header back to a 16-byte array
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.destination.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.source.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.packet_id.to_le_bytes());
        bytes[12] = self.flags.to_raw();
        bytes[13] = self.channel_hash;
        bytes[14] = self.next_hop;
        bytes[15] = self.relay_node;
        bytes
    }    /// Create an IV/nonce for packet encryption following the protocol specification
    ///
    /// IV format (16 bytes):
    /// - Bytes 0-7: packet_id (64-bit, native byte order)
    /// - Bytes 8-11: from_node (32-bit, native byte order)
    /// - Bytes 12-15: Must be zero (reserved/extraNonce, unused in current protocol)
    ///
    pub fn create_iv(&self) -> [u8; 16] {
        #[cfg(feature = "defmt")]
        defmt::trace!("Creating IV from header: packet_id=0x{:08X}, source=0x{:08X}", 
                    self.packet_id, self.source);
        
        let mut iv = [0u8; 16];
        let packet_id = self.packet_id as u64; // high 32 bits implicitly zero
        iv[..8].copy_from_slice(&packet_id.to_ne_bytes());
        iv[8..12].copy_from_slice(&self.source.to_ne_bytes());
        // iv[12..16] remains zero per Meshtastic protocol
        
        #[cfg(feature = "defmt")]
        defmt::trace!("Generated IV: {:02X}", iv);
        
        iv
    }

    /// Create an IV/nonce for packet encryption with explicit packet_id and from_node
    ///
    /// This is a convenience method that allows creating an IV without a complete header.
    /// For typical use cases, prefer `create_iv()` which uses the header's own packet_id and source.
    ///
    /// IV format (16 bytes):
    /// - Bytes 0-7: packet_id (64-bit, native byte order)
    /// - Bytes 8-11: from_node (32-bit, native byte order)
    /// - Bytes 12-15: Must be zero (reserved/extraNonce, unused in current protocol)
    pub fn create_iv_with_params(packet_id: u64, from_node: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&packet_id.to_ne_bytes());
        iv[8..12].copy_from_slice(&from_node.to_ne_bytes());
        // iv[12..16] remains zero per Meshtastic protocol
        iv
    }

    /// Create a new Header with the given parameters
    /// The flags_raw field is automatically calculated from the flags parameter
    pub fn new(
        destination: u32,
        source: u32,
        packet_id: u32,
        flags: HeaderFlags,
        channel_hash: u8,
        next_hop: u8,
        relay_node: u8,
    ) -> Self {
        Header {
            destination,
            source,
            packet_id,
            flags,
            channel_hash,
            next_hop,
            relay_node,
        }
    }
}

impl HeaderFlags {
    /// Create MeshtasticHeaderFlags from a raw byte
    pub fn from_raw(flags_raw: u8) -> Self {
        let hop_limit = flags_raw & 0b00000111;
        let want_ack = (flags_raw & 0b00001000) != 0;
        let via_mqtt = (flags_raw & 0b00010000) != 0;
        let hop_start = (flags_raw >> 5) & 0b00000111;

        #[cfg(feature = "defmt")]
        defmt::trace!("Parsing flags from raw byte 0x{:02X}: hop_limit={}, want_ack={}, via_mqtt={}, hop_start={}", 
                    flags_raw, hop_limit, want_ack, via_mqtt, hop_start);

        HeaderFlags {
            hop_limit,
            want_ack,
            via_mqtt,
            hop_start,
        }
    }

    /// Convert MeshtasticHeaderFlags to a raw byte
    pub fn to_raw(&self) -> u8 {
        (self.hop_start << 5)
            | if self.via_mqtt { 0b00010000 } else { 0 }
            | if self.want_ack { 0b00001000 } else { 0 }
            | (self.hop_limit & 0b00000111)
    }
}
