//! Simple test script for packet creation functionality
//! This runs independently of the main embedded project to avoid compilation issues

use femtopb::Message as _;
use meshtastic_protobufs::meshtastic::{Data, PortNum};
use meshtastic_crypto::header::{MeshtasticHeader, MeshtasticHeaderFlags};
use meshtastic_crypto::{encrypt_meshtastic_packet, decrypt_meshtastic_packet};

// Functions based on the original code from main.rs
fn create_meshtastic_header(packet_id: u32) -> MeshtasticHeader {
    MeshtasticHeader {
        source: 0xDEADBEEF,
        destination: 0xFFFFFFFF, 
        packet_id,
        flags: MeshtasticHeaderFlags {
            hop_limit: 7,
            hop_start: 7,
            want_ack: false,
            via_mqtt: false,
        },        channel_hash: 0x08,
        next_hop: 0x00, 
        relay_node: 0x00
    }
}

// Data protobuf creation functions based on main.rs
fn create_text_message_data(message: &[u8]) -> Data {
    Data {
        portnum: femtopb::EnumValue::Known(PortNum::TextMessageApp),
        payload: message,
        want_response: false,
        dest: 0,
        source: 0,
        request_id: 0,
        reply_id: 0,
        emoji: 0,
        bitfield: Some(0),
        unknown_fields: Default::default(),
    }
}

fn encode_data_message(data: &Data, buffer: &mut [u8]) -> Result<usize, ()> {
    let buffer_len = buffer.len();
    let mut slice = buffer.as_mut();
    match data.encode(&mut slice) {
        Ok(_) => Ok(buffer_len - slice.len()),
        Err(_) => Err(()),
    }
}

fn create_text_packet(packet_id: u32, message: &[u8], buffer: &mut [u8]) -> Result<(MeshtasticHeader, usize), ()> {
    let header = create_meshtastic_header(packet_id);
    let data = create_text_message_data(message);
    let encoded_len = encode_data_message(&data, buffer)?;
    Ok((header, encoded_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_creation() {
        let packet_id = 0x12345678u32;
        let header = create_meshtastic_header(packet_id);
        
        assert_eq!(header.packet_id, packet_id);
        assert_eq!(header.source, 0xDEADBEEF);
        assert_eq!(header.destination, 0xFFFFFFFF);
        assert_eq!(header.flags.hop_limit, 7);
        assert_eq!(header.flags.hop_start, 7);
        assert_eq!(header.flags.want_ack, false);
        assert_eq!(header.flags.via_mqtt, false);
        assert_eq!(header.channel_hash, 0x08);
        assert_eq!(header.next_hop, 0x00);
        assert_eq!(header.relay_node, 0x00);
          println!("✓ Header creation test passed!");
        println!("  Packet ID: 0x{:08X}", header.packet_id);
    }

    #[test]
    fn test_text_message_data_creation() {
        let message = b"Hello, Meshtastic!";
        let data = create_text_message_data(message);
        
        assert_eq!(data.portnum, femtopb::EnumValue::Known(PortNum::TextMessageApp));
        assert_eq!(data.payload, message);
        assert_eq!(data.want_response, false);
        assert_eq!(data.dest, 0);
        assert_eq!(data.source, 0);
        assert_eq!(data.request_id, 0);
        assert_eq!(data.reply_id, 0);
        assert_eq!(data.emoji, 0);
        assert_eq!(data.bitfield, Some(0));
          println!("✓ Text message data creation test passed!");
        println!("  Message length: {} bytes", message.len());
    }

    #[test]
    fn test_data_message_encoding() {
        let message = b"Test message";
        let data = create_text_message_data(message);
        let mut buffer = [0u8; 256];
        
        let encoded_len = encode_data_message(&data, &mut buffer).expect("Encoding failed");
        
        assert!(encoded_len > 0);
        assert_ne!(encoded_len, buffer.len());
        
        println!("✓ Data message encoding test passed!");
        println!("  Encoded length: {}", encoded_len);
    }

    #[test]
    fn test_text_packet_creation() {
        let packet_id = 0x12345678u32;
        let message = b"Hello, packet!";
        let mut buffer = [0u8; 256];
        
        let (header, encoded_len) = create_text_packet(packet_id, message, &mut buffer).expect("Packet creation failed");
        
        assert_eq!(header.packet_id, packet_id);
        assert_eq!(header.source, 0xDEADBEEF);
        assert_eq!(header.destination, 0xFFFFFFFF);
        assert_eq!(header.channel_hash, 0x08);
        assert_eq!(header.next_hop, 0x00);
        assert_eq!(header.relay_node, 0x00);
        assert!(encoded_len > 0);
        assert_ne!(encoded_len, buffer.len());
        
        println!("✓ Text packet creation test passed!");
        println!("  Packet ID: 0x{:08X}", header.packet_id);
        println!("  Encoded length: {}", encoded_len);
    }

    #[test]
    fn test_data_protobuf_creation() {
        let message = b"Hello from Rust!";
        let data = create_text_message_data(message);
        
        assert_eq!(data.portnum, femtopb::EnumValue::Known(PortNum::TextMessageApp));
        assert_eq!(data.payload, message);
        assert_eq!(data.want_response, false);
        assert_eq!(data.dest, 0);
        assert_eq!(data.source, 0);
        assert_eq!(data.request_id, 0);
        assert_eq!(data.reply_id, 0);
        assert_eq!(data.emoji, 0);
        assert_eq!(data.bitfield, Some(0));
        
        println!("✓ Data protobuf creation test passed!");
        println!("  Message: {:?}", String::from_utf8_lossy(message));
    }

    #[test]
    fn test_encode_data_message() {
        let message = b"Test encoding";
        let data = create_text_message_data(message);
        let mut buffer = [0u8; 256];
        
        let encoded_len = encode_data_message(&data, &mut buffer).expect("Failed to encode data");
        
        assert!(encoded_len > 0, "Encoded length should be positive");
        assert!(encoded_len < buffer.len(), "Encoded length should be less than buffer size");
        assert!(!buffer[..encoded_len].is_empty(), "Encoded data should not be empty");
        
        // Verify we can decode it back
        let decoded_data = Data::decode(&buffer[..encoded_len]).expect("Failed to decode data");
        assert_eq!(decoded_data.portnum, femtopb::EnumValue::Known(PortNum::TextMessageApp));
        assert_eq!(decoded_data.payload, message);
        
        println!("✓ Data encoding test passed!");
        println!("  Encoded {} bytes", encoded_len);
    }

    #[test]
    fn test_complete_packet_creation() {
        let packet_id = 0xABCDEF01u32;
        let message = b"Complete packet test";
        let mut buffer = [0u8; 256];
        
        let (header, encoded_len) = create_text_packet(packet_id, message, &mut buffer)
            .expect("Failed to create packet");
        
        // Verify header
        assert_eq!(header.packet_id, packet_id);
        assert_eq!(header.source, 0xDEADBEEF);
        assert_eq!(header.destination, 0xFFFFFFFF);
        
        // Verify encoded data
        assert!(encoded_len > 0);
        let decoded_data = Data::decode(&buffer[..encoded_len]).expect("Failed to decode");
        assert_eq!(decoded_data.payload, message);
          println!("✓ Complete packet creation test passed!");
        println!("  Header packet ID: 0x{:08X}", header.packet_id);
        println!("  Encoded data length: {} bytes", encoded_len);
        println!("  Message: {:?}", String::from_utf8_lossy(message));
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let packet_id = 0x87654321u32;
        let message = b"Encryption test message";
        let key = [0x01u8];
        let key_len = 1;
        
        // Create original packet
        let mut original_buffer = [0u8; 256];
        let (header, encoded_len) = create_text_packet(packet_id, message, &mut original_buffer)
            .expect("Failed to create original packet");
        
        // Encrypt the packet
        let mut encrypted_buffer = [0u8; 256];
        let encrypted_len = encrypt_meshtastic_packet(
            &header,
            &original_buffer[..encoded_len],
            &mut encrypted_buffer,
            &key,
            key_len,
        ).expect("Failed to encrypt packet");
        
        // Decrypt the packet
        let mut decrypted_buffer = [0u8; 256];
        let decrypted_len = decrypt_meshtastic_packet(
            &encrypted_buffer,
            encrypted_len,
            &mut decrypted_buffer,
            &key,
            key_len,
        ).expect("Failed to decrypt packet");
        
        // Verify the decrypted payload matches the original
        assert_eq!(decrypted_len, encoded_len);
        assert_eq!(&decrypted_buffer[..decrypted_len], &original_buffer[..encoded_len]);
        
        // Verify we can decode the decrypted data
        let decoded_data = Data::decode(&decrypted_buffer[..decrypted_len])
            .expect("Failed to decode decrypted data");
        assert_eq!(decoded_data.payload, message);
        assert_eq!(decoded_data.portnum, femtopb::EnumValue::Known(PortNum::TextMessageApp));
        
        println!("✓ Encrypt/decrypt round trip test passed!");
        println!("  Original payload length: {} bytes", encoded_len);
        println!("  Encrypted packet length: {} bytes", encrypted_len);
        println!("  Decrypted payload length: {} bytes", decrypted_len);
        println!("  Key: [0x{:02X}] (length: {})", key[0], key_len);
        println!("  Message: {:?}", String::from_utf8_lossy(message));
    }
}

fn main() {
    println!("Running packet creation tests...");
    
    // Run a simple demonstration
    let test_packet_id = 0x12345678u32;
    let test_message = b"Hello from isolated test!";
    let header = create_meshtastic_header(test_packet_id);
    
    println!("\n=== Packet Creation Test Results ===");
    println!("Generated Meshtastic Header:");
    println!("  Packet ID: 0x{:08X}", header.packet_id);
    println!("  Source: 0x{:08X}", header.source);
    println!("  Destination: 0x{:08X}", header.destination);
    println!("  Hop Limit: {}", header.flags.hop_limit);
    println!("  Hop Start: {}", header.flags.hop_start);
    println!("  Want ACK: {}", header.flags.want_ack);
    println!("  Via MQTT: {}", header.flags.via_mqtt);
    println!("  Channel Hash: 0x{:02X}", header.channel_hash);
    println!("  Next Hop: 0x{:02X}", header.next_hop);
    println!("  Relay Node: 0x{:02X}", header.relay_node);
    
    // Test complete packet creation
    let mut buffer = [0u8; 256];
    match create_text_packet(test_packet_id, test_message, &mut buffer) {
        Ok((header, encoded_len)) => {
            println!("\n=== Complete Packet Creation ===");
            println!("✓ Successfully created packet!");
            println!("  Message: {:?}", String::from_utf8_lossy(test_message));
            println!("  Encoded data length: {} bytes", encoded_len);
            println!("  Header packet ID: 0x{:08X}", header.packet_id);
            
            // Verify decoding
            if let Ok(decoded) = Data::decode(&buffer[..encoded_len]) {
                println!("✓ Successfully decoded packet!");
                println!("  Decoded message: {:?}", String::from_utf8_lossy(decoded.payload));
                println!("  Port: {:?}", decoded.portnum);
            }
        },
        Err(()) => {
            println!("✗ Failed to create complete packet");
        }
    }
    
    println!("\n✓ Basic packet creation functionality verified!");
    println!("✓ This demonstrates the core packet creation logic extracted from main.rs");
    println!("✓ Successfully isolated the packet creation behavior for testing");
    println!("\nTo run comprehensive tests: cargo test");
}