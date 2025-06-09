// Round trip tests for encrypt and decrypt functions
#[cfg(test)]
mod round_trip_tests {
    use meshtastic_crypto::{encrypt_meshtastic_packet, decrypt_meshtastic_packet};
    use meshtastic_crypto::header::{MeshtasticHeader, MeshtasticHeaderFlags};

    fn create_test_header() -> MeshtasticHeader {
        MeshtasticHeader {
            destination: 0x12345678,
            source: 0x87654321,
            packet_id: 0xABCDEF01,
            flags: MeshtasticHeaderFlags {
                hop_limit: 3,
                want_ack: true,
                via_mqtt: false,
                hop_start: 7,
            },
            channel_hash: 0x42,
            next_hop: 0x55,
            relay_node: 0xAA,
        }
    }

    #[test]
    fn test_round_trip_1_byte_key() {
        let header = create_test_header();
        let original_payload = b"Hello, Meshtastic!";
        let key = [0x42u8]; // 1-byte key
        let key_len = 1;
        
        let mut encrypted_packet = [0u8; 256];
        let mut decrypted_payload = [0u8; 256];
        
        // Encrypt
        let packet_len = encrypt_meshtastic_packet(
            &header,
            original_payload,
            &mut encrypted_packet,
            &key,
            key_len,
        ).expect("Encryption should succeed");
        
        assert_eq!(packet_len, 16 + original_payload.len());
        
        // Decrypt
        let decrypted_len = decrypt_meshtastic_packet(
            &encrypted_packet,
            packet_len,
            &mut decrypted_payload,
            &key,
            key_len,
        ).expect("Decryption should succeed");
        
        assert_eq!(decrypted_len, original_payload.len());
        assert_eq!(&decrypted_payload[..decrypted_len], original_payload);
    }

    #[test]
    fn test_round_trip_16_byte_key() {
        let header = create_test_header();
        let original_payload = b"This is a longer test message for 16-byte key!";
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let key_len = 16;
        
        let mut encrypted_packet = [0u8; 256];
        let mut decrypted_payload = [0u8; 256];
        
        // Encrypt
        let packet_len = encrypt_meshtastic_packet(
            &header,
            original_payload,
            &mut encrypted_packet,
            &key,
            key_len,
        ).expect("Encryption should succeed");
        
        assert_eq!(packet_len, 16 + original_payload.len());
        
        // Decrypt
        let decrypted_len = decrypt_meshtastic_packet(
            &encrypted_packet,
            packet_len,
            &mut decrypted_payload,
            &key,
            key_len,
        ).expect("Decryption should succeed");
        
        assert_eq!(decrypted_len, original_payload.len());
        assert_eq!(&decrypted_payload[..decrypted_len], original_payload);
    }

    #[test]
    fn test_round_trip_32_byte_key() {
        let header = create_test_header();
        let original_payload = b"Testing AES-256 with 32-byte key encryption and decryption round trip!";
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ];
        let key_len = 32;
        
        let mut encrypted_packet = [0u8; 256];
        let mut decrypted_payload = [0u8; 256];
        
        // Encrypt
        let packet_len = encrypt_meshtastic_packet(
            &header,
            original_payload,
            &mut encrypted_packet,
            &key,
            key_len,
        ).expect("Encryption should succeed");
        
        assert_eq!(packet_len, 16 + original_payload.len());
        
        // Decrypt
        let decrypted_len = decrypt_meshtastic_packet(
            &encrypted_packet,
            packet_len,
            &mut decrypted_payload,
            &key,
            key_len,
        ).expect("Decryption should succeed");
        
        assert_eq!(decrypted_len, original_payload.len());
        assert_eq!(&decrypted_payload[..decrypted_len], original_payload);
    }

    #[test]
    fn test_round_trip_empty_key() {
        let header = create_test_header();
        let original_payload = b"Testing with default key";
        let key = []; // Empty key should use default
        let key_len = 0;
        
        let mut encrypted_packet = [0u8; 256];
        let mut decrypted_payload = [0u8; 256];
        
        // Encrypt
        let packet_len = encrypt_meshtastic_packet(
            &header,
            original_payload,
            &mut encrypted_packet,
            &key,
            key_len,
        ).expect("Encryption should succeed");
        
        assert_eq!(packet_len, 16 + original_payload.len());
        
        // Decrypt
        let decrypted_len = decrypt_meshtastic_packet(
            &encrypted_packet,
            packet_len,
            &mut decrypted_payload,
            &key,
            key_len,
        ).expect("Decryption should succeed");
        
        assert_eq!(decrypted_len, original_payload.len());
        assert_eq!(&decrypted_payload[..decrypted_len], original_payload);
    }

    #[test]
    fn test_round_trip_different_headers() {
        // Test that different headers produce different encrypted outputs
        let key = [0x42u8];
        let key_len = 1;
        let payload = b"Same payload";
        
        let header1 = MeshtasticHeader {
            destination: 0x12345678,
            source: 0x87654321,
            packet_id: 0x11111111,
            flags: MeshtasticHeaderFlags {
                hop_limit: 3,
                want_ack: true,
                via_mqtt: false,
                hop_start: 7,
            },
            channel_hash: 0x42,
            next_hop: 0x55,
            relay_node: 0xAA,
        };
        
        let header2 = MeshtasticHeader {
            destination: 0x12345678,
            source: 0x87654321,
            packet_id: 0x22222222, // Different packet_id should change IV
            flags: MeshtasticHeaderFlags {
                hop_limit: 3,
                want_ack: true,
                via_mqtt: false,
                hop_start: 7,
            },
            channel_hash: 0x42,
            next_hop: 0x55,
            relay_node: 0xAA,
        };
        
        let mut encrypted1 = [0u8; 256];
        let mut encrypted2 = [0u8; 256];
        let mut decrypted1 = [0u8; 256];
        let mut decrypted2 = [0u8; 256];
        
        // Encrypt with both headers
        let len1 = encrypt_meshtastic_packet(&header1, payload, &mut encrypted1, &key, key_len)
            .expect("First encryption should succeed");
        let len2 = encrypt_meshtastic_packet(&header2, payload, &mut encrypted2, &key, key_len)
            .expect("Second encryption should succeed");
        
        assert_eq!(len1, len2);
        
        // The encrypted payload portions should be different (due to different IVs)
        assert_ne!(&encrypted1[16..len1], &encrypted2[16..len2]);
        
        // But both should decrypt to the same payload
        let dec_len1 = decrypt_meshtastic_packet(&encrypted1, len1, &mut decrypted1, &key, key_len)
            .expect("First decryption should succeed");
        let dec_len2 = decrypt_meshtastic_packet(&encrypted2, len2, &mut decrypted2, &key, key_len)
            .expect("Second decryption should succeed");
        
        assert_eq!(dec_len1, dec_len2);
        assert_eq!(&decrypted1[..dec_len1], payload);
        assert_eq!(&decrypted2[..dec_len2], payload);
    }

    #[test]
    fn test_encryption_changes_payload() {
        // Verify that encryption actually changes the payload
        let header = create_test_header();
        let original_payload = b"This should be encrypted";
        let key = [0x42u8];
        let key_len = 1;
        
        let mut encrypted_packet = [0u8; 256];
        
        let packet_len = encrypt_meshtastic_packet(
            &header,
            original_payload,
            &mut encrypted_packet,
            &key,
            key_len,
        ).expect("Encryption should succeed");
        
        // The encrypted payload (after the 16-byte header) should be different from original
        assert_ne!(&encrypted_packet[16..packet_len], original_payload);
    }

    #[test]
    fn test_error_cases() {
        let header = create_test_header();
        let payload = b"test";
        let key = [0x42u8];
        let key_len = 1;
        
        // Test empty payload
        let mut buffer = [0u8; 256];
        assert!(encrypt_meshtastic_packet(&header, &[], &mut buffer, &key, key_len).is_none());
        
        // Test buffer too small
        let mut small_buffer = [0u8; 10];
        assert!(encrypt_meshtastic_packet(&header, payload, &mut small_buffer, &key, key_len).is_none());
        
        // Test key length mismatch
        assert!(encrypt_meshtastic_packet(&header, payload, &mut buffer, &key, 2).is_none());
    }
}
