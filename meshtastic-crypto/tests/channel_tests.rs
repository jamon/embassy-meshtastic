// Test just the channel module
#[cfg(test)]
mod channel_tests {
    use meshtastic_crypto::channel::{generate_channel_hash, xor_hash};
    use meshtastic_crypto::key::MeshKey;

    #[test]
    fn test_generate_channel_hash_with_meshkey() {
        let key = MeshKey::new(&[0x01]).unwrap();
        let result = generate_channel_hash("LongFast", &key);
        assert_eq!(result, Some(0x08));
    }

    #[test]
    fn test_xor_hash_basic() {
        let result = xor_hash(&[0x01, 0x02, 0x03]);
        assert_eq!(result, 0x00);
    }
    
    #[test]
    fn test_empty_channel_name() {
        let key = MeshKey::new(&[0x01]).unwrap();
        let result = generate_channel_hash("", &key);
        assert_eq!(result, None);
    }
    
    #[test]
    fn test_different_key_types() {
        // 1-byte key
        let key1 = MeshKey::new(&[0x01]).unwrap();
        let hash1 = generate_channel_hash("test", &key1).unwrap();
        
        // Empty key (uses default)
        let key2 = MeshKey::new(&[]).unwrap();
        let hash2 = generate_channel_hash("test", &key2).unwrap();
        
        // 16-byte key
        let key3 = MeshKey::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]).unwrap();
        let hash3 = generate_channel_hash("test", &key3).unwrap();
        
        // They should all be different
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }
}
