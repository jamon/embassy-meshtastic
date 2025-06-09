//! Channel hash generation utilities for Meshtastic
//!
//! This module provides functions to generate channel hashes using the same
//! algorithm as the Meshtastic firmware, which combines the channel name
//! and the channel PSK (pre-shared key) using XOR operations.

use crate::key::MeshKey;

/// Compute XOR hash of a byte slice
///
/// This function XORs all bytes in the input slice together to produce
/// a single byte hash value.
///
/// # Arguments
/// * `data` - The byte slice to hash
///
/// # Returns
/// A single byte representing the XOR of all input bytes
pub fn xor_hash(data: &[u8]) -> u8 {
    let mut code = 0u8;
    for &byte in data {
        code ^= byte;
    }
    code
}

/// Generate a Meshtastic channel hash
///
/// The hash is computed by XORing the hash of the channel name with the hash
/// of the channel PSK. The MeshKey handles proper expansion of 1-byte keys
/// using the Meshtastic default key with the LSB replaced.
///
/// # Arguments
/// * `channel_name` - The name of the channel (as a string slice)
/// * `channel_key` - The MeshKey containing the channel PSK
///
/// # Returns
/// A channel hash value (0-255), or None if the inputs are invalid
///
/// # Examples
/// ```
/// use meshtastic_crypto::channel::generate_channel_hash;
/// use meshtastic_crypto::key::MeshKey;
///
/// let key = MeshKey::new(&[0x01]).unwrap();
/// let hash = generate_channel_hash("LongFast", &key).unwrap();
/// assert_eq!(hash, 0x08); // Correct hash value: 0x08 = 8
/// ```
pub fn generate_channel_hash(channel_name: &str, channel_key: &MeshKey) -> Option<u8> {
    // Convert channel name to bytes
    let name_bytes = channel_name.as_bytes();

    // If channel name is empty, we can't generate a valid hash
    if name_bytes.is_empty() {
        return None;
    }

    // Compute XOR hash of channel name
    let name_hash = xor_hash(name_bytes);

    // Compute XOR hash of channel key using the expanded key bytes
    let key_hash = xor_hash(channel_key.as_bytes());

    // Return combined hash
    Some(name_hash ^ key_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MeshKey;

    #[test]
    fn test_xor_hash_empty() {
        let result = xor_hash(&[]);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_xor_hash_single_byte() {
        let result = xor_hash(&[0x42]);
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_xor_hash_multiple_bytes() {
        let result = xor_hash(&[0x01, 0x02, 0x03]);
        assert_eq!(result, 0x01 ^ 0x02 ^ 0x03); // Should be 0x00
        assert_eq!(result, 0x00);
    }

    #[test]
    fn test_xor_hash_known_string() {
        let hello_bytes = b"hello";
        let result = xor_hash(hello_bytes);
        // 'h' ^ 'e' ^ 'l' ^ 'l' ^ 'o' = 0x68 ^ 0x65 ^ 0x6C ^ 0x6C ^ 0x6F
        let expected = 0x68u8 ^ 0x65u8 ^ 0x6Cu8 ^ 0x6Cu8 ^ 0x6Fu8;
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_generate_channel_hash_valid() {
        let channel_name = "LongFast";
        let channel_key = MeshKey::new(&[0x01]).unwrap();

        let result = generate_channel_hash(channel_name, &channel_key);
        assert!(result.is_some());

        // For 1-byte keys, we expect the result to use expanded Meshtastic default key
        assert_eq!(result.unwrap(), 0x08);
    }

    #[test]
    fn test_meshkey_creation_with_invalid_length() {
        // Test that MeshKey::new properly returns an error for invalid key lengths
        let invalid_key = [0xAA; 5]; // 5 bytes is not a valid length (should be 0, 1, or 16)
        let result = MeshKey::new(&invalid_key);
        assert!(result.is_err(), "MeshKey creation should fail for 5-byte key");
    }
    #[test]
    fn test_generate_channel_hash_empty_name() {
        let key = MeshKey::new(&[0x01]).unwrap();
        let result = generate_channel_hash("", &key);
        assert_eq!(result, None);
    }

    #[test]
    fn test_generate_channel_hash_empty_key() {
        let key = MeshKey::new(&[]).unwrap();
        let result = generate_channel_hash("LongFast", &key);
        assert!(result.is_some()); // Empty key creates a valid MeshKey with default key
    }

    #[test]
    fn test_generate_channel_hash_standard_meshtastic_key() {
        let channel_name = "LongFast";
        let channel_key = MeshKey::new(&[0x01]).unwrap(); // Standard Meshtastic default key

        let result = generate_channel_hash(channel_name, &channel_key);
        assert!(result.is_some());

        // This should produce a specific hash value
        let hash = result.unwrap();
        
        // For 1-byte keys, the expanded key should be used
        assert_eq!(hash, 0x08);
    }

    #[test]
    fn test_generate_channel_hash_different_channels() {
        let key = MeshKey::new(&[0x01]).unwrap();

        let hash1 = generate_channel_hash("LongFast", &key).unwrap();
        let hash2 = generate_channel_hash("LongSlow", &key).unwrap();
        let hash3 = generate_channel_hash("VeryLongSlow", &key).unwrap();

        // Different channel names should produce different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_generate_channel_hash_different_keys() {
        let channel_name = "LongFast";

        let key1 = MeshKey::new(&[0x01]).unwrap();
        let key2 = MeshKey::new(&[0x02]).unwrap();
        let key3 = MeshKey::new(&[0x03]).unwrap();

        let hash1 = generate_channel_hash(channel_name, &key1).unwrap();
        let hash2 = generate_channel_hash(channel_name, &key2).unwrap();
        let hash3 = generate_channel_hash(channel_name, &key3).unwrap();

        // Different keys should produce different hashes
        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_generate_channel_hash_consistency() {
        let channel_name = "TestChannel";
        let channel_key = MeshKey::new(&[0xAA]).unwrap();

        // Same inputs should always produce same output
        let hash1 = generate_channel_hash(channel_name, &channel_key).unwrap();
        let hash2 = generate_channel_hash(channel_name, &channel_key).unwrap();

        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_channel_hash_matches_manual_calculation() {
        // Test with a known channel name and 16-byte key for manual calculation
        let channel_name = "test";
        let key_bytes = [0xFF, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
        let channel_key = MeshKey::new(&key_bytes).unwrap();

        // Manual calculation (works correctly for 16-byte keys)
        let _name_bytes = channel_name.as_bytes(); // [0x74, 0x65, 0x73, 0x74]
        let manual_name_hash = 0x74u8 ^ 0x65u8 ^ 0x73u8 ^ 0x74u8; // = 0x16
        let manual_key_hash = key_bytes.iter().fold(0u8, |acc, &b| acc ^ b); // XOR all bytes
        let manual_result = manual_name_hash ^ manual_key_hash;

        let result = generate_channel_hash(channel_name, &channel_key).unwrap();
        assert_eq!(result, manual_result);
    }

    #[test]
    fn test_longfast_channel_with_01_key() {
        // This test verifies the specific case mentioned in the original issue:
        // Channel "LongFast" with key [0x01] should produce hash 0x08, not 0x0B
        let key = MeshKey::new(&[0x01]).unwrap();
        let result = generate_channel_hash("LongFast", &key);
        assert_eq!(result, Some(0x08));
    }
}
