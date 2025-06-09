// Example showing the updated channel hash generation using MeshKey
use meshtastic_crypto::channel::generate_channel_hash;
use meshtastic_crypto::key::MeshKey;

fn main() {
    println!("Testing updated channel hash generation with MeshKey");
    
    // Test with 1-byte key (should expand to Meshtastic default key)
    let key1 = MeshKey::new(&[0x01]).unwrap();
    let hash1 = generate_channel_hash("LongFast", &key1).unwrap();
    println!("Channel 'LongFast' with key [0x01]: hash = 0x{:02X}", hash1);
    assert_eq!(hash1, 0x08);
    
    // Test with 16-byte key
    let key2 = MeshKey::new(&[0xFF, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E]).unwrap();
    let hash2 = generate_channel_hash("test", &key2).unwrap();
    println!("Channel 'test' with 16-byte key: hash = 0x{:02X}", hash2);
    
    // Test with empty key (uses default Meshtastic key)
    let key3 = MeshKey::new(&[]).unwrap();
    let hash3 = generate_channel_hash("LongFast", &key3).unwrap();
    println!("Channel 'LongFast' with empty key: hash = 0x{:02X}", hash3);
    
    // Test different channels with same key
    let key4 = MeshKey::new(&[0x01]).unwrap();
    let hash4a = generate_channel_hash("LongSlow", &key4).unwrap();
    let hash4b = generate_channel_hash("VeryLongSlow", &key4).unwrap();
    println!("Channel 'LongSlow' with key [0x01]: hash = 0x{:02X}", hash4a);
    println!("Channel 'VeryLongSlow' with key [0x01]: hash = 0x{:02X}", hash4b);
    
    // Test different 1-byte keys
    let key5a = MeshKey::new(&[0x01]).unwrap();
    let key5b = MeshKey::new(&[0x02]).unwrap();
    let hash5a = generate_channel_hash("LongFast", &key5a).unwrap();
    let hash5b = generate_channel_hash("LongFast", &key5b).unwrap();
    println!("Channel 'LongFast' with key [0x01]: hash = 0x{:02X}", hash5a);
    println!("Channel 'LongFast' with key [0x02]: hash = 0x{:02X}", hash5b);
    assert_ne!(hash5a, hash5b); // Different keys should produce different hashes
    
    println!("All tests passed! Channel hash generation with MeshKey works correctly.");
}
