// Simple verification that the key functionality works correctly
use meshtastic_crypto::key::MeshKey;
use meshtastic_crypto::channel::generate_channel_hash;

fn main() {
    println!("=== Verifying Channel Hash with MeshKey ===");
    
    // Test the key case from the original issue: "LongFast" with [0x01] should give 0x08
    let key = MeshKey::new(&[0x01]).unwrap();
    let hash = generate_channel_hash("LongFast", &key).unwrap();
    
    println!("Channel: 'LongFast'");
    println!("Key: [0x01] (1-byte, expands to Meshtastic default with LSB=0x01)");
    println!("Hash: 0x{:02X}", hash);
    
    if hash == 0x08 {
        println!("✅ SUCCESS: Hash matches expected value (0x08)");
    } else {
        println!("❌ FAILED: Hash was 0x{:02X}, expected 0x08", hash);
    }
    
    // Show that empty keys work (use default key)
    let empty_key = MeshKey::new(&[]).unwrap();
    let empty_hash = generate_channel_hash("LongFast", &empty_key).unwrap();
    println!("\nEmpty key hash: 0x{:02X}", empty_hash);
    
    // Show that 16-byte keys work
    let full_key = MeshKey::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]).unwrap();
    let full_hash = generate_channel_hash("LongFast", &full_key).unwrap();
    println!("16-byte key hash: 0x{:02X}", full_hash);
    
    println!("\n=== All tests completed ===");
}
