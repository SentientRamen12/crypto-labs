use std::io::{self, Write};
use rand::Rng;
use crate::aes_ctr_mode::AesCtr;
use hex;
use crate::hmac::Hmac;


// Get message from user
fn get_message() -> Vec<u8> {
    print!("Enter a message to encrypt: ");
    io::stdout().flush().unwrap();
    let mut message = String::new();
    io::stdin().read_line(&mut message).unwrap();
    message.trim().as_bytes().to_vec()
}

// Get key from user
fn get_key() -> Option<Vec<u8>> {
    print!("Enter a 32-character key: ");
    io::stdout().flush().unwrap();
    let mut key = String::new();
    io::stdin().read_line(&mut key).unwrap();
    let key = key.trim().as_bytes().to_vec();

    if key.len() != 32 {
        println!("Error: Key must be exactly 32 characters!");
        None
    } else {
        Some(key)
    }
}

// Add new function to get MAC key
fn get_mac_key() -> Option<Vec<u8>> {
    print!("Enter a 32-character MAC key: ");
    io::stdout().flush().unwrap();
    let mut mac_key = String::new();
    io::stdin().read_line(&mut mac_key).unwrap();
    let mac_key = mac_key.trim().as_bytes().to_vec();

    if mac_key.len() != 32 {
        println!("Error: MAC key must be exactly 32 characters!");
        None
    } else {
        Some(mac_key)
    }
}

// Generate a random nonce
fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; 12];
    rng.fill(&mut nonce[..]);
    nonce
}

// Test the AES-CTR mode
pub fn test_aes_ctr_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("AES-256 CTR Mode Encryption/Decryption with HMAC-SHA256");
    println!("------------------------------------------------------");

    // Get the message
    let message = get_message();
    
    // Get the encryption key
    let key = match get_key() {
        Some(k) => k,
        None => return Ok(()),
    };

    // Get the MAC key
    let mac_key = match get_mac_key() {
        Some(k) => k,
        None => return Ok(()),
    };

    // Generate a random nonce
    let nonce = generate_nonce();

    // Create AES-CTR instance
    let cipher = AesCtr::new(&key, &nonce).expect("Failed to initialize AES-CTR");

    // Encrypt the message
    let encrypted = cipher.encrypt(&message);
    
    // Generate HMAC
    let mut hmac = Hmac::new(mac_key.clone());
    let mut auth_data = encrypted.clone();
    auth_data.extend_from_slice(&nonce);
    let signature = hmac.create_signature(&auth_data);

    println!("\nEncrypted (hex): {}", hex::encode(&encrypted));
    println!("Nonce (hex): {}", hex::encode(&nonce));
    println!("HMAC (hex): {}", hex::encode(&signature));

    // Verify HMAC before decryption
    let mut verify_hmac = Hmac::new(mac_key.clone());
    let is_valid = verify_hmac.verify_signature(&auth_data, &signature);
    
    if is_valid {
        // Decrypt the message
        let decrypted = cipher.decrypt(&encrypted);
        println!("\nDecrypted: {}", String::from_utf8_lossy(&decrypted));

        // Verify the decryption
        if message == decrypted {
            println!("\nVerification: Success - Message was correctly encrypted and decrypted!");
        } else {
            println!("\nVerification: Failed - Decrypted message doesn't match original!");
        }
    } else {
        println!("\nAuthentication failed: Message or nonce may have been tampered with!");
    }

    Ok(())
}