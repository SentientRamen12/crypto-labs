use rand::Rng;
use std::io::{self, Write};

mod aes_ctr;
mod aes_operations;
use aes_ctr::AesCtr;

fn get_message() -> Vec<u8> {
    print!("Enter a message to encrypt: ");
    io::stdout().flush().unwrap();
    let mut message = String::new();
    io::stdin().read_line(&mut message).unwrap();
    message.trim().as_bytes().to_vec()
}

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

fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; 12];
    rng.fill(&mut nonce[..]);
    nonce
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("AES-256 CTR Mode Encryption/Decryption");
    println!("--------------------------------------");

    // Get the message
    let message = get_message();
    
    // Get the key
    let key = match get_key() {
        Some(k) => k,
        None => return Ok(()),
    };

    // Generate a random nonce
    let nonce = generate_nonce();

    // Create AES-CTR instance
    let cipher = AesCtr::new(&key, &nonce).expect("Failed to initialize AES-CTR");

    // Encrypt the message
    let encrypted = cipher.encrypt(&message);
    println!("\nEncrypted (hex): {}", hex::encode(&encrypted));
    println!("Nonce (hex): {}", hex::encode(&nonce));

    // Decrypt the message
    let decrypted = cipher.decrypt(&encrypted);
    println!("\nDecrypted: {}", String::from_utf8_lossy(&decrypted));

    // Verify the decryption
    if message == decrypted {
        println!("\nVerification: Success - Message was correctly encrypted and decrypted!");
    } else {
        println!("\nVerification: Failed - Decrypted message doesn't match original!");
    }

    Ok(())
}