/* 
SOURCES
https://www.youtube.com/watch?v=-fpVv_T4xwA&t
*/
mod inbuilt;

fn get_message() -> Vec<u8> {
    use std::io::{self, Write};
    print!("Enter a message to encrypt: ");
    io::stdout().flush().unwrap();
    let mut message = String::new();
    io::stdin().read_line(&mut message).unwrap();
    message.trim().as_bytes().to_vec()
}

fn get_key() -> Option<Vec<u8>> {
    use std::io::{self, Write};
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

fn main() {
    let message = get_message();
    
    let key = match get_key() {
        Some(k) => k,
        None => return,
    };

    // Generate a random nonce
    let nonce = rand::random::<[u8; 16]>();

    // Encrypt the message
    let encrypted = inbuilt::aes_ctr_encrypt(&key, &nonce, &message);
    println!("Encrypted (hex): {}", hex::encode(&encrypted));

    // Decrypt the message
    let decrypted = inbuilt::aes_ctr_decrypt(&key, &nonce, &encrypted);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}