// HMAC implementation in Rust
// HMAC will create a signature of a message.
// Verifier will verify the signature of the message.
use sha2::{Sha256, Digest};

pub struct Hmac {
    key: Vec<u8>,
    ipad: Vec<u8>,
    opad: Vec<u8>,
}   

impl Hmac {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key, ipad: vec![0; 64], opad: vec![0; 64] }
    }

    pub fn create_signature(&mut self, message: &[u8]) -> Vec<u8> {
        // Initialize ipad and opad with constants
        self.ipad = vec![0x36; 64];
        self.opad = vec![0x5c; 64];

        // If key is longer than block size, hash it
        let mut working_key = if self.key.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.finalize().to_vec()
        } else {
            self.key.clone()
        };

        // Pad key with zeros if necessary
        working_key.resize(64, 0);

        // XOR key with ipad and opad
        for i in 0..64 {
            self.ipad[i] ^= working_key[i];
            self.opad[i] ^= working_key[i];
        }

        // Inner hash
        let mut inner_data = self.ipad.clone();
        inner_data.extend_from_slice(message);
        let mut hasher = Sha256::new();
        hasher.update(&inner_data);
        let inner_hash = hasher.finalize();

        // Outer hash
        let mut outer_data = self.opad.clone();
        outer_data.extend_from_slice(&inner_hash);
        let mut hasher = Sha256::new();
        hasher.update(&outer_data);
        hasher.finalize().to_vec()
    }

    pub fn verify_signature(&mut self, message: &[u8], signature: &[u8]) -> bool {
        let computed_signature = self.create_signature(message);
        computed_signature.as_slice() == signature
    }
}   
