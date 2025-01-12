// Implementing AES-CTR from scratch
use crate::aes_operations::{State, AesOperations};

#[derive(Debug, Clone)]
pub struct AesCtr {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

impl AesCtr {
    /// Creates a new AES-CTR instance
    /// key: 32 bytes for AES-256
    /// nonce: Should be unique for each encryption, typically 12 bytes
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, &'static str> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes for AES-256");
        }
        if nonce.len() != 12 {
            return Err("Nonce must be 12 bytes");
        }

        Ok(Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
        })
    }

    /// Generates the counter block for a given block index
    fn generate_counter_block(&self, counter: u32) -> [u8; 16] {
        let mut block = [0u8; 16];
        
        // Copy nonce (first 12 bytes)
        block[..12].copy_from_slice(&self.nonce);
        
        // Add counter in big-endian format (last 4 bytes)
        block[12..].copy_from_slice(&counter.to_be_bytes());
        
        block
    }

    /// Encrypts a counter block with AES-256
    fn encrypt_counter_block(&self, counter_block: &[u8]) -> State {
        let mut state = State::new(counter_block);
        
        // TODO: Add proper key expansion for the full AES-256 key schedule
        // For now, we'll just use the first 16 bytes of the key for demonstration
        AesOperations::add_round_key(&mut state, &self.key[..16]);
        
        for _ in 1..14 {  // AES-256 has 14 rounds
            AesOperations::sub_bytes(&mut state);
            AesOperations::shift_rows(&mut state);
            AesOperations::mix_columns(&mut state);
            AesOperations::add_round_key(&mut state, &self.key[16..32]); // This should use proper round keys
        }
        
        // Final round (no mix columns)
        AesOperations::sub_bytes(&mut state);
        AesOperations::shift_rows(&mut state);
        AesOperations::add_round_key(&mut state, &self.key[..16]); // This should use the final round key
        
        state
    }

    /// Encrypts a message using AES-256 in CTR mode
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        
        // Process each block
        for (block_index, chunk) in plaintext.chunks(16).enumerate() {
            // Generate and encrypt counter block
            let counter_block = self.generate_counter_block(block_index as u32);
            let encrypted_counter = self.encrypt_counter_block(&counter_block);
            
            // XOR with plaintext
            for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ encrypted_counter.as_bytes()[i]);
            }
        }
        
        ciphertext
    }

    /// Decrypts a message using AES-256 in CTR mode
    /// In CTR mode, encryption and decryption are the same operation
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        // CTR mode is symmetric - encryption and decryption are the same operation
        self.encrypt(ciphertext)
    }
}