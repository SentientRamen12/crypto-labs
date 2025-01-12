# AES-256 in CTR mode and HMAC-SHA256

## Description
This project implements AES-256 encryption in Counter (CTR) mode with HMAC-SHA256 for message authentication. It provides a secure way to encrypt data while ensuring its integrity.

## Setup
```bash
cargo new <project-name> 
```

### Dependencies Configuration
```toml
# Cargo.toml
[package]
name = "aes"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
ctr = "0.9"
rand = "0.8"
hex = "0.4"
sha2 = "0.10"
```

### Main Entry Point
```rust
# main.rs
mod aes_ctr_mode;
pub mod hmac;
mod demo;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    demo::test_aes_ctr_mode()
}
```

## Features
- AES-256 encryption in CTR mode
- Secure random key and nonce generation
- HMAC-SHA256 for message authentication
- Hex encoding support for encrypted data

## Run
```bash
cargo run
```

## Testing
```bash
cargo test
```

## Security Notes
- The implementation uses secure random number generation for keys and nonces
- CTR mode provides parallel encryption/decryption capabilities
- HMAC-SHA256 ensures message integrity and authenticity


