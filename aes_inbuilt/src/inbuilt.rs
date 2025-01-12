use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr64BE;

type Aes256Ctr = Ctr64BE<Aes256>;

pub fn aes_ctr_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
    let mut buffer = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn aes_ctr_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
    let mut buffer = ciphertext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}