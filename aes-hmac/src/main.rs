mod aes_ctr_mode;
pub mod hmac;
mod demo;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    demo::test_aes_ctr_mode()
}