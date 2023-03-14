use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(input)?)
}

pub fn bytes_to_str(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}
