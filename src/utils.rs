use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(input)?)
}

pub fn bytes_to_hex(input: &[u8]) -> String {
    hex::encode(input)
}

pub fn bytes_to_str(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    std::iter::zip(a, b)
        .map(|(&x, &y)| x ^ y)
        .collect::<Vec<u8>>()
}
