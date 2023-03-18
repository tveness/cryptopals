/// Detect AES in ECB mode
/// In this file are a bunch of hex-encoded ciphertexts.
///
/// One of them has been encrypted with ECB.
///
/// Detect it.
///
/// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte
/// plaintext block will always produce the same 16 byte ciphertext.
use crate::utils::*;
use anyhow::Result;
use std::collections::HashMap;

pub fn main() -> Result<()> {
    let ciphertexts = read_base64_lines("./data/8.txt")?;
    let chunk_size = 16;

    for (line_num, t) in ciphertexts.iter().enumerate() {
        match is_unique(t, chunk_size) {
            true => {}
            false => println!("Line: {line_num}"),
        }
    }

    Ok(())
}

fn is_unique(text: &[u8], chunk_size: usize) -> bool {
    let mut map = HashMap::new();

    let mut v = vec![0; chunk_size];
    for (i, b) in text.iter().enumerate() {
        let counter = i % chunk_size;
        v[counter] = *b;

        if counter == chunk_size - 1 {
            match map.insert(v.clone(), 1) {
                None => {}
                Some(_) => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique() {
        let text: Vec<u8> = vec![1, 2, 3, 1, 2, 3];
        assert!(is_unique(&text, 2));
        assert!(is_unique(&text, 3));
    }
}
