//! Byte-at-a-time ECB decryption (Simple)
//! Copy your oracle function to a new function that encrypts buffers under ECB mode using a
//! consistent but unknown key (for instance, assign a single random key, once, to a global
//! variable).
//!
//! Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the
//! following string:
//!
//! ```text
//! Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
//! aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
//! dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
//! YnkK
//! ```
//!
//! Spoiler alert.
//! Do not decode this string now. Don't do it.
//!
//! Base64 decode the string before appending it. Do not base64 decode the string by hand; make
//! your code do it. The point is that you don't know its contents.
//!
//! What you have now is a function that produces:
//!
//! ```text
//! AES-128-ECB(your-string || unknown-string, random-key)
//! ```
//!
//! It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
//!
//! Here's roughly how:
//!
//! Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
//! then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do
//! this step anyway.
//! Detect that the function is using ECB. You already know, but do this step anyways.
//! Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the
//! block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in
//! that last byte position.
//! Make a dictionary of every possible last byte by feeding different strings to the oracle; for
//! instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
//! Match the output of the one-byte-short input to one of the entries in your dictionary. You've
//! now discovered the first byte of unknown-string.
//! Repeat for the next byte.
//! Congratulations.
//! This is the first challenge we've given you whose solution will break real crypto. Lots of
//! people know that when you encrypt something in ECB mode, you can see penguins through it. Not
//! so many of them can decrypt the contents of those ciphertexts, and now you can. If our
//! experience is any guideline, this attack will get you code execution in security tests about
//! once a year.

use std::collections::HashMap;

use crate::utils::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    // Need a fixed key over the duration
    let key = random_key(16, &mut rng);

    // 1. Determine block size
    let mut padder: Vec<u8> = b"AA".to_vec();
    while is_unique(&oracle(&padder, &key)?[..padder.len()], padder.len() / 2) {
        padder.extend_from_slice(b"A");
    }
    let block_size = padder.len() / 2;
    println!("Inferred block size: {block_size}");

    // 2. Confirm ECB
    let ciphertext_mode = detect_mode_explicit(&oracle(&padder, &key)?, block_size);
    println!("Mode: {:?}", ciphertext_mode);

    let mut decrypted_message: Vec<u8> = Vec::with_capacity(oracle(b"", &key).len());

    while let Ok(next_byte) = get_next_byte(&decrypted_message, &key, block_size) {
        decrypted_message.push(next_byte);
        println!("{}", std::str::from_utf8(&decrypted_message).unwrap());
    }

    Ok(())
}
fn get_next_byte(current_state: &[u8], key: &[u8], bs: usize) -> Result<u8> {
    let base_buffer = b"";
    let mut lookup = HashMap::new();
    // Construct lookup table for current scenario
    for b in 0..255_u8 {
        let mut dangling = vec![];
        dangling.push(b);
        let enc = oracle(&dangling, &key)?[..bs].to_vec();
        lookup.insert(enc, b);
    }
    // Now run with slightly smaller dangling string
    let dangling = vec![];
    // Select correct block to look at
    let enc = oracle(&dangling, &key)?[..bs].to_vec();

    match lookup.get(&enc) {
        Some(b) => Ok(*b),
        None => Err(anyhow!("Failed to find correct block in lookup table")),
    }
}

pub fn detect_mode_explicit(ciphertext: &[u8], bs: usize) -> Mode {
    match is_unique(ciphertext, bs) {
        true => Mode::Cbc,
        false => Mode::Ecb,
    }
}

fn oracle(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let secret_base_64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let secret_bytes = general_purpose::STANDARD.decode(secret_base_64)?;
    let mut input = input.to_vec();
    input.extend_from_slice(&secret_bytes);
    // Make sure it's padded!
    let padded = pkcs7_pad(&input, key.len());

    let encrypted = ecb_encrypt(&padded, key, None)?;

    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cracking() {}
}
