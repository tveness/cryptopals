//! Byte-at-a-time ECB decryption (Harder)
//!
//! Take your oracle function from #12. Now generate a random count of random bytes and prepend
//! this string to every plaintext. You are now doing:
//!
//! AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
//!
//! Same goal: decrypt the target-bytes.
//! Stop and think for a second.
//!
//! What's harder than challenge #12 about doing this? How would you overcome that obstacle? The
//! hint is: you're using all the tools you already have; no crazy math is required.
//!
//! Think "STIMULUS" and "RESPONSE".

use std::collections::HashMap;

use crate::utils::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

fn oracle(prepend: &[u8], raw_input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let secret_base_64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let secret_bytes = general_purpose::STANDARD.decode(secret_base_64)?;
    let mut input = prepend.to_vec();
    input.extend_from_slice(&raw_input);
    input.extend_from_slice(&secret_bytes);
    // Make sure it's padded!
    let padded = pkcs7_pad(&input, key.len());

    let encrypted = ecb_encrypt(&padded, key, None)?;

    Ok(encrypted)
}

fn get_next_byte(
    prepend: &[u8],
    inferred_prepend_l: usize,
    current_state: &[u8],
    key: &[u8],
    bs: usize,
) -> Result<u8> {
    let mut lookup = HashMap::new();

    // Construct lookup table for current scenario
    // Say we know the message is "In a town"
    // Then the dangling is going to be padding this out so that
    // we know the string except for the last letter and that it matches with
    // the block size i.e.
    // |<------16------>|
    // |AAAAAAIn a townb|
    //
    // So the number of padding bytes is
    let padding_size = bs - 1 - (current_state.len() % bs);
    // Don't want trailing 1 from padding on the final byte
    for b in 2..255_u8 {
        // This runs from 0..=bs-1 as modulo is the same

        let mut padded: Vec<u8> = vec![65_u8; padding_size];
        padded.extend_from_slice(current_state);
        padded.push(b);
        let dangling = &padded[padded.len() - bs..padded.len()];
        let enc = oracle(prepend, dangling, key)?[..bs].to_vec();
        lookup.insert(enc, b);
    }
    // Now run with slightly smaller dangling string
    let padded: Vec<u8> = vec![65_u8; padding_size];
    // |<------16------>|
    // |AAAAAAIn a town?|
    // Select correct block to look at
    let block = current_state.len() / bs;
    let enc = oracle(prepend, &padded, key)?[block * bs..(block + 1) * bs].to_vec();

    match lookup.get(&enc) {
        Some(b) => Ok(*b),
        None => Err(anyhow!("Failed to find correct block in lookup table")),
    }
}

fn infer_prefix_length(secret_prefix: &[u8], key: &[u8]) -> Result<usize> {
    // The logic here is the following: add an "A" and see which is the first block to change
    // Keep adding "A"s until that block no longer changes
    // One before this point is then a clean boundary, and we can use this to run the same
    // game as before, except always cut these first blocks off if we pad accordingly
    //
    let bs: usize = 16;
    let mut probe: Vec<u8> = vec![];
    let mut reference = oracle(secret_prefix, &probe, key)?;
    probe.push(65_u8);
    let mut probed = oracle(secret_prefix, &probe, key)?;
    let ref_block = first_different_block(&reference, &probed);

    loop {
        reference = oracle(secret_prefix, &probe, key)?;
        probe.push(65_u8);
        probed = oracle(secret_prefix, &probe, key)?;
        let first_different = first_different_block(&reference, &probed);
        match first_different != ref_block {
            true => {
                let boundary = (ref_block + 1) * bs;
                let padding = probe.len() - 1;

                return Ok(boundary - padding);
            }
            false => {}
        }
    }
}

fn first_different_block(v1: &[u8], v2: &[u8]) -> usize {
    let l1 = v1.len();
    let l2 = v2.len();
    let bs: usize = 16;
    let min_length: usize = match l1 < l2 {
        true => l1,
        false => l2,
    } / bs;
    for b in 0..min_length {
        match v1[b * bs..(b + 1) * bs] == v2[b * bs..(b + 1) * bs] {
            false => return b,
            true => {}
        };
    }
    min_length
}

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    // Need a fixed key over the duration
    let key = random_key(16, &mut rng);
    let secret_prefix_length = rng.gen::<usize>() % 64_usize;
    let secret_prefix = random_key(secret_prefix_length, &mut rng);
    println!("Actual length: {}", secret_prefix_length);
    let inferred = infer_prefix_length(&secret_prefix, &key)?;
    println!("Inferred length: {:?}", inferred);

    Ok(())
}
