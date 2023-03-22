//! CTR bitflipping
//!
//! There are people in the world that believe that CTR resists bit flipping attacks of the kind to
//! which CBC mode is susceptible.
//!
//! Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode.
//! Inject an "admin=true" token.

use crate::stream::Ctr;
use crate::utils::*;
use rand::{prelude::*, thread_rng};

use crate::challenges::challenge16::contains_admin;

fn embed(input: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let mut prepend: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
    let append = b";comment2=%20like%20a%20pound%20of%20bacon";

    // Escape input ;,= -> A
    let input: Vec<u8> = input
        .iter()
        .map(|c| match c {
            59_u8 => 65_u8,
            61_u8 => 65_u8,
            _ => *c,
        })
        .collect();

    prepend.extend_from_slice(&input);
    prepend.extend_from_slice(append);

    let enc: Vec<u8> = ctr_encrypt(&prepend, key, nonce);
    Ok(enc)
}
fn generated_flipped(target: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let input = b"aaaaaaaaaaaaaaaa";
    // |comment1=cooking|%20MCs;userdata=|aaaaaaaaaaaaaaaa|;comment2=%20lik|e%20a%20pound%20|of%20bacon
    let unmodified = embed(input, key, nonce)?;
    let modified: Vec<u8> = unmodified
        .iter()
        .enumerate()
        .map(|(i, v)| match (32..48).contains(&i) {
            true => *v ^ target[i - 32] ^ input[i - 32],
            false => *v,
        })
        .collect();
    Ok(modified)
}
fn authorise(ciphertext: &[u8], key: &[u8], nonce: u64) -> Result<bool> {
    let dec = ctr_encrypt(ciphertext, key, nonce);

    Ok(contains_admin(&dec))
}

fn ctr_encrypt(text: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let ctr = Ctr::new(key, nonce);
    let dec: Vec<u8> = text.iter().zip(ctr).map(|(k, v)| k ^ v).collect();
    dec
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    let key = random_key(16, &mut rng);
    let nonce: u64 = rng.gen();

    let target = b";admin=true;aaaa";
    let modified = generated_flipped(target, &key, nonce)?;

    let target_decrypt = &ctr_encrypt(&modified, &key, nonce)[32..48];

    let target_str = std::str::from_utf8(target_decrypt).unwrap();
    println!("Decrypted: {}", target_str);

    let whoami = match authorise(&modified, &key, nonce) {
        Ok(true) => "admin",
        _ => "not-admin",
    };
    println!("whoami: {}", whoami);

    Ok(())
}
