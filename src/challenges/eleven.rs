//!  An ECB/CBC detection oracle
//! Now that you have ECB and CBC working:
//!
//! Write a function to generate a random AES key; that's just 16 random bytes.
//!
//! Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
//!
//! The function should look like:
//!
//! ```text
//! encryption_oracle(your-input)
//! => [MEANINGLESS JIBBER JABBER]
//! ```
//! Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
//!
//! Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
//!
//! Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

use crate::utils::*;
use anyhow::Result;
use rand::{prelude::*, Rng};

pub fn main() -> Result<()> {
    let input = b"IN A TOWN WHERE I WAS BORN LIVED";
    let encrypted = encryption_oracle(input)?;
    println!("Encrypted: {:?}", encrypted);
    Ok(())
}

pub fn encryption_oracle(input: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();

    let key = random_key(16, &mut rng);
    let prepend_bytes = random_bytes(5, 10, &mut rng);
    let append_bytes = random_bytes(5, 10, &mut rng);

    let mut modified_input = vec![];
    modified_input.extend_from_slice(&prepend_bytes);
    modified_input.extend_from_slice(&input);
    modified_input.extend_from_slice(&append_bytes);
    let coin_toss = rng.gen::<bool>();

    let encrypted = match coin_toss {
        true => cbc_encrypt(input, &key, None)?,
        false => ecb_encrypt(input, &key, None)?,
    };

    Ok(encrypted)
}

fn random_key(l: usize, rng: &mut ThreadRng) -> Vec<u8> {
    let mut v = vec![0; l];
    rng.fill(&mut v[..l]);
    v
}

fn random_bytes(a: usize, b: usize, rng: &mut ThreadRng) -> Vec<u8> {
    let len: usize = a + rng.gen::<usize>() % (b - a);
    let mut v = vec![0; len];
    rng.fill(&mut v[..len]);
    v
}
