//! The CBC padding oracle
//!
//! This is the best-known attack on modern block-cipher cryptography.
//!
//! Combine your padding code and your CBC code to write two functions.
//!
//! The first function should select at random one of the following 10 strings:
//!
//! MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
//! MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
//! MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
//! MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
//! MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
//! MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
//! MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
//! MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
//! MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
//! MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
//! ... generate a random AES key (which it should save for all future encryptions), pad the string
//! out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the
//! ciphertext and IV.
//!
//! The second function should consume the ciphertext produced by the first function, decrypt it,
//! check its padding, and return true or false depending on whether the padding is valid.
//!
//! What you're doing here.
//! This pair of functions approximates AES-CBC encryption as its deployed serverside in web
//! applications; the second function models the server's consumption of an encrypted session
//! token, as if it was a cookie.
//!
//! It turns out that it's possible to decrypt the ciphertexts provided by the first function.
//!
//! The decryption here depends on a side-channel leak by the decryption function. The leak is the
//! error message that the padding is valid or not.
//!
//! You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is
//! this:
//!
//! The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in
//! 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
//!
//! 02h in isolation is not valid padding.
//!
//! 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
//!
//! 03h 03h 03h is even less likely.
//!
//! So you can assume that if you corrupt a decryption AND it had valid padding, you know what that
//! padding byte is.
//!
//! It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have
//! nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a
//! specific bit of code that handles decryption. You can mount a padding oracle on any CBC block,
//! whether it's padded or not.

use crate::utils::*;
use base64::{engine::general_purpose, Engine as _};
use rand::seq::SliceRandom;
use thiserror::Error;

fn oracle(input: &[u8], key: &[u8]) -> Result<()> {
    match pkcs7_unpad(&cbc_decrypt(input, key, None)?) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Error)]
enum CrackingErr {
    #[error("Error counting up")]
    AscendingError,
    #[error("Error counting down")]
    DescendingError,
}

// The Asc/Desc is to catch the case when we do get the initial padding right but it is *not* \x01
// The cracking will eventually fail and we instead sweep from the other direction to not have the
// same coincidence
enum Dir {
    Ascending,
    Descending,
}

fn crack_pair(block_pair: &[u8], key: &[u8], dir: Dir) -> Result<Vec<u8>, CrackingErr> {
    // This is an expansion of the CBC bit-flip attack from before
    // Instead, the only information we get out is whether or not the padding is correct

    let bs = key.len();
    // This is the byte from the end we are targetting
    let mut modified_block = block_pair[bs..].to_vec();
    modified_block.extend_from_slice(&block_pair[bs..]);
    for target_byte in 0..bs {
        let mut b = match dir {
            Dir::Ascending => 0_u8,
            Dir::Descending => 255_u8,
        };
        modified_block[bs - target_byte - 1] = b;
        while oracle(&modified_block, key).is_err() {
            match dir {
                Dir::Ascending => {
                    if b == 255 {
                        return Err(CrackingErr::AscendingError);
                    }
                    b += 1
                }
                Dir::Descending => {
                    if b == 0 {
                        return Err(CrackingErr::DescendingError);
                    }

                    b -= 1
                }
            };
            modified_block[bs - target_byte - 1] = b;
        }
        // Now the padding should be correct ...\xtarget+1\xtarget+1
        // This implies that decoded[2*bs - target_byte - 1] ^ b = target_byte+1
        // i.e. decoded[2*bs - target_byte - 1] = b ^(target_byte+1)
        /*
        println!(
            "decoded[{}] = {:?}; b = {}",
            target_byte,
            b ^ (target_byte as u8 + 1) ^ block_pair[bs - target_byte - 1],
            b
        );
        */
        // Now that the padding is correct, we roughly know what is going on
        // If this is the first byte, then we know the decrypted block ends \x01 (unless we got
        // lucky and it end \x02\x02, or more, but this is unlikely)
        // If this is the second byte, it ends \x02 etc
        // To get the next byte, we now need to make sure all of the bytes we have so far get
        // updated
        for update_byte in 0..target_byte + 1 {
            let loc = bs - update_byte - 1;
            // When target_byte was 0, intend value was 1
            let tb = target_byte as u8;
            //println!("modified_byte was: {}", modified_block[loc]);
            modified_block[loc] = modified_block[loc] ^ (tb + 1) ^ (tb + 2);
            //println!("modified_byte now: {}", modified_block[loc]);
        }
        //println!();
    }

    // Now that this is complete, the modified block should now have the following form:
    // modified_block[..bs] ^ decrypted[bs..] = \xbs+1 ... \xbs+1
    // => decrypted[bs..] = \xbs+1 .. \xbs+1 ^ modified_block[..bs]
    // The +1 is because we overdid in on the last round of updating modified_block, where it was
    // \xbs..\xbs, and took it one step further
    let decrypted = modified_block[..bs]
        .iter()
        .enumerate()
        .map(|(i, x)| block_pair[i] ^ x ^ ((bs as u8) + 1))
        .collect();
    Ok(decrypted)
}

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = random_key(16, &mut rng);
    let bs = key.len();

    let base64_secret_strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"];
    let secret_bytes = base64_secret_strings.choose(&mut rng).unwrap();
    let secret = general_purpose::STANDARD.decode(secret_bytes)?;
    let secret_string = std::str::from_utf8(&secret)?;

    let padded = pkcs7_pad(&secret, 16);
    let ciphertext = cbc_encrypt(&padded, &key, None)?;

    let mut extended = vec![0_u8; bs];
    extended.extend_from_slice(&ciphertext);
    let mut answer = vec![];

    for chunk_num in 0..(extended.len() / bs - 1) {
        let block_pair = &extended[chunk_num * bs..(chunk_num + 2) * bs];
        let cracked = match crack_pair(block_pair, &key, Dir::Ascending) {
            Ok(x) => Ok(x),
            Err(_) => crack_pair(block_pair, &key, Dir::Descending),
        }?;

        answer.extend_from_slice(&cracked);
    }

    let answer = pkcs7_unpad(&answer).unwrap();
    println!("Cracked:  {:?}", answer);
    println!("Original: {:?}", secret);
    println!("Cracked:  {}", std::str::from_utf8(&answer).unwrap());
    println!("Original: {}", secret_string);
    assert_eq!(answer, secret);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_test() {
        for _ in 0..100 {
            main().unwrap();
        }
    }
}
