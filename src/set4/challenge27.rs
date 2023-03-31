//! Recover the key from CBC with IV=Key
//!
//! Take your code from the CBC exercise and modify it so that it repurposes the key for CBC
//! encryption as the IV.
//!
//! Applications sometimes use the key as an IV on the auspices that both the sender and the
//! receiver have to know the key already, and can save some space by using it as both a key and an
//! IV.
//!
//! Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get
//! the receiver to decrypt a value that will reveal the key.
//!
//! The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for
//! ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an
//! exception or return an error that includes the decrypted plaintext (this happens all the time
//! in real systems, for what it's worth).
//!
//! Use your code to encrypt a message that is at least 3 blocks long:
//!
//! AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3 Modify the message (you are now the attacker):
//!
//! C_1, C_2, C_3 -> C_1, 0, C_1 Decrypt the message (you are now the receiver) and raise the
//! appropriate error if high-ASCII is found.
//!
//! As the attacker, recovering the plaintext from the error, extract the key:
//!
//! P'_1 XOR P'_3'_1 XOR P'_3

use crate::utils::*;
use thiserror::Error;

use crate::set2::challenge16::contains_admin;

fn embed(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
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

    let padded = pkcs7_pad(&prepend, 16);
    let enc = cbc_encrypt(&padded, key, Some(key))?;
    Ok(enc)
}

#[derive(Debug, Error)]
pub enum ValidationErr {
    #[error("High ascii detected")]
    HighAscii { plaintext: Vec<u8> },
    #[error(transparent)]
    PaddingError(#[from] PaddingError),
    #[error(transparent)]
    CryptError(#[from] openssl::error::ErrorStack),
}

fn authorise(ciphertext: &[u8], key: &[u8]) -> Result<bool, ValidationErr> {
    let dec = cbc_decrypt(ciphertext, key, Some(key))?;

    for i in &dec[..] {
        if i > &128 {
            return Err(ValidationErr::HighAscii { plaintext: dec });
        }
    }

    let unpadded = pkcs7_unpad(&dec)?;

    Ok(contains_admin(&unpadded))
}

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = random_key(16, &mut rng);
    let input = b"aaaaaaaaaaaaaaaa";

    let unmodified = embed(input, &key)?;
    let mut modified: Vec<u8> = Vec::with_capacity(48);
    // Decrypts C1 and XORs it with IV (key)
    modified.extend_from_slice(&unmodified[..16]);
    modified.extend_from_slice(&[0_u8; 16]);
    // Decrypts C3 and XORs it with all 0s
    modified.extend_from_slice(&unmodified[..16]);

    // So P1' ^ P3' = P1 ^ IV ^0 ^ P1 = IV = key !

    println!("Modified {modified:?}");

    let decrypted = match authorise(&modified, &key) {
        Err(ValidationErr::HighAscii { plaintext }) => plaintext,
        Ok(x) => panic!("Shouldnt decrypt, plaintext: {}", x),
        Err(_) => panic!("Not supposed to work!"),
    };

    let p1 = &decrypted[..16];
    let p3 = &decrypted[32..48];

    let key_derived: Vec<u8> = p1.iter().zip(p3.iter()).map(|(a, b)| a ^ b).collect();

    println!("Key (original): {key:?}");
    println!("Key (derived):  {key_derived:?}");

    assert_eq!(key, key_derived);

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_keys() {
        main().unwrap();
    }
}
