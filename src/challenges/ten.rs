//! CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite
//! the fact that a block cipher natively only transforms individual blocks.
//!
//! In CBC mode, each ciphertext block is added to the next plaintext block before the next call to
//! the cipher core.
//!
//! The first plaintext block, which has no associated previous ciphertext block, is added to a
//! "fake 0th ciphertext block" called the initialization vector, or IV.
//!
//! Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt
//! instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR
//! function from the previous exercise to combine them.
//!
//! The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an
//! IV of all ASCII 0 (\x00\x00\x00 &c)
//!
//! Don't cheat.
//! Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of
//! even doing this stuff if you aren't going to learn from it?

use crate::utils::*;
use anyhow::Result;
use openssl::symm::{Cipher, Crypter, Mode};

pub fn main() -> Result<()> {
    let ciphertext = read_base64_file("./data/10.txt")?;
    let key = b"YELLOW SUBMARINE";

    //let ciphertext = pkcs7_pad(&ciphertext, keysize);

    let decrypted = cbc_decrypt(&ciphertext, key, None)?;

    println!("{}", std::str::from_utf8(&decrypted)?);

    Ok(())
}

pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut decrypted = vec![];
    let mut iv = match iv {
        None => vec![0; key.len()],
        Some(x) => x.to_vec(),
    };
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    // Pad is on by default, this the problem with the simpler "decrypt" option
    decrypter.pad(false);

    let keysize = key.len();
    let total_blocks = ciphertext.len() / keysize;

    // Must be big enough to contain padding of a complete block
    let mut plaintext = vec![0; 2 * keysize];

    for block_num in 0..total_blocks {
        // Grab next block
        let block_ciphertext = &ciphertext[block_num * keysize..keysize * (block_num + 1)];

        // Decrypt
        decrypter.update(&block_ciphertext, &mut plaintext)?;
        let xored = plaintext
            .iter()
            .take(keysize)
            .zip(iv.iter())
            .map(|(v1, v2)| v1 ^ v2)
            .collect::<Vec<u8>>();

        // Update iv with previous one
        iv = block_ciphertext.to_vec();

        // Add data to next slice
        decrypted.extend_from_slice(&xored);
    }
    Ok(decrypted)
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut encrypted = vec![];
    let mut iv = match iv {
        None => vec![0; key.len()],
        Some(x) => x.to_vec(),
    };
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    // Pad is on by default, this the problem with the simpler "decrypt" option
    encrypter.pad(false);

    let keysize = key.len();
    let total_blocks = plaintext.len() / keysize;

    // Must be big enough to contain padding of a complete block
    let mut ciphertext = vec![0; 2 * keysize];

    for block_num in 0..total_blocks {
        // Grab next block
        let block_plaintext = &plaintext[block_num * keysize..keysize * (block_num + 1)];

        let xored_plaintext = block_plaintext
            .iter()
            .take(keysize)
            .zip(iv.iter())
            .map(|(v1, v2)| v1 ^ v2)
            .collect::<Vec<u8>>();

        // Encrypt
        encrypter.update(&xored_plaintext, &mut ciphertext)?;

        // Update iv with previous one
        iv = ciphertext[..keysize].to_vec();

        // Add data to next slice
        encrypted.extend_from_slice(&ciphertext[..keysize]);
    }
    Ok(encrypted)
}
pub fn ecb_decrypt(ciphertext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut decrypted = vec![];
    let mut iv = match iv {
        None => vec![0; key.len()],
        Some(x) => x.to_vec(),
    };
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    // Pad is on by default, this the problem with the simpler "decrypt" option
    decrypter.pad(false);

    let keysize = key.len();
    let total_blocks = ciphertext.len() / keysize;

    // Must be big enough to contain padding of a complete block
    let mut plaintext = vec![0; 2 * keysize];

    for block_num in 0..total_blocks {
        // Grab next block
        let block_ciphertext = &ciphertext[block_num * keysize..keysize * (block_num + 1)];

        // Decrypt
        decrypter.update(&block_ciphertext, &mut plaintext)?;
        let xored = plaintext
            .iter()
            .take(keysize)
            .zip(iv.iter())
            .map(|(v1, v2)| v1 ^ v2)
            .collect::<Vec<u8>>();

        // Add data to next slice
        decrypted.extend_from_slice(&xored);
    }
    Ok(decrypted)
}

pub fn ecb_encrypt(plaintext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut encrypted = vec![];
    let mut iv = match iv {
        None => vec![0; key.len()],
        Some(x) => x.to_vec(),
    };
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
    // Pad is on by default, this the problem with the simpler "decrypt" option
    encrypter.pad(false);

    let keysize = key.len();
    let total_blocks = plaintext.len() / keysize;

    // Must be big enough to contain padding of a complete block
    let mut ciphertext = vec![0; 2 * keysize];

    for block_num in 0..total_blocks {
        // Grab next block
        let block_plaintext = &plaintext[block_num * keysize..keysize * (block_num + 1)];

        let xored_plaintext = block_plaintext
            .iter()
            .take(keysize)
            .zip(iv.iter())
            .map(|(v1, v2)| v1 ^ v2)
            .collect::<Vec<u8>>();

        // Encrypt
        encrypter.update(&xored_plaintext, &mut ciphertext)?;

        // Add data to next slice
        encrypted.extend_from_slice(&ciphertext[..keysize]);
    }
    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_cbc() {
        let key = b"YELLOW SUBMARINE";
        let message = b"IN A TOWN WHERE I WAS BORN LIVED".to_vec();
        let encrypted = cbc_encrypt(&message, key, None).unwrap();
        let decrypted = cbc_decrypt(&encrypted, key, None).unwrap();

        assert_eq!(&message, &decrypted);
    }
    #[test]
    fn round_trip_ecb() {
        let key = b"YELLOW SUBMARINE";
        let message = b"IN A TOWN WHERE I WAS BORN LIVED".to_vec();
        let encrypted = ecb_encrypt(&message, key, None).unwrap();
        let decrypted = ecb_decrypt(&encrypted, key, None).unwrap();

        assert_eq!(&message, &decrypted);
    }
}
