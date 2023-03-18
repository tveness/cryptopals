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
use openssl::symm::{decrypt, Cipher};

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
    let keysize = key.len();
    let total_blocks = ciphertext.len() / keysize;

    for block_num in 0..total_blocks {
        let block_ciphertext = &ciphertext[block_num * keysize..keysize * (block_num + 1)];
        println!("Block: {block_ciphertext:?}");
        println!("Block len: {:?}", block_ciphertext.len());
        println!("Key len: {keysize:?}");
        println!("Key: {key:?}");

        let plaintext = decrypt(cipher, key, None, block_ciphertext)?;
        println!("Plaintext: {}", std::str::from_utf8(&plaintext)?);

        iv = block_ciphertext.to_vec();
        decrypted.extend_from_slice(&plaintext);
    }
    println!("Decrypted: {}", std::str::from_utf8(&decrypted)?);

    Ok(decrypted)
}
