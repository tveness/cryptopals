use crate::utils::*;
use anyhow::Result;
use openssl::symm::{decrypt, Cipher};

pub fn main() -> Result<()> {
    let key = b"YELLOW SUBMARINE";
    let ciphertext = read_base64_file("./data/7.txt")?;
    let cipher = Cipher::aes_128_ecb();

    let plaintext = decrypt(cipher, key, None, &ciphertext)?;
    println!("{}", std::str::from_utf8(&plaintext)?);

    Ok(())
}
