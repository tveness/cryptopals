//! CBC bitflipping attacks
//! Generate a random AES key.
//!
//! Combine your padding code and CBC code to write two functions.
//!
//! The first function should take an arbitrary input string, prepend the string:
//!
//! "comment1=cooking%20MCs;userdata="
//! .. and append the string:
//!
//! ";comment2=%20like%20a%20pound%20of%20bacon"
//! The function should quote out the ";" and "=" characters.
//!
//! The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
//!
//! The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
//!
//! Return true or false based on whether the string exists.
//!
//! If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
//!
//! Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
//!
//! You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
//!
//! Completely scrambles the block the error occurs in
//! Produces the identical 1-bit error(/edit) in the next ciphertext block.
//! Stop and think for a second.
//! Before you implement this attack, answer this question: why does CBC mode have this property?

use crate::utils::*;

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
    let enc = cbc_encrypt(&padded, &key, None)?;
    Ok(enc)
}

fn authorise(ciphertext: &[u8], key: &[u8]) -> Result<bool> {
    let dec = cbc_decrypt(&ciphertext, &key, None)?;
    let unpadded = pkcs7_unpad(&dec)?;

    Ok(contains_admin(&unpadded))
}

fn contains_admin(input: &[u8]) -> bool {
    let admin = b";admin=true;";
    input[..].windows(admin.len()).any(|chunk| chunk == admin)
}

pub fn main() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_admin_resolve() {
        let has_admin = b"qweqpwoe;admin=true;sdopqwepoy";
        let not_has_admin = b"qweqpwoe;admon=true;sdopqwepoy";

        assert!(contains_admin(has_admin));
        assert!(!contains_admin(not_has_admin));
    }
}
