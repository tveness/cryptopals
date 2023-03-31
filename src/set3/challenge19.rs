//! Break fixed-nonce CTR mode using substitutions
//!
//! Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.
//!
//! In successive encryptions (not in one big running CTR stream), encrypt each line of the base64
//! decodes of the following, producing multiple independent ciphertexts:
//!
//! in 19.txt
//! (This should produce 40 short CTR-encrypted ciphertexts).
//!
//! Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted
//! against the same keystream. This is very bad.
//!
//! Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run
//! in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation,
//! it should be plain that:
//!
//! CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
//! And since the keystream is the same for every ciphertext:
//!
//! CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't say!")
//! Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to
//! validate guesses, catch common English trigrams, and so on.
//!
//! Don't overthink it.
//! Points for automating this, but part of the reason I'm having you do this is that I think this
//! approach is suboptimal.

use crate::utils::*;

use crate::stream::Ctr;
use crate::utils::read_base64_lines;

pub fn main() -> Result<()> {
    let data = read_base64_lines("./data/19.txt")?;
    let key = b"YELLOW SUBMARINE";
    let data = data
        .iter()
        .map(|x| {
            let stream = Ctr::new(key, 0);
            x.iter()
                .zip(stream)
                .map(|(v, k)| v ^ k)
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<Vec<u8>>>();
    // Decoded by hand from the stream and guessing bytes
    // Selecting targets using python ord(a)^ord(b)^c for whichever loks most plausible
    let mut keystream: Vec<u8> = vec![
        118, 209, 203, 75, 175, 162, 70, 226, 227, 175, 3, 93, 108, 19, 195, 114, 210, 236, 108,
        220, 152, 109, 18, 222, 207, 218, 31, 147, 175, 238, 115, 24, 45, 160, 142, 203, 17, 123,
    ];
    for d in data {
        let mut output = d
            .iter()
            .zip(keystream.iter())
            .map(|(v, k)| v ^ k)
            .collect::<Vec<u8>>();
        while std::str::from_utf8(&output).is_err() {
            let l = keystream.len();
            keystream[l - 1] += 1;

            output = d
                .iter()
                .zip(keystream.iter())
                .map(|(v, k)| v ^ k)
                .collect::<Vec<u8>>();
        }
        let output_str = std::str::from_utf8(&output).unwrap();

        //        println!("Keystream: {keystream:?}");
        println!("Output: {output_str}");
    }
    println!("Keystream: {keystream:?}");

    Ok(())
}
