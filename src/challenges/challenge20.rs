//! Break fixed-nonce CTR statistically
//!
//! In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with
//! the first, but solve the problem differently.
//!
//! Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the
//! same way you would repeating-key XOR.
//!
//! Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they
//! are effectively the same thing.
//!
//! To exploit this: take your collection of ciphertexts and truncate them to a common length (the
//! length of the smallest ciphertext will work).
//!
//! Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size
//! of the length of the ciphertext you XOR'd.

use crate::stream::Ctr;
use crate::utils::*;

pub fn main() -> Result<()> {
    let data_raw = read_base64_lines("./data/20.txt")?;
    let key = b"YELLOW SUBMARINE";
    let data = data_raw
        .iter()
        .map(|x| {
            // Fixed nonce = 0
            let stream = Ctr::new(key, 0);
            x.iter()
                .zip(stream)
                .map(|(v, k)| v ^ k)
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<Vec<u8>>>();

    let map = freq_map_from_file("./data/aiw.txt")?;

    // Now decrypt this statistically
    // First, truncate all of them
    let min_length = data.iter().map(|x| x.len()).min().unwrap();
    let data_truncated = data
        .iter()
        .map(|x| x[..min_length].to_vec())
        .collect::<Vec<Vec<u8>>>();

    // Rearrange and break with fixed-key XOR like many challenges ago
    // Original data: is of the form data.len() x min_length
    let data_rearranged = (0..min_length)
        .map(|i| data_truncated.iter().map(|x| x[i]).collect::<Vec<u8>>())
        .collect::<Vec<Vec<u8>>>();

    let single_xor_keys = data_rearranged
        .iter()
        .map(|d| crack_single_byte_xor(d, &map).unwrap())
        .collect::<Vec<u8>>();
    let unencrypted = data_truncated
        .iter()
        .map(|d| {
            d.iter()
                .zip(single_xor_keys.iter())
                .map(|(v, k)| v ^ k)
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<Vec<u8>>>();
    for u in unencrypted.iter() {
        let s = std::str::from_utf8(&u).unwrap();
        println!("Unencrytped: {}", s);
    }

    Ok(())
}
