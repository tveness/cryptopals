//! Break "random access read/write" AES CTR
//!
//! Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a
//! random key (for this exercise the key should be unknown to you, but hold on to it).
//!
//! Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with
//! different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".
//!
//! Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal
//! the key or the original plaintext; the attacker has the ciphertext and controls the offset and
//! "new text".
//!
//! Recover the original plaintext.
//!
//! Food for thought. A folkloric supposed benefit of CTR mode is the ability to easily "seek
//! forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do
//! is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a
//! disk.

use rand::{prelude::*, thread_rng};

use crate::stream::Ctr;
use crate::utils::*;

fn edit(
    ciphertext: &[u8],
    key: &[u8],
    nonce: u64,
    offset: usize,
    newtext: &[u8],
) -> Result<Vec<u8>> {
    let ctr = Ctr::new(key, nonce);
    let decrypted = ciphertext
        .iter()
        .zip(ctr)
        .map(|(k, v)| k ^ v)
        .collect::<Vec<u8>>();
    let edited = decrypted
        .iter()
        .enumerate()
        .map(
            |(i, v)| match (offset..(offset + newtext.len())).contains(&i) {
                true => {
                    let index = i - offset;
                    newtext[index]
                }
                false => *v,
            },
        )
        .collect::<Vec<u8>>();

    let ctr = Ctr::new(key, nonce);
    let encrypted_edited = edited
        .iter()
        .zip(ctr)
        .map(|(v, k)| v ^ k)
        .collect::<Vec<u8>>();

    Ok(encrypted_edited)
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();

    let nonce: u64 = rng.gen();
    let key = random_key(16, &mut rng);

    let all_lines: Vec<Vec<u8>> = read_base64_lines("./data/20.txt")?;
    for data in all_lines {
        let ctr = Ctr::new(&key, nonce);
        let encrypted = data
            .iter()
            .zip(ctr)
            .map(|(v, k)| v ^ k)
            .collect::<Vec<u8>>();

        // Fill with zeros, and then this is literally the keystream
        let newtext = vec![0_u8; encrypted.len()];
        let keystream = edit(&encrypted, &key, nonce, 0, &newtext)?;

        let data_recovered = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(k, v)| k ^ v)
            .collect::<Vec<u8>>();

        println!(
            "Recovered: {}",
            std::str::from_utf8(&data_recovered).unwrap()
        );

        assert_eq!(data_recovered, data);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn recovery() {
        main().unwrap();
    }
}
