use std::collections::HashMap;

use crate::utils::*;
use anyhow::Result;
///Break repeating-key XOR
/// It is officially on, now.
/// This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.
///
/// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
///
/// Here's how:
///
/// Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
/// Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
/// this is a test
/// and
/// wokka wokka!!!
/// is 37. Make sure your code agrees before you proceed.
/// For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
/// The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
/// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
/// Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
/// Solve each block as if it was single-character XOR. You already have code to do this.
/// For each block, the single-byte XOR key that produces the best looking histogram is the
/// repeating-key XOR key byte for that block. Put them together and you have the key.
/// This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR
/// ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more
/// people "know how" to break it than can actually break it, and a similar technique breaks
/// something much more important.
///
/// No, that's not a mistake.
/// We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

pub fn main() -> Result<()> {
    let bytes = read_base64_file("./data/6.txt")?;
    let keysize = get_keysize(&bytes);

    // Now slice the bytes into pieces xored with the same key
    // i.e. block 1: 0, keysize, 2*keysize, ...
    //      block 2: 1, keysize+1, 2*keysize+1, ...
    let whole_blocks: usize = bytes.len() / keysize;
    let key_chunks = (0..keysize)
        .map(|key_index| {
            (0..whole_blocks)
                .map(|block_num| bytes[block_num * keysize + key_index])
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<Vec<u8>>>();

    let ref_map = freq_map_from_file("./data/wap.txt")?;

    let key = key_chunks
        .iter()
        .map(|chunk| crack_single_byte_xor(chunk, &ref_map))
        .collect::<Result<Vec<u8>>>()?;
    println!("Key: {}", std::str::from_utf8(&key).unwrap());
    // Now crack each block
    let decoded = bytes
        .iter()
        .enumerate()
        .map(|(i, v)| v ^ key[i % keysize])
        .collect::<Vec<u8>>();

    println!("Decoded: {}", std::str::from_utf8(&decoded).unwrap());
    Ok(())
}

fn get_keysize(input: &[u8]) -> usize {
    let mut map = HashMap::new();
    for keysize in 1..40 {
        let ham = get_hamming_with_keysize(input, keysize);
        map.insert(keysize, ham / keysize as f64);
    }
    println!("{:?}", map);
    let top = map.iter().fold((0, 50.0), |acc, (x, v)| match *v < acc.1 {
        true => (*x, *v),
        false => acc,
    });
    println!("top: {top:?}");
    top.0
}

fn get_hamming_with_keysize(input: &[u8], keysize: usize) -> f64 {
    let block = input.iter();
    // Max block numbers
    let l: usize = (block.len() - keysize) / keysize;
    let blockshift = input.iter().skip(keysize).take(keysize * l);

    let s = std::iter::zip(block, blockshift)
        .map(|(x, y)| x ^ y)
        .map(ones)
        .sum::<u64>();
    s as f64 / (l as f64)
}
