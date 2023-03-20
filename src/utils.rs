#![allow(dead_code)]
use std::hash::Hash;
use std::io::BufRead;
use std::{collections::HashMap, fs::File, io::BufReader};

// Re-export useful functions introduced in specific challenges
pub use crate::challenges::eight::is_unique;
pub use crate::challenges::eleven::{detect_mode, random_key, Mode};
pub use crate::challenges::nine::pkcs7_pad;
pub use crate::challenges::ten::{cbc_decrypt, cbc_encrypt};
pub use crate::challenges::ten::{ecb_decrypt, ecb_encrypt};
pub use crate::challenges::thirteen::{pkcs7_unpad, PaddingError};

pub use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(input)?)
}

pub fn bytes_to_hex(input: &[u8]) -> String {
    hex::encode(input)
}

pub fn bytes_to_b64_str(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn freq_map_from_file(filename: &str) -> Result<HashMap<char, f64>> {
    let mut map = HashMap::new();
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        for c in line?.as_str().chars() {
            if c.is_alphabetic() {
                map.entry(c).and_modify(|v| *v += 1.0).or_insert(1.0);
            }
        }
    }
    let sum: f64 = map.values().sum();
    for val in map.values_mut() {
        *val /= sum;
    }

    Ok(map)
}
pub fn crack_single_byte_xor(input_bytes: &[u8], ref_map: &HashMap<char, f64>) -> Result<u8> {
    let mut scores = HashMap::new();
    for x in 0..255_u8 {
        let xored = xor_bytes(input_bytes, &[x]);
        // If it can be decoed, then work with it
        if let Ok(xor_str) = std::str::from_utf8(&xored) {
            let actual_freq_map = freq_map_from_str(xor_str)?;
            let score = kl_divergence(&actual_freq_map, ref_map);
            //println!("Score: {} {xor_str}", score);
            scores.insert(x, score);
        }
    }

    let best_score =
        scores
            .iter()
            .fold((0_u8, 1000.0), |acc, x| match *x.1 < acc.1 && *x.1 != 0.0 {
                true => (*x.0, *x.1),
                false => acc,
            });
    let b = best_score.0;
    Ok(b)
}
pub fn read_base64_lines(filename: &str) -> Result<Vec<Vec<u8>>> {
    let mut v = vec![];
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let l = line?;
        let s = l.trim_end_matches(char::is_whitespace);
        let res = general_purpose::STANDARD.decode(s)?;
        v.push(res);
    }
    Ok(v)
}

pub fn read_base64_file(filename: &str) -> Result<Vec<u8>> {
    let mut v = String::new();
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let l = line?;
        let s = l.trim_end_matches(char::is_whitespace);
        v.push_str(s);
    }
    let res = general_purpose::STANDARD.decode(v)?;
    Ok(res)
}

pub fn read_file(filename: &str) -> Result<Vec<String>> {
    let mut v = Vec::<String>::new();
    let f = File::open(filename)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        v.push(line?);
    }
    Ok(v)
}

pub fn freq_map_from_str(input: &str) -> Result<HashMap<char, f64>> {
    let mut map = HashMap::new();
    for c in input.chars() {
        if c.is_alphabetic() {
            map.entry(c).and_modify(|v| *v += 1.0).or_insert(1.0);
        }
    }
    let sum: f64 = map.values().sum();
    for val in map.values_mut() {
        *val /= sum;
    }

    Ok(map)
}

pub fn kl_divergence<T: Eq + Hash>(p: &HashMap<T, f64>, q: &HashMap<T, f64>) -> f64 {
    q.keys()
        .map(|k| {
            let px = p.get(k);
            let qx = q.get(k).unwrap();
            match px {
                None => 0.0,
                Some(px_val) => *px_val * ((*px_val + 0.01) / (*qx + 0.01)).ln(),
            }
        })
        .sum()
}

pub fn xor_bytes(a: &[u8], x: &[u8]) -> Vec<u8> {
    // Cycle x if possible
    std::iter::zip(a, x.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect::<Vec<u8>>()
}
pub fn ones(x: u8) -> u64 {
    (0..8)
        .map(|mask_shift| match x & (1 << mask_shift) {
            0 => 0,
            _ => 1,
        })
        .sum()
}

pub fn hamming(str1: &str, str2: &str) -> u64 {
    let s1b = str1.as_bytes();
    let s2b = str2.as_bytes();
    hamming_bytes(s1b, s2b)
}

pub fn hamming_bytes(b1: &[u8], b2: &[u8]) -> u64 {
    std::iter::zip(b1.iter(), b2.iter())
        .map(|(x, y)| x ^ y)
        .map(ones)
        .sum()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn ones_test() {
        assert_eq!(ones(4_u8), 1);
        assert_eq!(ones(5_u8), 2);
        assert_eq!(ones(7_u8), 3);
    }

    #[test]
    fn hamming_test() {
        let first = "this is a test";
        let second = "wokka wokka!!!";

        assert_eq!(hamming(first, second), 37);
    }
}
