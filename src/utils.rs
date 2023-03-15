use std::hash::Hash;
use std::io::BufRead;
use std::{collections::HashMap, fs::File, io::BufReader};

use anyhow::Result;
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
