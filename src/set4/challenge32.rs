//! Break HMAC-SHA1 with a slightly less artificial timing leak
//!
//! Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)
//!
//! Now break it again.

// Note that this is a little finicky as it pushes the boundaries of my machine, which may or may
// not be your machine

use itertools::Itertools;
use std::time::Duration;

use chrono::Utc;
use rand::thread_rng;

use crate::utils::*;

fn sha1_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut o_pad = vec![0x5c; 64];
    let mut i_pad = vec![0x36; 64];
    let kp = kprime(key);
    assert_eq!(kp.len(), 64);
    //println!("kp: {}", bytes_to_hex(&kp));

    i_pad = i_pad.iter().zip(kp.iter()).map(|(k, v)| k ^ v).collect();
    i_pad.extend_from_slice(message);
    let inner = sha1_hash(&i_pad);

    o_pad = o_pad.iter().zip(kp.iter()).map(|(k, v)| k ^ v).collect();

    o_pad.extend_from_slice(&inner);
    sha1_hash(&o_pad)
}

fn sha1_hash(m: &[u8]) -> Vec<u8> {
    let mut h = Sha1Hasher::default();
    h.hash(m, None)
}

fn kprime(key: &[u8]) -> Vec<u8> {
    let kl = key.len();
    let mut key = key.to_vec();
    let sl = match kl {
        0..=64 => 64 - kl,
        _ => {
            key = sha1_hash(&key);
            64 - 20
        }
    };

    key.extend_from_slice(&vec![0; sl]);
    key
}

fn insecure_compare(file: &[u8], hmac: &[u8], key: &[u8]) -> Auth {
    let true_hmac = sha1_hmac(key, file);
    let delay = 200;
    for (i, v) in true_hmac.iter().enumerate() {
        if hmac[i] != *v {
            return Auth::Invalid;
        }
        std::thread::sleep(Duration::from_micros(delay));
    }
    Auth::Valid
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    let key = random_key(16, &mut rng);
    let h = sha1_hmac(&key, b"file");

    println!("This one can take quite a while to run!");
    let mut guess: Vec<u8> = vec![0; 20];

    for i in 0..guess.len() {
        println!("True:  {}", bytes_to_hex(&h));
        let mut bs = vec![];
        for _ in 0..20 {
            let b = (0..255_u8)
                .map(|x| {
                    guess[i] = x;

                    let start = Utc::now();
                    match insecure_compare(b"file", &guess, &key) {
                        Auth::Valid => println!("Guess is valid!"),
                        Auth::Invalid => {}
                    };
                    let stop = Utc::now();

                    let d = (stop - start).num_microseconds().unwrap();
                    (x, d)
                })
                .collect::<Vec<(u8, i64)>>();
            bs.extend_from_slice(&b);
        }
        let b = get_max_b(&bs);

        guess[i] = b;
        println!("Guess: {}", bytes_to_hex(&guess[..i]));
    }
    println!("Guess: {}", bytes_to_hex(&guess));
    assert_eq!(h, guess);

    Ok(())
}

fn get_max_b(b: &[(u8, i64)]) -> u8 {
    let mut results = vec![vec![]; 255];
    for (v, t) in b {
        results[*v as usize].push(*t);
        results[*v as usize].sort();
    }
    //    println!("Results: {:?}", results);
    results
        .iter()
        .map(|x| x[x.len() / 2])
        .position_max()
        .unwrap() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_check() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let target = hex_to_bytes("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9").unwrap();

        let hmac = sha1_hmac(key, message);
        assert_eq!(hmac, target);
    }
}
