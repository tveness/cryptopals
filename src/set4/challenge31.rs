//! Implement and break HMAC-SHA1 with an artificial timing leak
//!
//! The psuedocode on Wikipedia should be enough. HMAC is very easy.
//!
//! Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application
//! that has a URL that takes a "file" argument and a "signature" argument, like so:
//!
//! http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
//! Have the server generate an HMAC key, and then verify that the "signature" on incoming requests
//! is valid for "file", using the "==" operator to compare the valid MAC for a file with the
//! "signature" parameter (in other words, verify the HMAC the way any normal programmer would
//! verify it).
//!
//! Write a function, call it "insecure_compare", that implements the == operation by doing
//! byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).
//!
//! In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).
//!
//! Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that
//! the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.
//!
//! Using the timing leak in this application, write a program that discovers the valid MAC for any
//! file.
//!
//! Why artificial delays?
//! Early-exit string compares are probably the most common source of cryptographic timing leaks,
//! but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in C,
//! C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play with
//! attacking real-world timing leaks, you have to start writing low-level timing code. We're
//! keeping things cryptographic in these challenges.

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
    let delay = 10;
    for (i, v) in true_hmac.iter().enumerate() {
        if hmac[i] != *v {
            return Auth::Invalid;
        }
        std::thread::sleep(Duration::from_millis(delay));
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
        for _ in 0..5 {
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
    let mut results = vec![0; b.len()];
    for (v, t) in b {
        results[*v as usize] += *t;
    }
    results.iter().position_max().unwrap() as u8
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
