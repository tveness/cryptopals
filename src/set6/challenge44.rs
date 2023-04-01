//! DSA nonce recovery from repeated nonce
//!
//! Cryptanalytic MVP award.
//! This attack (in an elliptic curve group) broke the PS3. It is a great, great attack.
//!
//! In this file find a collection of DSA-signed messages. (NB: each msg has a trailing space.)
//!
//! These were signed under the following pubkey:
//!
//! y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
//!     13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
//!     5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
//!     f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
//!     f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
//!     2971c3de5084cce04a2e147821
//! (using the same domain parameters as the previous exercise)
//!
//! It should not be hard to find the messages for which we have accidentally used a repeated "k".
//! Given a pair of such messages, you can discover the "k" we used with the following formula:
//!
//!          (m1 - m2)
//!      k = --------- mod q
//!          (s1 - s2)
//! 9th Grade Math: Study It!
//! If you want to demystify this, work out that equation from the original DSA equations.
//!
//! Basic cyclic group math operations want to screw you
//! Remember all this math is mod q; s2 may be larger than s1, for instance, which isn't a problem
//! if you're doing the subtraction mod q. If you're like me, you'll definitely lose an hour to
//! forgetting a paren or a mod q. (And don't forget that modular inverse function!)
//! What's my private key? Its SHA-1 (from hex) is:
//!
//!    ca8f6f7c66fa362d40760d135b763eb8527d3d52

// m1 = H(msg1), m2 = H(msg2)
// DSA maths:
// s = k^{-1} H(M) + xr mod q
// ks = H(M) + kxr mod q
// => k(s1 - s2) = m1 - m2 mod q, as k and therefore r are the same
// => k = (m1 - m2) / (s1 - s2) mod q

use num_bigint::BigInt;
use num_traits::Num;
use openssl::sha::sha1;

use super::challenge43::Params;
use crate::{
    set6::challenge43::{get_x_from_k, Sig},
    utils::*,
};

#[derive(Debug, Clone)]
struct Quad {
    message: String,
    s: BigInt,
    r: BigInt,
    m: BigInt,
}

pub fn main() -> Result<()> {
    let params = Params::default();
    let y = BigInt::from_str_radix(
        "2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
     13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
     5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
     f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
     f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
     2971c3de5084cce04a2e147821",
        16,
    )
    .unwrap();

    // First read the data from the file into triplets
    let big_str = std::fs::read_to_string("./data/44.txt").unwrap();
    let mut quads: Vec<Quad> = vec![];
    let splits: Vec<&str> = big_str.split('\n').collect();
    for quad in splits[..].chunks(4) {
        let msg = quad[0].trim_start_matches("msg: ");
        let s = quad[1].trim_start_matches("s: ").trim();
        let r = quad[2].trim_start_matches("r: ").trim();
        let m = quad[3].trim_start_matches("m: ").trim();

        let r = BigInt::from_str_radix(r, 10).unwrap();
        let q = Quad {
            message: msg.to_string(),
            r,
            s: BigInt::from_str_radix(s, 10).unwrap(),
            m: BigInt::from_str_radix(m, 16).unwrap(),
        };
        quads.push(q);
    }

    let mut pairs: Vec<Vec<Quad>> = vec![];
    // Read all data, now find two with the same nonce k
    for (i, qi) in quads.iter().enumerate() {
        // Skip means we don't find all pairs twice
        for (j, qj) in quads.iter().skip(i).enumerate() {
            if i != j && qi.r == qj.r && qi.message != qj.message {
                pairs.push(vec![qi.clone(), qj.clone()]);
            }
        }
    }

    // For each pair, find the k
    for p in pairs {
        println!("Pair: {p:?}");
        //let m1 = BigInt::from_bytes_be(Sign::Plus, p[0].message.as_bytes());
        //let m2 = BigInt::from_bytes_be(Sign::Plus, p[1].message.as_bytes());
        let mut mdiff = (&p[0].m - &p[1].m) % &params.q;
        while mdiff < 0.into() {
            mdiff += &params.q;
        }
        let mut sdiff: BigInt = &p[0].s - &p[1].s;
        while sdiff < 0.into() {
            sdiff += &params.q;
        }
        let sdiffinv = invmod(&sdiff, &params.q);
        let k = (mdiff * sdiffinv) % &params.q;
        println!("k: {k}");
        // Check that r is indeed the same

        let r = params.g.modpow(&k, &params.p) % &params.q;
        println!("r derived = {r}");
        println!("r true = {}", p[1].r);

        // Now get private key from this k again
        let sig = Sig {
            s: p[0].s.clone(),
            r: p[0].r.clone(),
        };

        let x = get_x_from_k(&sig, &k, &params, p[0].message.as_bytes());
        println!("x: {x}");
        let derived_y = params.g.modpow(&x, &params.p);
        assert_eq!(derived_y, y);

        let x_str = x.to_str_radix(16);
        let fingerprint = sha1(x_str.as_bytes());
        let fingerprint_hex = bytes_to_hex(&fingerprint);
        println!("Fingerprint: {fingerprint_hex}");

        assert_eq!(fingerprint_hex, "ca8f6f7c66fa362d40760d135b763eb8527d3d52");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_private_key() {
        main().unwrap();
    }
}
