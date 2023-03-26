//! Implement Diffie-Hellman
//!
//! For one of the most important algorithms in cryptography this exercise couldn't be a whole lot
//! easier.
//!
//! Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain
//! it. Just do what I do.
//!
//! Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power
//! mode 37 --- A = (g**a) % p.
//!
//! Do the same for "b" and "B".
//!
//! "A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a"
//! power mod 37 --- s = (B**a) % p.
//!
//! Do the same with A**b, check that you come up with the same "s".
//!
//! To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to
//!     create a key for encrypting and a key for a MAC).
//!
//! Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are
//! parameters NIST likes:
//!
//! p:
//! ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
//! e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
//! 3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
//! 6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
//! 24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
//! c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
//! bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
//! fffffffffffff
//!  
//! g: 2
//! This is very easy to do in Python or Ruby or other high-level languages that auto-promote
//! fixnums to bignums, but it isn't "hard" anywhere.
//!
//! Note that you'll need to write your own modexp (this is blackboard math, don't freak out),
//! because you'll blow out your bignum library raising "a" to the 1024-bit-numberth power. You can
//! find modexp routines on Rosetta Code for most languages.

use crate::utils::*;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::Zero;
use openssl::hash::{Hasher, MessageDigest};
use rand::thread_rng;

// BigInt has a modular exponentian built in already
/*
fn modexp<T: ToBigInt>(base: &T, exp: &T, modulus: &T) -> BigInt {
    let mut exp = exp.to_bigint().unwrap();
    let mut base = base.to_bigint().unwrap();
    let modulus = modulus.to_bigint().unwrap();

    base = base % &modulus;
    match exp == Zero::zero() {
        true => return One::one(),
        false => {}
    };

    let mut result = One::one();
    loop {
        if &exp % 2 == One::one() {
            result *= &base;
            result %= &modulus;
        }

        if exp == One::one() {
            return result;
        }

        // Exponent must now be even, so halve this, and square base
        exp /= 2;
        // Base essentially runs through all of the bits in the binary representation of the
        // number. base * base doubles the exponent, and so we do all the mulitpications until exp
        // is one
        base *= base.clone();
        base %= &modulus;
    }
}
*/

pub fn main() -> Result<()> {
    //let p: BigInt = 37.into();
    //let g: BigInt = 5.into();

    let p = BigInt::from_bytes_be(Sign::Plus,&hex_to_bytes("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap());
    let g: BigInt = 2.into();
    let mut rng = thread_rng();
    let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    println!("a: {a}, b: {b}");

    let pub_a: BigInt = g.modpow(&a, &p);
    let pub_b: BigInt = g.modpow(&b, &p);
    println!("A: {pub_a}, B: {pub_b}");

    let s_a: BigInt = pub_b.modpow(&a, &p);
    let s_b: BigInt = pub_a.modpow(&b, &p);
    println!("s: {s_a}");
    assert_eq!(s_a, s_b);

    let s_bytes = s_a.to_bytes_be().1;
    let mut h = Hasher::new(MessageDigest::sha256())?;
    h.update(&s_bytes)?;

    let key = h.finish()?;
    println!("Shared key: {}", bytes_to_hex(&key));

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn small_ints() {
        let p: BigInt = 37.into();
        let g: BigInt = 5.into();

        let mut rng = thread_rng();
        let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
        let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
        println!("a: {a}, b: {b}");

        let pub_a: BigInt = g.modpow(&a, &p);
        let pub_b: BigInt = g.modpow(&b, &p);
        println!("A: {pub_a}, B: {pub_b}");

        let s_a: BigInt = pub_b.modpow(&a, &p);
        let s_b: BigInt = pub_a.modpow(&b, &p);
        println!("s: {s_a}, s: {s_b}");
        assert_eq!(s_a, s_b);
    }

    #[test]
    fn big_ints() {
        main().unwrap();
    }
}
