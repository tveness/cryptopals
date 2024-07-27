//! Implement RSA
//!
//! There are two annoying things about implementing RSA. Both of them involve key generation; the
//! actual encryption/decryption in RSA is trivial.
//!
//! First, you need to generate random primes. You can't just agree on a prime ahead of time, like
//! you do in DH. You can write this algorithm yourself, but I just cheat and use OpenSSL's BN
//! library to do the work.
//!
//! The second is that you need an "invmod" operation (the multiplicative inverse), which is not an
//! operation that is wired into your language. The algorithm is just a couple lines, but I always
//! lose an hour getting it to work.
//!
//! I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod
//! algorithm working.
//!
//! Now:
//!
//! Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a
//! prime table. Call them "p" and "q".
//! Let n be p * q. Your RSA math is modulo n.
//! Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
//! Let e be 3.
//! Compute d = invmod(e, et). invmod(17, 3120) is 2753.
//! Your public key is [e, n]. Your private key is [d, n].
//! To encrypt: c = m**e%n. To decrypt: m = c**d%n
//! Test this out with a number, like "42".
//! Repeat with bignum primes (keep e=3).
//! Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x"
//! on the front of it to turn it into a number. The math cares not how stupidly you feed it
//! strings.

use crate::utils::*;
use num_bigint::{BigInt, ToBigInt};
use num_integer::Integer;
use num_traits::One;
use num_traits::Zero;
use openssl::bn::BigNum;

fn prime(bits: i32) -> BigInt {
    let mut big = BigNum::new().unwrap();
    big.generate_prime(bits, false, None, None).unwrap();
    let ps = big.to_dec_str().unwrap();
    let p: BigInt = ps.parse().unwrap();
    p
}

pub fn invmod<T: ToBigInt>(a: &T, m: &T) -> BigInt {
    let m_orig = m.to_bigint().unwrap();
    let a = a.to_bigint().unwrap();

    if m_orig.is_one() {
        return One::one();
    }

    let (mut a, mut m, mut x, mut inv) = (a, m_orig.clone(), BigInt::zero(), BigInt::one());

    while a > One::one() {
        let (div, rem) = a.div_rem(&m);
        inv -= div * &x;
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }

    while inv < Zero::zero() {
        inv += &m_orig;
    }

    inv
}

pub fn et_n(bits: i32, e: &BigInt) -> (BigInt, BigInt) {
    let mut et: BigInt = 0.into();
    let mut n = 0.into();
    while &et % e == Zero::zero() {
        let (p, q) = (prime(bits), prime(bits));
        et = (&p - 1) * (&q - 1);
        n = &p * &q;
    }
    (et, n)
}

pub fn main() -> Result<()> {
    let bits = 256;
    let e: BigInt = 3.into();

    let (et, n) = et_n(bits, &e);

    let d = invmod(&e, &et);

    println!("d: {d}, e: {e}, et: {et}");
    println!("e*d % et = {}", (&e * &d) % &et);
    println!("invmod(17. 3120): {}", invmod(&17, &3120));

    let public_key = (e, n.clone());
    let private_key = (d, n);

    // NB secret as an integer must be less than n!
    let secret = b"super secret message";
    println!("Secret: {}", bytes_to_hex(secret));

    let encrypted = rsa_encrypt(&public_key, secret);
    println!("Encrypted: {}", bytes_to_hex(&encrypted));

    let decrypted = rsa_decrypt(&private_key, &encrypted);
    println!("Decrypted: {}", bytes_to_hex(&decrypted));

    assert_eq!(secret.to_vec(), decrypted);

    Ok(())
}

pub fn rsa_encrypt(public_key: &(BigInt, BigInt), data: &[u8]) -> Vec<u8> {
    let data = BigInt::from_bytes_be(num_bigint::Sign::Plus, data);

    let encrypted = data.modpow(&public_key.0, &public_key.1);
    encrypted.to_bytes_be().1.to_vec()
}

pub fn rsa_decrypt(private_key: &(BigInt, BigInt), data: &[u8]) -> Vec<u8> {
    let data = BigInt::from_bytes_be(num_bigint::Sign::Plus, data);

    let decrypted = data.modpow(&private_key.0, &private_key.1);
    decrypted.to_bytes_be().1.to_vec()
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn invmod_test() {
        let target: BigInt = 1969.into();
        let im = invmod(&42, &2017);
        assert_eq!(im, target);

        let target: BigInt = 2753.into();
        let im = invmod(&17, &3120);
        assert_eq!(im, target);
    }

    #[test]
    fn rsa() {
        main().unwrap();
    }
}
