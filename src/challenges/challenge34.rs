use crate::dh::nist_params;
use crate::utils::*;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use openssl::hash::{Hasher, MessageDigest};
use rand::thread_rng;

// What happens here?
//
// A has p, g, A = (g**a) mod p
//
// B receives p, g, p
// B has p, g, B = (g**b) mod p
// B now thinks the shared secret is p**b mod p = 0
//
// A thinks the shared secret key is p**a mod p = 0
//
// Uh oh...

pub fn main() -> Result<()> {
    let (p, g) = nist_params();

    let mut rng = thread_rng();
    let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    println!("a: {a}, b: {b}");

    let pub_a: BigInt = g.modpow(&a, &p);
    let pub_b: BigInt = g.modpow(&b, &p);
    println!("A: {pub_a}, B: {pub_b}");

    // Injected parameters!
    let s_a: BigInt = p.modpow(&a, &p);
    let s_b: BigInt = p.modpow(&b, &p);
    println!("s: {s_a}");
    assert_eq!(s_a, s_b);

    let s_bytes = s_a.to_bytes_be().1;
    let mut h = Hasher::new(MessageDigest::sha256())?;
    h.update(&s_bytes)?;

    let shared_key = h.finish()?.to_vec();

    let mut h = Hasher::new(MessageDigest::sha256())?;
    h.update(&[0])?;
    let m_key = h.finish()?.to_vec();

    println!("Shared key:    {}", bytes_to_hex(&shared_key));
    println!("M deduces key: {}", bytes_to_hex(&m_key));

    assert_eq!(shared_key, m_key);

    // Send some secret messages and M can intercept

    Ok(())
}
