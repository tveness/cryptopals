//! Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
//!
//! Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have
//! to do the network part of this if you don't want; just simulate that. The protocol is:
//!
//! A->B
//! Send "p", "g", "A"
//! B->A
//! Send "B"
//! A->B
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//! B->A
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//! (In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC
//! with random IVs appended or prepended to the message).
//!
//! Now implement the following MITM attack:
//!
//! A->M
//! Send "p", "g", "A"
//! M->B
//! Send "p", "g", "p"
//! B->M
//! Send "B"
//! M->A
//! Send "p"
//! A->M
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//! M->B
//! Relay that to B
//! B->M
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//! M->A
//! Relay that to A
//! M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over
//! the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that
//! does to the predictability of the key.
//!
//! Decrypt the messages from M's vantage point as they go by.
//!
//! Note that you don't actually have to inject bogus parameters to make this attack work; you
//! could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But
//! do the parameter injection attack; it's going to come up again.

use crate::dh::nist_params;
use crate::utils::*;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use openssl::hash::{Hasher, MessageDigest};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

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

    let shared_key = &h.finish()?[..16].to_vec();

    let mut h = Hasher::new(MessageDigest::sha256())?;
    h.update(&[0])?;
    let m_key = &h.finish()?[..16].to_vec();

    println!("Shared key:    {}", bytes_to_hex(shared_key));
    println!("M deduces key: {}", bytes_to_hex(m_key));

    println!("Shared key length: {}", shared_key.len());
    assert_eq!(shared_key, m_key);

    println!("=== BEGINNING COMMUNICATIONS ===");
    let a_iv = random_key(16, &mut rng);
    let a_plaintext: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(u8::from)
        .collect();
    println!("A plaintext: {:?}", std::str::from_utf8(&a_plaintext)?);
    let a_plaintext = pkcs7_pad(&a_plaintext, 16);
    let a_ciphertext = cbc_encrypt(&a_plaintext, shared_key, Some(&a_iv))?;
    let a_message = (a_iv, a_ciphertext);

    let m_decrypted = cbc_decrypt(&a_message.1, m_key, Some(&a_message.0))?;
    assert_eq!(a_plaintext, m_decrypted);

    println!(
        "M intercepted A: {}",
        std::str::from_utf8(&pkcs7_unpad(&m_decrypted).unwrap()).unwrap()
    );

    let b_decrypted = cbc_decrypt(&a_message.1, shared_key, Some(&a_message.0))?;
    let b_iv = random_key(16, &mut rng);
    let b_ciphertext = cbc_encrypt(&b_decrypted, shared_key, Some(&b_iv))?;
    let b_message = (b_iv, b_ciphertext);

    let m_decrypted = cbc_decrypt(&b_message.1, m_key, Some(&b_message.0))?;
    println!(
        "M intercepted B: {}",
        std::str::from_utf8(&pkcs7_unpad(&m_decrypted)?).unwrap()
    );
    // Send some secret messages and M can intercept
    assert_eq!(a_plaintext, m_decrypted);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paramter_injection() {
        main().unwrap();
    }
}
