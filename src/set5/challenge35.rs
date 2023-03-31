//! Implement DH with negotiated groups, and break with malicious "g" parameters
//!
//! A->B
//! Send "p", "g"
//! B->A
//! Send ACK
//! A->B
//! Send "A"
//! B->A
//! Send "B"
//! A->B
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
//! B->A
//! Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
//! Do the MITM attack again, but play with "g". What happens with:
//!
//!     g = 1
//!     g = p
//!     g = p - 1
//! Write attacks for each.
//!
//! When does this ever happen?
//! Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.

use crate::dh::nist_params;
use crate::utils::*;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use openssl::hash::{Hasher, MessageDigest};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

// What happens here?
//
// A has p, g, A = (g**a) mod p
//
// B receives p, g', p
//
// g' = 1 => B = (1**b) mod p = 1 => s_A = B**a mod p = 1, s_B = A**b = very different
// g' = p => B = (p**b) mod p = 0 => s_A = B**a mod p = 0
// g' = p-1 => B = (p-1)**(b) mod p = (p-1), b odd, 1 b even => s_a = (-1)*(a+b) mod p, s_B = A**b
// = very different
//
// In all of these cases M will know the secret key A uses by simply changing the g B see
// But A and B will *not* have a shared secret
//

pub fn main() -> Result<()> {
    let (p, g) = nist_params();

    let mut rng = thread_rng();
    let a: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    let b: BigInt = rng.gen_bigint_range(&Zero::zero(), &p);
    println!("a: {a}, b: {b}");
    let gbs: [BigInt; 3] = [1.into(), p.clone(), p.clone() - 1];

    for gb in &gbs {
        println!("Injected g for B!");

        let pub_a: BigInt = g.modpow(&a, &p);
        let pub_b: BigInt = gb.modpow(&b, &p);
        println!("A: {pub_a}, B: {pub_b}");

        // Injected parameters!
        let s_a: BigInt = pub_b.modpow(&a, &p);
        let s_b: BigInt = pub_a.modpow(&b, &p);
        println!("s_a: {s_a}");
        println!("s_b: {s_b}");

        let s_bytes = s_a.to_bytes_be().1;
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(&s_bytes)?;

        let shared_key = &h.finish()?[..16].to_vec();

        let mut h = Hasher::new(MessageDigest::sha256())?;
        // g' = 1 => B = (1**b) mod p = 1 => s_A = B**a mod p = 1, s_B = A**b = very different
        // g' = p => B = (p**b) mod p = 0 => s_A = B**a mod p = 0
        // g' = p-1 => B = (p-1)**(b) mod p = (p-1), b odd, 1 b even => s_a = (-1)*(a+b) mod p, s_B = A**b
        let one: BigInt = One::one();
        let zero: BigInt = Zero::zero();
        let pms: BigInt = p.clone() - 1;
        let m_s_a: BigInt = match gb {
            _ if gb == &one => {
                println!("s_a should be: 1");

                one.clone()
            }
            _ if gb == &p => {
                println!("s_a should be: 0");
                zero.clone()
            }
            _ if gb == &pms => {
                println!("s_a should be: pm 1");
                pms
            }
            _ => panic!("Not covered"),
        };

        h.update(&m_s_a.to_bytes_be().1)?;
        let m_key = &h.finish()?[..16].to_vec();

        println!("Shared key:    {}", bytes_to_hex(shared_key));

        println!("=== BEGINNING COMMUNICATIONS ===");
        let a_iv = random_key(16, &mut rng);
        let a_plaintext: Vec<u8> = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(22)
            .map(u8::from)
            .collect();
        println!("A plaintext: {}", std::str::from_utf8(&a_plaintext)?);
        let a_plaintext = pkcs7_pad(&a_plaintext, 16);
        let a_ciphertext = cbc_encrypt(&a_plaintext, shared_key, Some(&a_iv))?;
        let a_message = (a_iv, a_ciphertext);

        let m_decrypted = cbc_decrypt(&a_message.1, m_key, Some(&a_message.0))?;

        // 50/50 chance sign is wrong on last g
        let m_plaintext = match pkcs7_unpad(&m_decrypted) {
            Ok(x) => x,
            Err(_) => {
                let mut h = Hasher::new(MessageDigest::sha256())?;
                let one: BigInt = One::one();
                let m_s_a = one.clone();

                h.update(&m_s_a.to_bytes_be().1)?;
                let m_key = &h.finish()?[..16].to_vec();
                let m_decrypted = cbc_decrypt(&a_message.1, m_key, Some(&a_message.0))?;
                pkcs7_unpad(&m_decrypted)?
            }
        };
        println!(
            "M intercepted A: {}",
            std::str::from_utf8(&m_plaintext).unwrap()
        );
        let a_unpadded = pkcs7_unpad(&a_plaintext)?;

        assert_eq!(a_unpadded, m_plaintext);
    }
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
