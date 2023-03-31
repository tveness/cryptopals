//! Implement an E=3 RSA Broadcast attack
//!
//! Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt
//! without padding.
//!
//! Assume you can be coerced into encrypting the same plaintext three times, under three different
//! public keys. You can; it's happened.
//!
//! Then an attacker can trivially decrypt your message, by:
//!
//! Capturing any 3 of the ciphertexts and their corresponding pubkeys
//! Using the CRT to solve for the number represented by the three ciphertexts (which are residues
//! mod their respective pubkeys)
//! Taking the cube root of the resulting number
//! The CRT says you can take any number and represent it as the combination of a series of
//! residues mod a series of moduli. In the three-residue case, you have:
//!
//! result =
//!   (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
//!   (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
//!   (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
//! where:
//!
//!  c_0, c_1, c_2 are the three respective residues mod
//!  n_0, n_1, n_2
//!
//!  m_s_n (for n in 0, 1, 2) are the product of the moduli
//!  EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
//!
//!  N_012 is the product of all three moduli
//! To decrypt RSA using a simple cube root, leave off the final modulus operation; just take the
//! raw accumulated result and cube-root it.

use crate::utils::*;
use num_bigint::BigInt;

pub fn main() -> Result<()> {
    let e: BigInt = 3.into();

    let (et1, n1) = et_n(256, &e);
    let d1 = invmod(&e, &et1);
    let public_key1 = (e.clone(), n1.clone());
    let _private_key1 = (d1, n1.clone());

    let (et2, n2) = et_n(256, &e);
    let d2 = invmod(&e, &et2);
    let public_key2 = (e.clone(), n2.clone());
    let _private_key2 = (d2, n2.clone());

    let (et3, n3) = et_n(256, &e);
    let d3 = invmod(&e, &et3);
    let public_key3 = (e, n3.clone());
    let _private_key3 = (d3, n3.clone());

    let secret = b"super secret";
    let secret_num = BigInt::from_bytes_be(num_bigint::Sign::Plus, secret);

    let c1 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &rsa_encrypt(&public_key1, secret));
    let c2 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &rsa_encrypt(&public_key2, secret));
    let c3 = BigInt::from_bytes_be(num_bigint::Sign::Plus, &rsa_encrypt(&public_key3, secret));

    let ms_1 = &n2 * &n3;
    let ms_2 = &n1 * &n3;
    let ms_3 = &n1 * &n2;

    // CRT:
    // x = a1 mod n1
    // x = a2 mod n2
    // x = a3 mod n3
    //
    // Here we have the ciphertexts are
    // m**3 = c1 mod n1
    // m**3 = c2 mod n2
    // m**3 = c3 mod n3

    let result: BigInt = (&c1 * &ms_1 * invmod(&ms_1, &n1)
        + &c2 * &ms_2 * invmod(&ms_2, &n2)
        + &c3 * &ms_3 * invmod(&ms_3, &n3))
        % (&n1 * &n2 * &n3);
    let cuberoot = result.cbrt();
    println!("Cube root: {cuberoot}");
    println!("Secret:    {}", secret_num);
    assert_eq!(secret_num, cuberoot);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crt() {
        main().unwrap();
    }
}
