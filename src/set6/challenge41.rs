//! Implement unpadded message recovery oracle
//!
//! Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring".
//! Here's why.
//!
//! Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages
//! which (again: Javascript) aren't padded before encryption at all.
//!
//! You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit
//! the same message twice: let's say the server keeps hashes of previous messages for some
//! liveness interval, and that the message has an embedded timestamp:
//!
//! {
//!   time: 1356304276,
//!   social: '555-55-5555',
//! }
//! You'd like to capture other people's messages and use the server to decrypt them. But when you
//! try, the server takes the hash of the ciphertext and uses it to reject the request. Any bit you
//! flip in the ciphertext irrevocably scrambles the decryption.
//!
//! This turns out to be trivially breakable:
//!
//! Capture the ciphertext C
//! Let N and E be the public modulus and exponent respectively
//! Let S be a random number > 1 mod N. Doesn't matter what.
//! Now:
//! C' = ((S**E mod N) C) mod N
//! Submit C', which appears totally different from C, to the server, recovering P', which appears
//! totally different from P
//! Now:
//!           P'
//!     P = -----  mod N
//!           S
//! Oops!
//!
//! Implement that attack.
//!
//! Careful about division in cyclic groups.
//! Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N. So
//! you'll need a modinv() function.

use crate::utils::*;
use num_bigint::{BigInt, RandBigInt, Sign};
use rand::thread_rng;

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    let secret = random_bytes(16, 32, &mut rng);
    println!("Original secret: {}", bytes_to_hex(&secret));
    let e: BigInt = 3.into();
    let (et, n) = et_n(256, &e);
    let d = invmod(&e, &et);
    let public_key = (e.clone(), n.clone());
    let private_key = (d, n.clone());

    let encrypted = rsa_encrypt(&public_key, &secret);
    let encrypted_num = BigInt::from_bytes_be(Sign::Plus, &encrypted);
    let s = rng.gen_bigint_range(&2.into(), &n);

    let encryptedp = (s.modpow(&e, &n) * encrypted_num) % &n;

    let ppbytes = rsa_decrypt(&private_key, &encryptedp.to_bytes_be().1);
    let pp = BigInt::from_bytes_be(Sign::Plus, &ppbytes);
    let sinv = invmod(&s, &n);
    let p = (pp * sinv) % &n;

    let pbytes = p.to_bytes_be().1;
    println!("Derived secret:  {}", bytes_to_hex(&pbytes));
    assert_eq!(pbytes, secret);

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn message_recovery() {
        main().unwrap();
    }
}
