//! RSA parity oracle
//!
//! When does this ever happen?
//! This is a bit of a toy problem, but it's very helpful for understanding what RSA is doing (and
//! also for why pure number-theoretic encryption is terrifying). Trust us, you want to do this
//! before trying the next challenge. Also, it's fun.
//! Generate a 1024 bit RSA key pair.
//!
//! Write an oracle function that uses the private key to answer the question "is the plaintext of
//! this message even or odd" (is the last bit of the message 0 or 1). Imagine for instance a
//! server that accepted RSA-encrypted messages and checked the parity of their decryption to
//! validate them, and spat out an error if they were of the wrong parity.
//!
//! Anyways: function returning true or false based on whether the decrypted plaintext was even or odd, and nothing else.
//!
//! Take the following string and un-Base64 it in your code (without looking at it!) and encrypt it to the public key, creating a ciphertext:
//!
//! VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==
//! With your oracle function, you can trivially decrypt the message.
//!
//! Here's why:
//!
//! RSA ciphertexts are just numbers. You can do trivial math on them. You can for instance
//! multiply a ciphertext by the RSA-encryption of another number; the corresponding plaintext will
//! be the product of those two numbers.
//! If you double a ciphertext (multiply it by (2**e)%n), the resulting plaintext will (obviously)
//! be either even or odd.
//! If the plaintext after doubling is even, doubling the plaintext didn't wrap the modulus --- the
//! modulus is a prime number. That means the plaintext is less than half the modulus.
//! You can repeatedly apply this heuristic, once per bit of the message, checking your oracle
//! function each time.
//!
//! Your decryption function starts with bounds for the plaintext of [0,n].
//!
//! Each iteration of the decryption cuts the bounds in half; either the upper bound is reduced by
//! half, or the lower bound is.
//!
//! After log2(n) iterations, you have the decryption of the message.
//!
//! Print the upper bound of the message as a string at each iteration; you'll see the message
//! decrypt "hollywood style".
//!
//! Decrypt the string (after encrypting it to a hidden private key) above.

use num_bigint::{BigInt, Sign};

use crate::utils::*;

#[derive(Clone, Debug)]
pub struct Key {
    pub key: BigInt,
    pub modulus: BigInt,
}

enum Parity {
    Even,
    Odd,
}

fn parity_oracle(ciphertext_num: &BigInt, private_key: &Key) -> Parity {
    let plaintext = ciphertext_num.modpow(&private_key.key, &private_key.modulus);

    let zero: BigInt = 0.into();
    let two: BigInt = 2.into();
    match (plaintext % two) == zero {
        true => Parity::Even,
        false => Parity::Odd,
    }
}
#[derive(Debug)]
struct Range {
    pub lower: BigInt,
    pub upper: BigInt,
}
fn rsa(key: &Key, number: &BigInt) -> BigInt {
    number.modpow(&key.key, &key.modulus)
}

pub fn main() -> Result<()> {
    let bits = 512;
    let e: BigInt = 3.into();
    let (et, n) = et_n(bits, &e);
    let d = invmod(&e, &et);

    let public_key = Key {
        key: e,
        modulus: n.clone(),
    };
    let private_key = Key { key: d, modulus: n };

    let secret_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==";
    let secret = decode_b64_str(secret_b64).unwrap();
    let secret_num = BigInt::from_bytes_be(Sign::Plus, &secret);

    // Ciphertext is encrypted with the public key
    let ciphertext = rsa(&public_key, &secret_num);

    // All the work is in the deduce function, which only uses the private key to pass to the oracle
    let de = deduce(&ciphertext, &public_key, &private_key);
    println!("Secret number: {}", secret_num);
    println!("Deduce number: {}", de);
    assert_eq!(secret_num, de);

    // We now have the secret, and simply have to convert it back to a str
    let secret_deduced = de.to_bytes_be().1;
    println!(
        "Deduced secret: {}",
        std::str::from_utf8(&secret_deduced).unwrap()
    );

    Ok(())
}

fn deduce(ciphertext: &BigInt, public_key: &Key, private_key: &Key) -> BigInt {
    // This is an exclusive range
    let mut range = Range {
        lower: 0.into(),
        upper: public_key.modulus.clone(),
    };
    let mut running_ciphertext = ciphertext.clone();
    let two: BigInt = 2.into();
    let multiplier = two.modpow(&public_key.key, &public_key.modulus);
    let mut range_multiplier: BigInt = 1.into();
    let mut running: BigInt = 1.into();
    let one: BigInt = 1.into();

    // Explanation
    //
    // Each additional step gets us one more digit of accuracy in the binary
    // fractional representation of the secret number
    // The first step puts the unknown quantity either in (0,floor(p/2)) or (floor(p/2)+1,p)
    // After n steps, the window is of a size p / 2**n below the upper bound
    // If the answer was in the upper half, the upper bound stays the same, so
    // j/2**n -> 2j/2**(n+1)
    // If the answer was in the lower half, the upper bound decreases by half the accuracy window
    // i.e j/2**n -> 2j-1 / 2**(n+1)

    while &range.upper - &range.lower != one {
        running_ciphertext *= &multiplier;
        running_ciphertext %= &public_key.modulus;
        range_multiplier *= &two;

        match parity_oracle(&running_ciphertext, private_key) {
            // Lower half i.e. < midpoint
            Parity::Even => {
                running *= &two;
                running -= &one;
                // Upper end of range is fraction we are bounded above by * modulus + 1 (for ceil)
                range.upper = 1 + (&running * &public_key.modulus) / &range_multiplier;
            }

            // Upper half
            Parity::Odd => {
                running *= &two;
                // Lower end of range is upper - size of accuracy window - 1 (for floor)
                range.lower = &range.upper - 1 - &public_key.modulus / &range_multiplier;
            }
        }
    }
    range.lower
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_deduction() {
        let e: BigInt = 3.into();
        let p: BigInt = 17.into();
        let q: BigInt = 11.into();
        let et = (&p - 1) * (&q - 1);
        let d = invmod(&e, &et);
        let n = &p * &q;
        // n = 187

        let public_key = Key {
            key: e.clone(),
            modulus: n.clone(),
        };
        let private_key = Key {
            key: d.clone(),
            modulus: n.clone(),
        };
        for secret_num in 0..187 {
            let secret_num: BigInt = secret_num.into();
            // Encrypt secret
            let ciphertext = rsa(&public_key, &secret_num);
            let deduced = deduce(&ciphertext, &public_key, &private_key);
            println!("Secret num:  {}", secret_num);
            println!("Deduced num: {}", deduced);
            assert_eq!(secret_num, deduced);
        }
    }
}
