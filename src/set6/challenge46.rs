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
use num_traits::{One, Zero};

use crate::utils::*;

#[derive(Debug)]
struct Key {
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
    let secret = decode_b64_str(&secret_b64).unwrap();
    let secret_num = BigInt::from_bytes_be(Sign::Plus, &secret);

    let ciphertext = rsa(&private_key, &secret_num);
    // We are now all set up to begin the decryption
    // We want to build a running list of the value of each bit
    // When we multiply by 2**e, even parity tells us it didn't wrap, odd parity tells us it did wrap
    // When we multiply by 4**e, then the same is true again. Let's check this in a simple case
    // p = 29
    // plaintext = 3
    // ciphertext = 27 = 27
    // original range: [0,28]
    // double plaintext => 6 => even [0,14]
    // double plaintext => 12 => even [0,7]
    // double plaintext => 24 => even [0,3]
    // double plaintext => 48 => 21 => odd [1,3]
    // double plaintext => 42 => 13 => odd [2,3]
    // double plaintext => 26 => even [3,3]
    //
    //
    // Mock up v small
    // p = 17, q= 11
    // e = 3
    // et = (p-1)(q-1) = 16*10 = 160
    // d = invmod(3,160) = 187
    // n = 187
    let e: BigInt = 3.into();
    let p: BigInt = 17.into();
    let q: BigInt = 11.into();
    let et = (&p - 1) * (&q - 1);
    let d = invmod(&e, &et);
    let n = &p * &q;
    // Now run this by hand
    // plaintext = 3 => [0,186]
    // 6 [0,93]
    // 12 [0,46]
    // 24 [0,23]
    // 48 [0,11]
    // 96 [0,5]
    // 192 -> 5 [3,5]
    // 10 [3,4]
    // 20 [3,3]

    // It's really only the bits which are wrapping around
    // So we need to keep track of which bit we're on
    // 111111111
    // 000000000
    // 19 [0,93], [94,186]
    //
    // [0,186]
    // First round [0,93] [94,186]
    // => [186 -> 186 - 186/2 +1]
    //
    //
    // lower + (upper-lower)/2
    // 38 => [0,93], [0, 46], [47,93]
    let public_key = Key {
        key: e.clone(),
        modulus: n.clone(),
    };
    let private_key = Key {
        key: d.clone(),
        modulus: n.clone(),
    };
    for secret_num in 10..187 {
        let secret_num: BigInt = secret_num.into();

        //println!("modinv: {}", d);
        println!("Secret number: {}", secret_num);
        let ciphertext = rsa(&public_key, &secret_num);
        // This is an exclusive range
        let mut range = Range {
            lower: 0.into(),
            upper: public_key.modulus.clone(),
        };
        let mut running_ciphertext = ciphertext.clone();
        let two: BigInt = 2.into();
        let multiplier = two.modpow(&public_key.key, &public_key.modulus);
        let mut range_multiplier: BigInt = 1.into();
        let mut running: BigInt = 0.into();

        // Every time the answer is in the lower half, the upper range decrease
        // For upper range, everything is floor
        // In the first round, this would take the upper range to floor(n/2)
        // In the second round, it would be n/4 if twice, or 3n/4 if lower first
        // The formula is thus (2**rounds-(binary sum of lowers successes) * n)/2**rounds

        // Every time the answer is in the upper half, the lower range should increase
        // For lower range everything is ceil
        // In the first round, this would take the lower range to n/2
        // In the second round, this would be 3n/4 if twice, or n/4 if upper first
        // The formula is thus (2**rounds - (binary sum of upper successes) *n)/2**rounds
        //
        // The binary sums of upper and lower successes should be equal to 2**rounds - 1
        // 2**rounds - 1 = U + L => 2**rounds - U = L+1
        let one: BigInt = 1.into();

        // We choose to store *lower successes* in running
        println!("Range: {range:?}");
        while &range.upper - &range.lower != one {
            running_ciphertext *= &multiplier;
            running_ciphertext %= &public_key.modulus;

            //println!("Adding: {}", plaintext % 2 == 1.into());
            match parity_oracle(&running_ciphertext, &private_key) {
                // Lower half i.e. < midpoint
                Parity::Even => {
                    // Lower success increase
                    running *= &two;
                    running += &one;
                    range.upper = 1
                        + (((2 * &range_multiplier - &running) * &public_key.modulus)
                            / (2 * &range_multiplier));
                }

                // Upper half
                Parity::Odd => {
                    running *= &two;
                    range.lower = &range.upper - &public_key.modulus / (2 * &range_multiplier) - 1;
                }
            }
            range_multiplier *= &two;
            println!(
                "Running:{}/{range_multiplier}",
                &range_multiplier - &running
            );
            println!("Range: {range:?}");
        }
        //println!("Correct number: {}", plaintext);
        println!("Deduced number: {}", &range.lower);
        assert_eq!(secret_num, range.lower);
    }

    //
    //

    Ok(())
}
