//! 61. Duplicate-Signature Key Selection in ECDSA (and RSA)
//!
//! Suppose you have a message-signature pair. If I give you a public key
//! that verifies the signature, can you trust that I'm the author?
//!
//! You shouldn't. It turns out to be pretty easy to solve this problem
//! across a variety of digital signature schemes. If you have a little
//! flexibility in choosing your public key, that is.
//!
//! Let's consider the case of ECDSA.
//!
//! First, implement ECDSA. If you still have your old DSA implementation
//! lying around, this should be straightforward. All the same, here's a
//! refresher if you need it:
//!
//!     function sign(m, d):
//!         k := random_scalar(1, n)
//!         r := (k * G).x
//!         s := (H(m) + d*r) * k^-1
//!         return (r, s)
//!
//!     function verify(m, (r, s), Q):
//!         u1 := H(m) * s^-1
//!         u2 := r * s^-1
//!         R := u1*G + u2*Q
//!         return r = R.x
//!
//! Remember that all the scalar operations are mod n, the order of the
//! base point G. (d, Q) is the signer's key pair. H(m) is a hash of the
//! message.
//!
//! Note that the verification function requires arbitrary point
//! addition. This means your Montgomery ladder (which only performs
//! scalar multiplication) won't work here. This is no big deal; just fall
//! back to your old Weierstrass imlpementation.
//!
//! Once you've got this implemented, generate a key pair for Alice and
//! use it to sign some message m.
//!
//! It would be tough for Eve to find a Q' to verify this signature if all
//! the domain parameters are fixed. But the domain parameters might not
//! be fixed - some protocols let the user specify them as part of their
//! public key.
//!
//! Let's rearrange some terms. Consider this equality:
//!
//!     R = u1*G + u2*Q
//!
//! Let's do some regrouping:
//!
//!     R = u1*G + u2*(d*G)
//!     R = (u1 + u2*d)*G
//!
//! Consider R, u1, and u2 to be fixed. That leaves Alice's secret d and
//! the base point G. Since we don't know d, we'll need to choose a new
//! pair of values for which the equality holds. We can do it by starting
//! from the secret and working backwards.
//!
//! 1. Choose a random d' mod n.
//!
//! 2. Calculate t := u1 + u2*d'.
//!
//! 3. Calculate G' := t^-1 * R.
//!
//! 4. Calculate Q' := d' * G'.
//!
//! 5. Eve's public key is Q' with domain parameters (E(GF(p)), n, G').
//!    E(GF(p)) is the elliptic curve Alice originally chose.
//!
//! Note that Eve's public key is totally valid: both the base point and
//! her public point are members of the subgroup of prime order n. Since
//! E(GF(p)) and n are unchanged from Alice's public key, they should pass
//! the same validation rules.
//!
//! Assuming the role of Eve, derive a public key and domain parameters to
//! verify Alice's signature over the message.
//!
//! Let's do the same thing with RSA. Same setup: we have some message and
//! a signature over it. How do we craft a public key to verify the
//! signature?
//!
//! Well, first let's refresh ourselves on RSA. Signature verification
//! looks like this:
//!
//!     s^e = pad(m) mod N
//!
//! Where (m, s) is the message-signature pair and (e, N) is Alice's
//! public key.
//!
//! So what we're really looking for is the pair (e', N') to make that
//! equality hold up. If this is starting to look a little familiar, it
//! should: what we're doing here is looking for the discrete logarithm of
//! pad(m) with base s.
//!
//! We know discrete logarithms are easy to solve with Pohlig-Hellman in
//! groups with many small subgroups. And the choice of group is up to us,
//! so we can't fail!
//!
//! But we should exercise some care. If we choose our primes incorrectly,
//! the discrete logarithm won't exist.
//!
//! Okay, check the method:
//!
//! 1. Pick a prime p. Here are some conditions for p:
//!
//!    a. p-1 should be smooth. How smooth is up to you, but you will need
//!       to find discrete logarithms in each of these subgroups. You can
//!       use something like Shanks or Pollard's rho to compute these in
//!       square-root time.
//!
//!    b. s shouldn't be in any subgroup that pad(m) is not in. If it is,
//!       the discrete logarithm won't exist. The simplest thing to do is
//!       make sure they're both primitive roots. To check if an element g
//!       is a primitive root mod p, check that:
//!
//!           g^((p-1)/q) != 1 mod p
//!
//!       For every factor q of p-1.
//!
//! 2. Now pick a prime q. Ensure the same conditions as before, but add these:
//!
//!    a. Don't reuse any factors of p-1 other than 2. It's possible to
//!       make this work with repeated factors, but it's a huge
//!       headache. Better just to avoid it.
//!
//!    b. Make sure p*q is greater than Alice's modulus N. This is just to
//!       make sure the signature and padded message will fit under your
//!       new modulus.
//!
//! 3. Use Pohlig-Hellman to derive ep = e' mod p and eq = e' mod q.
//!
//! 4. Use the Chinese Remainder Theorem to put ep and eq together:
//!
//!        e' = crt([ep, eq], [p-1, q-1])
//!
//! 5. Your public modulus is N' = p * q.
//!
//! 6. You can derive d' in the normal fashion.
//!
//! Easy as pie. e' will be a lot larger than the typical public exponent,
//! but that's still legal.
//!
//! Since RSA signing and decryption are equivalent operations, you can
//! use this same technique for other surprising results. Try generating a
//! random (or chosen) ciphertext and creating a key to decrypt it to a
//! plaintext of your choice!

use std::str::FromStr;

use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::One;
use openssl::sha::sha256;
use rand::rngs::ThreadRng;

use crate::{
    set6::challenge43::Params,
    set8::challenge59::{Curve, CurveParams, Point},
    utils::*,
};

trait Dsa<T> {
    fn sign(&self, m: &[u8], d: &BigInt, rng: &mut ThreadRng) -> Signature;
    fn verify(&self, m: &[u8], sig: Signature, q: &T) -> DsaResult;
}

#[derive(Debug, PartialEq)]
pub enum DsaResult {
    Valid,
    Invalid,
}

#[derive(Debug)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Dsa<BigInt> for Params {
    fn sign(&self, m: &[u8], x: &BigInt, rng: &mut ThreadRng) -> Signature {
        let hm: BigInt = BigInt::from_bytes_le(Sign::Plus, &sha256(m));

        let k = rng.gen_bigint_range(&BigInt::one(), &self.q);
        let kinv: BigInt = invmod(&k, &self.q);

        let r = self.g.modpow(&k, &self.p).mod_floor(&self.q);
        // d is private key
        let s = (kinv * (hm + x * &r)).mod_floor(&self.q);

        Signature { r, s }
    }

    fn verify(&self, m: &[u8], sig: Signature, q: &BigInt) -> DsaResult {
        let hm: BigInt = BigInt::from_bytes_le(Sign::Plus, &sha256(m));
        let Signature { r, s } = sig;

        let sinv = invmod(&s, &self.q);
        //println!("sinv: {:?}", sinv);
        let u1 = (&sinv * hm).mod_floor(&self.q);
        //println!("u1: {:?}", u1);
        let u2 = (&sinv * &r).mod_floor(&self.q);
        //println!("u2: {:?}", u2);
        let test_r = (&self.g.modpow(&u1, &self.p) * &q.modpow(&u2, &self.p))
            .mod_floor(&self.p)
            .mod_floor(&self.q);
        //println!("Allegedly kG: {:?}", test_r);
        match r == test_r {
            true => DsaResult::Valid,
            false => DsaResult::Invalid,
        }
    }
}

impl Dsa<Point> for Curve {
    fn sign(&self, m: &[u8], d: &BigInt, rng: &mut ThreadRng) -> Signature {
        let k = rng.gen_bigint_range(&BigInt::one(), &self.params.ord);
        let kinv: BigInt = invmod(&k, &self.params.ord);
        //println!("k: {:?}", k);
        //println!("kin: {:?}", kinv);
        //println!("k*k-1: {:?}", (&k * &kinv).mod_floor(&self.params.ord));
        //println!("k: {:?}", k);
        //println!("kG: {:?}", self.gen(&k));
        //println!("G: {:?}", self.params.bp);
        //println!("(k*kinvG): {:?}", self.scale(&self.gen(&kinv), &k));
        //println!("(kinv*k G): {:?}", self.scale(&self.gen(&k), &kinv));

        let r: BigInt = self.gen(&k).get_x().unwrap();
        let hm: BigInt = BigInt::from_bytes_le(Sign::Plus, &sha256(m));
        //println!("Hash: {:?}", hm);

        let s = ((&hm + d * &r) * &kinv).mod_floor(&self.params.ord);

        Signature { r, s }
    }

    fn verify(&self, m: &[u8], signature: Signature, q: &Point) -> DsaResult {
        let hm: BigInt = BigInt::from_bytes_le(Sign::Plus, &sha256(m));
        //println!("Hash: {:?}", hm);
        let Signature { r, s } = signature;

        let sinv = invmod(&s, &self.params.ord);
        //println!("sinv: {:?}", sinv);
        let u1 = &sinv * hm;
        //println!("u1: {:?}", u1);
        let u2 = &sinv * &r;
        //println!("u2: {:?}", u2);
        let test_r = self.add(&self.gen(&u1), &self.scale(q, &u2));
        //println!("Allegedly kG: {:?}", test_r);
        match r == test_r.get_x().unwrap() {
            true => DsaResult::Valid,
            false => DsaResult::Invalid,
        }
    }
}

pub fn main() -> Result<()> {
    let curve = Curve {
        params: CurveParams {
            a: BigInt::from_str("-95051").unwrap(),
            b: BigInt::from_str("11279326").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: Point::P {
                x: BigInt::from_str("182").unwrap(),
                y: BigInt::from_str("85518893674295321206118380980485522083").unwrap(),
            },
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        },
    };

    unimplemented!()
}

#[cfg(test)]
mod tests {

    use num_traits::Num;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use super::*;

    #[test]
    fn dsa_test() {
        let curve = Curve {
            params: CurveParams {
                a: BigInt::from_str("-95051").unwrap(),
                b: BigInt::from_str("11279326").unwrap(),
                p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
                bp: Point::P {
                    x: BigInt::from_str("182").unwrap(),
                    y: BigInt::from_str("85518893674295321206118380980485522083").unwrap(),
                },
                //ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
                ord: BigInt::from_str("29246302889428143187362802287225875743").unwrap(),
            },
        };

        let ord = BigInt::from_str("29246302889428143187362802287225875743").unwrap();

        let mut rng = thread_rng();

        for _ in 1..10 {
            // Generate key-pair
            // private key
            let d = rng.gen_bigint_range(&BigInt::one(), &ord);
            // public key
            let q = curve.gen(&d);
            let message: String = rng
                .clone()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            println!("Public key: {q:?}");
            println!("Message: {message}");
            let message_bytes = message.as_bytes();
            let sig = curve.sign(message_bytes, &d, &mut rng);
            println!("Signature: {sig:?}");

            let verify = curve.verify(message_bytes, sig, &q);
            println!("Verified: {:?}", verify);

            assert_eq!(verify, DsaResult::Valid);
        }
    }
    #[test]
    fn dsa_test_rsa() {
        let p: BigInt = BigInt::from_str_radix(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7\
         859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
         2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
         ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
         b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
         1a584471bb1",
            16,
        )
        .unwrap();

        let q: BigInt =
            BigInt::from_str_radix("f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();

        let g: BigInt = BigInt::from_str_radix(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
         458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
         322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
         0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
         878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
         9fc95302291",
            16,
        )
        .unwrap();
        let params = Params { p, q, g };
        let mut rng = thread_rng();

        for _ in 1..10 {
            // Generate key-pair
            // private key
            let x = rng.gen_bigint_range(&BigInt::one(), &params.q);
            // public key
            let y = params.g.modpow(&x, &params.p);
            let message: String = rng
                .clone()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            println!("Public key: {y:?}");
            println!("Message: {message}");
            let message_bytes = message.as_bytes();
            let sig = params.sign(message_bytes, &x, &mut rng);
            println!("Signature: {sig:?}");

            let verify = params.verify(message_bytes, sig, &y);
            println!("Verified: {:?}", verify);

            assert_eq!(verify, DsaResult::Valid);
        }
    }
}
