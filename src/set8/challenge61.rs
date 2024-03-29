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

use crate::utils::*;

pub fn main() -> Result<()> {
    unimplemented!()
}
