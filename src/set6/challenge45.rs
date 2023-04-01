//! DSA parameter tampering
//!
//! Take your DSA code from the previous exercise. Imagine it as part of an algorithm in which the
//! client was allowed to propose domain parameters (the p and q moduli, and the g generator).
//!
//! This would be bad, because attackers could trick victims into accepting bad parameters.
//! Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and
//! generators that were 1 mod p.
//!
//! Use the parameters from the previous exercise, but substitute 0 for "g". Generate a signature.
//! You will notice something bad. Verify the signature. Now verify any other signature, for any
//! other string.
//!
//! Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA
//! public key that will validate against any string. For arbitrary z:
//!
//!   r = ((y**z) % p) % q
//!
//!         r
//!   s =  --- % q
//!         z
//! Sign "Hello, world". And "Goodbye, world".

use num_bigint::{BigInt, RandBigInt, Sign};
use openssl::sha::sha1;
use rand::thread_rng;

use crate::{
    set6::challenge43::{sign, verify, Params, Sig},
    utils::*,
};
pub fn sign_broken(private_key: &BigInt, params: &Params, message: &[u8]) -> Sig {
    let Params { q, p, g } = params;

    let mut rng = thread_rng();
    let h: BigInt = BigInt::from_bytes_be(Sign::Plus, &sha1(message));
    let k = rng.gen_bigint_range(&1.into(), q);
    let kinv = invmod(&k, q);
    let two: BigInt = 2.into();
    let qm2 = q - &two;
    let kinvprime = k.modpow(&qm2, q);
    assert_eq!(kinv, kinvprime);

    let r = g.modpow(&k, p) % q;
    let s = (kinv * (&h + private_key * &r)) % q;

    Sig { r, s }
}

pub fn main() -> Result<()> {
    let params = Params {
        g: 0.into(),
        ..Params::default()
    };

    // Generate private and public keys
    let mut rng = thread_rng();

    let x = rng.gen_bigint_range(&0.into(), &params.q);
    let y = params.g.modpow(&x, &params.p);

    println!("x: {x}");
    let message = b"test message";
    // r = (y**z) mod p mod q
    // When g is 0, y = g**x mod p = 1
    // r=0
    println!("Producing signature");
    // We had to go in and remove the r!=0 to make this work
    let sig = sign_broken(&y, &params, message);

    println!("Signature: {:?}", sig);
    //  Deduced values:
    //  s = h/k when r=0;
    //  r = g**k mod p
    //  => k = h/s % q
    //  Let's deduce k, and then decude the private key
    let h = BigInt::from_bytes_be(Sign::Plus, &sha1(message));
    let sinv = invmod(&sig.s, &params.q);
    let k = (&h * &sinv) % &params.q;
    // r will be the same, and s for an abitrary message is h/k;
    let kinv = invmod(&k, &params.q);
    let forged_sig = Sig {
        r: 0.into(),
        s: (&h * &kinv) % &params.q,
    };

    println!("Forged sig: {:?}", forged_sig);

    // This forged signature is invalid because verify checks if r is 0!
    // In that sense, the original signature is also invalid
    // and indeed there are no valid signatures any more

    // Let's try the other attack, g=p+1
    // The idea here is that g gets modified in the *memory of the verifier*
    let mut params = Params::default();
    let y = params.g.modpow(&x, &params.p);
    // y gets generated, now g gets changed

    params.g = params.p.clone() + 1;
    // How does verification work?
    // v = g**(h/s) * y**(r/s) mod p mod q
    // r = g**(h/s) * y**(r/s)
    // Write this as an exponential r= y**z
    // y**z = g**(h/s) * y**(r/s) mod p mod q
    // Because g has now been corrupted (but y is stored), this drops down to
    // y**z = y**(r/s) =>
    // s = r/z mod q
    // r = y**z mod q
    // for arbitrary z

    println!("=====");
    let sig = sign(&x, &params, b"any message");
    println!("sig: {:?}", sig);
    let verified = verify(&y, &params, b"any message", &sig);
    println!("Verified: {:?}", verified);
    println!("=====");

    // This signature will valid literally anything
    let z: BigInt = rng.gen_bigint_range(&1.into(), &params.q);
    let r = y.modpow(&z, &params.p) % &params.q;
    let s = &r * invmod(&z, &params.q) % &params.q;
    let sig = Sig { r, s };

    // Sig should now verify anything!
    println!("sig: {:?}", sig);
    let verified = verify(&y, &params, b"Hello, world!", &sig);
    assert_eq!(verified, Auth::Valid);

    println!("Verified: {:?}", verified);

    let verified = verify(&y, &params, b"Goodbye, world!", &sig);
    println!("Verified: {:?}", verified);
    assert_eq!(verified, Auth::Valid);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forging() {
        main().unwrap();
    }
}
