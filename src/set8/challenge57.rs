//! 57. Diffie-Hellman Revisited: Subgroup-Confinement Attacks
//!
//! This set is going to focus on elliptic curves. But before we get to
//! that, we're going to kick things off with some classic Diffie-Hellman.
//!
//! Trust me, it's gonna make sense later.
//!
//! Let's get right into it. First, build your typical Diffie-Hellman key
//! agreement: Alice and Bob exchange public keys and derive the same
//! shared secret. Then Bob sends Alice some message with a MAC over
//! it. Easy as pie.
//!
//! Use these parameters:
//!
//!     p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
//!     g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
//!
//! The generator g has order q:
//!
//!     q = 236234353446506858198510045061214171961
//!
//! "Order" is a new word, but it just means g^q = 1 mod p. You might
//! notice that q is a prime, just like p. This isn't mere chance: in
//! fact, we chose q and p together such that q divides p-1 (the order or
//! size of the group itself) evenly. This guarantees that an element g of
//! order q will exist. (In fact, there will be q-1 such elements.)
//!
//! Back to the protocol. Alice and Bob should choose their secret keys as
//! random integers mod q. There's no point in choosing them mod p; since
//! g has order q, the numbers will just start repeating after that. You
//! can prove this to yourself by verifying g^x mod p = g^(x + k*q) mod p
//! for any x and k.
//!
//! The rest is the same as before.
//!
//! How can we attack this protocol? Remember what we said before about
//! order: the fact that q divides p-1 guarantees the existence of
//! elements of order q. What if there are smaller divisors of p-1?
//!
//! Spoiler alert: there are. I chose j = (p-1) / q to have many small
//! factors because I want you to be happy. Find them by factoring j,
//! which is:
//!
//!     j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570
//!
//! You don't need to factor it all the way. Just find a bunch of factors
//! smaller than, say, 2^16. There should be plenty. (Friendly tip: maybe
//! avoid any repeated factors. They only complicate things.)
//!
//! Got 'em? Good. Now, we can use these to recover Bob's secret key using
//! the Pohlig-Hellman algorithm for discrete logarithms. Here's how:
//!
//! 1. Take one of the small factors j. Call it r. We want to find an
//!    element h of order r. To find it, do:
//!
//!        h := rand(1, p)^((p-1)/r) mod p
//!
//!    If h = 1, try again.
//!
//! 2. You're Eve. Send Bob h as your public key. Note that h is not a
//!    valid public key! There is no x such that h = g^x mod p. But Bob
//!    doesn't know that.
//!
//! 3. Bob will compute:
//!
//!        K := h^x mod p
//!
//!    Where x is his secret key and K is the output shared secret. Bob
//!    then sends back (m, t), with:
//!
//!        m := "crazy flamboyant for the rap enjoyment"
//!        t := MAC(K, m)
//!
//! 4. We (Eve) can't compute K, because h isn't actually a valid public
//!    key. But we're not licked yet.
//!
//!    Remember how we saw that g^x starts repeating when x > q? h has the
//!    same property with r. This means there are only r possible values
//!    of K that Bob could have generated. We can recover K by doing a
//!    brute-force search over these values until t = MAC(K, m).
//!
//!    Now we know Bob's secret key x mod r.
//!
//! 5. Repeat steps 1 through 4 many times. Eventually you will know:
//!
//!        x = b1 mod r1
//!        x = b2 mod r2
//!        x = b3 mod r3
//!        ...
//!
//!    Once (r1*r2*...*rn) > q, you'll have enough information to
//!    reassemble Bob's secret key using the Chinese Remainder Theorem.
//!

use std::str::FromStr;

use crate::utils::*;
use hmac_sha256::HMAC;
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, Zero};
use rand::rngs::ThreadRng;
use rand::thread_rng;

/*
fn primes_below(limit: &BigInt) -> Vec<BigInt> {
    let mut count: BigInt = 2.into();
    let mut primes: Vec<BigInt> = vec![count.clone()];
    while &count < limit {
        match primes.iter().any(|p| &count % p == BigInt::zero()) {
            true => {}
            false => primes.push(count.clone()),
        }
        count += 1;
    }

    primes
}
*/

pub fn get_factors(n: &BigInt, limit: &BigInt) -> Vec<BigInt> {
    let mut factors = vec![];
    //let primes = primes_below(limit);
    let mut n = n.clone();
    let mut p: BigInt = 2.into();
    while &p < limit {
        // Check if factor
        if n.is_multiple_of(&p) {
            factors.push(p.clone());
        }
        // Divide out all instances of this factor
        while n.is_multiple_of(&p) {
            n /= &p;
        }
        p += 1;
    }

    factors
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    let p = BigInt::from_str("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771")?;
    let g = BigInt::from_str("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143")?;
    let q = BigInt::from_str("236234353446506858198510045061214171961")?;

    let a_priv = rng.gen_bigint_range(&BigInt::zero(), &q);
    let b_priv = rng.gen_bigint_range(&BigInt::zero(), &q);

    let a_pub = g.modpow(&a_priv, &p);
    let b_pub = g.modpow(&b_priv, &p);

    let shared = a_pub.modpow(&b_priv, &p);
    let sharedp = b_pub.modpow(&a_priv, &p);
    println!("Shared:  {}", shared);
    println!("Shared': {}", sharedp);
    assert_eq!(shared, sharedp);

    println!("g^q mod p = {}", g.modpow(&q, &p));
    let j: BigInt = (&p - &BigInt::from_u16(1).unwrap()) / &q;
    println!("j: {}", j);

    let two: BigInt = 2.into();
    let limit = two.pow(16);
    let j_fac = get_factors(&j, &limit);
    let mut rng = thread_rng();
    println!("j factors: {:?}", j_fac);

    let mut total_prod: BigInt = 1.into();
    let mut rx = vec![];
    for r in j_fac {
        // h = rand(1, p)^((p-1)/r) mod p
        let h = get_h(&p, &r, &mut rng);
        //println!("h: {}", h);

        // Bob computes "shared key"
        // K := h^x mod p
        let k = h.modpow(&b_priv, &p);
        // m := "crazy flamboyant for the rap enjoyment"
        // t := MAC(K, m)
        let m = "crazy flamboyant for the rap enjoyment";
        let t = HMAC::mac(m, k.to_bytes_be().1);
        //println!("t: {:?}", t);
        // Only r possible values of K Bob could have
        // So find it!
        let mut x_crack: BigInt = 1.into();
        loop {
            let k_crack = h.modpow(&x_crack, &p);
            if HMAC::mac(m, k_crack.to_bytes_be().1) == t {
                break;
            } else {
                x_crack += 1;
            }
        }
        println!("x mod {}: {}", r, x_crack);

        rx.push((r.clone(), x_crack));

        total_prod *= &r;
        if total_prod > q {
            break;
        }
    }

    // Now crack using CRT
    assert!(total_prod > q);

    let mut result: BigInt = BigInt::zero();
    for (r, x) in rx {
        let ms = &total_prod / &r;
        result += x * &ms * invmod(&ms, &r);
    }
    result %= &total_prod;

    println!("Cracked x: {}", result);
    println!("B secret : {}", b_priv);

    assert_eq!(result, b_priv);

    Ok(())
}

pub fn get_h(p: &BigInt, r: &BigInt, rng: &mut ThreadRng) -> BigInt {
    let one: BigInt = 1.into();
    let pow = (p - &one) / r;
    loop {
        let h = rng.gen_bigint_range(&one, p).modpow(&pow, p);
        if h != one {
            return h;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subgroup_confinement() {
        main().unwrap();
    }
}
