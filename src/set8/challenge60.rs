//! 60. Single-Coordinate Ladders and Insecure Twists
//!
//! All our hard work is about to pay some dividends. Here's a list of
//! cool-kids jargon you'll be able to deploy after completing this
//! challenge:
//!
//! * Montgomery curve
//! * single-coordinate ladder
//! * isomorphism
//! * birational equivalence
//! * quadratic twist
//! * trace of Frobenius
//!
//! Not that you'll understand it all; you won't. But you'll at least be
//! able to silence crypto-dilettantes on Twitter.
//!
//! Now, to the task at hand. In the last problem, we implemented ECDH
//! using a short Weierstrass curve form, like this:
//!
//!     y^2 = x^3 + a*x + b
//!
//! For a long time, this has been the most popular curve form. The NIST
//! P-curves standardized in the 90s look like this. It's what you'll see
//! first in most elliptic curve tutorials (including this one).
//!
//! We can do a lot better. Meet the Montgomery curve:
//!
//!     B*v^2 = u^3 + A*u^2 + u
//!
//! Although it's almost as old as the Weierstrass form, it's been buried
//! in the literature until somewhat recently. The Montgomery curve has a
//! killer feature in the form of a simple and efficient algorithm to
//! compute scalar multiplication: the Montgomery ladder.
//!
//! Here's the ladder:
//!
//!     function ladder(u, k):
//!         u2, w2 := (1, 0)
//!         u3, w3 := (u, 1)
//!         for i in reverse(range(bitlen(p))):
//!             b := 1 & (k >> i)
//!             u2, u3 := cswap(u2, u3, b)
//!             w2, w3 := cswap(w2, w3, b)
//!             u3, w3 := ((u2*u3 - w2*w3)^2,
//!                        u * (u2*w3 - w2*u3)^2)
//!             u2, w2 := ((u2^2 - w2^2)^2,
//!                        4*u2*w2 * (u2^2 + A*u2*w2 + w2^2))
//!             u2, u3 := cswap(u2, u3, b)
//!             w2, w3 := cswap(w2, w3, b)
//!         return u2 * w2^(p-2)
//!
//! You are not expected to understand this.
//!
//! No, really! Most people don't understand it. Instead, they visit the
//! Explicit-Formulas Database (https://www.hyperelliptic.org/EFD/), the
//! one-stop shop for state-of-the-art ECC implementation techniques. It's
//! like cheat codes for elliptic curves. Worth visiting for the
//! bibliography alone.
//!
//! With that said, we should try to demystify this a little bit. Here's
//! the CliffsNotes:
//!
//! 1. Points on a Montgomery curve are (u, v) pairs, but this function
//!    only takes u as an input. Given *just* the u coordinate of a point
//!    P, this function computes *just* the u coordinate of k*P. Since we
//!    only care about u, this is a single-coordinate ladder.
//!
//! 2. So what the heck is w? It's part of an alternate point
//!    representation. Instead of a coordinate u, we have a coordinate
//!    u/w. Think of it as a way to defer expensive division (read:
//!    inversion) operations until the very end.
//!
//! 3. cswap is a function that swaps its first two arguments (or not)
//!    depending on whether its third argument is one or zero. Choosy
//!    implementers choose arithmetic implementations of cswap, not
//!    branching ones.
//!
//! 4. The core of the inner loop is a differential addition followed by a
//!    doubling operation. Differential addition means we can add two
//!    points P and Q only if we already know P - Q. We'll take this
//!    difference to be the input u and maintain it as an invariant
//!    throughout the ladder. Indeed, our two initial points are:
//!
//!        u2, w2 := (1, 0)
//!        u3, w3 := (u, 1)
//!
//!    Representing the identity and the input u.
//!
//! 5. The return statement performs the modular inversion using a trick
//!    due to Fermat's Little Theorem:
//!
//!        a^p     = a    mod p
//!        a^(p-1) = 1    mod p
//!        a^(p-2) = a^-1 mod p
//!
//! 6. A consequence of the Montgomery ladder is that we conflate (u, v)
//!    and (u, -v). But this encoding also conflates zero and
//!    infinity. Both are represented as zero. Note that the usual
//!    exceptional case where w = 0 is handled gracefully: our trick for
//!    doing the inversion with exponentiation outputs zero as expected.
//!
//!    This is fine: we're still working in a subgroup of prime order.
//!
//! Go ahead and implement the ladder. Remember that all computations are
//! in GF(233970423115425145524320034830162017933).
//!
//! Oh yeah, the curve parameters. You might be thinking that since we're
//! switching to a new curve format, we also need to pick out a whole new
//! curve. But you'd be totally wrong! It turns out that some short
//! Weierstrass curves can be converted into Montgomery curves.
//!
//! This is because all finite cyclic groups with an equal number of
//! elements share a kind of equivalence we call "isomorphism". It makes
//! sense, if you think about it - if the order is the same, all the same
//! subgroups will be present, and in the same proportions.
//!
//! So all we need to do is:
//!
//! 1. Find a Montgomery curve with an equal order to our curve.
//!
//! 2. Figure out how to map points back and forth between curves.
//!
//! You can perform this conversion algebraically. But it's kind of a
//! pain, so here you go:
//!
//!     v^2 = u^3 + 534*u^2 + u
//!
//! Through cunning and foresight, I have chosen this curve specifically
//! to have a really simple map between Weierstrass and Montgomery
//! forms. Here it is:
//!
//!     u = x - 178
//!     v = y
//!
//! Which makes our base point:
//!
//!     (4, 85518893674295321206118380980485522083)
//!
//! Or, you know. Just 4.
//!
//! Anyway, implement the ladder. Verify ladder(4, n) = 0. Map some points
//! back and forth between your Weierstrass and Montgomery representations
//! and verify them.
//!
//! One nice thing about the Montgomery ladder is its lack of special
//! cases. Specifically, no special handling of: P1 = O; P2 = O; P1 = P2;
//! or P1 = -P2. Contrast that with our Weierstrass addition function and
//! its battalion of ifs.
//!
//! And there's a security benefit, too: by ignoring the v coordinate, we
//! take away a lot of leeway from the attacker. Recall that the ability
//! to choose arbitrary (x, y) pairs let them cherry-pick points from any
//! curve they can think of. The single-coordinate ladder robs the
//! attacker of that freedom.
//!
//! But hang on a tick! Give this a whirl:
//!
//!     ladder(76600469441198017145391791613091732004, 11)
//!
//! What the heck? What's going on here?
//!
//! Let's do a quick sanity check. Here's the curve equation again:
//!
//!     v^2 = u^3 + 534*u^2 + u
//!
//! Plug in u and take the square root to recover v.
//!
//! You should detect that something is quite wrong. This u does not
//! represent a point on our curve! Not every u does.
//!
//! This means that even though we can only submit one coordinate, we
//! still have a little bit of leeway to find invalid
//! points. Specifically, an input u such that u^3 + 534*u^2 + u is not a
//! quadratic residue can never represent a point on our curve. So where
//! the heck are we?
//!
//! The other curve we're on is a sister curve called a "quadratic twist",
//! or simply "the twist". There is actually a whole family of quadratic
//! twists to our curve, but they're all isomorphic to each
//! other. Remember that that means they have the same number of points,
//! the same subgroups, etc. So it doesn't really matter which particular
//! twist we use; in fact, we don't even need to pick one.
//!
//! We're mostly interested in the subgroups present on the twist, which
//! means we need to know how many points it contains. Fortunately, it
//! turns out to be easier to count the combined set of points on the
//! curve and its twist at the same time. Let's do it:
//!
//! 1. For every nonzero u up to the modulus p, if u^3 + A*u^2 + u is a
//!    square in GF(p), there are two points on the original curve.
//!
//! 2. If the above sum is a nonsquare in GF(p), there are two points on
//!    the twisted curve.
//!
//! It should be clear that these add up to 2*(p-1) points in total, since
//! there are p-1 nonzero integers in GF(p) and two points for each. Let's
//! continue:
//!
//! 3. Both the original curve and its twist have a point (0, 0). This is
//!    just a regular point, not the group identity.
//!
//! 4. Both the original curve and its twist have an abstract point at
//!    infinity which serves as the group identity.
//!
//! So we have 2*p + 2 points across both curves. Since we already know
//! how many points are on the original curve, we can easily calculate the
//! order of the twist.
//!
//! If Alice chose a curve with an insecure twist, i.e. one with a
//! partially smooth order, then some doors open back up for Eve. She can
//! choose low-order points on the twisted curve, send them to Alice, and
//! perform the invalid-curve attack as before.
//!
//! The only caveat is that she won't be able to recover the full secret
//! using off-curve points, only a fraction of it. But we know how to
//! handle that.
//!
//! So:
//!
//! 1. Calculate the order of the twist and find its small factors. This
//!    one should have a bunch under 2^24.
//!
//! 2. Find points with those orders. This is simple:
//!
//!    a. Choose a random u mod p and verify that u^3 + A*u^2 + u is a
//!       nonsquare in GF(p).
//!
//!    b. Call the order of the twist n. To find an element of order q,
//!       calculate ladder(u, n/q).
//!
//! 3. Send these points to Alice to recover portions of her secret.
//!
//! 4. When you've exhausted all the small subgroups in the twist, recover
//!    the remainder of Alice's secret with the kangaroo attack.
//!
//! HINT: You may come to notice that k*u = -k*u, resulting in a
//! combinatorial explosion of potential CRT outputs. Try sending extra
//! queries to narrow the range of possibilities.

use std::{
    ops::{BitAnd, Shr},
    str::FromStr,
};

use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, Zero};
use rand::thread_rng;

use crate::{set8::challenge57::get_factors, utils::*};

use super::challenge59::ts_sqrt;

//  B*v^2 = u^3 + A*u^2 + u
#[allow(non_snake_case, dead_code)]
struct MontgomeryCurve {
    A: BigInt,
    B: BigInt,
    p: BigInt,
    bp: BigInt,
    ord: BigInt,
}

impl MontgomeryCurve {
    fn ladder(&self, u: &BigInt, k: &BigInt) -> BigInt {
        let one = BigInt::from_usize(1).unwrap();
        let two = BigInt::from_usize(2).unwrap();
        let (mut u2, mut w2) = (one.clone(), BigInt::zero());
        let (mut u3, mut w3) = (u.clone(), one.clone());
        for i in (0..self.p.bits()).rev() {
            //            println!("i: {i}");
            let b = one.clone().bitand(k.shr(i));
            if b == one {
                std::mem::swap(&mut u2, &mut u3);
                std::mem::swap(&mut w2, &mut w3);
            }
            (u3, w3) = (
                (&u2 * &u3 - &w2 * &w3) * (&u2 * &u3 - &w2 * &w3) % &self.p,
                u * (&u2 * &w3 - &w2 * &u3) * (&u2 * &w3 - &w2 * &u3) % &self.p,
            );

            (u2, w2) = (
                (&u2 * &u2 - &w2 * &w2) * (&u2 * &u2 - &w2 * &w2) % &self.p,
                4 * &u2 * &w2 * (&u2 * &u2 + &self.A * &u2 * &w2 + &w2 * &w2) % &self.p,
            );

            if b == one {
                std::mem::swap(&mut u2, &mut u3);
                std::mem::swap(&mut w2, &mut w3);
            }
        }

        (&u2 * w2.modpow(&(&self.p - two), &self.p)) % &self.p
    }

    fn add(&self, u1: &BigInt, u2: &BigInt) -> Result<BigInt> {
        //     B*v^2 = u^3 + A*u^2 + u
        let v1 = self.get_v(&u1)?.mod_floor(&self.p);
        let v2 = self.get_v(&u2)?.mod_floor(&self.p);
        println!("v1: {}", v1);
        println!("v2: {}", v2);

        let u3 = match u1 == u2 {
            // Distinct points
            false => {
                println!("Distinct");
                let num: BigInt = &v2 - &v1;
                let den: BigInt = u2 - u1;
                &self.B * &num * &num * invmod(&(&den * &den), &self.p) - &self.A - u1 - u2
            }
            // Doubling point
            true => {
                println!("Double");
                let one = BigInt::from_usize(1).unwrap();
                let num: BigInt = 3 * u1 * u1 + 2 * &self.A * u1 + &one;
                let den: BigInt = 2 * &self.B * &v1;
                &self.B * &num * &num * invmod(&(&den * &den), &self.p) - &self.A - u1 - u1
            }
        };
        Ok(u3.mod_floor(&self.p))
    }

    fn get_v(&self, u: &BigInt) -> Result<BigInt> {
        let vsq = (u * u * u + &self.A * u * u + u) * invmod(&self.B, &self.p);

        ts_sqrt(&vsq, &self.p)
    }
}

pub fn main() -> Result<()> {
    let curve = MontgomeryCurve {
        A: BigInt::from_str("534").unwrap(),
        B: BigInt::from_str("1").unwrap(),
        p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
        bp: BigInt::from_str("4").unwrap(),
        ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
    };
    println!("ladder(4,n): {}", curve.ladder(&curve.bp, &curve.ord));

    let u = BigInt::from_str("76600469441198017145391791613091732004").unwrap();
    let k = BigInt::from_str("11").unwrap();
    println!(
        "ladder(76600469441198017145391791613091732004, 11): {}",
        curve.ladder(&u, &k)
    );

    // v^2 = u^3 + 534*u^2 + u
    println!("corresponding v: {:?}", curve.get_v(&u));

    let twist_ord: BigInt = 2 * &curve.p + BigInt::from_usize(2).unwrap() - &curve.ord;

    println!("Order: {}", curve.ord);
    println!("Twist order: {}", twist_ord);
    let limit = BigInt::from_usize(2).unwrap().pow(20);
    let twist_factors = get_factors(&twist_ord, &limit);

    println!("Twist order factors: {:?}", twist_factors);
    let mut rng = thread_rng();
    let b_priv = rng.gen_bigint_range(&BigInt::zero(), &curve.ord);
    let b_pub = curve.ladder(&curve.bp, &b_priv);

    let mut rx: Vec<(BigInt, BigInt)> = vec![];
    for r in &twist_factors[1..] {
        println!("r: {}", r);
        let p = gen_twist_point(&curve, &r, &twist_ord);
        println!("ladder(p,r): {}", curve.ladder(&p, &r));
        // Send point to Bob
        let b_shared = curve.ladder(&p, &b_priv);
        // Now crack this
        rx.push((r.clone(), get_residue(&curve, &p, &b_shared, &r)));
    }
    println!("Residues: {:?}", rx);

    let crt_result = crt(&rx);
    println!("Crt result: {:?}", crt_result);
    let x = crt_result.0;
    let m = crt_result.1;

    // index = x mod m

    // Now do a Kangaroo on this
    //
    // index = x + n m
    // b_pub = ladder(base, index)
    // Which we can think of in the same way as p
    // y = ladder(ladder(base, x), n m)

    Ok(())
}

fn get_residue(curve: &MontgomeryCurve, pt: &BigInt, b_shared: &BigInt, r: &BigInt) -> BigInt {
    let mut index = BigInt::zero();
    while &curve.ladder(&pt, &index) != b_shared {
        index += 1;
        if &index > r {
            panic!("index bigger than r");
        }
    }
    index
}

fn gen_twist_point(curve: &MontgomeryCurve, r: &BigInt, twist_order: &BigInt) -> BigInt {
    let mut rng = thread_rng();
    let nr: BigInt = twist_order / r;
    println!("nr: {nr}");

    loop {
        let u = rng.gen_bigint_range(&BigInt::zero(), &curve.p);

        match curve.get_v(&u) {
            Ok(_) => {}
            Err(_) => {
                //println!("Found a u: {u}");
                let p = curve.ladder(&u, &nr);
                //println!("Found a p: {p}");
                if p != BigInt::zero() {
                    return p;
                }
            }
        }
    }
}

/// Takes vector of (modulus, residue) and returns result of CRT
fn crt(rx: &[(BigInt, BigInt)]) -> (BigInt, BigInt) {
    let total_prod = rx
        .iter()
        .fold(BigInt::from_usize(1).unwrap(), |a, (r, _)| a * r);

    let mut result: BigInt = BigInt::zero();
    for (r, x) in rx {
        let ms = &total_prod / r;
        result += x * &ms * invmod(&ms, r);
    }
    (result % &total_prod, total_prod)
}

#[cfg(test)]
mod tests {
    use crate::set8::challenge59::{Curve, CurveParams, Point};

    use super::*;

    #[test]
    fn montgomery_order_test() {
        let curve = MontgomeryCurve {
            A: BigInt::from_str("534").unwrap(),
            B: BigInt::from_str("1").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: BigInt::from_str("4").unwrap(),
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        };
        println!("ladder(4,n): {}", curve.ladder(&curve.bp, &curve.ord));
        assert_eq!(curve.ladder(&curve.bp, &curve.ord), BigInt::zero());
    }

    #[test]
    fn montgomery_ec_test() {
        let ec = Curve {
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

        let mc = MontgomeryCurve {
            A: BigInt::from_str("534").unwrap(),
            B: BigInt::from_str("1").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: BigInt::from_str("4").unwrap(),
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        };

        for n in 1..100 {
            let p = ec.gen(&n.into()).get_x();
            let q = mc.ladder(&mc.bp, &n.into());
            assert_eq!(p, Some(q + BigInt::from_usize(178).unwrap()));
        }
    }

    #[test]
    fn montgomery_add_test() {
        let mc = MontgomeryCurve {
            A: BigInt::from_str("534").unwrap(),
            B: BigInt::from_str("1").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: BigInt::from_str("4").unwrap(),
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        };

        let twop_add = mc.add(&mc.bp, &mc.bp).unwrap();
        let twop_lad = mc.ladder(&mc.bp, &BigInt::from_usize(2).unwrap());
        println!("2P add: {}", twop_add);
        println!("2P lad: {}", twop_lad);
        assert_eq!(twop_add, twop_lad);

        let threep_add = mc.add(&twop_lad, &mc.bp).unwrap();
        let threep_lad = mc.ladder(&mc.bp, &BigInt::from_usize(3).unwrap());
        println!("3P add: {}", threep_add);
        println!("3P lad: {}", threep_lad);
        assert_eq!(threep_add, threep_lad);
    }
}
