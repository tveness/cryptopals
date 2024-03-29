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

// Regarding the hint, what does this mean?
// Well, the problem here is that because we are only working with the one coordinate we lose some
// information on which point on the curve we are on: we are either at (x,y) or its inverse
// (x, p-y) = -(x,y)
// The index we recover is therefore one of two
// Can we do better than this?
// Imagine we have
// x1 mod r1    OR    x1' mod r1
// x2 mod r2    OR    x2' mod r2
//
// CRT then gives us 4 possible outputs
// r1' = (r1)^{-1} mod r2
// r2' = (r2)^{-2} mod r1

// CRT would say this a solution
// x2 r1 r1' + x1 r2 r2'   mod (r1 r2)
//
// This follows as if we take this mod r1 then the first term drops out as it is a multiple of r1
// and the second term resolves to x1, and straightforwardly the other way, too
//
// So, our options are
// 1.   x1 r2 r2' + x2 r1 r1'
// 2.   - x1 r2 r2' + x2 r1 r1'
// 3.   x1 r2 r2' - x2 r1 r1'
// 4.   - x1 r2 r2' - x2 r1 r1'
// If we do another query with an element of order r1 r2, then we can knock this back down to two
//
// So the procedure here is not to do all of the factorings straight away, but to build it up
// slowly.

use anyhow::anyhow;
use indicatif::ProgressBar;
use std::{
    collections::HashMap,
    ops::{BitAnd, Shr},
    str::FromStr,
};

use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, Zero};
use rand::thread_rng;

use crate::{set8::challenge57::get_factors, utils::*};

use super::challenge59::{ts_sqrt, Curve, CurveParams, Point};

// How can we solve the DLP in this case?
// The ladder allows us to calculate n Q very efficiently i.e. is equivalent to our "scale" of
// before
// But this isn't really what we do with DLP: we hop the following way
// g^x -> g^(x+x') -> g^(x+x'+x'')
// which is equivalent to adding
// We can keep track of the index and redo the ladder every time i.e. calculate
// b P, (b+x1)P, (b+x1+x2)P, etc. very efficiently
// The tame kangaroo is easily doable in this way
// BUT how do we do this for the wild kangaroo?
//
// In this case, it will be easier to do this for the Weierstrass curve as we already have all the
// addition sorted out
// Furthermore, I prefer giant-step baby-step :)

// b_pub = (x+modulus n) P

// b_priv = x+modulus n
// (b_priv -x) = (modulus n)P
// (b_priv - x) = n (modulus P)

/*
fn dlp(b_pub: &BigInt, x: &BigInt, modulus: &BigInt) -> Option<BigInt> {
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

    // Convert b_pub to true b_pub
    let b_pub = b_pub - BigInt::from_usize(178).unwrap();

    // b_pub = x + modulus*n
    // We wish to find n
    let modn: BigInt = &b_pub - x;

    let limit = 2_usize.pow(20);
    let m = 2_usize.pow(10);
    // Now we're going to do giant step baby step
    let h = HashMap::new();
    // y' = n *(modulus * P)
    // n = i + j m
    // First do giant step
    for j in 0..m {
        let jm: BigInt = curve.scale(
            &curve.params.bp,
            &(&curve.params.ord - &BigInt::from_usize(j * m).unwrap()),
        );
        let i = curve.add(&b_pub, &jm);
        h.insert(i, j);
    }

    None
}
*/

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

    /*
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
    */

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
    let limit = BigInt::from_usize(2).unwrap().pow(24);
    let twist_factors = get_factors(&twist_ord, &limit);

    println!("Twist order factors: {:?}", twist_factors);
    println!(
        "Effective order: {} bits",
        (&curve.ord
            / twist_factors
                .iter()
                .fold(BigInt::from_usize(1).unwrap(), |a, x| a * x))
        .bits()
    );
    let mut rng = thread_rng();
    let b_priv = rng.gen_bigint_range(&BigInt::zero(), &curve.ord);
    let b_pub = curve.ladder(&curve.bp, &b_priv);

    let mut rx: Vec<(BigInt, BigInt)> = vec![];

    let mut running_modulus = BigInt::from_usize(1).unwrap();
    let mut running_residue = BigInt::zero();

    for r in &twist_factors[1..] {
        println!("r: {}", r);

        let p = gen_twist_point(&curve, r, &twist_ord);
        println!("ladder(p,r): {}", curve.ladder(&p, r));
        // Send point to Bob
        let b_shared = curve.ladder(&p, &b_priv);
        // Now crack this
        let res = get_residue(&curve, &p, &b_shared, r).mod_floor(r);
        // res is "+ve" root
        println!("res: {}", res);
        println!("-res: {}", (-&res).mod_floor(r));
        println!("b_priv % r: {}", b_priv.mod_floor(r));

        // The true residue could be +- this, so try both
        match running_modulus == BigInt::from_usize(1).unwrap() {
            false => {
                let p = r.clone();
                let q = running_modulus.clone();
                let p_i = invmod(&p, &q);
                let q_i = invmod(&q, &p);

                let rrp = running_residue.mod_floor(&q);
                let rrm = (-&running_residue).mod_floor(&q);
                println!("rrp: {}", rrp);
                println!("rrm: {}", rrm);

                let resp = res.mod_floor(&p);
                let resm = (-&res).mod_floor(&p);
                println!("resp: {}", resp);
                println!("resm: {}", resm);

                let crt_a: BigInt = (&rrp * &p * &p_i + &resp * &q * &q_i).mod_floor(&(&p * &q));
                let crt_b: BigInt = (&rrp * &p * &p_i + &resm * &q * &q_i).mod_floor(&(&p * &q));
                let crt_c: BigInt = (&rrm * &p * &p_i + &resp * &q * &q_i).mod_floor(&(&p * &q));
                let crt_d: BigInt = (&rrm * &p * &p_i + &resm * &q * &q_i).mod_floor(&(&p * &q));

                running_modulus = &p * &q;
                println!("Running modulus: {}", running_modulus);
                let p_new = gen_twist_point(&curve, &running_modulus, &twist_ord);

                println!(
                    "ladder(p_new,{}): {}",
                    running_modulus,
                    curve.ladder(&p_new, &running_modulus)
                );
                println!("ladder(p_new,{}): {}", p, curve.ladder(&p_new, &p));
                println!("ladder(p_new,{}): {}", q, curve.ladder(&p_new, &q));
                let b_a = curve.ladder(&p_new, &crt_a);
                let b_b = curve.ladder(&p_new, &crt_b);
                let b_c = curve.ladder(&p_new, &crt_c);
                let b_d = curve.ladder(&p_new, &crt_d);
                let b_new = curve.ladder(&p_new, &b_priv);

                println!("x_a: {}", crt_a);
                println!("x_b: {}", crt_b);
                println!("x_c: {}", crt_c);
                println!("x_d: {}", crt_d);
                println!("b_priv % mod: {}", b_priv.mod_floor(&running_modulus));
                println!("b_a: {}", b_a);
                println!("b_b: {}", b_b);
                println!("b_c: {}", b_c);
                println!("b_d: {}", b_d);
                println!("b_new: {}", b_new);

                if b_a == b_new {
                    running_residue = crt_a;
                } else if b_b == b_new {
                    running_residue = crt_b;
                } else if b_c == b_new {
                    running_residue = crt_c;
                } else if b_d == b_new {
                    running_residue = crt_d;
                } else {
                    panic!("Neither worked!");
                }
                println!("running res: {}", running_residue);
                println!(
                    "running res: {}",
                    (-&running_residue).mod_floor(&running_modulus)
                );
            }
            true => {
                running_modulus = &running_modulus * r;
                running_residue = res.mod_floor(r);
            }
        };
        rx.push((r.clone(), res.clone()));
    }
    println!("Residues: {:?}", rx);

    //let crt_result = crt(&rx);
    //println!("Crt result: {:?}", crt_result);
    //let x = crt_result.0;
    //let m = crt_result.1;

    //// Check CRT is working
    //println!("bpriv = {x} mod {m}");
    println!("bpriv mod m = {}", &b_priv % &running_modulus);
    println!("running residue = {}", running_residue);
    println!("-running residue = {}", &running_modulus - &running_residue);

    // We're now going to big-step little-step this
    // Unfortunately, the ladder is not terribly helpful here, so we'll instead use the Weierstrass
    // curve, as here we have good old addition
    let bits = (twist_ord / &running_modulus).bits() as u32;
    println!("Remaining bits: {}", bits);

    let cracked = match shanks_for_mc(&running_residue, &running_modulus, &b_pub, bits) {
        Some(x) => x,
        None => match shanks_for_mc(
            &(&running_modulus - &running_residue),
            &running_modulus,
            &b_pub,
            bits,
        ) {
            Some(x) => x,
            None => panic!("Never found!"),
        },
    };
    println!("Cracked: {}", cracked);
    let other_cracked: BigInt = &curve.ord - &cracked;
    println!("Other cracked: {}", other_cracked);
    println!("b_priv: {}", b_priv);

    let found: bool = (cracked == b_priv) || (other_cracked == b_priv);

    assert!(found);

    // index = x mod m

    // Now do a Kangaroo on this
    //
    // index = x + n m
    // b_pub = ladder(base, index)
    // Which we can think of in the same way as p
    // y = ladder(ladder(base, x), n m)

    Ok(())
}

fn shanks_for_mc(res: &BigInt, modulus: &BigInt, b_pub: &BigInt, bits: u32) -> Option<BigInt> {
    // First convert b_pub point from Montgomery curve to Weierstrass
    // N.B. that b_priv will actually be ill-defined from this procedure, as there are two points
    // which generate b_pub: b_priv, and ord-b_priv
    // This must be true, because (x,y) and (x,-y) add to give O by the geometric rule

    // So, we will pick the positive sqrt of the equation to get started and work from there
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

    //     u = x - 178
    //     v = y
    let x = b_pub + &BigInt::from_usize(178).unwrap();
    // y^2 = x^3 + ax + b
    let y2: BigInt =
        (&x * &x * &x + &curve.params.a * &x + &curve.params.b).mod_floor(&curve.params.p);

    let y_one = ts_sqrt(&y2, &curve.params.p).unwrap();

    let ys: [BigInt; 2] = [y_one.clone(), &curve.params.p - &y_one];

    for y in ys {
        // We now have b_pub as a point
        let b_pub = Point::P { x: x.clone(), y };
        println!("Reconstructed Weierstrass point: {:?}", b_pub);

        // b_pub now = b_priv P, where P is our base point
        // We have established that b_pub = (res + n * modulus) P
        // So, let's scan over all the different ms until we have a hit
        // We will just store the x-coordinate for simplicty
        let mut hm = HashMap::new();

        let m = 2_usize.pow(bits / 2);
        // Let's now make the hash-table of giant steps
        // We will denote n = i + j m, m = 0...sqrt(n)

        // For the giant step
        // dj = (-m modulus P)
        let dj = curve
            .scale(
                &curve.params.bp,
                &(modulus * &BigInt::from_usize(m).unwrap()),
            )
            .invert(&curve.params.p);
        // b_sub = b_pub - res P
        let mut b_sub = curve.add(
            &b_pub,
            &curve.scale(&curve.params.bp, res).invert(&curve.params.p),
        );

        println!("Reconstructed Weierstrass point - res P: {:?}", b_sub);

        let fake_index = BigInt::from_str("362400").unwrap();

        println!(
            "Fake recon: {:?}",
            curve.scale(&curve.params.bp, &(modulus * &fake_index))
        );
        println!("m: {}", m);

        // Should be
        // j= 353
        // i= 928
        //let b_priv = BigInt::from_str("146907443384").unwrap();

        let spinner = ProgressBar::new_spinner();
        for j in 0..m {
            if j.is_multiple_of(&1000) {
                spinner.set_message(format!("Giant step {}: {}", j, m));
                spinner.tick();
            }
            // Now subtract off m P at each step
            // b_sub = (b_priv - res - j m modulus) P
            //let b_sub_alleged = curve.scale(
            //    &curve.params.bp,
            //    &(&b_priv - res - (j * m) * modulus).mod_floor(&curve.params.ord),
            //);
            //println!("j: {}", j);
            ////println!("True b_sub: {:?}", b_sub_alleged);
            //println!("b_sub:      {:?}", b_sub);
            //if b_sub_alleged != b_sub {
            //    panic!("Differing");
            //}

            hm.insert(b_sub.clone(), j);
            b_sub = curve.add(&b_sub, &dj);
            // Should then simply need to scan the hashmap for i P
        }
        spinner.finish();

        // Print correct point
        // j= 353
        //let j = BigInt::from_usize(353).unwrap();
        //let b_sub_alleged = curve.scale(
        //    &curve.params.bp,
        //    &(&b_priv - res - (j * m) * modulus).mod_floor(&curve.params.ord),
        //);
        //println!("Seeking: {:?}", b_sub_alleged);

        //// i= 928
        //let i_true = BigInt::from_usize(928).unwrap();
        //let b_sub_alleged = curve.scale(&curve.params.bp, &(&i_true * modulus));
        //println!("i_true: {:?}", b_sub_alleged);

        // Now baby step
        // The entries in the hashmap should now be in the range (0..m) modulus P,
        // so we just need to check if this is in there
        let di = curve.scale(&curve.params.bp, modulus);
        let mut i_p = Point::O;
        let spinner = ProgressBar::new_spinner();
        for i in 0..m {
            if i.is_multiple_of(&1000) {
                spinner.set_message(format!("Baby step {}: {}", i, m));
                spinner.tick();
            }
            let ib = BigInt::from_usize(i).unwrap();
            if i != 0 {
                //i_p = curve.scale(&curve.params.bp, &(modulus * &ib));
                i_p = curve.add(&i_p, &di);
            }

            let b_x = i_p.clone();
            if let Some(f) = hm.get(&b_x) {
                //println!("Found a hit: i: {}, j: {}", ib, f);
                //println!("res: {res}");
                spinner.finish();
                //let ib = BigInt::from_str("928").unwrap();
                //let f = BigInt::from_str("353").unwrap();
                let index: BigInt = &ib + m * f;
                //println!("Index: {}", index);
                let full_index: BigInt = res + modulus * &index;
                return Some(full_index);
            }
        }
        spinner.finish();
    }

    None
}

fn get_residue(curve: &MontgomeryCurve, pt: &BigInt, b_shared: &BigInt, r: &BigInt) -> BigInt {
    loop {
        if let Ok(res) = try_get_residue(curve, pt, b_shared, r) {
            return res;
        }
    }
}

fn try_get_residue(
    curve: &MontgomeryCurve,
    pt: &BigInt,
    b_shared: &BigInt,
    r: &BigInt,
) -> Result<BigInt> {
    let mut index = BigInt::zero();
    while &curve.ladder(pt, &index) != b_shared {
        index += 1;
        if &index > r {
            return Err(anyhow!("Residue not found"));
        }
    }
    Ok(index)
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

/*
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
*/

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
    fn montgomery_dup_test() {
        let mc = MontgomeryCurve {
            A: BigInt::from_str("534").unwrap(),
            B: BigInt::from_str("1").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: BigInt::from_str("4").unwrap(),
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        };

        let i1 = BigInt::from_usize(50).unwrap();
        let p1 = mc.ladder(&mc.bp, &i1);

        let i2 = &mc.ord - BigInt::from_usize(50).unwrap();
        let p2 = mc.ladder(&mc.bp, &i2);
        println!("i1: {i1}");
        println!("i2: {i2}");
        println!("p1: {p1}");
        println!("p2: {p2}");

        assert_eq!(p1, p2);
    }

    #[test]
    fn montgomery_shanks_test() {
        let mc = MontgomeryCurve {
            A: BigInt::from_str("534").unwrap(),
            B: BigInt::from_str("1").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: BigInt::from_str("4").unwrap(),
            ord: BigInt::from_str("233970423115425145498902418297807005944").unwrap(),
        };

        let wc = Curve {
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

        let mut rng = thread_rng();

        let f1 = BigInt::from_str("405373").unwrap();
        let modulus: BigInt = f1;
        // Generate a random index which we can find quickly
        let res = rng.gen_bigint_range(&BigInt::zero(), &modulus);
        let index = rng.gen_bigint_range(&BigInt::zero(), &modulus);
        //let index: BigInt = &i + &j * &modulus;
        //let res = BigInt::from_usize(50).unwrap();
        //let index = BigInt::from_usize(160).unwrap();
        //
        //
        // Fix with some which fail the test
        //let res = BigInt::from_str("268184").unwrap();
        //let index = BigInt::from_str("362400").unwrap();

        // b_priv: 146907443384

        let b_priv: BigInt = &res + &modulus * &index;

        let wp = wc.scale(&wc.params.bp, &b_priv);
        println!("Weierstrass point: {:?}", wp);

        let b_sub = wc.scale(&wc.params.bp, &(&modulus * &index));
        println!("Weierstrass - res: {:?}", b_sub);

        let b_pub = mc.ladder(&mc.bp, &b_priv);
        let bits = index.bits() as u32;
        println!("res: {res}");
        println!("Index: {index}");
        println!("b_priv: {b_priv}");
        println!("Bits: {bits}");
        let crack = shanks_for_mc(&res, &modulus, &b_pub, bits + 1);
        println!("b_pub: {b_pub}");
        if let Some(x) = crack.clone() {
            println!("b_pub? {}", mc.ladder(&mc.bp, &x));
        }
        assert_eq!(Some(b_priv), crack);
    }

    #[test]
    fn ec_scaling_test() {
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

        let minus_4 = curve
            .scale(&curve.params.bp, &BigInt::from_str("4").unwrap())
            .invert(&curve.params.p);

        let plus_24 = curve.scale(&curve.params.bp, &BigInt::from_str("16").unwrap());
        let minus_5 = curve
            .scale(&curve.params.bp, &BigInt::from_str("5").unwrap())
            .invert(&curve.params.p);

        let mut minus_4_alt = plus_24;
        minus_4_alt = curve.add(&minus_4_alt, &minus_5);
        minus_4_alt = curve.add(&minus_4_alt, &minus_5);
        minus_4_alt = curve.add(&minus_4_alt, &minus_5);
        minus_4_alt = curve.add(&minus_4_alt, &minus_5);

        assert_eq!(minus_4, minus_4_alt);
    }
}
