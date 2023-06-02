//! 59. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
//!
//! I'm not going to show you any graphs - if you want to see one, you can
//! find them in, like, every other elliptic curve tutorial on the
//! internet. Personally, I've never been able to gain much insight from
//! them.
//!
//! They're also really hard to draw in ASCII.
//!
//! The key thing to understand about elliptic curves is that they're a
//! setting analogous in many ways to one we're more familiar with, the
//! multiplicative integers mod p. So if we learn how certain primitive
//! operations are defined, we can reason about them using a lot of tools
//! we already have in our utility belts.
//!
//! Let's dig in. An elliptic curve E is just an equation like this:
//!
//!     y^2 = x^3 + a*x + b
//!
//! The choice of the a and b coefficients defines the curve.
//!
//! The elements in our group are going to be (x, y) coordinates
//! satisfying the curve equation. Now, there are infinitely many pairs
//! like that on the curve, but we only want to think about some of
//! them. We'll trim our set of points down by considering the curve in
//! the context of a finite field.
//!
//! For the moment, it's not too important to know what a finite field
//! is. You can basically just think of it as "integers mod p" with all
//! the usual operations you expect: multiplication, division (via modular
//! inversion), addition, and subtraction.
//!
//! We'll use the notation GF(p) to talk about a finite field of size
//! p. (The "GF" is for "Galois field", another name for a finite field.)
//! When we take a curve E over field GF(p) (written E(GF(p))), what we're
//! saying is that only points with both x and y in GF(p) are valid.
//!
//! For example, (3, 6) might be a valid point in E(GF(7)), but it
//! wouldn't be a valid point in E(GF(5)); 6 is not a member of GF(5).
//!
//! (3, 4.7) wouldn't be a valid point on either curve, since 4.7 is not
//! an integer and thus not a member of either field.
//!
//! What about (3, -1)? This one is on the curve, but remember we're in
//! some GF(p). So in GF(7), -1 is actually 6. That means (3, -1) and (3,
//! 6) are the same point. In GF(5), -1 is 4, so blah blah blah you get
//! what I'm saying.
//!
//! Okay: if these points are going to form a group analogous to the
//! multiplicative integers mod p, we need to have an analogous set of
//! primitive functions to work with them.
//!
//! 1. In the multiplicative integers mod p, we combined two elements by
//!    multiplying them together and taking the remainder modulo p.
//!
//!    We combine elliptic curve points by adding them. We'll talk about
//!    what that means in a hot second.
//!
//! 2. We used 1 as a multiplicative identity: y * 1 = y for all y.
//!
//!    On an elliptic curve, we define the identity O as an abstract
//!    "point at infinity" that doesn't map to any actual (x, y)
//!    pair. This might feel like a bit of a hack, but it works.
//!
//!    On the curve, we have the straightforward rule that P + O = P for
//!    all P.
//!
//!    In your code, you can just write something like O := object(),
//!    since it only ever gets used in pointer comparisons. Or you can use
//!    some sentinel coordinate that doesn't satisfy the curve equation;
//!    (0, 1) is popular.
//!
//! 3. We had a modinv function to invert an integer mod p. This acted as
//!    a stand-in for division. Given y, it finds x such that y * x = 1.
//!
//!    Inversion is way easier in elliptic curves. Just flip the sign on
//!    y, and remember that we're in GF(p):
//!
//!        invert((x, y)) = (x, -y) = (x, p-y)
//!
//!    Just like with multiplicative inverses, we have this rule on
//!    elliptic curves:
//!
//!        P + (-P) = P + invert(P) = O
//!
//! Incidentally, these primitives, along with a finite set of elements,
//! are all we need to define a finite cyclic group, which is all we need
//! to define the Diffie-Hellman function. Not important to understand the
//! abstract jargon, just FYI.
//!
//! Let's talk about addition. Here it is:
//!
//!     function add(P1, P2):
//!         if P1 = O:
//!             return P2
//!
//!         if P2 = O:
//!             return P1
//!
//!         if P1 = invert(P2):
//!             return O
//!
//!         x1, y1 := P1
//!         x2, y2 := P2
//!
//!         if P1 = P2:
//!             m := (3*x1^2 + a) / 2*y1
//!         else:
//!             m := (y2 - y1) / (x2 - x1)
//!
//!         x3 := m^2 - x1 - x2
//!         y3 := m*(x1 - x3) - y1
//!
//!         return (x3, y3)
//!
//! The first three checks are simple - they pretty much just implement
//! the rules we have for the identity and inversion.
//!
//! After that we, uh, use math. You can read more about that part
//! elsewhere, if you're interested. It's not too important to us, but it
//! (sort of) makes sense in the context of those graphs I'm not showing
//! you.
//!
//! There's one more thing we need. In the multiplicative integers, we
//! expressed repeated multiplication as exponentiation, e.g.:
//!
//!     y * y * y * y * y = y^5
//!
//! We implemented this using a modexp function that walked the bits of
//! the exponent with a square-and-multiply inner loop.
//!
//! On elliptic curves, we'll use scalar multiplication to express
//! repeated addition, e.g.:
//!
//!     P + P + P + P + P = 5*P
//!
//! Don't be confused by the shared notation: scalar multiplication is not
//! analogous to multiplication in the integers. It's analogous to
//! exponentiation.
//!
//! Your scalarmult function will look pretty much exactly the same as
//! your modexp function, except with the primitives swapped out.
//!
//! Actually, you wanna hear something great? You could define a generic
//! scale function parameterized over a group that works as a drop-in
//! implementation for both. Like this:
//!
//!     function scale(x, k):
//!         result := identity
//!         while k > 0:
//!             if odd(k):
//!                 result := combine(result, x)
//!             x := combine(x, x)
//!             k := k >> 1
//!         return result
//!
//! The combine function would delegate to modular multiplication or
//! elliptic curve point depending on the group. It's kind of like the
//! definition of a group constitutes a kind of interface, and we have
//! these two different implementations we can swap out freely.
//!
//! To extend this metaphor, here's a generic Diffie-Hellman:
//!
//!     function generate_keypair():
//!         secret := random(1, baseorder)
//!         public := scale(base, secret)
//!         return (secret, public)
//!
//!     function compute_secret(peer_public, self_secret):
//!         return scale(peer_public, self_secret)
//!
//! Simplicity itself! The base and baseorder attributes map to g and q in
//! the multiplicative integer setting. It's pretty much the same on a
//! curve: we'll have a base point G and its order n such that:
//!
//!     n*G = O
//!
//! The fact that these two settings share so many similarities (and can
//! even share a naive implementation) is great news. It means we already
//! have a lot of the tools we need to reason about (and attack) elliptic
//! curves!
//!
//! Let's put this newfound knowledge into action. Implement a set of
//! functions up to and including elliptic curve scalar
//! multiplication. (Remember that all computations are in GF(p), i.e. mod
//! p.) You can use this curve:
//!
//!     y^2 = x^3 - 95051*x + 11279326
//!
//! Over GF(233970423115425145524320034830162017933). Use this base point:
//!
//!     (182, 85518893674295321206118380980485522083)
//!
//! It has order 29246302889428143187362802287225875743.
//!
//! Oh yeah, order. Finding the order of an elliptic curve group turns out
//! to be a bit tricky, so just trust me when I tell you this one has
//! order 233970423115425145498902418297807005944. That factors to 2^3 *
//! 29246302889428143187362802287225875743.
//!
//! Note: it's totally possible to pick an elliptic curve group whose
//! order is just a straight-up prime number. This would mean that every
//! point on the curve (except the identity) would have the same order,
//! since the group order would have no other divisors. The NIST P-curves
//! are like this.
//!
//! Our curve has almost-prime order. There's just that small cofactor of
//! 2^3, which is beneficial for reasons we'll cover later. Don't worry
//! about it for now.
//!
//! If your implementation works correctly, it should be easy to verify:
//! remember that multiplying the base point by its order should yield the
//! group identity.
//!
//! Implement ECDH and verify that you can do a handshake correctly. In
//! this case, Alice and Bob's secrets will be scalars modulo the base
//! point order and their public elements will be points. If you
//! implemented the primitives correctly, everything should "just work".
//!
//! Next, reconfigure your protocol from #57 to use it.
//!
//! Can we apply the subgroup-confinement attacks from #57 in this
//! setting? At first blush, it seems like it will be pretty difficult,
//! since the cofactor is so small. We can recover, like, three bits by
//! sending a point with order 8, but that's about it. There just aren't
//! enough small-order points on the curve.
//!
//! How about not on the curve?
//!
//! Wait, what? Yeah, points *not* on the curve. Look closer at our
//! combine function. Notice anything missing? The b parameter of the
//! curve is not accounted for anywhere. This is because we have four
//! inputs to the calculation: the curve parameters (a, b) and the point
//! coordinates (x, y). Given any three, you can calculate the fourth. In
//! other words, we don't need b because b is already baked into every
//! valid (x, y) pair.
//!
//! There's a dangerous assumption there: namely, that the peer will
//! submit a valid (x, y) pair. If Eve can submit an invalid pair, that
//! really opens up her play: now she can pick points from any curve that
//! differs only in its b parameter. All she has to do is find some curves
//! with small subgroups and cherry-pick a few points of small
//! order. Alice will unwittingly compute the shared secret on the wrong
//! curve and leak a few bits of her private key in the process.
//!
//! How do we find suitable curves? Well, remember that I mentioned
//! counting points on elliptic curves is tricky. If you're very brave,
//! you can implement Schoof-Elkies-Atkins. Or you can use a computer
//! algebra system like SageMath. Or you can just use these curves I
//! generated for you:
//!
//!     y^2 = x^3 - 95051*x + 210
//!     y^2 = x^3 - 95051*x + 504
//!     y^2 = x^3 - 95051*x + 727
//!
//! They have orders:
//!
//!     233970423115425145550826547352470124412
//!     233970423115425145544350131142039591210
//!     233970423115425145545378039958152057148
//!
//! They should have a fair few small factors between them. So: find some
//! points of small order and send them to Alice. You can use the same
//! trick from before to find points of some prime order r. Suppose the
//! group has order q. Pick some random point and multiply by q/r. If you
//! land on the identity, start over.
//!
//! It might not be immediately obvious how to choose random points, but
//! you can just pick an x and calculate y. This will require you to
//! implement a modular square root algorithm; use Tonelli-Shanks, it's
//! pretty straightforward.
//!
//! Implement the key-recovery attack from #57 using small-order points
//! from invalid curves.

use anyhow::anyhow;
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, Zero};
use rand::thread_rng;
use std::{ops::Shr, str::FromStr};

use crate::{set8::challenge57::get_factors, utils::*};

#[derive(Debug)]
pub struct CurveParams {
    pub a: BigInt,
    pub b: BigInt,
    pub p: BigInt,
    pub ord: BigInt,
    pub bp: Point,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Point {
    P { x: BigInt, y: BigInt },
    O,
}

impl Point {
    #[allow(dead_code)]
    pub fn get_x(&self) -> Option<BigInt> {
        match self {
            Point::P { x, .. } => Some(x.clone()),
            Point::O => None,
        }
    }

    fn invert(&self, p: &BigInt) -> Self {
        if let Self::P { x, y } = self {
            Self::P {
                x: x.clone(),
                y: p - y.clone(),
            }
        } else {
            Self::O
        }
    }
}

pub struct Curve {
    pub params: CurveParams,
}

impl Curve {
    /// Adds two points on an elliptic curve
    ///
    /// y^2 = x^3 + ax + b
    ///
    /// P+Q=S
    /// R=-S
    ///
    /// For distinct points
    /// Straight line going through P, Q is given by
    /// y = y_p + m * (x-x_p)
    /// m = (y_q-y_p)/(x_q-x_p)
    ///
    /// Plug this into EC, and find third root
    ///
    /// (y_p + m(x-x_p))^2 = x^3 + ax + b
    ///
    /// x^3 + ax + b - y_p^2 - m^2 (x-x_p)^2 - 2m(x-x_p)y_p = 0
    /// Has form
    /// (x-x_p)(x-x_q)(x-x_s) = 0
    /// and so x^2 component is of form -x^2(x_p+x_q+x_s)
    /// i.e.
    /// x_p + x_q + x_s = m^2
    /// i.e. x_s = m^2 - x_p - x_q
    /// y_s follow from straight line
    /// y_s = y_p + m(x_s-x_p)
    /// and R follows by reflection in x-axis i.e. x_r = x_s, y_r = -y_s
    ///
    /// x_r = m^2 - x_p - x_q
    /// y_r = m(x_p - x_r) - y_p
    ///
    /// For doubling a point, m is simply the gradient
    /// 2 y y' = 3x^2 + a
    /// => m = (3 x_p^2 + a)/(2 y_p)
    /// And the rest follows in the same way
    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        if p1 == &Point::O {
            return p2.clone();
        }
        if p2 == &Point::O {
            return p1.clone();
        }
        if p1 == &p2.invert(&self.params.p) {
            return Point::O;
        }

        if let (Point::P { x: x1, y: y1 }, Point::P { x: x2, y: y2 }) = (p1, p2) {
            let m: BigInt = match (x1, y1) == (x2, y2) {
                true => {
                    let three: BigInt = 3.into();
                    let two: BigInt = 2.into();
                    (three * x1 * x1 + &self.params.a) * invmod(&(two * y1), &self.params.p)
                }
                false => {
                    let dy = (y2 - y1).mod_floor(&self.params.p);
                    let dx = (x2 - x1).mod_floor(&self.params.p);
                    dy * invmod(&dx, &self.params.p)
                }
            }
            .mod_floor(&self.params.p);

            let x3: BigInt = ((&m * &m) - x1 - x2).mod_floor(&self.params.p);
            let y3: BigInt = (&m * (x1 - &x3) - y1).mod_floor(&self.params.p);

            Point::P { x: x3, y: y3 }
        } else {
            panic!("Unexpected");
        }
    }

    pub fn gen(&self, n: &BigInt) -> Point {
        self.scale(&self.params.bp, n)
    }

    //     function scale(x, k):
    //         result := identity
    //         while k > 0:
    //             if odd(k):
    //                 result := combine(result, x)
    //             x := combine(x, x)
    //             k := k >> 1
    //         return result
    pub fn scale(&self, point: &Point, exp: &BigInt) -> Point {
        let mut result: Point = Point::O;
        let mut k = exp.clone();
        let mut x = point.clone();

        while k > BigInt::zero() {
            if k.is_odd() {
                result = self.add(&x, &result);
            }
            x = self.add(&x, &x);
            k = k.shr(1);
        }
        result
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

    let mut rng = thread_rng();

    // Generate A's private key
    let a_priv = rng.gen_bigint_range(&BigInt::zero(), &curve.params.ord);
    let a_pub = curve.gen(&a_priv);

    // Generate B's private key
    let b_priv = rng.gen_bigint_range(&BigInt::zero(), &curve.params.ord);
    let b_pub = curve.gen(&b_priv);

    let b_shared = curve.scale(&a_pub, &b_priv);
    let a_shared = curve.scale(&b_pub, &a_priv);
    assert_eq!(a_shared, b_shared);

    println!("B public key: {:?}", b_pub);
    // y^2 = x^3 - 95051*x + 210
    // 233970423115425145550826547352470124412
    let curve1 = Curve {
        params: CurveParams {
            a: BigInt::from_str("-95051").unwrap(),
            b: BigInt::from_str("210").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: Point::P {
                x: BigInt::from_str("182").unwrap(),
                y: BigInt::from_str("85518893674295321206118380980485522083").unwrap(),
            },
            ord: BigInt::from_str("233970423115425145550826547352470124412").unwrap(),
        },
    };
    let two = BigInt::from_usize(2).unwrap();
    let limit = two.pow(20);
    let curve1_orders = get_factors(&curve1.params.ord, &limit);
    let mut rx = vec![];
    println!("Curve 1 factors: {:?}", curve1_orders);

    // Pick an order for this curve

    rx.extend_from_slice(&get_residues(&curve1, &curve1_orders, &curve, &b_priv));

    println!("Recovered: {:?}", rx);

    // y^2 = x^3 - 95051*x + 504
    // 233970423115425145544350131142039591210
    let curve2 = Curve {
        params: CurveParams {
            a: BigInt::from_str("-95051").unwrap(),
            b: BigInt::from_str("504").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: Point::P {
                x: BigInt::from_str("182").unwrap(),
                y: BigInt::from_str("85518893674295321206118380980485522083").unwrap(),
            },
            ord: BigInt::from_str("233970423115425145544350131142039591210").unwrap(),
        },
    };

    let curve2_orders = get_factors(&curve2.params.ord, &limit);
    // Ensure we don't duplicate r, as we already have that information
    let curve2_orders: Vec<_> = curve2_orders
        .into_iter()
        .filter(|r| !rx.iter().any(|(x, _)| r == x))
        .collect();
    println!("Curve 2 factors: {:?}", curve2_orders);
    rx.extend_from_slice(&get_residues(&curve2, &curve2_orders, &curve, &b_priv));

    println!("Recovered: {:?}", rx);
    // y^2 = x^3 - 95051*x + 727
    // 233970423115425145545378039958152057148
    let curve3 = Curve {
        params: CurveParams {
            a: BigInt::from_str("-95051").unwrap(),
            b: BigInt::from_str("727").unwrap(),
            p: BigInt::from_str("233970423115425145524320034830162017933").unwrap(),
            bp: Point::P {
                x: BigInt::from_str("182").unwrap(),
                y: BigInt::from_str("85518893674295321206118380980485522083").unwrap(),
            },
            ord: BigInt::from_str("233970423115425145545378039958152057148").unwrap(),
        },
    };
    let curve3_orders = get_factors(&curve3.params.ord, &limit);
    // Ensure we don't duplicate r, as we already have that information
    let curve3_orders: Vec<_> = curve3_orders
        .into_iter()
        .filter(|r| !rx.iter().any(|(x, _)| r == x))
        .collect();
    println!("Curve 3 factors: {:?}", curve3_orders);
    rx.extend_from_slice(&get_residues(&curve3, &curve3_orders, &curve, &b_priv));

    println!("Recovered: {:?}", rx);
    // CRT
    // First get total product
    let total_prod = rx
        .iter()
        .fold(BigInt::from_usize(1).unwrap(), |a, (r, _)| a * r);

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
fn get_residues(
    curve: &Curve,
    orders: &[BigInt],
    orig_curve: &Curve,
    b_priv: &BigInt,
) -> Vec<(BigInt, BigInt)> {
    let mut recovered = vec![];

    // Skip first factor
    for r in &orders[1..] {
        let p1 = get_curve_pt(curve, r);
        println!("Random point of order {r}: {p1:?}");
        println!("r P1 = {:?}", curve.scale(&p1, r));
        // Now send this point to B and see what we get back
        // (Note that this point still has the same small order in the "real curve" which B uses, as b
        // does not enter into it

        let b1 = orig_curve.scale(&p1, b_priv);
        // Reverse b_priv modulo r for this
        let mut b_r = BigInt::zero();
        while curve.scale(&p1, &b_r) != b1 {
            b_r += 1;
        }
        recovered.push((r.clone(), b_r));
    }
    recovered
}

/// Tonelli-Shanks modular sqrt
/// Adapted from https://crypto.stanford.edu/pbc/notes/ep/tonelli.html
pub fn ts_sqrt(n: &BigInt, modulus: &BigInt) -> Result<BigInt> {
    if !is_sq(n, modulus) {
        return Err(anyhow!("No sqrt exists for point"));
    }

    // First factor p-1
    let mut s = BigInt::zero();
    let one = BigInt::from_usize(1).unwrap();
    let two = BigInt::from_usize(2).unwrap();
    let mut q: BigInt = modulus - BigInt::from_usize(1).unwrap();
    while q.is_multiple_of(&two) {
        q = q.div_floor(&two);
        s += &one;
    }

    // p-1 = q * 2^s
    //println!("p-1:   {}", modulus - &one);
    //println!("q*2^s: {}", &q * two.exp(&s));

    // Now find a z which is quadratic non-residue
    let z = quad_non_res(modulus);

    // Set vars
    let mut m = s.clone();
    let mut c = z.modpow(&q, modulus);
    let mut t = n.modpow(&q, modulus);
    let qp = (&q + &one).div_floor(&two);
    let mut r = n.modpow(&qp, modulus);

    loop {
        // println!("In main loop");
        match t {
            z if t == BigInt::zero() => return Ok(z),
            _ if t == one => return Ok(r),
            _ => {}
        }
        let mut i = BigInt::zero();
        while i < m {
            if t.modpow(&two.exp(&i), modulus) == one {
                break;
            }
            i = &i + &one;
            // println!("i: {}", i);
        }

        // println!("i: {}", i);
        let b = c.modpow(&two.exp(&(m - &i - &one)), modulus);
        m = i;
        c = (&b * &b) % modulus;
        t = (&t * &b * &b) % modulus;
        r = (r * &b) % modulus;
    }
}

trait Exp {
    fn exp(&self, other: &BigInt) -> Self;
}

impl Exp for BigInt {
    fn exp(&self, other: &BigInt) -> Self {
        let mut count = other.clone();
        let mut result = BigInt::from_usize(1).unwrap();
        let mut x = self.clone();
        let two = BigInt::from_usize(2).unwrap();
        while count != BigInt::zero() {
            if count.is_odd() {
                result *= &x;
            }
            x = &x * &x;
            count = count.div_floor(&two);
        }
        result
    }
}

fn is_sq(n: &BigInt, modulus: &BigInt) -> bool {
    let one = BigInt::from_usize(1).unwrap();
    // a^p = a mod p
    // (ord) P = O
    // (ord+1) P = P
    //
    let power: BigInt = (modulus - &one).div_floor(&BigInt::from_usize(2).unwrap());
    let d = n.modpow(&power, modulus);
    d == one
}

fn quad_non_res(modulus: &BigInt) -> BigInt {
    let mut rng = thread_rng();
    loop {
        let z = rng.gen_bigint_range(&BigInt::zero(), modulus);

        if !is_sq(&z, modulus) {
            return z;
        }
    }
}

fn get_curve_pt(curve: &Curve, r: &BigInt) -> Point {
    let mut rng = thread_rng();

    loop {
        let x = rng.gen_bigint_range(&BigInt::zero(), &curve.params.p);
        if let Ok(y) = get_y(curve, &x) {
            let p = Point::P { x, y };
            let sp = curve.scale(&p, &(&curve.params.ord / r));
            if sp != Point::O {
                return sp;
            }
        }
    }
}

fn get_y(curve: &Curve, x: &BigInt) -> Result<BigInt> {
    //y^2 = x^3 + ax + b
    let y2 = x * x * x + &curve.params.a * x + &curve.params.b;
    ts_sqrt(&y2, &curve.params.p)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn scale_test() {
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
        let mut running = Point::O;
        println!("Base point: {:?}", running);
        for i in 0..1_000 {
            running = curve.add(&curve.params.bp, &running);
            let scaled = curve.scale(&curve.params.bp, &BigInt::from_usize(i + 1).unwrap());
            println!("{}*P", i + 1);
            println!("Running: {:?}", running);
            println!("Scaled:  {:?}", scaled);
            assert_eq!(running, scaled);
        }
    }

    #[test]
    fn ec_abelian() {
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
        let p1 = Point::P {
            x: BigInt::from_str("231110995916992900219346197897292237295").unwrap(),
            y: BigInt::from_str("63844552430235414594643301238328922535").unwrap(),
        };
        let p2 = Point::P {
            x: BigInt::from_str("98092099574465157328748843078997945208").unwrap(),
            y: BigInt::from_str("160574384385092871957843305589437197340").unwrap(),
        };

        let p6 = curve.add(&p2, &p1);
        let p6a = curve.add(&p1, &p2);

        assert_eq!(p6, p6a);
    }

    #[test]
    fn ord() {
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

        // Test the order!
        let p_ord = curve.scale(&curve.params.bp, &curve.params.ord);
        println!("P_ord: {:?}", p_ord);
        assert_eq!(p_ord, Point::O);
    }

    #[test]
    fn dh_ec() {
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

        let ord = BigInt::from_str("29246302889428143187362802287225875743").unwrap();

        let mut rng = thread_rng();

        // Generate A's private key
        let a_priv = rng.gen_bigint_range(&BigInt::zero(), &ord);
        let a_pub = curve.gen(&a_priv);

        // Generate B's private key
        let b_priv = rng.gen_bigint_range(&BigInt::zero(), &ord);
        let b_pub = curve.gen(&b_priv);

        let b_shared = curve.scale(&a_pub, &b_priv);
        let a_shared = curve.scale(&b_pub, &a_priv);
        assert_eq!(a_shared, b_shared);
    }

    #[test]
    fn bigint_pow() {
        let two = BigInt::from_usize(2).unwrap();
        let fifteen = BigInt::from_usize(15).unwrap();
        let ans = BigInt::from_usize(2_usize.pow(15)).unwrap();
        assert_eq!(two.exp(&fifteen), ans);

        let three = BigInt::from_usize(3).unwrap();
        let fifteen = BigInt::from_usize(15).unwrap();
        let ans = BigInt::from_usize(3_usize.pow(15)).unwrap();
        assert_eq!(three.exp(&fifteen), ans);
    }

    #[test]
    fn sqrt_test() {
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

        for i in 1..10_000 {
            let pt = BigInt::from_usize(i).unwrap();
            println!("pt: {}", pt);
            if let Ok(s_d) = ts_sqrt(&pt, &curve.params.p) {
                let recon = (&s_d * &s_d) % &curve.params.p;
                println!("s_d: {}", s_d);
                println!("s_d * s_d = {}", recon);
                assert_eq!(pt, recon);
            }
        }
    }
}
