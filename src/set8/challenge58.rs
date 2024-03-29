//! 58. Pollard's Method for Catching Kangaroos
//!
//! The last problem was a little contrived. It only worked because I
//! helpfully foisted those broken group parameters on Alice and
//! Bob. While real-world groups may include some small subgroups, it's
//! improbable to find this many in a randomly generated group.
//!
//! So what if we can only recover some fraction of the Bob's secret key?
//! It feels like there should be some way to use that knowledge to
//! recover the rest. And there is: Pollard's kangaroo algorithm.
//!
//! This is a generic attack for computing a discrete logarithm (or
//! "index") known to lie within a certain contiguous range [a, b]. It has
//! a work factor approximately the square root of the size of the range.
//!
//! The basic strategy is to try to find a collision between two
//! pseudorandom sequences of elements. One will start from an element of
//! known index, and the other will start from the element y whose index
//! we want to find.
//!
//! It's important to understand how these sequences are
//! generated. Basically, we just define some function f mapping group
//! elements (like the generator g, or a public key y) to scalars (a
//! secret exponent, like x), i.e.:
//!
//!     f(y) = <some x>
//!
//! Don't worry about how f is implemented for now. Just know that it's a
//! function mapping where we are (some y) to the next jump we're going to
//! take (some x). And it's deterministic: for a given y, it should always
//! return the same x.
//!
//! Then we do a loop like this:
//!
//!     y := y * g^f(y)
//!
//! The key thing here is that the next step we take is a function whose
//! sole input is the current element. This means that if our two
//! sequences ever happen to visit the same element y, they'll proceed in
//! lockstep from there.
//!
//! Okay, let's get a bit more specific. I mentioned we're going to
//! generate two sequences this way. The first is our control
//! sequence. This is the tame kangaroo in Pollard's example. We do
//! something like this:
//!
//!     xT := 0
//!     yT := g^b
//!
//!     for i in 1..N:
//!         xT := xT + f(yT)
//!         yT := yT * g^f(yT)
//!
//! Recall that b is the upper bound on the index of y. So we're starting
//! the tame kangaroo's run at the very end of that range. Then we just
//! take N leaps and accumulate our total distance traveled in xT. At the
//! end of the loop, yT = g^(b + xT). This will be important later.
//!
//! Note that this algorithm doesn't require us to build a big look-up
//! table a la Shanks' baby-step giant-step, so its space complexity is
//! constant. That's kinda neat.
//!
//! Now: let's catch that wild kangaroo. We'll do a similar loop, this
//! time starting from y. Our hope is that at some point we'll collide
//! with the tame kangaroo's path. If we do, we'll eventually end up at
//! the same place. So on each iteration, we'll check if we're there.
//!
//!     xW := 0
//!     yW := y
//!
//!     while xW < b - a + xT:
//!         xW := xW + f(yW)
//!         yW := yW * g^f(yW)
//!
//!         if yW = yT:
//!             return b + xT - xW
//!
//! Take a moment to puzzle out the loop condition. What that relation is
//! checking is whether we've gone past yT and missed it. In other words,
//! that we didn't collide. This is a probabilistic algorithm, so it's not
//! guaranteed to work.
//!
//! Make sure also that you understand the return statement. If you think
//! through how we came to the final values for yW and yT, it should be
//! clear that this value is the index of the input y.
//!
//! There are a couple implementation details we've glossed over -
//! specifically the function f and the iteration count N. I do something
//! like this:
//!
//!     f(y) = 2^(y mod k)
//!
//! For some k, which you can play around with. Making k bigger will allow
//! you to take bigger leaps in each loop iteration.
//!
//! N is then derived from f - take the mean of all possible outputs of f
//! and multiply it by a small constant, e.g. 4. You can make the constant
//! bigger to better your chances of finding a collision at the (obvious)
//! cost of extra computation. The reason N needs to depend on f is that f
//! governs the size of the jumps we can make. If the jumps are bigger, we
//! need a bigger runway to land on, or else we risk leaping past it.
//!
//! Implement Pollard's kangaroo algorithm. Here are some (less
//! accommodating) group parameters:
//!
//!     p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
//!     q = 335062023296420808191071248367701059461
//!     j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
//!     g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
//!
//! And here's a sample y:
//!
//!     y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
//!
//! The index of y is in the range [0, 2^20]. Find it with the kangaroo
//! algorithm.
//!
//! Wait, that's small enough to brute force. Here's one whose index is in
//! [0, 2^40]:
//!
//!     y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
//!
//! Find that one, too. It might take a couple minutes.
//!
//!     ~~ later ~~
//!
//! Enough about kangaroos, let's get back to Bob. Suppose we know Bob's
//! secret key x = n mod r for some r < q. It's actually not totally
//! obvious how to apply this algorithm to get the rest! Because we only
//! have:
//!
//!     x = n mod r
//!
//! Which means:
//!
//!     x = n + m*r
//!
//! For some unknown m. This relation defines a set of values that are
//! spread out at intervals of r, but Pollard's kangaroo requires a
//! continuous range!
//!
//! Actually, this isn't a big deal. Because check it out - we can just
//! apply the following transformations:
//!
//!     x = n + m*r
//!     y = g^x = g^(n + m*r)
//!     y = g^n * g^(m*r)
//!     y' = y * g^-n = g^(m*r)
//!     g' = g^r
//!     y' = (g')^m
//!
//! Now simply search for the index m of y' to the base element g'. Notice
//! that we have a rough bound for m: [0, (q-1)/r]. After you find m, you
//! can plug it into your existing knowledge of x to recover the rest of
//! the secret.
//!
//! Take the above group parameters and generate a key pair for Bob. Use
//! your subgroup-confinement attack from the last problem to recover as
//! much of Bob's secret as you can. You'll be able to get a good chunk of
//! it, but not the whole thing. Then use the kangaroo algorithm to run
//! down the remaining bits.

use anyhow::anyhow;
use hmac_sha256::HMAC;
use indicatif::ProgressBar;
use num_bigint::{BigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{FromPrimitive, ToPrimitive, Zero};
use rand::thread_rng;
use std::collections::HashMap;
use std::str::FromStr;

use crate::{
    set8::challenge57::{get_factors, get_h},
    utils::*,
};

#[allow(dead_code)]
pub fn shanks(g: &BigInt, p: &BigInt, upper: &BigInt, y: &BigInt) -> Result<BigInt> {
    // Trying to solve g^x = y
    // x is in a range say, [0,2^n]
    // So we can break the problem down into two steps, the giant and the baby step, each of order
    // sqrt(n).
    // x = i + m*j, m = sqrt(n)
    // This means that i runs from 1-> floor(sqrt(n)), j from 1-> floor(sqrt(n))
    //
    // Pre-compute all of y* g^(-mj) -> sqrt(n) operations, and store in a hash table:
    // y*g^(-mj) : j
    //
    // Now calculate g^i for all i, and find the collision with the hash table
    // We now have j and i, so can calculate the index

    let mut h = HashMap::new();
    let m: BigInt = upper.sqrt();
    let thou = BigInt::from_u32(1000).unwrap();

    let mut i = BigInt::zero();

    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Baby step {}: {}", i, m));
    // Big step hashmap
    while i <= m {
        let gi = g.modpow(&i, p);
        h.insert(gi, i.clone());
        if i.is_multiple_of(&thou) {
            spinner.set_message(format!("Baby step {}: {}", i, m));
            spinner.tick();
        }
        i += 1;
    }
    spinner.set_message("Baby step completed".to_string());
    spinner.finish();

    let mut j = BigInt::zero();
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Giant step {}: {}", i, m));
    while j <= m {
        if j.is_multiple_of(&thou) {
            spinner.set_message(format!("Giant step {}: {}", j, m));
            spinner.tick();
        }

        let gmj = g.modpow(&(&m * &j), p);
        let gmjinv = invmod(&gmj, p);
        let yp = (y * gmjinv) % p;

        if let Some(i_true) = h.get(&yp) {
            let index: BigInt = i_true + &j * m;
            spinner.set_message("Giant step completed".to_string());
            spinner.finish();
            return Ok(index);
        }
        j += 1;
    }
    spinner.set_message("Giant step completed, no solution found".to_string());
    spinner.finish();

    Err(anyhow!("Index not in bound"))
}

fn try_kangaroo<F>(
    f: F,
    n: &BigInt,
    g: &BigInt,
    p: &BigInt,
    a: &BigInt,
    b: &BigInt,
    y: &BigInt,
) -> Result<BigInt>
where
    F: Copy + FnOnce(&BigInt) -> BigInt,
{
    let mut count = BigInt::zero();
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Tame kangaroo step {}: {}", count, n));
    // Tame kangaroo
    let mut xt = BigInt::zero();
    let mut yt = g.modpow(b, p);
    let thou = BigInt::from_u32(1000).unwrap();
    while &count < n {
        let ff = f(&yt);
        xt += &ff;
        yt = (yt * g.modpow(&ff, p)) % p;
        count += 1;
        if count.is_multiple_of(&thou) {
            spinner.tick();
            spinner.set_message(format!("Tame kangaroo step {}/{}", count, n));
            //println!("xt: {}", xt);
            //println!("count: {}", count);
            //println!("f: {}", ff);
        }
    }
    spinner.set_message("Tame kangaroo set trap".to_string());
    spinner.finish();

    // Wild kangaroo
    let mut xw = BigInt::zero();
    let xw_max: BigInt = b - a + &xt;
    let mut yw = y.clone();
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Wild kangaroo xw/xw_max {}: {}", xw, xw_max));

    count = 1.into();
    while xw < b - a + &xt {
        count += 1;
        let ff = f(&yw);
        if count.is_multiple_of(&thou) {
            spinner.set_message(format!("Wild kangaroo xw/xw_max {}: {}", xw, xw_max));
            spinner.tick();
        }
        xw += &ff;
        yw = (yw * g.modpow(&ff, p)) % p;
        if yw == yt {
            spinner.set_message("Caught the wild kangaroo!".to_string());
            spinner.finish();
            return Ok(b + xt - xw);
        }
    }

    spinner.finish();
    Err(anyhow!("Wild kangaroo never landed on the tame kangaroo"))
}

#[allow(dead_code)]
fn kangaroo<F>(f: F, g: &BigInt, p: &BigInt, a: &BigInt, b: &BigInt, y: &BigInt) -> BigInt
where
    F: Copy + FnOnce(&BigInt) -> BigInt,
{
    let mut k = BigInt::from_u32(11).unwrap();
    let one = BigInt::from_u32(1).unwrap();
    let two = BigInt::from_u32(2).unwrap();
    let mut n = two.modpow(&(&one + &k), p) / &k;
    let stretch = BigInt::from_u32(8).unwrap();
    loop {
        println!("Loop");
        if let Ok(z) = try_kangaroo(f, &n, g, p, a, b, y) {
            return z;
        }
        k += 1;
        n = &stretch * two.modpow(&(&one + &k), p) / &k;
    }
}

pub fn main() -> Result<()> {
    let p = BigInt::from_str("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623").unwrap();
    let q = BigInt::from_str("335062023296420808191071248367701059461").unwrap();
    let j = BigInt::from_str("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702").unwrap();
    let g = BigInt::from_str("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357").unwrap();

    // Generate a keypair for Bob
    let mut rng = thread_rng();
    let b_priv = rng.gen_bigint_range(&BigInt::zero(), &q);
    let b_pub = g.modpow(&b_priv, &p);

    let two: BigInt = 2.into();
    let limit = two.pow(20);
    let j_fac = get_factors(&j, &limit);
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
        x_crack %= &r;
        println!("x mod {}: {}", r, x_crack);

        rx.push((r.clone(), x_crack));

        total_prod *= &r;
        if total_prod > q {
            break;
        }
    }

    // Incomplete CRT
    let mut result: BigInt = BigInt::zero();
    for (r, x) in rx {
        let ms = &total_prod / &r;
        result += x * &ms * invmod(&ms, &r);
    }
    result %= &total_prod;

    let r = total_prod.clone();
    let x_crack = result;

    let one = BigInt::from_u32(1).unwrap();
    println!("We now know x mod r = {}", x_crack);
    println!("r: {}", r);
    println!("Upper bound: {}", (&q - &one) / &r);
    println!("Time to figure out the rest");

    // y = g**(x) = g**(n+mr), where n is x_crack
    let gn = g.modpow(&x_crack, &p);
    let gninv = invmod(&gn, &p);
    let yp: BigInt = (&b_pub * &gninv) % &p;
    let gp: BigInt = g.modpow(&r, &p);

    let upper_index: BigInt = (&q - &one) / &r;

    let k = BigInt::from_u32(23).unwrap();
    let stretch = BigInt::from_u32(4).unwrap();
    let n = stretch * (two.modpow(&(&one + &k), &p) / &k);

    let index = try_kangaroo(
        |z| {
            let zmod = z.mod_floor(&k).to_u32().unwrap();
            two.pow(zmod)
        },
        &n,
        &gp,
        &p,
        &BigInt::zero(),
        &upper_index,
        &yp,
    )
    .unwrap();
    let b_priv_deduced: BigInt = &x_crack + &index * &r;
    println!("b_priv_dedu = {}", b_priv_deduced);
    println!("b_priv_true = {}", b_priv);
    assert_eq!(b_priv_deduced, b_priv);

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn small_shanks() {
        let p = BigInt::from_str("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623").unwrap();
        let _q = BigInt::from_str("335062023296420808191071248367701059461").unwrap();
        let _j = BigInt::from_str("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702").unwrap();
        let g = BigInt::from_str("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357").unwrap();
        let y = BigInt::from_str("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119").unwrap();
        let two = BigInt::from_u32(2).unwrap();
        let upper_bound: BigInt = two.pow(20);

        let index = shanks(&g, &p, &upper_bound, &y).unwrap();

        let deduced = g.modpow(&index, &p);
        println!("index: {} vs 2^20: {}", index, upper_bound);
        println!("g**index mod p = {}", deduced);
        println!("y = {}", y);
        assert_eq!(deduced, y);
    }

    #[ignore = "slow"]
    #[test]
    fn big_shanks() {
        let p = BigInt::from_str("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623").unwrap();
        let _q = BigInt::from_str("335062023296420808191071248367701059461").unwrap();
        let _j = BigInt::from_str("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702").unwrap();
        let g = BigInt::from_str("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357").unwrap();
        let y = BigInt::from_str("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733").unwrap();
        let two = BigInt::from_u32(2).unwrap();
        let upper_bound: BigInt = two.pow(40);

        let index = shanks(&g, &p, &upper_bound, &y).unwrap();

        let deduced = g.modpow(&index, &p);
        println!("index: {} vs 2^20: {}", index, upper_bound);
        println!("g**index mod p = {}", deduced);
        println!("y = {}", y);
        assert_eq!(deduced, y);
    }
    #[test]
    fn small_kangaroo() {
        let p = BigInt::from_str("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623").unwrap();
        let _q = BigInt::from_str("335062023296420808191071248367701059461").unwrap();
        let _j = BigInt::from_str("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702").unwrap();
        let g = BigInt::from_str("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357").unwrap();

        let five = BigInt::from_u32(5).unwrap();
        let two = BigInt::from_u32(2).unwrap();
        let _one = BigInt::from_u32(1).unwrap();
        let _three = BigInt::from_u32(3).unwrap();

        let k = BigInt::from_u32(11).unwrap();
        let upper_index = BigInt::from_u32(20).unwrap();
        let n = two.modpow(&(&five + &k), &p) / &k;
        let y = BigInt::from_str("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119").unwrap();
        println!("Finding index in range [0,2^20]");
        let index = try_kangaroo(
            |z| {
                let zmod = z.mod_floor(&k).to_u32().unwrap();
                //        println!("z: {}", z);
                //        println!("zmod: {}", zmod);

                two.pow(zmod)
            },
            &n,
            &g,
            &p,
            &BigInt::zero(),
            &upper_index,
            &y,
        )
        .unwrap();

        let deduced = g.modpow(&index, &p);
        println!("index: {} vs 2^20: {}", index, two.pow(20));
        println!("g**index mod p = {}", deduced);
        println!("y = {}", y);
        assert_eq!(deduced, y);
    }

    #[ignore = "slow"]
    #[test]
    fn big_kangaroo() {
        let p = BigInt::from_str("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623").unwrap();
        let _q = BigInt::from_str("335062023296420808191071248367701059461").unwrap();
        let _j = BigInt::from_str("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702").unwrap();
        let g = BigInt::from_str("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357").unwrap();

        let _five = BigInt::from_u32(5).unwrap();
        let two = BigInt::from_u32(2).unwrap();
        let one = BigInt::from_u32(1).unwrap();

        let y = BigInt::from_str("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733").unwrap();
        let upper_index = BigInt::from_u32(40).unwrap();
        let stretch = BigInt::from_u32(8).unwrap();

        let k = BigInt::from_u32(22).unwrap();
        let n = stretch * (two.modpow(&(&one + &k), &p) / &k);

        let index = try_kangaroo(
            |z| {
                let zmod = z.mod_floor(&k).to_u32().unwrap();
                two.pow(zmod)
            },
            &n,
            &g,
            &p,
            &BigInt::zero(),
            &upper_index,
            &y,
        )
        .unwrap();
        let deduced = g.modpow(&index, &p);
        println!("g**index mod p = {}", deduced);
        println!("y = {}", y);
        assert_eq!(deduced, y);
    }
}
