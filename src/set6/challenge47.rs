#![allow(non_snake_case)]
use std::collections::BTreeSet;
use std::ops::Bound::Included;
use std::ops::Mul;

use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{FromPrimitive, Zero};
use rand::thread_rng;

use crate::utils::*;

use super::challenge46::Key;

// Need some sort of intervals struct
#[derive(Debug, PartialEq, Clone)]
struct Interval {
    start: BigInt,
    end: BigInt,
}

impl Interval {
    pub fn new(start: &BigInt, end: &BigInt) -> Self {
        Self {
            start: start.clone(),
            end: end.clone(),
        }
    }
}

// Represents series of disjoint intervals
#[derive(Default)]
struct IntervalTree {
    lefts: BTreeSet<BigInt>,
    rights: BTreeSet<BigInt>,
}

impl IntervalTree {
    pub fn get_intervals(&self) -> Vec<Interval> {
        // Intervals are disjoint, so the ordering is the same
        self.lefts
            .iter()
            .zip(self.rights.iter())
            .map(|(x, y)| Interval {
                start: x.clone(),
                end: y.clone(),
            })
            .collect()
    }

    pub fn insert_interval(&mut self, interval: &Interval) {
        // There are four cases to consider:
        // 1. Interval is disjoint
        // 2. Interval overlaps one set on the left
        // 3. Interval overlaps one set on the right
        // 4. Interval joins two intervals

        // How does this play out? We start by taking lefts and rights and doing "split_off"
        // Imagine our intervals are (4,8) (11,13) (20,25)
        // And we wish to insert (x,y)
        // Our two BTreeSets are [4,11,20], [8,13,25]
        // We can find the elements which are included in the range defined by this
        //let left_pt: BigInt = &interval.start - 1;
        //let right_pt: BigInt = &interval.end + 1;

        // Count how many left points are inside interval
        let left_number = self
            .lefts
            .range((
                Included(&(interval.start.clone())),
                Included(&(interval.end.clone())),
            ))
            .count();
        let right_number = self
            .rights
            .range((
                Included(&(interval.start.clone())),
                Included(&(interval.end.clone())),
            ))
            .count();

        // There are three options here:
        // 1. They are equal, in which case our interval completely encompasses them and we can
        //    delete all of them and insert our new interval markers
        // 2. L = R+1, which means that we can delete all the lefts, and all of the rights, but
        //    only insert the leftmost point
        //    [ () () (  ]   )
        // 3. L+1 = R, which means that we can delete all the rights and all the lefts in the
        //    interval, and only insert the rightmost point
        // All of these cases delete all of them, so lets do that!
        let mut left_split = self
            .lefts
            .split_off(&interval.start)
            .split_off(&interval.end);
        self.lefts.append(&mut left_split);

        let mut left_split = self
            .rights
            .split_off(&interval.start)
            .split_off(&interval.end);
        self.rights.append(&mut left_split);

        // Now add the points back in which ought to be there
        match left_number == right_number {
            true => {
                self.lefts.insert(interval.start.clone());
                self.rights.insert(interval.end.clone());
            }
            false => match left_number < right_number {
                true => {
                    self.rights.insert(interval.end.clone());
                }
                false => {
                    self.lefts.insert(interval.start.clone());
                }
            },
        }

        // Finally, we do a quick check to "fuse" intervals
        // (    )[    ](     )
        // ->
        // (                 )
        // or any combination thereof
        let left_pt: BigInt = &interval.start - 1;
        if self.rights.remove(&left_pt) {
            self.lefts.remove(&interval.start);
        }
        let right_pt: BigInt = &interval.end + 1;
        if self.lefts.remove(&right_pt) {
            self.rights.remove(&interval.end);
        }
    }
}

// Make a finite state machine for the state of the algorithm matching Bleichenbacher '98
#[derive(Debug)]
enum Step {
    Step1,
    Step2a,
    Step2b,
    Step2c,
    Step3,
    Step4,
}

pub struct Attacker {
    intervals: IntervalTree,
    c0: BigInt,
    s0: BigInt,
    s: BigInt,
    publickey: Key,
    privatekey: Key,
    b: BigInt,
    state: Step,
    c: BigInt,
}

// What does this padding mean for the plaintext?
// k is number of bytes, hence
// 0x02,0x00,...,0x00,0x00
// ->
// 0x02,0xff,...,0xff,0x00
//
// The loose bound here is 2**(8(k-2)), all the way through to 2**(8k) - 1
// This is 2B -> 3B-1
// Whenever we have a valid plaintext, it must be in this interval
//
//

pub fn is_pkcs(c: &BigInt, private_key: &Key) -> bool {
    // First decrypt with the private key
    let c_decrypted = c.modpow(&private_key.key, &private_key.modulus);

    let cb = c_decrypted.to_bytes_be().1;
    let mut k = private_key.modulus.bits() as usize;
    k = num_integer::Integer::div_ceil(&k, &8);
    if cb.len() != k - 1 {
        return false;
    }
    cb[0] == 0x02
    /*
    let mut p_bytes = vec![0x00];
    p_bytes.extend_from_slice(&c_decrypted.to_bytes_be().1);
    for (i, b) in p_bytes.iter().enumerate() {
        if i == 0 && *b != 0x00 {
            return false;
        }
        if i == 1 && *b != 0x02 {
            return false;
        }
        if i > 1 && i <= 9 && *b == 0x00 {
            return false;
        }
        if i > 9 && *b == 0x00 {
            return true;
        }
    }
    false
    */
}

impl Attacker {
    pub fn new(c: &BigInt, public_key: &Key, private_key: &Key) -> Self {
        let mut intervals = IntervalTree::default();
        let c0 = BigInt::zero();
        let k: u32 = private_key.modulus.bits() as u32 / 8;
        let b = BigInt::from_u8(2).unwrap().pow(8 * (k - 2));
        let c = c.clone();
        let publickey: Key = public_key.clone();
        let privatekey: Key = private_key.clone();
        let state = Step::Step1;

        let twob: BigInt = 2 * &b;
        let one: BigInt = 1.into();
        let tbm1: BigInt = 3 * &b - one;

        let interval = Interval::new(&twob, &tbm1);
        intervals.insert_interval(&interval);
        let s: BigInt = BigInt::zero();
        let s0: BigInt = BigInt::zero();

        Self {
            s,
            s0,
            intervals,
            c0,
            publickey,
            privatekey,
            b,
            state,
            c,
        }
    }

    pub fn run(&mut self) -> BigInt {
        loop {
            println!("State: {:?}", self.state);
            match self.state {
                Step::Step1 => self.step1(),
                Step::Step2a => self.step2a(),
                Step::Step2b => self.step2b(),
                Step::Step2c => self.step2c(),
                Step::Step3 => self.step3(),
                Step::Step4 => return self.step4(),
            }
        }
    }
    fn step1(&mut self) {
        let mut rng = thread_rng();
        // Start with
        self.s = 1.into();
        loop {
            self.c0 = self
                .c
                .clone()
                .mul(self.s.modpow(&self.publickey.key, &self.publickey.modulus))
                .mod_floor(&self.publickey.modulus);
            if is_pkcs(&self.c0, &self.privatekey) {
                self.s0 = self.s.clone();
                break;
            }
            self.s = rng.gen_bigint_range(&BigInt::zero(), &self.publickey.modulus);
        }

        self.state = Step::Step2a;
    }
    fn try_si(&self) -> bool {
        // (c0 *(s)**e) mod n
        let c = (&self.c0 * &self.s.modpow(&self.publickey.key, &self.publickey.modulus))
            % &self.publickey.modulus;
        is_pkcs(&c, &self.privatekey)
    }
    fn step2a(&mut self) {
        let three_b: BigInt = &BigInt::from_u8(3).unwrap() * &self.b;
        // Initialise s = n/3B;
        self.s = self.publickey.modulus.clone();
        self.s = self.s.div_ceil(&three_b);

        while !self.try_si() {
            self.s += 1;
        }

        self.state = Step::Step3;
    }
    fn step2b(&mut self) {
        self.s += 1;
        while !self.try_si() {
            self.s += 1;
        }

        self.state = Step::Step3;
    }
    fn step2c(&mut self) {
        assert_eq!(self.intervals.get_intervals().len(), 1);
        let B: BigInt = self.b.clone();
        let n: BigInt = self.publickey.modulus.clone();

        assert_eq!(self.intervals.get_intervals().len(), 1);
        // There is only one interval
        let Interval { start: a, end: b } = self.intervals.get_intervals()[0].clone();
        // Print size of interval just to check it's getting smaller
        println!("Size of diff:        {}", &b - &a);
        println!("Size of diff (bits): {}", (&b - &a).bits());
        // r = 2(bs - 2B)/n
        let mut r: BigInt = 2 * (&b * &self.s - 2 * &B);
        r = r.div_ceil(&n);
        self.s = 2 * &B + &r * &n;
        self.s = self.s.div_ceil(&b);
        let mut upper: BigInt = (3 * &B + &r * &n) / &a;

        while !self.try_si() {
            self.s += 1;

            if self.s > upper {
                r += 1;
                upper = (3 * &B + &r * &n) / &a;
                self.s = 2 * &B + &r * &n;
                self.s = self.s.div_ceil(&b);
            }
        }
        self.state = Step::Step3;
    }
    fn step3(&mut self) {
        // First narrow set of solutions

        //println!("Intervals: {:?}", self.intervals.get_intervals());
        let mut new_m = IntervalTree::default();
        let si = &self.s;
        let two = BigInt::from_u8(2).unwrap();

        for interval in self.intervals.get_intervals() {
            let Interval { start: a, end: b } = interval;
            //println!("a,b: {a}, {b}");

            let B: BigInt = self.b.clone();
            let n = self.publickey.modulus.clone();

            let mut r: BigInt = &a * si - 3 * &B + 1;
            r = r.div_ceil(&n);

            let mut max_r: BigInt = &b * si - 2 * &B;
            max_r = max_r.div_floor(&n);

            while r <= max_r {
                // max of a and
                // (2B + rn)/s
                let mut lval: BigInt = &two * &B + &r * &n;
                lval = lval.div_ceil(si);
                lval = lval.max(a.clone());

                // min of b and
                // (3B - 1 + rn)/s
                let mut rval: BigInt = 3 * &B - 1 + &r * &n;
                rval = rval.div_floor(si);
                rval = rval.min(b.clone());

                //println!("l,r: {lval}, {rval}");
                let new_interval = Interval::new(&lval, &rval);
                new_m.insert_interval(&new_interval);
                r += 1;
            }
        }

        self.intervals = new_m;
        //println!("Intervals: {:?}", self.intervals.get_intervals());

        // Now determine which step to go to
        if self.intervals.get_intervals().len() == 1 {
            let Interval { start: a, end: b } = self.intervals.get_intervals()[0].clone();
            match a == b {
                true => self.state = Step::Step4,
                false => self.state = Step::Step2c,
            }
        } else {
            self.state = Step::Step2b;
        }
    }
    fn step4(&self) -> BigInt {
        // To get here, m should contain one interval
        let Interval { start: a, .. } = self.intervals.get_intervals()[0].clone();
        let s0inv = invmod(&self.s0, &self.publickey.modulus);
        (a * s0inv) % &self.publickey.modulus
    }
}

pub fn main() -> Result<()> {
    // Set up problem
    let bits = 128;
    let e: BigInt = 3.into();
    let (et, n) = et_n(bits, &e);
    let d = invmod(&e, &et);

    let public_key = Key {
        key: e,
        modulus: n.clone(),
    };
    let private_key = Key { key: d, modulus: n };
    let message = b"kick it, CC";
    let mut pkcs_message: Vec<u8> = vec![0x00, 0x02];
    let bytes = &private_key.modulus.bits() / 8;
    pkcs_message.extend_from_slice(&vec![0xff; bytes as usize - 3 - message.len()]);
    pkcs_message.push(0x00);
    pkcs_message.extend_from_slice(message);

    println!("PKCS message length: {}", pkcs_message.len());
    println!("bytes: {}", bytes);
    // PKCS pad this

    let m = BigInt::from_bytes_be(Sign::Plus, &pkcs_message);
    println!("m true: {m}");
    let c = m.modpow(&public_key.key, &public_key.modulus);

    // Check is is pkcs padded
    println!("Is pkcs padded? {}", is_pkcs(&c, &private_key));

    let mut attacker = Attacker::new(&c, &public_key, &private_key);

    let md = attacker.run();

    println!("m true: {m}");
    println!("m     : {md}");
    let decrypted_padded = md.to_bytes_be().1;
    // Now strip off padding
    let index = decrypted_padded.iter().position(|&x| x == 0x00).unwrap();
    let decrypted = &decrypted_padded[index + 1..];
    let decrypted_message = std::str::from_utf8(decrypted).unwrap();
    println!("Message: {}", decrypted_message);
    assert_eq!(decrypted, message);

    Ok(())
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn interval_tests() {
        let mut tree = IntervalTree::default();
        println!("Empty tree: {:?}", tree.get_intervals());
        assert_eq!(tree.get_intervals(), vec![]);
        let five_ten_int = Interval::new(
            &BigInt::from_i32(5).unwrap(),
            &BigInt::from_i32(10).unwrap(),
        );
        tree.insert_interval(&five_ten_int);
        assert_eq!(tree.get_intervals(), vec![five_ten_int.clone()]);
        let twelve_thirteen_int = Interval::new(
            &BigInt::from_i32(12).unwrap(),
            &BigInt::from_i32(13).unwrap(),
        );
        tree.insert_interval(&twelve_thirteen_int);
        assert_eq!(
            tree.get_intervals(),
            vec![five_ten_int, twelve_thirteen_int]
        );
        let eleven_fifteen_int = Interval::new(
            &BigInt::from_i32(11).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        tree.insert_interval(&eleven_fifteen_int);
        let five_fifteen_int = Interval::new(
            &BigInt::from_i32(5).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        assert_eq!(tree.get_intervals(), vec![five_fifteen_int]);
        let two_six_int =
            Interval::new(&BigInt::from_i32(2).unwrap(), &BigInt::from_i32(6).unwrap());
        tree.insert_interval(&two_six_int);
        let two_fifteen_int = Interval::new(
            &BigInt::from_i32(2).unwrap(),
            &BigInt::from_i32(15).unwrap(),
        );
        assert_eq!(tree.get_intervals(), vec![two_fifteen_int]);

        println!("Tree: {:?}", tree.get_intervals());
        let mut tree = IntervalTree::default();
        let five_five_int =
            Interval::new(&BigInt::from_i32(5).unwrap(), &BigInt::from_i32(5).unwrap());
        let five_six_int =
            Interval::new(&BigInt::from_i32(5).unwrap(), &BigInt::from_i32(6).unwrap());
        let six_six_int =
            Interval::new(&BigInt::from_i32(5).unwrap(), &BigInt::from_i32(6).unwrap());
        tree.insert_interval(&five_five_int);
        tree.insert_interval(&six_six_int);
        assert_eq!(tree.get_intervals(), vec![five_six_int]);
    }

    #[ignore = "slow"]
    #[test]
    fn bleichenbacher_small() {
        main().unwrap();
    }
}
