use std::collections::BTreeSet;
use std::ops::Bound::Included;

use num_bigint::{BigInt, RandBigInt};
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
//
struct IntervalTree {
    lefts: BTreeSet<BigInt>,
    rights: BTreeSet<BigInt>,
}
impl Default for IntervalTree {
    fn default() -> Self {
        IntervalTree {
            lefts: Default::default(),
            rights: Default::default(),
        }
    }
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
enum Step {
    Step1,
    Step2a,
    Step2b,
    Step2c,
    Step3,
    Step4,
}

struct Attacker {
    intervals: IntervalTree,
    svec: Vec<BigInt>,
    c0: BigInt,
    publickey: Key,
    privatekey: Key,
    i: usize,
    b: BigInt,
    state: Step,
    c: BigInt,
}

fn is_pkcs(c: &BigInt, k: &Key) -> bool {
    todo!()
}

impl Attacker {
    pub fn new() -> Self {
        todo!()
    }

    pub fn run(&mut self) -> BigInt {
        loop {
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
        let mut s0 = rng.gen_bigint_range(&BigInt::zero(), &self.publickey.modulus);
        loop {
            let c0 = &self.c * s0.modpow(&self.publickey.key, &self.publickey.modulus)
                % &self.publickey.modulus;
            if is_pkcs(&c0, &self.privatekey) {
                self.c0 = c0;
                self.svec = vec![s0];
                self.i = 1;
                break;
            }
        }

        self.state = Step::Step2a;
    }
    fn step2a(&mut self) {
        let mut s1: BigInt = &self.publickey.modulus / (3 * &self.b);
        loop {
            let c = &self.c0 * &s1.modpow(&self.publickey.key, &self.publickey.modulus)
                % &self.publickey.modulus;
            if is_pkcs(&c, &self.privatekey) {
                self.svec.push(s1);
                break;
            }
            s1 += 1;
        }

        self.state = Step::Step3;
    }
    fn step2b(&mut self) {
        let mut s1: BigInt = self.svec[self.i].clone() + 1;
        loop {
            let c = &self.c0 * &s1.modpow(&self.publickey.key, &self.publickey.modulus)
                % &self.publickey.modulus;
            if is_pkcs(&c, &self.privatekey) {
                self.svec.push(s1);
                break;
            }
            s1 += 1;
        }

        self.state = Step::Step3;
    }
    fn step2c(&mut self) {
        let Interval { start: a, end: b } = self.intervals.get_intervals()[0].clone();
        let mut r = 2 * (&b * &self.svec[self.i] - 2 * &self.b) / &self.publickey.modulus;
        'outer: loop {
            let mut si: BigInt = (2 * &self.b + &r * &self.publickey.modulus) / &b;
            let upper: BigInt = (3 * &self.b + &r * &self.publickey.modulus) / &a;
            while &si < &upper {
                let c = &self.c0 * &si.modpow(&self.publickey.key, &self.publickey.modulus);

                if is_pkcs(&c, &self.privatekey) {
                    self.svec.push(si);
                    break 'outer;
                }
                si += 1;
            }
            r += 1;
        }
        self.state = Step::Step3;
    }
    fn step3(&mut self) {
        // First narrow set of solutions

        let mut new_m = IntervalTree::default();

        for interval in self.intervals.get_intervals() {
            let Interval { start: a, end: b } = interval;

            let mut r = (&a * &self.svec[self.i] - 3 * &self.b + 1) / &self.publickey.modulus;
            let upper = (&b * &self.svec[self.i] - 2 * &self.b) / &self.publickey.modulus;
            while &r <= &upper {
                let mut l: BigInt = BigInt::from_i32(1).unwrap()
                    + (2 * &self.b + &r * &self.publickey.modulus) / &self.svec[self.i];
                if &l < &a {
                    l = a.clone();
                }
                let mut r: BigInt = (2 * &self.b - BigInt::from_u8(1).unwrap()
                    + &r * &self.publickey.modulus)
                    / &self.svec[self.i];
                if &r < &b {
                    r = b.clone();
                }
                let new_interval = Interval::new(&l, &r);
                new_m.insert_interval(&new_interval);
                r += 1;
            }
        }

        // Now determine which step to go to
        if self.intervals.get_intervals().len() == 1 {
            let Interval { start: a, end: b } = self.intervals.get_intervals()[0].clone();
            match a == b {
                true => self.state = Step::Step4,
                false => {
                    self.i += 1;
                    self.state = Step::Step2c;
                }
            }
        } else {
            self.i += 1;
            self.state = Step::Step2b;
        }
    }
    fn step4(&self) -> BigInt {
        // To get here, m should contain one interval
        let Interval { start: a, .. } = self.intervals.get_intervals()[0].clone();
        let s0inv = invmod(&self.svec[0], &self.publickey.modulus);
        let m = (a * s0inv) % &self.publickey.modulus;
        m
    }
}

pub fn main() -> Result<()> {
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
    }
}
