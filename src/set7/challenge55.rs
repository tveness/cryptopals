//! MD4 Collisions
//!
//! MD4 is a 128-bit cryptographic hash function, meaning it should take a work factor of roughly
//! 2^64 to find collisions.
//! It turns out we can do much better.
//!
//! The paper "Cryptanalysis of the Hash Functions MD4 and RIPEMD" by Wang et al details a
//! cryptanalytic attack that lets us find collisions in 2^8 or less.
//!
//! Given a message block M, Wang outlines a strategy for finding a sister message block M',
//! differing only in a few bits, that will collide with it. Just so long as a short set of
//! conditions holds true for M.
//!
//! What sort of conditions? Simple bitwise equalities within the intermediate hash function state,
//! e.g. a[1][6] = b[0][6]. This should be read as: "the sixth bit (zero-indexed) of a[1] (i.e. the
//! first update to 'a') should equal the sixth bit of b[0] (i.e. the initial value of 'b')".
//!
//! It turns out that a lot of these conditions are trivial to enforce. To see why, take a look at
//! the first (of three) rounds in the MD4 compression function. In this round, we iterate over
//! each word in the message block sequentially and mix it into the state. So we can make sure all
//! our first-round conditions hold by doing this:
//!
//! # calculate the new value for a[1] in the normal fashion
//! a[1] = (a[0] + f(b[0], c[0], d[0]) + m[0]).lrot(3)
//!
//! # correct the erroneous bit
//! a[1] ^= ((a[1][6] ^ b[0][6]) << 6)
//!
//! # use algebra to correct the first message block
//! m[0] = a[1].rrot(3) - a[0] - f(b[0], c[0], d[0])
//!
//! Simply ensuring all the first round conditions puts us well within the range to generate
//! collisions, but we can do better by correcting some additional conditions in the second round.
//! This is a bit trickier, as we need to take care not to stomp on any of the first-round
//! conditions.
//!
//! Once you've adequately massaged M, you can simply generate M' by flipping a few bits and test
//! for a collision. A collision is not guaranteed as we didn't ensure every condition. But
//! hopefully we got enough that we can find a suitable (M, M') pair without too much effort.
//!
//! Implement Wang's attack.

use std::collections::HashSet;

use hex;
use indicatif::ProgressBar;
use rand::{thread_rng, Rng};

use crate::{set4::challenge30::md4_hash, utils::*};

// Round 1 conditions
//
// a1 | a1,7 = b0,7
// d1 | d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
// c1 | c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
// b1 | b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
//
// First one
// a[1][6] = b[0][6]
// # calculate the new value for a[1] in the normal fashion
// a[1] = (a[0] + f(b[0], c[0], d[0]) + m[0]).lrot(3)
//
// # correct the erroneous bit
// a[1] ^= ((a[1][6] ^ b[0][6]) << 6)
//
// # use algebra to correct the first message block
// m[0] = a[1].rrot(3) - a[0] - f(b[0], c[0], d[0])
//
// Pseudocode from cryptopals:
// a[1]
//
// Round 2 conditions
//
// a2 | a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
// d2 | d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
// c2 | c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
// b2 | b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0

trait Bittable {
    fn get_bit(&self, bit: usize) -> Self;
    fn set_bit(&mut self, bit: usize, val: &Self);
}

impl Bittable for u32 {
    fn get_bit(&self, bit: usize) -> u32 {
        (self >> bit) & 0x01
    }

    fn set_bit(&mut self, bit: usize, val: &u32) {
        // If 0, then this becomes 0000000
        // If 1, then this becomes 0001000
        // x^0 = 0
        // x^1 = !x
        let shift_val = 1 << bit;
        match val {
            0x01 => *self = *self | shift_val,
            0x00 => *self = *self & !shift_val,
            _ => unreachable!(),
        };
    }
}

// Copying a lot from challenge 30 where we implemented MD4 (foreshadowing!)

fn check_round1(data: &[u8]) -> bool {
    // Split the data into the appropriate chunks, again
    let m: Vec<u32> = data
        .chunks(4)
        .map(|x| {
            let y: Vec<u8> = x.iter().copied().rev().collect();
            u8s_to_u32(&y)
        })
        .collect();

    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;
    let x: Vec<u32> = m.to_vec();

    a = a.wrapping_add(round1(b, c, d, x[0])).rotate_left(3);
    assert_eq!(a.get_bit(6), b.get_bit(6));

    d = d.wrapping_add(round1(a, b, c, x[1])).rotate_left(7);
    assert_eq!(d.get_bit(6), 0);
    assert_eq!(d.get_bit(7), a.get_bit(7));
    assert_eq!(d.get_bit(10), a.get_bit(10));

    c = c.wrapping_add(round1(d, a, b, x[2])).rotate_left(11);
    assert_eq!(c.get_bit(6), 1);
    assert_eq!(c.get_bit(7), 1);
    assert_eq!(c.get_bit(10), 0);
    assert_eq!(c.get_bit(25), d.get_bit(25));

    b = b.wrapping_add(round1(c, d, a, x[3])).rotate_left(19);

    assert_eq!(b.get_bit(6), 1);
    assert_eq!(b.get_bit(7), 0);
    assert_eq!(b.get_bit(10), 0);
    assert_eq!(b.get_bit(25), 0);

    // Now update a
    a = a.wrapping_add(round1(b, c, d, x[4])).rotate_left(3);
    // And check that the condition applies
    assert_eq!(a.get_bit(7), 1);
    assert_eq!(a.get_bit(10), 1);
    assert_eq!(a.get_bit(25), 0);
    assert_eq!(a.get_bit(13), b.get_bit(13));

    d = d.wrapping_add(round1(a, b, c, x[5])).rotate_left(7);
    // And check conditions
    assert_eq!(d.get_bit(13), 0);
    assert_eq!(d.get_bit(18), a.get_bit(18));
    assert_eq!(d.get_bit(19), a.get_bit(19));
    assert_eq!(d.get_bit(20), a.get_bit(20));
    assert_eq!(d.get_bit(21), a.get_bit(21));
    assert_eq!(d.get_bit(25), 1);

    c = c.wrapping_add(round1(d, a, b, x[6])).rotate_left(11);
    assert_eq!(c.get_bit(12), d.get_bit(12));
    assert_eq!(c.get_bit(13), 0);
    assert_eq!(c.get_bit(14), d.get_bit(14));
    assert_eq!(c.get_bit(18), 0);
    assert_eq!(c.get_bit(19), 0);
    assert_eq!(c.get_bit(20), 1);
    assert_eq!(c.get_bit(21), 0);

    b = b.wrapping_add(round1(c, d, a, x[7])).rotate_left(19);

    assert_eq!(b.get_bit(12), 1);
    assert_eq!(b.get_bit(13), 1);
    assert_eq!(b.get_bit(14), 0);
    assert_eq!(b.get_bit(16), c.get_bit(16));
    assert_eq!(b.get_bit(18), 0);
    assert_eq!(b.get_bit(19), 0);
    assert_eq!(b.get_bit(20), 0);
    assert_eq!(b.get_bit(21), 0);

    a = a.wrapping_add(round1(b, c, d, x[8])).rotate_left(3);
    assert_eq!(a.get_bit(12), 1);
    assert_eq!(a.get_bit(13), 1);
    assert_eq!(a.get_bit(14), 1);
    assert_eq!(a.get_bit(16), 0);
    assert_eq!(a.get_bit(18), 0);
    assert_eq!(a.get_bit(19), 0);
    assert_eq!(a.get_bit(20), 0);
    assert_eq!(a.get_bit(21), 1);
    assert_eq!(a.get_bit(22), b.get_bit(22));
    assert_eq!(a.get_bit(25), b.get_bit(25));

    d = d.wrapping_add(round1(a, b, c, x[9])).rotate_left(7);
    assert_eq!(d.get_bit(12), 1);
    assert_eq!(d.get_bit(13), 1);
    assert_eq!(d.get_bit(14), 1);
    assert_eq!(d.get_bit(16), 0);
    assert_eq!(d.get_bit(19), 0);
    assert_eq!(d.get_bit(20), 1);
    assert_eq!(d.get_bit(21), 1);
    assert_eq!(d.get_bit(22), 0);
    assert_eq!(d.get_bit(25), 1);
    assert_eq!(d.get_bit(29), a.get_bit(29));

    c = c.wrapping_add(round1(d, a, b, x[10])).rotate_left(11);
    assert_eq!(c.get_bit(16), 1);
    assert_eq!(c.get_bit(19), 0);
    assert_eq!(c.get_bit(20), 0);
    assert_eq!(c.get_bit(21), 0);
    assert_eq!(c.get_bit(22), 0);
    assert_eq!(c.get_bit(25), 0);
    assert_eq!(c.get_bit(29), 1);
    assert_eq!(c.get_bit(31), d.get_bit(31));

    b = b.wrapping_add(round1(c, d, a, x[11])).rotate_left(19);
    assert_eq!(b.get_bit(19), 0);
    assert_eq!(b.get_bit(20), 1);
    assert_eq!(b.get_bit(21), 1);
    assert_eq!(b.get_bit(22), c.get_bit(22));
    assert_eq!(b.get_bit(25), 1);
    assert_eq!(b.get_bit(29), 0);
    assert_eq!(b.get_bit(31), 0);

    a = a.wrapping_add(round1(b, c, d, x[12])).rotate_left(3);
    assert_eq!(a.get_bit(22), 0);
    assert_eq!(a.get_bit(25), 0);
    assert_eq!(a.get_bit(26), b.get_bit(26));
    assert_eq!(a.get_bit(28), b.get_bit(28));
    assert_eq!(a.get_bit(29), 1);
    assert_eq!(a.get_bit(31), 0);

    d = d.wrapping_add(round1(a, b, c, x[13])).rotate_left(7);
    assert_eq!(d.get_bit(22), 0);
    assert_eq!(d.get_bit(25), 0);
    assert_eq!(d.get_bit(26), 1);
    assert_eq!(d.get_bit(28), 1);
    assert_eq!(d.get_bit(29), 0);
    assert_eq!(d.get_bit(31), 1);

    c = c.wrapping_add(round1(d, a, b, x[14])).rotate_left(11);
    assert_eq!(c.get_bit(18), d.get_bit(18));
    assert_eq!(c.get_bit(22), 1);
    assert_eq!(c.get_bit(25), 1);
    assert_eq!(c.get_bit(26), 0);
    assert_eq!(c.get_bit(28), 0);
    assert_eq!(c.get_bit(29), 0);

    // b4 b4[18] = 0, b4[25] = c4[25] = 1, b4[26] = 1, b4[28] = 1, b4[29] = 0

    // Set and verify
    b = b.wrapping_add(round1(c, d, a, x[15])).rotate_left(19);
    assert_eq!(b.get_bit(18), 0);
    assert_eq!(b.get_bit(25), c.get_bit(25));
    assert_eq!(b.get_bit(26), 1);
    assert_eq!(b.get_bit(28), 1);
    assert_eq!(b.get_bit(29), 0);

    true
}
pub fn massage_round1(data: &[u8]) -> Vec<u8> {
    // Split the data into the appropriate chunks, again
    let m: Vec<u32> = data
        .chunks(4)
        .map(|x| {
            let y: Vec<u8> = x.iter().copied().rev().collect();
            u8s_to_u32(&y)
        })
        .collect();

    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;
    let mut x: Vec<u32> = m.to_vec();
    // Round 1
    // In the paper ai is (4i-3)th step i.e. a2 is o=4, and so life is easier than it has
    // to be!

    // calculate the new value for a[1] in the normal fashion
    let mut a1: u32 = a.wrapping_add(f(b, c, d).wrapping_add(x[0])).rotate_left(3);
    // a1 | a[1][6] = b[0][6]
    a1.set_bit(6, &b.get_bit(6));
    x[0] = a1.rotate_right(3).wrapping_sub(a).wrapping_sub(f(b, c, d));

    // Now update a
    a = a.wrapping_add(round1(b, c, d, x[0])).rotate_left(3);
    // And check that the condition applies
    assert_eq!(a.get_bit(6), b.get_bit(6));

    // d1 | d[1][6] = 0, d[1][7] = a[1][7], d[1][10] = a[1][10]
    let mut d1 = d.wrapping_add(f(a, b, c)).wrapping_add(x[1]).rotate_left(7);
    // Correct the bits
    d1.set_bit(6, &0);
    d1.set_bit(7, &a1.get_bit(7));
    d1.set_bit(10, &a1.get_bit(10));

    x[1] = d1.rotate_right(7).wrapping_sub(d).wrapping_sub(f(a, b, c));

    {
        let d1 = d.wrapping_add(round1(a, b, c, x[1])).rotate_left(7);
        assert_eq!(d1.get_bit(6), 0);
        assert_eq!(d1.get_bit(7), a1.get_bit(7));
        assert_eq!(d1.get_bit(10), a1.get_bit(10));
    }

    // Now update d for real
    d = d.wrapping_add(round1(a, b, c, x[1])).rotate_left(7);
    // And check conditions
    assert_eq!(d.get_bit(6), 0);
    assert_eq!(d.get_bit(7), a.get_bit(7));
    assert_eq!(d.get_bit(10), a.get_bit(10));

    // c1 | c[1][6] = 1, c[1][7] = 1, c[1][10] = 0, c[1][25] = d[1][25]

    let mut c1 = c.wrapping_add(round1(d, a, b, x[2])).rotate_left(11);

    c1.set_bit(6, &1);
    c1.set_bit(7, &1);
    c1.set_bit(10, &0);
    c1.set_bit(25, &d.get_bit(25));

    x[2] = c1.rotate_right(11).wrapping_sub(c).wrapping_sub(f(d, a, b));

    // Update and check that conditions hold
    c = c.wrapping_add(round1(d, a, b, x[2])).rotate_left(11);
    assert_eq!(c.get_bit(6), 1);
    assert_eq!(c.get_bit(7), 1);
    assert_eq!(c.get_bit(10), 0);
    assert_eq!(c.get_bit(25), d.get_bit(25));

    // b1 | b[1][6] = 1, b[1][7] = 0, b[1][10] = 0, b[1][25] = 0
    let mut b1 = b.wrapping_add(round1(c, d, a, x[3])).rotate_left(19);
    b1.set_bit(6, &1);
    b1.set_bit(7, &0);
    b1.set_bit(10, &0);
    b1.set_bit(25, &0);

    x[3] = b1.rotate_right(19).wrapping_sub(b).wrapping_sub(f(c, d, a));

    // Set and verify
    b = b.wrapping_add(round1(c, d, a, x[3])).rotate_left(19);

    assert_eq!(b.get_bit(6), 1);
    assert_eq!(b.get_bit(7), 0);
    assert_eq!(b.get_bit(10), 0);
    assert_eq!(b.get_bit(25), 0);

    // calculate the new value for a[2] in the normal fashion
    let mut a2: u32 = a.wrapping_add(f(b, c, d).wrapping_add(x[4])).rotate_left(3);
    // a2 a[2][7] = 1, a[2][10] = 1, a[2][25] = 0, a[2][13] = b[1][13]
    a2.set_bit(7, &1);
    a2.set_bit(10, &1);
    a2.set_bit(25, &0);
    a2.set_bit(13, &b.get_bit(13));
    x[4] = a2.rotate_right(3).wrapping_sub(a).wrapping_sub(f(b, c, d));

    // Now update a
    a = a.wrapping_add(round1(b, c, d, x[4])).rotate_left(3);
    // And check that the condition applies
    assert_eq!(a.get_bit(7), 1);
    assert_eq!(a.get_bit(10), 1);
    assert_eq!(a.get_bit(25), 0);
    assert_eq!(a.get_bit(13), b.get_bit(13));

    // d2 d2[13] = 0, d2[18] = a2[18], d2[19] = a2[19], d2[20] = a2[20],
    // d2[21] = a2[21], d2[25] = 1
    let mut d2 = d.wrapping_add(f(a, b, c)).wrapping_add(x[5]).rotate_left(7);
    // Correct the bits
    d2.set_bit(13, &0);
    d2.set_bit(18, &a.get_bit(18));
    d2.set_bit(19, &a.get_bit(19));
    d2.set_bit(20, &a.get_bit(20));
    d2.set_bit(21, &a.get_bit(21));
    d2.set_bit(25, &1);

    x[5] = d2.rotate_right(7).wrapping_sub(d).wrapping_sub(f(a, b, c));

    // Now update d for real
    d = d.wrapping_add(round1(a, b, c, x[5])).rotate_left(7);
    // And check conditions
    assert_eq!(d.get_bit(13), 0);
    assert_eq!(d.get_bit(18), a.get_bit(18));
    assert_eq!(d.get_bit(19), a.get_bit(19));
    assert_eq!(d.get_bit(20), a.get_bit(20));
    assert_eq!(d.get_bit(21), a.get_bit(21));
    assert_eq!(d.get_bit(25), 1);

    // c2 c2[12] = d2[12], c2[13] = 0, c2[14] = d2[14], c2[18] = 0, c2[19] = 0,
    // c2[20] = 1, c2[21] = 0
    let mut c2 = c.wrapping_add(round1(d, a, b, x[6])).rotate_left(11);

    c2.set_bit(12, &d.get_bit(12));
    c2.set_bit(13, &0);
    c2.set_bit(14, &d.get_bit(14));
    c2.set_bit(18, &0);
    c2.set_bit(19, &0);
    c2.set_bit(20, &1);
    c2.set_bit(21, &0);

    x[6] = c2.rotate_right(11).wrapping_sub(c).wrapping_sub(f(d, a, b));

    // Update and check that conditions hold
    c = c.wrapping_add(round1(d, a, b, x[6])).rotate_left(11);
    assert_eq!(c.get_bit(12), d.get_bit(12));
    assert_eq!(c.get_bit(13), 0);
    assert_eq!(c.get_bit(14), d.get_bit(14));
    assert_eq!(c.get_bit(18), 0);
    assert_eq!(c.get_bit(19), 0);
    assert_eq!(c.get_bit(20), 1);
    assert_eq!(c.get_bit(21), 0);

    // b2 b2[12] = 1, b2[13] = 1, b2[14] = 0, b2[16] = c2[16], b2[18] = 0,
    // b2[19] = 0, b2[20] = 0 b2[21] = 0
    let mut b2 = b.wrapping_add(round1(c, d, a, x[7])).rotate_left(19);
    b2.set_bit(12, &1);
    b2.set_bit(13, &1);
    b2.set_bit(14, &0);
    b2.set_bit(16, &c.get_bit(16));
    b2.set_bit(18, &0);
    b2.set_bit(19, &0);
    b2.set_bit(20, &0);
    b2.set_bit(21, &0);

    x[7] = b2.rotate_right(19).wrapping_sub(b).wrapping_sub(f(c, d, a));

    // Set and verify
    b = b.wrapping_add(round1(c, d, a, x[7])).rotate_left(19);

    assert_eq!(b.get_bit(12), 1);
    assert_eq!(b.get_bit(13), 1);
    assert_eq!(b.get_bit(14), 0);
    assert_eq!(b.get_bit(16), c.get_bit(16));
    assert_eq!(b.get_bit(18), 0);
    assert_eq!(b.get_bit(19), 0);
    assert_eq!(b.get_bit(20), 0);
    assert_eq!(b.get_bit(21), 0);

    // a3 a3[12] = 1, a3[13] = 1, a3[14] = 1, a3[16] = 0, a3[18] = 0,
    // a3[19] = 0, a3[20] = 0, a3[22] = b2[22]
    // a3[21] = 1, a3[25] = b2[25]

    let mut a3: u32 = a.wrapping_add(f(b, c, d).wrapping_add(x[8])).rotate_left(3);
    a3.set_bit(12, &1);
    a3.set_bit(13, &1);
    a3.set_bit(14, &1);
    a3.set_bit(16, &0);
    a3.set_bit(18, &0);
    a3.set_bit(19, &0);
    a3.set_bit(20, &0);
    a3.set_bit(21, &1);
    a3.set_bit(22, &b.get_bit(22));
    a3.set_bit(25, &b.get_bit(25));

    x[8] = a3.rotate_right(3).wrapping_sub(a).wrapping_sub(f(b, c, d));

    // Now update a
    a = a.wrapping_add(round1(b, c, d, x[8])).rotate_left(3);
    // And check that the condition applies

    assert_eq!(a.get_bit(12), 1);
    assert_eq!(a.get_bit(13), 1);
    assert_eq!(a.get_bit(14), 1);
    assert_eq!(a.get_bit(16), 0);
    assert_eq!(a.get_bit(18), 0);
    assert_eq!(a.get_bit(19), 0);
    assert_eq!(a.get_bit(20), 0);
    assert_eq!(a.get_bit(21), 1);
    assert_eq!(a.get_bit(22), b.get_bit(22));
    assert_eq!(a.get_bit(25), b.get_bit(25));

    // d3 d3[12] = 1, d3[13] = 1, d3[14] = 1, d3[16] = 0, d3[19] = 0,
    // d3[20] = 1, d3[21] = 1, d3[22] = 0, d3[25] = 1, d3[29] = a3[29]

    let mut d3 = d.wrapping_add(f(a, b, c)).wrapping_add(x[9]).rotate_left(7);
    // Correct the bits
    d3.set_bit(12, &1);
    d3.set_bit(13, &1);
    d3.set_bit(14, &1);
    d3.set_bit(16, &0);
    d3.set_bit(19, &0);
    d3.set_bit(20, &1);
    d3.set_bit(21, &1);
    d3.set_bit(22, &0);
    d3.set_bit(25, &1);
    d3.set_bit(29, &a.get_bit(29));

    x[9] = d3.rotate_right(7).wrapping_sub(d).wrapping_sub(f(a, b, c));

    // Now update d for real
    d = d.wrapping_add(round1(a, b, c, x[9])).rotate_left(7);
    // And check conditions

    assert_eq!(d.get_bit(12), 1);
    assert_eq!(d.get_bit(13), 1);
    assert_eq!(d.get_bit(14), 1);
    assert_eq!(d.get_bit(16), 0);
    assert_eq!(d.get_bit(19), 0);
    assert_eq!(d.get_bit(20), 1);
    assert_eq!(d.get_bit(21), 1);
    assert_eq!(d.get_bit(22), 0);
    assert_eq!(d.get_bit(25), 1);
    assert_eq!(d.get_bit(29), a.get_bit(29));

    // c3 c3[16] = 1, c3[19] = 0, c3[20] = 0, c3[21] = 0,
    // c3[22] = 0, c3[25] = 0, c3[29] = 1, c3[31] = d3[31]
    let mut c3 = c.wrapping_add(round1(d, a, b, x[10])).rotate_left(11);

    c3.set_bit(16, &1);
    c3.set_bit(19, &0);
    c3.set_bit(20, &0);
    c3.set_bit(21, &0);
    c3.set_bit(22, &0);
    c3.set_bit(25, &0);
    c3.set_bit(29, &1);
    c3.set_bit(31, &d.get_bit(31));

    x[10] = c3.rotate_right(11).wrapping_sub(c).wrapping_sub(f(d, a, b));

    // Update and check that conditions hold
    c = c.wrapping_add(round1(d, a, b, x[10])).rotate_left(11);
    assert_eq!(c.get_bit(16), 1);
    assert_eq!(c.get_bit(19), 0);
    assert_eq!(c.get_bit(20), 0);
    assert_eq!(c.get_bit(21), 0);
    assert_eq!(c.get_bit(22), 0);
    assert_eq!(c.get_bit(25), 0);
    assert_eq!(c.get_bit(29), 1);
    assert_eq!(c.get_bit(31), d.get_bit(31));

    // b3 b3[19] = 0, b3[20] = 1, b3[21] = 1, b3[22] = c3[22],
    // b3[25] = 1, b3[29] = 0, b3[31] = 0
    let mut b3 = b.wrapping_add(round1(c, d, a, x[11])).rotate_left(19);

    b3.set_bit(19, &0);
    b3.set_bit(20, &1);
    b3.set_bit(21, &1);
    b3.set_bit(22, &c.get_bit(22));
    b3.set_bit(25, &1);
    b3.set_bit(29, &0);
    b3.set_bit(31, &0);

    x[11] = b3.rotate_right(19).wrapping_sub(b).wrapping_sub(f(c, d, a));

    // Set and verify
    b = b.wrapping_add(round1(c, d, a, x[11])).rotate_left(19);
    assert_eq!(b.get_bit(19), 0);
    assert_eq!(b.get_bit(20), 1);
    assert_eq!(b.get_bit(21), 1);
    assert_eq!(b.get_bit(22), c.get_bit(22));
    assert_eq!(b.get_bit(25), 1);
    assert_eq!(b.get_bit(29), 0);
    assert_eq!(b.get_bit(31), 0);

    // a4 a4[22] = 0, a4[25] = 0, a4[26] = b3[26], a4[28] = b3[28],
    // a4[29] = 1, a4[31] = 0
    let mut a4: u32 = a
        .wrapping_add(f(b, c, d).wrapping_add(x[12]))
        .rotate_left(3);
    a4.set_bit(22, &0);
    a4.set_bit(25, &0);
    a4.set_bit(26, &b.get_bit(26));
    a4.set_bit(28, &b.get_bit(28));
    a4.set_bit(29, &1);
    a4.set_bit(31, &0);

    x[12] = a4.rotate_right(3).wrapping_sub(a).wrapping_sub(f(b, c, d));

    // Now update a
    a = a.wrapping_add(round1(b, c, d, x[12])).rotate_left(3);
    // And check that the condition applies
    assert_eq!(a.get_bit(22), 0);
    assert_eq!(a.get_bit(25), 0);
    assert_eq!(a.get_bit(26), b.get_bit(26));
    assert_eq!(a.get_bit(28), b.get_bit(28));
    assert_eq!(a.get_bit(29), 1);
    assert_eq!(a.get_bit(31), 0);

    // d4 d4[22] = 0, d4[25] = 0, d4[26] = 1, d4[28] = 1,
    // d4[29] = 0, d4[31] = 1
    let mut d4 = d
        .wrapping_add(f(a, b, c))
        .wrapping_add(x[13])
        .rotate_left(7);
    // Correct the bits
    d4.set_bit(22, &0);
    d4.set_bit(25, &0);
    d4.set_bit(26, &1);
    d4.set_bit(28, &1);
    d4.set_bit(29, &0);
    d4.set_bit(31, &1);

    x[13] = d4.rotate_right(7).wrapping_sub(d).wrapping_sub(f(a, b, c));

    // Now update d for real
    d = d.wrapping_add(round1(a, b, c, x[13])).rotate_left(7);

    assert_eq!(d.get_bit(22), 0);
    assert_eq!(d.get_bit(25), 0);
    assert_eq!(d.get_bit(26), 1);
    assert_eq!(d.get_bit(28), 1);
    assert_eq!(d.get_bit(29), 0);
    assert_eq!(d.get_bit(31), 1);

    // c4 c4[18] = d4[18], c4[22] = 1, c4[25] = 1, c4[26] = 0,
    // c4[28] = 0, c4[29] = 0
    let mut c4 = c.wrapping_add(round1(d, a, b, x[14])).rotate_left(11);

    c4.set_bit(18, &d.get_bit(18));
    c4.set_bit(22, &1);
    c4.set_bit(25, &1);
    c4.set_bit(26, &0);
    c4.set_bit(28, &0);
    c4.set_bit(29, &0);

    x[14] = c4.rotate_right(11).wrapping_sub(c).wrapping_sub(f(d, a, b));

    // Update and check that conditions hold
    c = c.wrapping_add(round1(d, a, b, x[14])).rotate_left(11);
    assert_eq!(c.get_bit(18), d.get_bit(18));
    assert_eq!(c.get_bit(22), 1);
    assert_eq!(c.get_bit(25), 1);
    assert_eq!(c.get_bit(26), 0);
    assert_eq!(c.get_bit(28), 0);
    assert_eq!(c.get_bit(29), 0);

    // b4 b4[18] = 0, b4[25] = c4[25] = 1, b4[26] = 1, b4[28] = 1, b4[29] = 0

    let mut b4 = b.wrapping_add(round1(c, d, a, x[15])).rotate_left(19);

    b4.set_bit(18, &0);
    b4.set_bit(25, &c.get_bit(25));
    b4.set_bit(26, &1);
    b4.set_bit(28, &1);
    b4.set_bit(29, &0);

    x[15] = b4.rotate_right(19).wrapping_sub(b).wrapping_sub(f(c, d, a));

    // Set and verify
    b = b.wrapping_add(round1(c, d, a, x[15])).rotate_left(19);
    assert_eq!(b.get_bit(18), 0);
    assert_eq!(b.get_bit(25), c.get_bit(25));
    assert_eq!(b.get_bit(26), 1);
    assert_eq!(b.get_bit(28), 1);
    assert_eq!(b.get_bit(29), 0);

    let mut massaged_block: Vec<u8> = vec![];
    for b in x[..16].iter() {
        for byte in u32_to_u8s(*b).iter().rev() {
            massaged_block.push(*byte);
        }
    }
    massaged_block
}

pub fn massage_a5_round2(data: &[u8], tofix: Corrections) -> Vec<u8> {
    let m: Vec<u32> = data
        .chunks(4)
        .map(|x| {
            let y: Vec<u8> = x.iter().copied().rev().collect();
            u8s_to_u32(&y)
        })
        .collect();

    // Reset to canonical values
    let mut a: u32 = 0x67452301;
    let mut a_p: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    let x: Vec<u32> = m[..16].to_vec();
    let mut x_p: Vec<u32> = m[..16].to_vec();
    // Round 1

    // Table 1, row 1
    match tofix {
        Corrections::A5i18 => {
            let bit = 1 << (18 - 3);
            // xor with 1 flips this bit
            x_p[0] = x_p[0] ^ bit;
        }
        Corrections::A5i25 => {
            let bit = 1 << (25 - 3);
            x_p[0] = x_p[0] ^ bit;
        }
        Corrections::A5i26 => {
            let bit = 1 << (26 - 3);
            x_p[0] = x_p[0] ^ bit;
        }
        Corrections::A5i28 => {
            let bit = 1 << (28 - 3);
            x_p[0] = x_p[0] ^ bit;
        }
        Corrections::A5i31 => {
            let bit = 1 << (31 - 3);
            x_p[0] = x_p[0] ^ bit;
        }
        _ => panic!("Trying to fix something we can't do here"),
    }

    a = a.wrapping_add(round1(b, c, d, x[0])).rotate_left(3);
    a_p = a_p.wrapping_add(round1(b, c, d, x_p[0])).rotate_left(3);

    // Table 1, row 2
    let d1 = d.wrapping_add(round1(a, b, c, x[0 + 1])).rotate_left(7);
    x_p[1] = d1
        .rotate_right(7)
        .wrapping_sub(d)
        .wrapping_sub(f(a_p, b, c));
    d = d.wrapping_add(round1(a_p, b, c, x[0 + 1])).rotate_left(7);

    // Table 1, row 3
    let c1 = c.wrapping_add(round1(d, a, b, x[0 + 2])).rotate_left(11);
    x_p[2] = c1
        .rotate_right(11)
        .wrapping_sub(c)
        .wrapping_sub(f(d, a_p, b));
    c = c
        .wrapping_add(round1(d, a_p, b, x_p[0 + 2]))
        .rotate_left(11);

    // Table 1, row 4

    let b1 = b.wrapping_add(round1(c, d, a, x[0 + 3])).rotate_left(19);
    x_p[3] = b1
        .rotate_right(19)
        .wrapping_sub(b)
        .wrapping_sub(f(c, d, a_p));
    b = b
        .wrapping_add(round1(c, d, a_p, x_p[0 + 3]))
        .rotate_left(19);

    // Table 1, row 5
    let a2 = a.wrapping_add(round1(b, c, d, x[4])).rotate_left(3);
    x_p[4] = a2
        .rotate_right(3)
        .wrapping_sub(a_p)
        .wrapping_sub(f(b, c, d));

    //a = a.wrapping_add(round1(b, c, d, x[4])).rotate_left(3);

    let mut massaged_block: Vec<u8> = vec![];
    for b in x_p[..16].iter() {
        for byte in u32_to_u8s(*b).iter().rev() {
            massaged_block.push(*byte);
        }
    }
    massaged_block
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Corrections {
    A5i18,
    A5i25,
    A5i26,
    A5i28,
    A5i31,
    D5i18,
    D5i25,
    D5i26,
    D5i28,
    D5i31,
    C5i25,
    C5i26,
    C5i28,
    C5i29,
    C5i31,
    B5i28,
    B5i29,
    B5i31,
    A6i28,
    A6i31,
    D6i28,
    C6i28,
    C6i29,
    C6i31,
}

pub fn check_round2(data: &[u8]) -> Vec<Corrections> {
    let mut set = HashSet::new();

    let m: Vec<u32> = data
        .chunks(4)
        .map(|x| {
            let y: Vec<u8> = x.iter().copied().rev().collect();
            u8s_to_u32(&y)
        })
        .collect();

    // Reset to canonical values
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    let x: Vec<u32> = m[..16].to_vec();
    // Round 1
    for &o in &[0, 4, 8, 12] {
        a = a.wrapping_add(round1(b, c, d, x[o])).rotate_left(3);
        d = d.wrapping_add(round1(a, b, c, x[o + 1])).rotate_left(7);
        c = c.wrapping_add(round1(d, a, b, x[o + 2])).rotate_left(11);
        b = b.wrapping_add(round1(c, d, a, x[o + 3])).rotate_left(19);
    }

    // Now we must ensure the round two conditions
    // a5 a5[18] = c4[18], a5[25] = 1, a5[26] = 0, a5[28] = 1, a5[31] = 1
    a = a.wrapping_add(round2(b, c, d, x[0])).rotate_left(3);

    if a.get_bit(18) != c.get_bit(18) {
        set.insert(Corrections::A5i18);
    }
    if a.get_bit(25) != 1 {
        set.insert(Corrections::A5i25);
    }
    if a.get_bit(26) != 0 {
        set.insert(Corrections::A5i26);
    }
    if a.get_bit(28) != 1 {
        set.insert(Corrections::A5i28);
    }
    if a.get_bit(31) != 1 {
        set.insert(Corrections::A5i31);
    }

    // d5 d5[18] = a5[18], d5[25] = b4[25], d5[26] = b4[26],
    // d5[28] = b4[28], d5[31] = b4[31]

    d = d.wrapping_add(round2(a, b, c, x[4])).rotate_left(5);
    if d.get_bit(18) != a.get_bit(18) {
        set.insert(Corrections::D5i18);
    }
    if d.get_bit(25) != b.get_bit(25) {
        set.insert(Corrections::D5i25);
    }
    if d.get_bit(26) != b.get_bit(26) {
        set.insert(Corrections::D5i26);
    }
    if d.get_bit(28) != b.get_bit(28) {
        set.insert(Corrections::D5i28);
    }
    if d.get_bit(31) != b.get_bit(31) {
        set.insert(Corrections::D5i31);
    }

    // c5 c5[25] = d5[25], c5[26] =  { return false; }
    // c5[29] = d5[29], c5[31] = d5[31]

    c = c.wrapping_add(round2(d, a, b, x[8])).rotate_left(9);
    if c.get_bit(25) != d.get_bit(25) {
        set.insert(Corrections::C5i25);
    }
    if c.get_bit(26) != d.get_bit(26) {
        set.insert(Corrections::C5i26);
    }
    if c.get_bit(28) != d.get_bit(28) {
        set.insert(Corrections::C5i28);
    }
    if c.get_bit(29) != d.get_bit(29) {
        set.insert(Corrections::C5i29);
    }
    if c.get_bit(31) != d.get_bit(31) {
        set.insert(Corrections::C5i31);
    }

    b = b.wrapping_add(round2(c, d, a, x[12])).rotate_left(13);
    if b.get_bit(28) != c.get_bit(28) {
        set.insert(Corrections::B5i28);
    }
    if b.get_bit(29) != 1 {
        set.insert(Corrections::B5i29);
    }
    if b.get_bit(31) != 0 {
        set.insert(Corrections::B5i31);
    }

    // a6 a6[28] = 1, a6[31] = 1
    a = a.wrapping_add(round2(b, c, d, x[1])).rotate_left(3);
    if a.get_bit(28) != 1 {
        set.insert(Corrections::A6i28);
    }
    if a.get_bit(31) != 1 {
        set.insert(Corrections::A6i31);
    }

    // d6 d6[28] = b5[28]
    d = d.wrapping_add(round2(a, b, c, x[5])).rotate_left(5);
    if d.get_bit(28) != b.get_bit(28) {
        set.insert(Corrections::D6i28);
    }

    // c6 c6[28] = d6[28], c6[29] = d6[29] + 1, c6[31] = d6[31] + 1
    c = c.wrapping_add(round2(d, a, b, x[9])).rotate_left(9);
    if c.get_bit(28) != d.get_bit(28) {
        set.insert(Corrections::C6i28);
    }
    if c.get_bit(29) != ((d.get_bit(29) + 1) % 2) {
        set.insert(Corrections::C6i29);
    }
    if c.get_bit(31) != ((d.get_bit(31) + 1) % 2) {
        set.insert(Corrections::C6i31);
    }

    // Round 2 check complete!
    set.into_iter().collect()
}

fn round1(x: u32, y: u32, z: u32, xx: u32) -> u32 {
    f(x, y, z).wrapping_add(xx)
}
fn round2(x: u32, y: u32, z: u32, xx: u32) -> u32 {
    g(x, y, z).wrapping_add(xx).wrapping_add(0x5a827999)
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn generate_md4_candidate_pair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();

    let mut message: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
    //println!("Pre-massage: {}", bytes_to_hex(&message));

    message = massage_round1(&message);
    //println!("Post-massage: {}", bytes_to_hex(&message));
    // Round 1 massaging conditions should hold
    check_round1(&message);
    // Check round 2 problems
    let mut corrections = check_round2(&message);
    //println!("Corrections: {:?}", corrections);
    // Now try to correct them
    if corrections.contains(&Corrections::A5i18) {
        message = massage_a5_round2(&message, Corrections::A5i18);
        corrections = check_round2(&message);
    }
    if corrections.contains(&Corrections::A5i25) {
        message = massage_a5_round2(&message, Corrections::A5i25);
        corrections = check_round2(&message);
    }
    if corrections.contains(&Corrections::A5i26) {
        message = massage_a5_round2(&message, Corrections::A5i26);
        corrections = check_round2(&message);
    }
    if corrections.contains(&Corrections::A5i28) {
        message = massage_a5_round2(&message, Corrections::A5i28);
        corrections = check_round2(&message);
    }
    if corrections.contains(&Corrections::A5i31) {
        message = massage_a5_round2(&message, Corrections::A5i31);
        //corrections = check_round2(&message);
    }
    //println!("Post-post-massage: {}", bytes_to_hex(&message));
    message = massage_round1(&message);
    //corrections = check_round2(&message);
    //println!("New corrections (A5s removed): {:?}", corrections);
    check_round1(&message);

    let message_p = flip_bits(&message);

    (message, message_p)
}

fn flip_bits(message: &[u8]) -> Vec<u8> {
    // Split the data into the appropriate chunks, again
    let mut x: Vec<u32> = message
        .chunks(4)
        .map(|x| {
            let y: Vec<u8> = x.iter().copied().rev().collect();
            u8s_to_u32(&y)
        })
        .collect();

    x[1] = x[1].wrapping_add(1 << 31);
    x[2] = x[2].wrapping_add((1 << 31) - (1 << 28));
    x[12] = x[12].wrapping_sub(1 << 16);

    let mut output: Vec<u8> = vec![];
    for b in x[..16].iter() {
        for byte in u32_to_u8s(*b).iter().rev() {
            output.push(*byte);
        }
    }
    output
}

pub fn main() -> Result<()> {
    let mut tries = 1;
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Tries: {}", tries));
    loop {
        spinner.set_message(format!("Tries: {}", tries));
        spinner.tick();
        tries += 1;

        let (message, message_p) = generate_md4_candidate_pair();
        let hash = md4_hash(&message);
        let hash_p = md4_hash(&message_p);
        //println!("try:   {}", tries);
        //println!("h:   {}", bytes_to_hex(&message));
        //println!("h':  {}", bytes_to_hex(&message_p));

        if hash == hash_p && message != message_p {
            spinner.finish();
            println!("Original: {}", bytes_to_hex(&message));
            print!("Flipped:  ");
            for (i, b) in message_p.iter().enumerate() {
                match message[i] == *b {
                    true => print!("{}", hex::encode([*b])),
                    false => print!("\x1b[91m{}\x1b[0m", hex::encode([*b])),
                }
            }
            println!();
            println!("Hash: {}", hash);
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_set_bit() {
        // 100
        let mut x = 0x04;
        assert_eq!(x.get_bit(0), 0x00);
        assert_eq!(x.get_bit(1), 0x00);
        assert_eq!(x.get_bit(2), 0x01);

        x.set_bit(1, &0x01);
        assert_eq!(x, 0x06);

        x.set_bit(1, &0x00);
        assert_eq!(x, 0x04);
    }
}
