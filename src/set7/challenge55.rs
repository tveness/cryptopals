//! MD4 Collisions
//!
//! MD4 is a 128-bit cryptographic hash function, meaning it should take a work factor of roughly
//! 2^64 to find collisions.
//!
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

use crate::utils::*;

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

pub fn main() -> Result<()> {
    Ok(())
}
