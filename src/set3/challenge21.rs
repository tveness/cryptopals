//! Implement the MT19937 Mersenne Twister RNG
//! You can get the psuedocode for this from Wikipedia.
//!
//! If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you
//! MT19937 as "rand()"; don't use rand(). Write the RNG yourself.

use crate::utils::*;

// For MT19937:
// (w,n,m,r) = (32,624,397,31)
// a = 9908B0DF_{32}
// (u,d) = (11, FFFFFFFF_{32})
// (s,b) = (7, 9D2C5680_{32})
// (t,c) = (15, EFC60000_{32})
// l = 18

const W: u32 = 32;
const N: u32 = 624;
const M: u32 = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;

pub const U: u32 = 11;
pub const D: u32 = 0xFFFFFFFF;
pub const S: u32 = 7;
pub const B: u32 = 0x9D2C5680;
pub const T: u32 = 15;
pub const C: u32 = 0xEFC60000;
pub const L: u32 = 18;
const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1 << R) - 1;
// In this case lowest W bits is all of them
const UPPER_MASK: u32 = ((1_u64 << W as u64) - 1_u64) as u32 & !LOWER_MASK;

pub const LOWEST_W: u64 = 0xFFFFFFFF;

pub struct Mt {
    pub state: Vec<u32>,
    pub index: usize,
}

impl Mt {
    pub fn seed(seed: u32) -> Mt {
        let mut state = vec![0; N as usize];
        state[0] = seed;

        let l = state.len();
        for i in 1..l {
            let mut overflow: u64 = F as u64;
            overflow *= (state[i - 1] ^ (state[i - 1] >> (W - 2))) as u64;
            overflow += i as u64;
            state[i] = (overflow & LOWEST_W) as u32;
        }

        Mt {
            state,
            index: N as usize,
        }
    }

    fn twist(&mut self) {
        let n = self.state.len();
        for i in 0..(n - 1) {
            let x = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % n] & LOWER_MASK);
            let mut xa = x >> 1;
            if (x % 2) != 0 {
                xa ^= A;
            }
            let si = (i + M as usize) % n;
            self.state[i] = self.state[si] ^ xa;
        }

        self.index = 0;
    }
}

impl Iterator for Mt {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index as u32 == N {
            self.twist();
        }

        let mut y = self.state[self.index] as u64;
        y = y ^ ((y >> U as u64) & D as u64);
        y = y ^ ((y << S as u64) & B as u64);
        y = y ^ ((y << T as u64) & C as u64);
        y = y ^ (y >> L as u64);
        self.index += 1;

        Some((y & LOWEST_W) as u32)
    }
}

pub fn main() -> Result<()> {
    let twister = Mt::seed(0);
    for n in twister.take(10) {
        println!("{n}");
    }
    Ok(())
}
