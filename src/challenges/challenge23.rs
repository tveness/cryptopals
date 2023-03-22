//! Clone an MT19937 RNG from its output
//!
//! The internal state of MT19937 consists of 624 32 bit integers.
//!
//! For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly,
//! MT19937 achieves a period of 2**19937, which is Big.
//!
//! Each time MT19937 is tapped, an element of its internal state is subjected to a tempering
//! function that diffuses bits through the result.
//!
//! The tempering function is invertible; you can write an "untemper" function that takes an
//! MT19937 output and transforms it back into the corresponding element of the MT19937 state
//! array.
//!
//! To invert the temper transform, apply the inverse of each of the operations in the temper
//! transform in reverse order. There are two kinds of operations in the temper transform each
//! applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a
//! left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the
//! "left" operation.
//!
//! Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs,
//! untemper each of them to recreate the state of the generator, and splice that state into a new
//! instance of the MT19937 generator.
//!
//! The new "spliced" generator should predict the values of the original.
//!
//! Stop and think for a second. How would you modify MT19937 to make this attack hard? What would
//! happen if you subjected each tempered output to a cryptographic hash?

use rand::{prelude::*, thread_rng};

use crate::challenges::challenge21::{B, C, D, L, LOWEST_W, S, T, U};
use crate::utils::*;

// ABCDEFGHIJKLMN
// ^
// 0000ABCDEFGHIJ, where shifted r by l
// &
//  qwpeouqwe
// top l bits are good
//
// top_l = answer & 111100000
// next l = shift by l and ^
// and repeat
fn unshift_r(value: u32, s: u32, mask: u32) -> u32 {
    let top_s = ((1_u64 << 32_u64) - (1_u64 << (32_u64 - s as u64))) as u32;
    let mut working_value = 0;
    for i in 0..((32 / s as usize) + 1) {
        let i = i as u32;
        let window_mask = top_s >> (s * i);
        working_value += window_mask & ((value) ^ (mask & (working_value >> s)));
    }
    working_value
}

// ABCDEFGHIJKLMN
// ^
// (FGHIJLKMN00000 & C)
// So again we mask and shift and mask
//
// 0000000000000001
// ^
// 000001000000000 & C
//

fn unshift_l(value: u32, s: u32, mask: u32) -> u32 {
    let s = s as u64;
    let bottom_s = (1_u64 << s) - 1;
    let value = value as u64;
    let mask = mask as u64;
    let mut working_value: u64 = 0;
    for i in 0..((32 / s as usize) + 1) {
        let i = i as u64;
        let window_mask = bottom_s << (s * i);
        working_value += window_mask & (value ^ (mask & (working_value << s)));
    }
    (working_value & LOWEST_W) as u32
}

fn untemper(value: u32) -> u32 {
    // y = y ^ (y >> L as u64);
    //println!("Input: {value}");
    let mut y = unshift_r(value, L, 0xFFFFFFFF_u32);
    //println!("Untemper 1: {y}");
    //y = y ^ ((y << T as u64) & C as u64);
    y = unshift_l(y, T, C);
    //println!("Untemper 2: {y}");
    //y = y ^ ((y << S as u64) & B as u64);
    y = unshift_l(y, S, B);
    //println!("Untemper 3: {y}");
    //y = y ^ ((y >> U as u64) & D as u64);
    y = unshift_r(y, U, D);
    //println!("Untemper 4: {y}");
    y
}

#[allow(dead_code)]
fn temper(value: u32) -> u32 {
    let mut y = value as u64;
    //println!("Original: {y}");
    y = y ^ ((y >> U as u64) & D as u64);
    //println!("Temper 1: {y}");
    y = y ^ ((y << S as u64) & B as u64);
    //println!("Temper 2: {y}");
    y = y ^ ((y << T as u64) & C as u64);
    //println!("Temper 3: {y}");
    y = y ^ (y >> L as u64);
    //println!("Output: {y}");
    y as u32
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();

    let random_seed = rng.gen::<u32>();
    let mt = Mt::seed(random_seed);

    let untempered_state = mt.take(624).map(untemper).collect::<Vec<u32>>();

    let mt_spliced = Mt {
        state: untempered_state,
        index: 0,
    };

    let mt = Mt::seed(random_seed);

    let first_byte_run = mt.take(50).collect::<Vec<u32>>();
    let first_byte_run_s = mt_spliced.take(50).collect::<Vec<u32>>();
    println!("First byte run from mt: {:?}", first_byte_run);
    println!("First byte run from mt_spliced: {:?}", first_byte_run_s);
    assert_eq!(first_byte_run_s, first_byte_run);

    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn challenge_test() {
        main().unwrap();
    }
    #[test]
    fn untemper_test() {
        for i in 0..1000 {
            assert_eq!(untemper(temper(i)), i);
        }
    }

    #[test]
    fn unshift_r_test() {
        for i in 0..1000 {
            let i = i as u64;
            let y = i ^ ((i >> U as u64) & D as u64);
            let un = unshift_r(y as u32, U, D);
            assert_eq!(i as u32, un);
        }
    }

    #[test]
    fn unshift_l_test() {
        for i in 0..1000 {
            let i = i as u64;
            let y = i ^ ((i << T as u64) & C as u64);
            println!("Partially tempered {y}");
            let un = unshift_l(y as u32, T, C);
            assert_eq!(i as u32, un);
        }
    }
}
