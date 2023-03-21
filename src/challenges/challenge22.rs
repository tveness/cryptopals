//! Crack an MT19937 seed
//!
//! Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the
//! same sequence of outputs given a seed).
//!
//! Write a routine that performs the following operation:
//!
//! Wait a random number of seconds between, I don't know, 40 and 1000.
//! Seeds the RNG with the current Unix timestamp
//! Waits a random number of seconds again.
//! Returns the first 32 bit output of the RNG.
//! You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although
//! you're missing some of the fun of this exercise if you do that.
//!
//! From the 32 bit RNG output, discover the seed.

use rand::{prelude::*, thread_rng};

use crate::utils::*;
use chrono::Utc;

pub fn main() -> Result<()> {
    let mut rng = thread_rng();

    let random_offset = rng.gen::<i64>() % 1000;
    let offset_timestamp = Utc::now().timestamp() - random_offset;
    let mut mt = Mt::seed(offset_timestamp as u32);

    let first_byte = mt.next();

    let now = Utc::now().timestamp();
    let mut back_count = 0;
    while Mt::seed((now - back_count) as u32).next() != first_byte {
        back_count += 1;
    }

    println!("Cracked offset: {back_count}");
    println!("True offset:    {random_offset}");

    assert_eq!(back_count, random_offset);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mt_cracker() {
        main().unwrap();
    }
}
