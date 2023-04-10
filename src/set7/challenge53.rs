//! Kelsey and Schneier's Expandable Messages
//!
//! One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to
//! second preimage attacks. That means that if I give you x and y such that H(x) = y, you should
//! have a tough time finding x' such that H(x') = H(x) = y.
//!
//! How tough? Brute-force tough. For a 2^b hash function, we want second preimage attacks to cost
//! 2^b operations.
//!
//! This turns out not to be the case for very long messages.
//!
//! Consider the problem we're trying to solve: we want to find a message that will collide with
//! H(x) in the very last block. But there are a ton of intermediate blocks, each with its own
//! intermediate hash state.
//!
//! What if we could collide into one of those? We could then append all the following blocks from
//! the original message to produce the original H(x). Almost.
//!
//! We can't do this exactly because the padding will mess things up.
//!
//! What we need are expandable messages.
//!
//! In the last problem we used multicollisions to produce 2^n colliding messages for n*2^(b/2)
//! effort. We can use the same principles to produce a set of messages of length (k, k + 2^k - 1)
//! for a given k.
//!
//! Here's how:
//!
//! Starting from the hash function's initial state, find a collision between a single-block
//! message and a message of 2^(k-1)+1 blocks. DO NOT hash the entire long message each time.
//! Choose 2^(k-1) dummy blocks, hash those, then focus on the last block.
//! Take the output state from the first step. Use this as your new initial state and find another
//! collision between a single-block message and a message of 2^(k-2)+1 blocks.
//! Repeat this process k total times. Your last collision should be between a single-block message
//! and a message of 2^0+1 = 2 blocks.
//! Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate
//! message (short or long) from each pair.
//!
//! Now we're ready to attack a long message M of 2^k blocks.
//!
//! Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
//! Hash M and generate a map of intermediate hash states to the block indices that they correspond
//! to.
//! From your expandable message's final state, find a single-block "bridge" to intermediate state
//! in your map. Note the index i it maps to.
//! Use your expandable message to generate a prefix of the right length such that len(prefix ||
//! bridge || M[i..]) = len(M).
//! The padding in the final block should now be correct, and your forgery should hash to the same
//! value as M.

use indicatif::{ProgressBar, ProgressStyle};
use rand::{thread_rng, Rng};
use std::collections::HashMap;

use crate::utils::*;

use super::challenge52::{hash_full, CrapHasher, Crash};
// The idea is quite simple, in reality
// We wish to produce a series of choices: long/short to build up a message of arbitrary length
// Each of these long or short blocks hash to the same value at the end
// Making the short block 0 is a bad idea, because then we lose the birthday-attack advantage
// The shortest option is 1, or 2**k for increasing k
// If we build upwards, we can start with 1,2; 1,3; 1,5; 1,9; ...; 1,2**(k-1) + 1, allowing us to
// produce any length of filler with length k -> k + 2**(k-1) + ... + 1 = 2**(k) + k -1
// We have 2**(b/2) operations per block, and so can create an expandable message the cost of
// (k-1)*2**(b/2), a long cry from 2**b

#[derive(Default, Debug)]
struct Expandable {
    short_blocks: Vec<Vec<u8>>,
    long_blocks: Vec<Vec<u8>>,
    hashes: Vec<u16>,
}

impl Expandable {
    pub fn new(l: usize) -> Self {
        let mut expandable = Self::default();
        let pb = ProgressBar::new(l as u64);
        pb.set_message("Generating expandable message");
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        for _ in 0..l {
            expandable.extend();
            pb.inc(1);
        }
        pb.finish();

        expandable
    }

    pub fn extend(&mut self) {
        // Get current k
        let k = self.short_blocks.len();
        // Get starting seed value
        let mut short_comp = vec![];
        for s in &self.short_blocks {
            short_comp.extend_from_slice(s);
        }

        // If this is the first block, starting from seed 0
        let seed = match k {
            0 => 0,
            _ => hash_full::<Crash>(&short_comp, 0),
        };

        // Now generate padding
        let padding = vec![0x00; 16 * (2_usize.pow(k as u32))];
        let long_seed = hash_full::<Crash>(&padding, seed);

        // Okay, now all set up
        // Create two hashmaps for both long and short blocks
        let mut short_map = HashMap::<u16, Vec<u8>>::new();
        let mut long_map = HashMap::<u16, Vec<u8>>::new();

        let mut rng = thread_rng();
        loop {
            let short_block: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
            let long_block: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

            let short_hash = hash_full::<Crash>(&short_block, seed);
            let long_hash = hash_full::<Crash>(&long_block, long_seed);
            // Now check for collisions
            // First, is short in long?
            if let Some(long_collision) = long_map.get(&short_hash) {
                self.short_blocks.push(short_block.to_vec());

                let mut long_appended = padding;
                long_appended.extend_from_slice(long_collision);
                assert_eq!(short_hash, hash_full::<Crash>(&long_appended, seed));

                self.long_blocks.push(long_appended);

                self.hashes.push(short_hash);
                break;
            }
            // Is long in short?
            if let Some(short_collision) = short_map.get(&long_hash) {
                assert_eq!(long_hash, hash_full::<Crash>(short_collision, seed));

                self.short_blocks.push(short_collision.clone());

                let mut long_appended = padding;
                long_appended.extend_from_slice(&long_block);

                self.long_blocks.push(long_appended);

                self.hashes.push(long_hash);
                break;
            }
            // Otherwise, insert both and keep going
            short_map.insert(short_hash, short_block);
            long_map.insert(long_hash, long_block);
        }
    }
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();

    // Random message of length 2**16 blocks blocks
    let message: Vec<u8> = (0..16 * 65536).map(|_| rng.gen::<u8>()).collect();
    let mut message_hashes = vec![];

    // Calculate intermediate message hashes message
    let mut hasher = Crash::default();
    for block in message.chunks(16) {
        hasher.update(block);
        message_hashes.push(hasher.peek());
    }

    let message_hash = hash_full::<Crash>(&message, 0);

    // Generate expandable messages until we find a match
    loop {
        let k = 16;
        let expandable = Expandable::new(k);
        let expandable_hash = expandable.hashes[expandable.hashes.len() - 1];

        let short_length: usize = expandable.short_blocks.iter().map(|x| x.len()).sum();
        let long_length: usize = expandable.long_blocks.iter().map(|x| x.len()).sum();

        println!(
            "Generated expandable messages from length {} to {} blocks, all with hash {}",
            short_length / 16,
            long_length / 16,
            expandable_hash
        );

        let short_lengths: Vec<usize> = expandable
            .short_blocks
            .iter()
            .map(|x| x.len() / 16)
            .collect();
        let long_lengths: Vec<usize> = expandable
            .long_blocks
            .iter()
            .map(|x| x.len() / 16)
            .collect();
        println!("Short lengths: {:?}", short_lengths);
        println!("Long lengths:  {:?}", long_lengths);

        // Scan through expandable messages and check if there is a collision
        // Must skip first k because our expandable message has a minimum length of k
        // Do any of the intermediate hashes match our expandable hash?
        if let Some(index) = message_hashes
            .iter()
            .skip(k)
            .position(|x| *x == expandable_hash)
        {
            // Message hashes are in correspondence, so message_hash[0] is the hash of block 0
            // As such, we want to take the position one beyond this in order to actually replace the
            // block with the matching hash
            let index = index + 1;
            println!("Collision found!");
            let position = k + index;
            println!("Block number: {}", position);

            // Construct expandable message with this length
            let mut expandable_message = vec![];

            // Toggle bits on index to build up long/short sequence
            for i in 0..k {
                let bits = (index >> i) & 0x01;
                match bits == 0x01 {
                    // If (position - k) has a 1 in its ith bit, then add a long block
                    true => expandable_message.extend_from_slice(&expandable.long_blocks[i]),
                    // If (position - k) has a 0 in its ith bit, then add a short block
                    false => expandable_message.extend_from_slice(&expandable.short_blocks[i]),
                }
            }
            // The length of the expandable message should now be equal to block position
            assert_eq!(expandable_message.len() / 16, position);

            // Patch on remainder of the blocks from the original message
            expandable_message.extend_from_slice(&message[16 * position..]);

            // Check lengths match
            assert_eq!(expandable_message.len(), message.len());

            // And check that hashes match!
            let expandable_hash_full = hash_full::<Crash>(&expandable_message, 0);
            assert_eq!(expandable_hash_full, message_hash);

            assert_ne!(expandable_message, message);
            println!(
                "Expanded message total length: {}",
                expandable_message.len()
            );
            println!("Original message total length: {}", message.len());
            println!(
                "Expanded message first block: {:?}",
                &expandable_message[0..16]
            );
            println!("Original message first block: {:?}", &message[0..16]);
            println!("Expanded message full hash: {}", expandable_hash_full);
            println!("Original message full hash: {}", message_hash);

            return Ok(());
        }
        println!("Didn't find a match, regenerating expandable message");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths() {
        let n = 10;
        let expandable = Expandable::new(n);
        let mut rng = thread_rng();

        let mut message_one = vec![];
        let mut message_two = vec![];

        // Generate two message branches
        for i in 0..n {
            match rng.gen::<bool>() {
                true => {
                    message_two.extend_from_slice(&expandable.long_blocks[i]);
                    message_one.extend_from_slice(&expandable.short_blocks[i]);
                }
                false => {
                    message_one.extend_from_slice(&expandable.long_blocks[i]);
                    message_two.extend_from_slice(&expandable.short_blocks[i]);
                }
            }
        }

        // Lengths of messages should be different
        assert_ne!(message_one.len(), message_two.len());

        // Hashes should be identical
        let hash_one = hash_full::<Crash>(&message_one, 0);
        let hash_two = hash_full::<Crash>(&message_two, 0);
        assert_eq!(hash_one, hash_two);
    }

    #[test]
    fn collision() {
        main().unwrap();
    }
}
