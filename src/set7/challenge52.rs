//! Iterated Hash Function Multicollisions
//!
//! While we're on the topic of hash functions...
//!
//! The major feature you want in your hash function is collision-resistance. That is, it should be
//! hard to generate collisions, and it should be really hard to generate a collision for a given
//! hash (aka preimage).
//!
//! Iterated hash functions have a problem: the effort to generate lots of collisions scales sublinearly.
//!
//! What's an iterated hash function? For all intents and purposes, we're talking about the
//! Merkle-Damgard construction. It looks like this:
//!
//! function MD(M, H, C):
//!   for M[i] in pad(M):
//!     H := C(M[i], H)
//!   return H
//! For message M, initial state H, and compression function C.
//!
//! This should look really familiar, because SHA-1 and MD4 are both in this category. What's cool
//! is you can use this formula to build a makeshift hash function out of some spare crypto
//! primitives you have lying around (e.g. C = AES-128).
//!
//! Back on task: the cost of collisions scales sublinearly. What does that mean? If it's feasible
//! to find one collision, it's probably feasible to find a lot.
//!
//! How? For a given state H, find two blocks that collide. Now take the resulting hash from this
//! collision as your new H and repeat. Recognize that with each iteration you can actually double
//! your collisions by subbing in either of the two blocks for that slot.
//!
//! This means that if finding two colliding messages takes 2^(b/2) work (where b is the bit-size
//! of the hash function), then finding 2^n colliding messages only takes n*2^(b/2) work.
//!
//! Let's test it. First, build your own MD hash function. We're going to be generating a LOT of
//! collisions, so don't knock yourself out. In fact, go out of your way to make it bad. Here's one
//! way:
//!
//! Take a fast block cipher and use it as C.
//! Make H pretty small. I won't look down on you if it's only 16 bits. Pick some initial H.
//! H is going to be the input key and the output block from C. That means you'll need to pad it on
//! the way in and drop bits on the way out.
//! Now write the function f(n) that will generate 2^n collisions in this hash function.
//!
//! Why does this matter? Well, one reason is that people have tried to strengthen hash functions
//! by cascading them together. Here's what I mean:
//!
//! Take hash functions f and g.
//! Build h such that h(x) = f(x) || g(x).
//! The idea is that if collisions in f cost 2^(b1/2) and collisions in g cost 2^(b2/2), collisions
//! in h should come to the princely sum of 2^((b1+b2)/2).
//!
//! But now we know that's not true!
//!
//! Here's the idea:
//!
//! Pick the "cheaper" hash function. Suppose it's f.
//! Generate 2^(b2/2) colliding messages in f.
//! There's a good chance your message pool has a collision in g.
//! Find it.
//! And if it doesn't, keep generating cheap collisions until you find it.
//!
//! Prove this out by building a more expensive (but not too expensive) hash function to pair with
//! the one you just used. Find a pair of messages that collide under both functions. Measure the
//! total number of calls to the collision function.

use std::collections::HashMap;

use crate::utils::*;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};

// Crap hash function
struct Crash {
    state: u16,
}

impl Crash {
    fn update(&mut self, block: &[u8]) {
        let bs = 16;
        // Pad out to correct block size
        for chunk in block.chunks(bs) {
            self.state = self.eat(chunk);
        }
    }

    fn eat(&self, chunk: &[u8]) -> u16 {
        let mut ciphertext = vec![0; 2 * 16];
        let mut key: Vec<u8> = vec![0x00; 14];
        key.push(((self.state >> 8) & 0xff) as u8);
        key.push((self.state & 0xff) as u8);

        let cipher = Cipher::aes_128_ecb();

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, None).unwrap();
        encrypter.pad(false);

        encrypter.update(chunk, &mut ciphertext).unwrap();

        let new_state = ((ciphertext[0] as u16) << 8) + (ciphertext[1] as u16);
        new_state
    }

    // Consumes self in finalising
    fn finalise(self) -> u16 {
        self.state
    }
}

impl Crash {
    fn from(hash: u16) -> Self {
        Self { state: hash }
    }
}

impl Default for Crash {
    fn default() -> Self {
        let state = 0;
        Self { state }
    }
}

fn find_collision(state: u16) -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let mut map = HashMap::<u16, Vec<u8>>::new();
    // Now go through these blocks in a deterministic fashion
    loop {
        let random_block: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
        let mut hasher = Crash::from(state);
        hasher.update(&random_block);
        let hash = hasher.finalise();
        if let Some(old) = map.get(&hash) {
            if old != &random_block {
                return (old.to_vec(), random_block);
            }
        } else {
            map.insert(hash, random_block);
        }
    }
}

fn hash(block: &[u8], state: u16) -> u16 {
    let mut hasher = Crash::from(state);
    hasher.update(block);
    hasher.finalise()
}

fn gen_collision_pairs(initial_state: u16, length: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Pairs of blocks
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    let mut states = vec![initial_state];
    for i in 0..length {
        // Okay, now how are we going to generate collisions?
        // First, we find a collision given a particular initial state
        let pair = find_collision(states[i]);

        //println!("Pair: {:?}", pair);

        let hash0 = hash(&pair.0, states[i]);
        //println!("Hash0: {}", hash0);

        //let hash1 = hash(&pair.1, states[i]);
        //println!("Hash1: {}", hash1);
        //assert_eq!(hash0, hash1);

        pairs.push(pair);
        states.push(hash0);
        //println!("States: {:?}", states);
    }
    pairs
}

pub fn main() -> Result<()> {
    let data = b"YELLOW SUBMARINE";
    let mut hasher = Crash::default();
    hasher.update(data);
    let hash_val = hasher.finalise();
    println!("Hash: {}", hash_val);

    let n = 10;
    let collision_pairs = gen_collision_pairs(0, n);
    println!("List of colliding pairs: {:?}", collision_pairs);

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_tree() {
        let mut rng = thread_rng();
        let initial_val = rng.gen::<u16>();

        let n = 10;
        let collision_pairs = gen_collision_pairs(initial_val, n);

        // Pick two random paths through the tree and verify hashes are the same
        let mut hasher_one = Crash::from(initial_val);
        let mut hasher_two = Crash::from(initial_val);
        for i in 0..n {
            match rng.gen::<bool>() {
                true => hasher_one.update(&collision_pairs[i].1),
                false => hasher_one.update(&collision_pairs[i].0),
            }
            match rng.gen::<bool>() {
                true => hasher_two.update(&collision_pairs[i].1),
                false => hasher_two.update(&collision_pairs[i].0),
            }
        }

        let hash_val_one = hasher_one.finalise();
        let hash_val_two = hasher_two.finalise();

        assert_eq!(hash_val_one, hash_val_two);
    }
}
