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
use indicatif::{ProgressBar, ProgressStyle};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};

trait CrapHasher {
    /// Updates the inner state with some data
    fn update(&mut self, block: &[u8]);
    /// Consumes the hasher and produces the final output
    fn finalise(self) -> u16;
    /// Initialiases hasher with specified state
    fn new(hash: u16) -> Self;
}

// Crap hash function
struct Crash {
    state: u16,
}

impl Crash {
    // Eats a single block
    fn eat(&self, chunk: &[u8]) -> u16 {
        let mut ciphertext = vec![0; 2 * 16];
        let mut key: Vec<u8> = vec![0x00; 30];
        key.push(((self.state >> 8) & 0xff) as u8);
        key.push((self.state & 0xff) as u8);

        let cipher = Cipher::chacha20();

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, None).unwrap();
        encrypter.pad(false);

        encrypter.update(chunk, &mut ciphertext).unwrap();

        let new_state = ((ciphertext[0] as u16) << 8) + (ciphertext[1] as u16);
        new_state
    }
}

impl CrapHasher for Crash {
    fn new(hash: u16) -> Self {
        Self { state: hash }
    }

    fn update(&mut self, block: &[u8]) {
        let bs = 16;
        // Pad out to correct block size
        for chunk in block.chunks(bs) {
            self.state = self.eat(chunk);
        }
    }

    // Consumes self in finalising
    fn finalise(self) -> u16 {
        self.state
    }
}

impl Default for Crash {
    fn default() -> Self {
        let state = 0;
        Self { state }
    }
}

// Slower crap hash function
struct SlowCrash {
    state: u16,
}

impl SlowCrash {
    fn eat(&self, chunk: &[u8]) -> u16 {
        let mut ciphertext = vec![0; 2 * 32];
        let mut key: Vec<u8> = vec![0x00; 28];
        key.push(((self.state >> 8) & 0xff) as u8);
        key.push((self.state & 0xff) as u8);
        key.push(((self.state >> 8) & 0xff) as u8);
        key.push((self.state & 0xff) as u8);

        let cipher = Cipher::aes_256_ecb();

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key, None).unwrap();
        encrypter.pad(false);

        encrypter.update(chunk, &mut ciphertext).unwrap();

        let new_state = ((ciphertext[0] as u16) << 8) + (ciphertext[1] as u16);
        new_state
    }
}

impl CrapHasher for SlowCrash {
    fn new(hash: u16) -> Self {
        Self { state: hash }
    }

    fn update(&mut self, block: &[u8]) {
        let bs = 16;
        // Pad out to correct block size
        for chunk in block.chunks(bs) {
            self.state = self.eat(chunk);
        }
    }

    // Consumes self in finalising
    fn finalise(self) -> u16 {
        self.state
    }
}

impl Default for SlowCrash {
    fn default() -> Self {
        let state = 0;
        Self { state }
    }
}

fn find_collision<T: CrapHasher>(state: u16) -> (Vec<u8>, Vec<u8>) {
    let mut rng = thread_rng();
    let mut map = HashMap::<u16, Vec<u8>>::new();
    // Now go through these blocks in a deterministic fashion
    loop {
        let random_block: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
        let mut hasher = T::new(state);
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

fn hash<T: CrapHasher>(block: &[u8], state: u16) -> u16 {
    let mut hasher = T::new(state);
    hasher.update(block);
    hasher.finalise()
}

fn hash_full<T: CrapHasher>(block: &[u8], state: u16) -> u16 {
    let mut hasher = T::new(state);
    for chunk in block.chunks(16) {
        hasher.update(chunk);
    }
    hasher.finalise()
}

fn gen_collision_pairs<T: CrapHasher>(
    initial_state: u16,
    length: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    // Pairs of blocks
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    let mut states = vec![initial_state];

    let pb = ProgressBar::new(length as u64);
    pb.set_message("Generating collisions");
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    for i in 0..length {
        // Okay, now how are we going to generate collisions?
        // First, we find a collision given a particular initial state
        let pair = find_collision::<T>(states[i]);

        //println!("Pair: {:?}", pair);

        let hash0 = hash::<T>(&pair.0, states[i]);
        //println!("Hash0: {}", hash0);

        //let hash1 = hash(&pair.1, states[i]);
        //println!("Hash1: {}", hash1);
        //assert_eq!(hash0, hash1);

        pairs.push(pair);
        states.push(hash0);
        //println!("States: {:?}", states);
        pb.inc(1);
    }
    pb.finish();
    pairs
}

fn get_bits_for_slow_collision(
    collision_pairs: &Vec<(Vec<u8>, Vec<u8>)>,
) -> Option<(usize, usize)> {
    let mut map = HashMap::new();
    let n = collision_pairs.len();

    let pb = ProgressBar::new((1 << n) as u64);
    pb.set_message("Generating slow collisions");
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    // Now run through each of these and determine whether there is a collision for slow_crash
    // How many options utilise the full tree? n choices, so 2**n distinct hashes, 2**n = 1 <<<
    // (n+1)
    for i in 0..(1 << n) {
        let mut slow_hasher = SlowCrash::default();
        for bit in 0..n {
            match ((i >> bit) & 0x01) == 0x01 {
                true => slow_hasher.update(&collision_pairs[bit].0),
                false => slow_hasher.update(&collision_pairs[bit].1),
            }
        }
        let h = slow_hasher.finalise();

        if let Some(old) = map.get(&h) {
            pb.finish_with_message(format!("Found collision after {} attempts", i));
            println!("Total calls: {}", i);
            return Some((*old, i));
        } else {
            pb.inc(1);
            map.insert(h, i);
        }
    }
    None
}

fn get_slow_and_fast_collision(search_size: usize) -> (Vec<(Vec<u8>, Vec<u8>)>, (usize, usize)) {
    // Keep generating until we find a collision pair
    loop {
        let collision_pairs = gen_collision_pairs::<Crash>(0, search_size);
        if let Some(bitpair) = get_bits_for_slow_collision(&collision_pairs) {
            return (collision_pairs, bitpair);
        }
        println!("Had to loop");
    }
}

pub fn main() -> Result<()> {
    let data = b"YELLOW SUBMARINE";
    let mut hasher = Crash::default();
    hasher.update(data);
    let hash_val = hasher.finalise();
    println!("Hash: {}", hash_val);

    // New hash function is crash(x) || slowcrash(x)
    // So, make 2**n colliding hashes
    // Given output space is of size 2**(16) expect to have ~sqrt these before a collision is found
    // i.e 2**8 = 256

    let n = 16;
    // Does this until a solution is found
    let (collision_pairs, bitpair) = get_slow_and_fast_collision(n);

    println!("Bitpair: {:?}", bitpair);
    // Bitpair now determines two blocks
    let mut a_blocks = vec![];
    let mut b_blocks = vec![];

    // Reconstruct blocks from bit-patterns
    for bit in 0..n {
        match ((bitpair.0 >> bit) & 0x01) == 0x01 {
            true => a_blocks.extend_from_slice(&collision_pairs[bit].0),
            false => a_blocks.extend_from_slice(&collision_pairs[bit].1),
        }
        match ((bitpair.1 >> bit) & 0x01) == 0x01 {
            true => b_blocks.extend_from_slice(&collision_pairs[bit].0),
            false => b_blocks.extend_from_slice(&collision_pairs[bit].1),
        }
    }

    // Now calculate hashes for each of these
    let regular_hash_a = hash_full::<Crash>(&a_blocks, 0);
    let regular_hash_b = hash_full::<Crash>(&b_blocks, 0);
    println!("Fast hash a: {}", regular_hash_a);
    println!("Fast hash b: {}", regular_hash_b);

    assert_eq!(regular_hash_a, regular_hash_b);

    let slow_hash_a = hash_full::<SlowCrash>(&a_blocks, 0);
    let slow_hash_b = hash_full::<SlowCrash>(&b_blocks, 0);
    println!("Slow hash a: {}", slow_hash_a);
    println!("Slow hash b: {}", slow_hash_b);
    assert_eq!(slow_hash_a, slow_hash_b);

    assert_ne!(a_blocks, b_blocks);
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
        let collision_pairs = gen_collision_pairs::<Crash>(initial_val, n);

        // Pick two random paths through the tree and verify hashes are the same
        let mut hasher_one = Crash::new(initial_val);
        let mut hasher_two = Crash::new(initial_val);
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

    #[test]
    fn double_collision() {
        main().unwrap();
    }
}
