//! Kelsey and Kohno's Nostradamus Attack
//!
//! Hash functions are sometimes used as proof of a secret prediction.
//!
//! For example, suppose you wanted to predict the score of every Major League Baseball game in a
//! season. (2,430 in all.) You might be concerned that publishing your predictions would affect
//! the outcomes.
//!
//! So instead you write down all the scores, hash the document, and publish the hash. Once the
//! season is over, you publish the document. Everyone can then hash the document to verify your
//! soothsaying prowess.
//!
//! But what if you can't accurately predict the scores of 2.4k baseball games? Have no fear -
//! forging a prediction under this scheme reduces to another second preimage attack.
//!
//! We could apply the long message attack from the previous problem, but it would look pretty
//! shady. Would you trust someone whose predicted message turned out to be 2^50 bytes long?
//!
//! It turns out we can run a successful attack with a much shorter suffix. Check the method:
//!
//! Generate a large number of initial hash states. Say, 2^k.
//! Pair them up and generate single-block collisions. Now you have 2^k hash states that collide
//! into 2^(k-1) states.
//! Repeat the process. Pair up the 2^(k-1) states and generate collisions. Now you have 2^(k-2)
//! states.
//! Keep doing this until you have one state. This is your prediction.
//! Well, sort of. You need to commit to some length to encode in the padding. Make sure it's long
//! enough to accommodate your actual message, this suffix, and a little bit of glue to join them
//! up. Hash this padding block using the state from step 4 - THIS is your prediction.
//! What did you just build? It's basically a funnel mapping many initial states into a common
//! final state. What's critical is we now have a big field of 2^k states we can try to collide
//! into, but the actual suffix will only be k+1 blocks long.
//!
//! The rest is trivial:
//!
//! Wait for the end of the baseball season. (This may take some time.)
//! Write down the game results. Or, you know, anything else. I'm not too particular.
//! Generate enough glue blocks to get your message length right. The last block should collide
//! into one of the leaves in your tree.
//! Follow the path from the leaf all the way up to the root node and build your suffix using the
//! message blocks along the way.
//! The difficulty here will be around 2^(b-k). By increasing or decreasing k in the tree
//! generation phase, you can tune the difficulty of this step. It probably makes sense to do more
//! work up-front, since people will be waiting on you to supply your message once the event
//! passes. Happy prognosticating!

struct MiniFunnel {
    pub block_a: Vec<u8>,
    pub block_b: Vec<u8>,
    pub output_hash: u16,
}

// Pairs off two hashes by finding blocks which collide them
impl MiniFunnel {
    fn new(input_a: u16, input_b: u16) -> Self {
        let mut rng = thread_rng();
        let mut map_a = HashMap::new();
        let mut map_b = HashMap::new();
        loop {
            let random_a: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
            let random_b: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

            let hash_a = hash::<Crash>(&random_a, input_a);
            let hash_b = hash::<Crash>(&random_b, input_b);

            map_a.insert(hash_a, random_a.clone());
            map_b.insert(hash_b, random_b.clone());

            // Check if hash_a in b
            if let Some(block_b) = map_b.get(&hash_a) {
                let block_a = random_a;
                return Self {
                    block_a,
                    block_b: block_b.clone(),
                    output_hash: hash_a,
                };
            }

            // Check if hash_b in a
            if let Some(block_a) = map_a.get(&hash_b) {
                let block_b = random_b;
                return Self {
                    block_a: block_a.clone(),
                    block_b,
                    output_hash: hash_b,
                };
            }
        }
    }
}

#[derive(Debug)]
struct Funnel {
    map: HashMap<u16, (Vec<u8>, u16)>,
    final_hash: u16,
    initial_layer: Vec<u16>,
}

impl Funnel {
    fn new(layers: usize) -> Self {
        let mut rng = thread_rng();
        let mut map = HashMap::<u16, (Vec<u8>, u16)>::new();
        let mut current_layer: Vec<u16> = (0..2_i32.pow(layers as u32) as usize)
            .map(|_| rng.gen::<u16>())
            .collect();
        let initial_layer = current_layer.clone();
        let mut next_layer: Vec<u16> = vec![];

        let pb = ProgressBar::new(layers as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        pb.set_message("Generating funnel layers");

        for _l in 0..layers {
            for p in current_layer.chunks(2) {
                // Ensures this is a full tree and has no loops/shortcuts
                loop {
                    let minifunnel = MiniFunnel::new(p[0], p[1]);
                    if map.get(&minifunnel.output_hash) == None {
                        map.insert(p[0], (minifunnel.block_a, minifunnel.output_hash));
                        map.insert(p[1], (minifunnel.block_b, minifunnel.output_hash));
                        next_layer.push(minifunnel.output_hash);
                        break;
                    }
                }
            }
            current_layer = next_layer;
            next_layer = vec![];
            //println!("Layer {}: {:?}", l + 1, current_layer);
            pb.inc(1);
        }
        pb.finish();
        Self {
            map,
            final_hash: current_layer[0],
            initial_layer,
        }
    }

    fn get_sequence(&self, input_hash: u16) -> Option<Vec<u8>> {
        if !self.initial_layer.contains(&input_hash) {
            return None;
        }
        let mut output = vec![];
        let mut next_index = input_hash;
        while let Some((block, n)) = self.map.get(&next_index) {
            output.extend_from_slice(block);
            if *n == self.final_hash {
                return Some(output);
            } else {
                next_index = *n;
            }
        }
        None
    }
}

use super::challenge52::{hash, Crash};
use crate::{set7::challenge52::hash_full, utils::*};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub fn main() -> Result<()> {
    nost(12)
}

fn nost(funnel_depth: usize) -> Result<()> {
    let funnel = Funnel::new(funnel_depth);
    let mut rng = thread_rng();

    println!(
        "I can predict the random bytes to come out of the hat, the hash of my prediction is: {}, and will be {} blocks long",
        funnel.final_hash,
        funnel_depth+3
    );

    let answer: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    println!("The bytes from the hat are: {:?}", answer);

    let mut forged_answer = answer.clone();
    // Padding
    forged_answer.extend_from_slice(&[0x00; 16]);
    // Random block to find collision
    forged_answer.extend_from_slice(&[0x00; 16]);
    let mut forged_hash = hash_full::<Crash>(&forged_answer, 0);

    let mut seq = funnel.get_sequence(forged_hash);

    let mut loop_num = 1;
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Retro-diction, loop {}", loop_num));
    loop {
        if let Some(x) = seq {
            spinner.finish();
            forged_answer.extend_from_slice(&x);
            let forged_hash_final = hash_full::<Crash>(&forged_answer, 0);
            println!("This is my prediction (the first block, followed by one of zero padding, and the rest is just to, uh, obfuscate my prediction):");
            println!("{:?}", forged_answer);
            println!("Sequence hash: {}", forged_hash_final);
            println!("Blocks: {}", forged_answer.len() / 16);

            assert_eq!(&forged_answer[..16], &answer[..16]);
            assert_eq!(forged_hash_final, funnel.final_hash);
            assert_eq!(forged_answer.len() / 16, funnel_depth + 3);

            break;
        }
        let random_bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
        forged_answer = forged_answer[..32].to_vec();
        forged_answer.extend_from_slice(&random_bytes);
        forged_hash = hash_full::<Crash>(&forged_answer, 0);
        seq = funnel.get_sequence(forged_hash);
        loop_num += 1;
        spinner.set_message(format!("Retro-diction, loop {}", loop_num));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair() {
        let a = 15_u16;
        let b = 16_u16;
        let f = MiniFunnel::new(a, b);

        let hash_a = hash::<Crash>(&f.block_a, a);
        let hash_b = hash::<Crash>(&f.block_b, b);

        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a, f.output_hash);
    }

    #[test]
    fn nostradamus() {
        nost(10).unwrap();
    }
}
