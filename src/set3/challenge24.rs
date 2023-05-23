use std::collections::VecDeque;

use anyhow::anyhow;
use rand::{prelude::*, thread_rng};

use crate::utils::*;

struct MtStream {
    mt: Mt,
    localbuffer: VecDeque<u8>,
}

impl MtStream {
    pub fn new(seed: u32) -> MtStream {
        let mt = Mt::seed(seed);
        let localbuffer = VecDeque::<u8>::new();

        MtStream { mt, localbuffer }
    }
}

impl Iterator for MtStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.localbuffer.is_empty() {
            let byte = self.mt.next().unwrap();
            let b1 = (byte & 0xff000000_u32) >> 24;
            let b2 = (byte & 0x00ff0000_u32) >> 16;
            let b3 = (byte & 0x0000ff00_u32) >> 8;
            let b4 = byte & 0x000000ff_u32;
            self.localbuffer.push_back(b1 as u8);
            self.localbuffer.push_back(b2 as u8);
            self.localbuffer.push_back(b3 as u8);
            self.localbuffer.push_back(b4 as u8);
        }
        self.localbuffer.pop_front()
    }
}

pub fn main() -> Result<()> {
    mt_seed_cracker()?;

    pw_reset_token()?;
    Ok(())
}

fn pw_reset_token() -> Result<()> {
    let mut rng = thread_rng();

    let coin = rng.gen::<bool>();
    let timestamp = chrono::Utc::now().timestamp();

    let token = match coin {
        true => {
            let mts = MtStream::new(timestamp as u32);

            mts.take(64).collect::<Vec<u8>>()
        }
        false => {
            let mut v = vec![0; 64];
            rng.fill(&mut v[..]);
            v
        }
    };

    let mts = MtStream::new(timestamp as u32);
    let rec_token = mts.take(64).collect::<Vec<u8>>();
    let is_token = { token == rec_token };

    println!("Was token? {coin}");
    println!("Detected?  {is_token}");

    assert_eq!(coin, is_token);

    Ok(())
}

fn mt_seed_cracker() -> Result<()> {
    let mut rng = thread_rng();

    // Random 16-bit seed
    let random_seed = rng.gen::<u32>() & 0x0000ffff_u32;
    let mts = MtStream::new(random_seed);

    let mut input: Vec<u8> = random_bytes(5, 10, &mut rng);
    let controlled = b"AAAAAAAAAAAAAA";
    input.extend_from_slice(controlled);

    let encrypted = input
        .iter()
        .zip(mts)
        .map(|(v, k)| v ^ k)
        .collect::<Vec<u8>>();

    let cracked_seed = crack_seed(&encrypted, controlled)?;

    println!("True seed: {random_seed}");
    println!("Cracked seed: {cracked_seed}");
    assert_eq!(random_seed, cracked_seed);

    Ok(())
}

fn crack_seed(encrypted: &[u8], controlled: &[u8]) -> Result<u32> {
    let l = encrypted.len();
    let cl = controlled.len();
    for i in 0..(1 << 16) {
        let mts = MtStream::new(i);
        let decrypted = encrypted
            .iter()
            .zip(mts)
            .map(|(v, k)| v ^ k)
            .collect::<Vec<u8>>();
        if &decrypted[l - cl..] == controlled {
            return Ok(i);
        }
    }

    Err(anyhow!("Could not find seed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crack_seed_test() {
        mt_seed_cracker().unwrap();
    }

    #[test]
    fn password_token() {
        for _ in 0..100 {
            pw_reset_token().unwrap();
        }
    }

    #[test]
    fn test_mt_stream() {
        for seed in 0..10 {
            let mts = MtStream::new(seed);
            let total = mts
                .take(4)
                .enumerate()
                .map(|(i, v)| (v as u32) << ((3 - i) * 8))
                .sum::<u32>();

            let first = Mt::seed(seed).next().unwrap();
            assert_eq!(first, total);
        }
    }
}
