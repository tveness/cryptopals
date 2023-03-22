use std::collections::VecDeque;

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
    let mut rng = thread_rng();

    // Random 16-bit seed
    let random_seed = rng.gen::<u32>() & 0x0000ffff_u32;
    let mts = MtStream::new(random_seed);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mt_stream() {
        for seed in 0..10 {
            let mts = MtStream::new(seed);
            let total = mts
                .take(4)
                .enumerate()
                .map(|(i, v)| (v as u32) << (3 - i) * 8)
                .sum::<u32>();

            let first = Mt::seed(seed).next().unwrap();
            assert_eq!(first, total);
        }
    }
}
