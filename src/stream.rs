use byteorder::{LittleEndian, WriteBytesExt};

use crate::utils::ecb_encrypt;

pub struct Ctr {
    key: Vec<u8>,
    nonce: u64,
    byte_buffer: Vec<u8>,
    byte_count: usize,
    block_size: usize,
}

impl Ctr {
    pub fn new(key: &[u8], nonce: u64) -> Ctr {
        let key: Vec<u8> = key.to_vec();
        let byte_count = 0;
        let block_size = 16;
        let byte_buffer = Vec::with_capacity(block_size);

        Self {
            key,
            nonce,
            byte_count,
            byte_buffer,
            block_size,
        }
    }

    fn update_block(&mut self) {
        let block = self.byte_count / self.block_size;
        let mut input = vec![];
        input.write_u64::<LittleEndian>(self.nonce).unwrap();
        input.write_u64::<LittleEndian>(block as u64).unwrap();
        self.byte_buffer = ecb_encrypt(&input, &self.key, None).unwrap();
    }
}

impl Iterator for Ctr {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.byte_count % self.block_size;
        if index == 0 {
            self.update_block();
        }
        let byte = self.byte_buffer[index];
        self.byte_count += 1;
        Some(byte)
    }
}
