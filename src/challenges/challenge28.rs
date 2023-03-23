//! Implement a SHA-1 keyed MAC
//!
//! Find a SHA-1 implementation in the language you code in.
//!
//! Don't cheat. It won't work.
//! Do not use the SHA-1 implementation your language already provides (for instance, don't use the
//! "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
//! Write a function to authenticate a message under a secret key by using a secret-prefix MAC,
//! which is simply:
//! ```raw
//! SHA1(key || message)
//! ```
//! Verify that you cannot tamper with the message without breaking the MAC you've produced, and
//! that you can't produce a new MAC without knowing the secret key.

use crate::utils::*;

struct Sha1Hasher {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        Sha1Hasher { h0, h1, h2, h3, h4 }
    }
}

impl Sha1Hasher {
    pub fn load(hash: &[u8]) -> Self {
        // Beautiful, what could go wrong?
        if let &[h0, h1, h2, h3, h4] = &hash
            .chunks(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, v)| (*v as u32) << (8 * (3 - i)))
                    .sum()
            })
            .collect::<Vec<u32>>()[..]
        {
            Sha1Hasher { h0, h1, h2, h3, h4 }
        } else {
            panic!("Invalid hash");
        }
    }

    /// Implementation of RFC3174
    /// https://www.rfc-editor.org/rfc/rfc3174
    ///
    /// Example and intermediate values at
    /// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
    pub fn hash(&mut self, data: &[u8]) -> Vec<u8> {
        // Pre-process
        let mut data: Vec<u8> = data.to_vec();
        let ml = data.len() as u64;
        // Add 1 bit
        data.push(0x80);
        // Number of bits left to pad
        let remainder = (8 * data.len()) % 512;
        let k = match remainder {
            0..=448 => 512 - 64 - remainder,    // runs from 0 to 448
            449..=512 => 1024 - remainder - 64, // runs from 448 -> 512
            _ => panic!("Unable to pad properly"),
        };
        //println!("k: {k}");

        let pad: Vec<u8> = vec![0; k / 8];

        data.extend_from_slice(&pad);

        //let blank_four = vec![0, 0, 0, 0];
        //data.extend_from_slice(&blank_four);
        let ml_v: Vec<u8> = (0..8)
            .map(|i| (((8 * ml) >> ((7 - i) * 8)) & 0xff) as u8)
            .collect();
        //let ml_v: Vec<u8> = u32_to_u8s(8 * ml as u32);
        data.extend_from_slice(&ml_v);
        //println!("dl: {}", data.len() * 8);

        assert_eq!((data.len() * 8) % 512, 0);

        /*
        println!("==Initial hash values==");
        println!("H[0] = {:x}", self.h0);
        println!("H[1] = {:x}", self.h1);
        println!("H[2] = {:x}", self.h2);
        println!("H[3] = {:x}", self.h3);
        println!("H[4] = {:x}", self.h4);
        */

        // Want each chunk to be 512 bits
        for chunk in data.chunks(64) {
            //println!("Chunk size: {} bits", chunk.len() * 8);
            // Each chunk is 16 32-bit big-endian words
            let mut w: Vec<u32> = chunk.chunks(4).map(u8s_to_u32).collect();
            /*
            println!("==Block contents==");
            for (i, v) in w.iter().enumerate() {
                println!("W[{i}] = {v:x}");
            }
            */

            // Extend w length from 16 -> 80 32 bit words
            let extender = vec![0; 80 - 16];
            w.extend_from_slice(&extender);

            for i in 16..80 {
                w[i] = Self::lr(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            let mut a = self.h0;
            let mut b = self.h1;
            let mut c = self.h2;
            let mut d = self.h3;
            let mut e = self.h4;

            for (t, _) in w.iter().enumerate().take(80) {
                let (f, k) = match t {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999_u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1_u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC_u32),
                    60..=79 => (b ^ c ^ d, 0xCA62C1D6_u32),
                    _ => panic!("Out of index"),
                };
                //let f = (b & c) | ((!b) & d);
                //let k = 0x5a827999_u32;

                //                let k = k as u64;
                let temp: u64 = [
                    Self::lr(a, 5) as u64,
                    f as u64,
                    e as u64,
                    w[t] as u64,
                    k as u64,
                ]
                .iter()
                .sum();
                let temp = (temp & 0xffffffff) as u32;
                //let temp = (temp % std::u32::MAX as u64) as u32;

                e = d;
                d = c;
                c = Self::lr(b, 30);
                b = a;
                a = temp;
                //println!("t= {t:02} {a:08x} {b:08x} {c:08x} {d:08x} {e:08x}");
            }
            self.h0 = (((self.h0 as u64) + (a as u64)) & 0xffffffff) as u32;
            self.h1 = (((self.h1 as u64) + (b as u64)) & 0xffffffff) as u32;
            self.h2 = (((self.h2 as u64) + (c as u64)) & 0xffffffff) as u32;
            self.h3 = (((self.h3 as u64) + (d as u64)) & 0xffffffff) as u32;
            self.h4 = (((self.h4 as u64) + (e as u64)) & 0xffffffff) as u32;
            /*
            println!("H[0] = {:x}", self.h0);
            println!("H[1] = {:x}", self.h1);
            println!("H[2] = {:x}", self.h2);
            println!("H[3] = {:x}", self.h3);
            println!("H[4] = {:x}", self.h4);
            */
        }

        let mut hh = vec![];
        let h0bits = u32_to_u8s(self.h0);
        let h1bits = u32_to_u8s(self.h1);
        let h2bits = u32_to_u8s(self.h2);
        let h3bits = u32_to_u8s(self.h3);
        let h4bits = u32_to_u8s(self.h4);

        hh.extend_from_slice(&h0bits);
        hh.extend_from_slice(&h1bits);
        hh.extend_from_slice(&h2bits);
        hh.extend_from_slice(&h3bits);
        hh.extend_from_slice(&h4bits);
        hh
    }

    fn lr(val: u32, amount: u32) -> u32 {
        //let lower_mask = (1 << (32 - amount)) - 1;
        //println!("Lower mask: {lower_mask:x}");
        //let upper_mask = !lower_mask;
        //println!("Upper mask: {upper_mask:x}");
        //((val & lower_mask) << amount) | ((val & upper_mask) >> (32 - amount))
        let val = val as u64;
        let lr = (val << amount) | (val >> (32 - amount));

        (lr & 0xffffffff) as u32
    }
}

fn u32_to_u8s(input: u32) -> Vec<u8> {
    (0..4)
        .map(|i| ((input >> ((3 - i) * 8)) & 0xff) as u8)
        .collect()
}

fn u8s_to_u32(input: &[u8]) -> u32 {
    input
        .iter()
        .enumerate()
        .map(|(i, v)| (*v as u32) << ((3 - i) * 8))
        .sum()
}

pub fn main() -> Result<()> {
    //let a = b"The quick brown fox jumps over the lazy dog";
    let a = b"";
    //let a = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    let mut hasher = Sha1Hasher::default();
    let h = hasher.hash(a);
    let hex = bytes_to_hex(&h);
    println!("hex: {hex}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lrotate_test() {
        assert_eq!(Sha1Hasher::lr(0x0000ffff, 8), 0x00ffff00);
        assert_eq!(Sha1Hasher::lr(0x00ffff00, 8), 0xffff0000);
        assert_eq!(Sha1Hasher::lr(0xabcd0000, 8), 0xcd0000ab);
    }

    #[test]
    fn sha1test() {
        let str_hash = vec![
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ];
        for (s, b) in str_hash.iter() {
            println!("input: {s}");
            println!("expected output: {b}");
            let mut hasher = Sha1Hasher::default();
            let h = hasher.hash(s.as_bytes());
            let output_text = bytes_to_hex(&h);
            println!("actual output: {}", output_text);
            let output_bytes = hex_to_bytes(b).unwrap();
            assert_eq!(h, output_bytes);
        }
    }
}
