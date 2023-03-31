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

use rand::thread_rng;

use crate::utils::*;

pub struct Sha1Hasher {
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
        if let &[h0, h1, h2, h3, h4] = &hash.chunks(4).map(u8s_to_u32).collect::<Vec<u32>>()[..] {
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
    pub fn hash(&mut self, data: &[u8], data_length: Option<usize>) -> Vec<u8> {
        // Pre-process
        let mut data: Vec<u8> = data.to_vec();
        let ml = match data_length {
            None => data.len() as u64,
            Some(x) => x as u64,
        };
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
        //println!("Padded:           {}", bytes_to_hex(&data));

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
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
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

                let temp: u32 = [a.rotate_left(5), f, e, w[t], k]
                    .iter()
                    .fold(0, |acc, x| acc.wrapping_add(*x));

                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
                //println!("t= {t:02} {a:08x} {b:08x} {c:08x} {d:08x} {e:08x}");
            }
            self.h0 = self.h0.wrapping_add(a);
            self.h1 = self.h1.wrapping_add(b);
            self.h2 = self.h2.wrapping_add(c);
            self.h3 = self.h3.wrapping_add(d);
            self.h4 = self.h4.wrapping_add(e);
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
}

pub fn u32_to_u8s(input: u32) -> Vec<u8> {
    (0..4)
        .map(|i| ((input >> ((3 - i) * 8)) & 0xff) as u8)
        .collect()
}

pub fn u8s_to_u32(input: &[u8]) -> u32 {
    input
        .iter()
        .enumerate()
        .map(|(i, v)| (*v as u32) << ((3 - i) * 8))
        .sum()
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut a = vec![];
    a.extend_from_slice(key);
    a.extend_from_slice(message);

    let mut hasher = Sha1Hasher::default();
    hasher.hash(&a, None)
}

#[derive(Debug, PartialEq)]
pub enum Auth {
    Valid,
    Invalid,
}

pub fn authenticate(key: &[u8], message: &[u8], m: &[u8]) -> Auth {
    match m == &mac(key, message)[..] {
        true => Auth::Valid,
        false => Auth::Invalid,
    }
}

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    let key = random_key(16, &mut rng);
    let message = b"super secret test message";

    let m = mac(&key, message);

    println!("Generate message and MAC");
    println!("Authenticate MAC: {:?}", authenticate(&key, message, &m));

    println!("Modify message");
    let message_mod = b"supeR secret test message";
    println!(
        "Authenticate MAC: {:?}",
        authenticate(&key, message_mod, &m)
    );

    println!("Modify MAC");
    let mut m_mod = m;
    m_mod[5] = 2;
    println!(
        "Authenticate MAC: {:?}",
        authenticate(&key, message, &m_mod)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let h = hasher.hash(s.as_bytes(), None);
            let output_text = bytes_to_hex(&h);
            println!("actual output: {}", output_text);
            let output_bytes = hex_to_bytes(b).unwrap();
            assert_eq!(h, output_bytes);
        }
    }

    #[test]
    fn check_loader() {
        let mut hasher = Sha1Hasher::default();
        let h = hasher.hash(b"abc", None);

        let default_hashes = [
            0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32,
            0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0,
        ];
        let mut loaded_hasher = Sha1Hasher::load(&default_hashes);
        let hl = loaded_hasher.hash(b"abc", None);
        assert_eq!(h, hl);
    }
}
