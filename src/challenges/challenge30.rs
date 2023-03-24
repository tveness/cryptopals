//! Break an MD4 keyed MAC using length extension
//!
//! Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against
//! SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for
//! an implementation of MD4.
//!
//! You're thinking, why did we bother with this?
//! Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m)
//!     MAC with SHA1. Which meant that SHA1 code was floating all over the Internet. MD4 code, not so
//!     much.

use crate::utils::*;

/// MD4 implementation according to RFC1186
/// https://www.rfc-editor.org/rfc/rfc1186
struct Md4Hasher {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Md4Hasher {
    pub fn prepare(data: &[u8], bogus_ml: usize) -> Vec<u8> {
        let ml = data.len();
        let mut data = data.to_vec();
        // Want to pad so there are 64 bits left over
        // Modulo is how much room there is
        let modulo = 64 - ml % 64;
        let pl = modulo
            + match modulo {
                // If very short, we need to add a whole extra block
                0..=8 => 64,
                9..=64 => 0,
                _ => panic!("Modulo is invalid"),
            }
            - 8;

        let remainder = (ml + pl) % 64;
        // Exactly 64 bits on the end
        assert_eq!(remainder, 64 - 8);

        // Add 1 bit
        data.extend_from_slice(&vec![0x80]);
        // Add rest of padding
        data.extend_from_slice(&vec![0; pl - 1]);

        // Append length
        let le: Vec<u8> = u32_to_u8s(8 * bogus_ml as u32)
            .iter()
            .map(|x| *x)
            .rev()
            .collect();
        data.extend_from_slice(&le);
        data.extend_from_slice(&vec![0, 0, 0, 0]);

        assert_eq!(data.len() % 64, 0);
        data
    }
    pub fn bogus_hash(&mut self, data: &[u8], ml: usize) -> Vec<u8> {
        let data = Self::prepare(data, ml);

        self.process(&data)
    }

    pub fn hash(&mut self, data: &[u8]) -> Vec<u8> {
        let data = Self::prepare(data, data.len());

        self.process(&data)
    }
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let m: Vec<u32> = data
            .chunks(4)
            .map(|x| {
                let y: Vec<u8> = x.iter().map(|x| *x).rev().collect();
                u8s_to_u32(&y)
            })
            .collect();
        let n = m.len();

        for i in 0..(n / 16) {
            let mut a = self.a;
            let mut b = self.b;
            let mut c = self.c;
            let mut d = self.d;
            let x: Vec<u32> = m[i * 16..(i + 1) * 16].to_vec();
            // Round 1
            for &o in &[0, 4, 8, 12] {
                a = a.wrapping_add(Self::round1(b, c, d, x[o])).rotate_left(3);
                d = d
                    .wrapping_add(Self::round1(a, b, c, x[o + 1]))
                    .rotate_left(7);
                c = c
                    .wrapping_add(Self::round1(d, a, b, x[o + 2]))
                    .rotate_left(11);
                b = b
                    .wrapping_add(Self::round1(c, d, a, x[o + 3]))
                    .rotate_left(19);
            }

            // Round 2
            for o in 0..4 {
                a = a.wrapping_add(Self::round2(b, c, d, x[o])).rotate_left(3);
                d = d
                    .wrapping_add(Self::round2(a, b, c, x[o + 4]))
                    .rotate_left(5);
                c = c
                    .wrapping_add(Self::round2(d, a, b, x[o + 8]))
                    .rotate_left(9);
                b = b
                    .wrapping_add(Self::round2(c, d, a, x[o + 12]))
                    .rotate_left(13);
            }

            // Round 3
            for &o in &[0, 2, 1, 3] {
                a = a.wrapping_add(Self::round3(b, c, d, x[o])).rotate_left(3);
                d = d
                    .wrapping_add(Self::round3(a, b, c, x[o + 8]))
                    .rotate_left(9);
                c = c
                    .wrapping_add(Self::round3(d, a, b, x[o + 4]))
                    .rotate_left(11);
                b = b
                    .wrapping_add(Self::round3(c, d, a, x[o + 12]))
                    .rotate_left(15);
            }

            //
            self.a = self.a.wrapping_add(a);
            self.b = self.b.wrapping_add(b);
            self.c = self.c.wrapping_add(c);
            self.d = self.d.wrapping_add(d);
        }
        let ab: Vec<u8> = u32_to_u8s(self.a).iter().map(|x| *x).rev().collect();
        let bb: Vec<u8> = u32_to_u8s(self.b).iter().map(|x| *x).rev().collect();
        let cb: Vec<u8> = u32_to_u8s(self.c).iter().map(|x| *x).rev().collect();
        let db: Vec<u8> = u32_to_u8s(self.d).iter().map(|x| *x).rev().collect();

        let mut result = vec![];
        result.extend_from_slice(&ab);
        result.extend_from_slice(&bb);
        result.extend_from_slice(&cb);
        result.extend_from_slice(&db);
        result
        // First append data to be 448 module 512
    }

    fn round1(x: u32, y: u32, z: u32, xx: u32) -> u32 {
        Self::f(x, y, z).wrapping_add(xx)
    }
    fn round2(x: u32, y: u32, z: u32, xx: u32) -> u32 {
        Self::g(x, y, z).wrapping_add(xx).wrapping_add(0x5a827999)
    }
    fn round3(x: u32, y: u32, z: u32, xx: u32) -> u32 {
        Self::h(x, y, z).wrapping_add(xx).wrapping_add(0x6ed9eba1)
    }

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((!x) & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    pub fn new() -> Self {
        Self {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
        }
    }

    pub fn load(digest: &[u8]) -> Self {
        let c: Vec<u32> = digest.chunks(4).map(u8s_to_u32_le).collect();
        if let &[a, b, c, d] = &c[..] {
            Self { a, b, c, d }
        } else {
            panic!("Invalid digest");
        }
    }
}

fn u8s_to_u32_le(b: &[u8]) -> u32 {
    b.iter()
        .enumerate()
        .map(|(i, v)| (*v as u32) << (i * 8))
        .sum()
}

pub fn main() -> Result<()> {
    let mut h = Md4Hasher::new();
    let dat = b"";

    let digest = h.hash(dat);
    println!("Digest:     {}", bytes_to_hex(&digest));
    println!("MD4 ('a') = bde52cb31de33e46245e05fbdbd6fb24 ");

    Ok(())
}

fn hash(b: &[u8]) -> Vec<u8> {
    let mut h = Md4Hasher::new();
    h.hash(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_laod() {
        // From RFC
        let h = hex_to_bytes("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        let b = b"";
        let loader = hex_to_bytes("0123456789abcdeffedcba9876543210").unwrap();
        let mut hasher = Md4Hasher::load(&loader);
        assert_eq!(h, hasher.hash(b));
    }

    #[test]
    fn extension_check() {
        let message = b"abc";
        let mut hasher = Md4Hasher::new();
        let mac = hasher.hash(message);

        let extension = b"defg";
        let mut e_hasher = Md4Hasher::load(&mac);
        // Need to modify this hasing function to do the padding correctly
        let original_padding_l = Md4Hasher::prepare(message, message.len()).len();
        let e_mac = e_hasher.bogus_hash(extension, original_padding_l + extension.len());

        let mut manual_extension: Vec<u8> = Md4Hasher::prepare(message, message.len());
        manual_extension.extend_from_slice(extension);

        let mut m_hasher = Md4Hasher::new();
        let me_mac = m_hasher.hash(&manual_extension);

        println!("emac: {}", bytes_to_hex(&e_mac));
        println!("mmac: {}", bytes_to_hex(&me_mac));

        assert_eq!(e_mac, me_mac);
    }

    #[test]
    fn test_hashes() {
        // From RFC
        let h = hex_to_bytes("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        let b = b"";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("bde52cb31de33e46245e05fbdbd6fb24").unwrap();
        let b = b"a";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("a448017aaf21d8525fc10ae87aa6729d").unwrap();
        let b = b"abc";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("d9130a8164549fe818874806e1c7014b").unwrap();
        let b = b"message digest";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("d79e1c308aa5bbcdeea8ed63df412da9").unwrap();
        let b = b"abcdefghijklmnopqrstuvwxyz";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("043f8582f241db351ce627e153e7f0e4").unwrap();
        let b = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(h, hash(b));

        let h = hex_to_bytes("e33b4ddc9c38f2199c3e7b164fcc0536").unwrap();
        let b = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        assert_eq!(h, hash(b));
    }
}
