//! Implement CTR, the stream cipher mode
//!
//! The string:
//!
//! ```raw
//! L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
//! ```
//! ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode
//! that turns AES into a stream cipher, with the following parameters:
//!
//! ```raw
//!       key=YELLOW SUBMARINE
//!       nonce=0
//!       format=64 bit unsigned little endian nonce,
//!              64 bit little endian block count (byte count / 16)
//! ```
//!
//! CTR mode is very simple.
//!
//! Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte
//! block of keystream, which is XOR'd against the plaintext.
//!
//! For instance, for the first 16 bytes of a message with these parameters:
//!
//! ```raw
//! keystream = AES("YELLOW SUBMARINE",
//!                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
//! ```
//!
//! ... for the next 16 bytes:
//!
//! ```raw
//! keystream = AES("YELLOW SUBMARINE",
//!                 "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
//! ```
//!
//! ... and then:
//!
//! ```raw
//! keystream = AES("YELLOW SUBMARINE",
//!                 "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
//! ```
//!
//! CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing
//! keystream and stop generating keystream.
//!
//! Decryption is identical to encryption. Generate the same keystream, XOR, and recover the
//! plaintext.
//!
//! Decrypt the string at the top of this function, then use your CTR function to encrypt and
//! decrypt other things.
//!
//! This is the only block cipher mode that matters in good code.
//! Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because
//! most of what we want to encrypt is better described as a stream than as a sequence of blocks.
//! Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt"
//! transforms. Constructions like CTR are what he was talking about.

use std::iter::zip;

use crate::stream::Ctr;
use crate::utils::*;

pub fn main() -> Result<()> {
    let key = b"YELLOW SUBMARINE";
    let ctr_stream = Ctr::new(key, 0);

    let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let input_bytes = decode_b64_str(input)?;

    let decoded = zip(input_bytes.iter(), ctr_stream)
        .map(|(v, e)| *v ^ e)
        .collect::<Vec<u8>>();

    let decoded_str = std::str::from_utf8(&decoded).unwrap();
    println!("Decoded: {decoded_str}");

    let target = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
    assert_eq!(target, decoded_str);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_decoding() {
        main().unwrap();
    }
}
