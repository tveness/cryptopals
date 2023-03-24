//! Break a SHA-1 keyed MAC using length extension
//!
//! Secret-prefix SHA-1 MACs are trivially breakable.
//!
//! The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and
//! use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it
//! more data".
//!
//! Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash
//! in this fashion will appear to have been hashed with the secret key.
//!
//! To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the
//! bit-length of the message; your forged message will need to include that padding. We call this
//! "glue padding". The final message you actually forge will be:
//!
//! SHA1(key || original-message || glue-padding || new-message)
//! (where the final padding on the whole constructed message is implied)
//!
//! Note that to generate the glue padding, you'll need to know the original bit length of the
//! message; the message itself is known to the attacker, but the secret key isn't, so you'll need
//! to guess at it.
//!
//! This sounds more complicated than it is in practice.
//!
//! To implement the attack, first write the function that computes the MD padding of an arbitrary
//! message and verify that you're generating the same padding that your SHA-1 implementation is
//! using. This should take you 5-10 minutes.
//!
//! Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1
//! hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
//!
//! Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c
//! (they normally start at magic numbers). With the registers "fixated", hash the additional data
//! you want to forge.
//!
//! Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from
//! /usr/share/dict/words or something) of the string:
//!
//! "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
//! Forge a variant of this message that ends with ";admin=true".
//!
//! This is a very useful attack.
//! For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.

use rand::thread_rng;

use crate::utils::*;

pub fn main() -> Result<()> {
    // We have our SHA-1 implementation, and the helper function should already be there to resume
    // from a particular hash
    let mut rng = thread_rng();
    let key = random_key(16, &mut rng);
    let base_message =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    let mut message = key.clone();
    message.extend_from_slice(base_message);

    let mut hasher = Sha1Hasher::default();
    let mac = hasher.hash(&message, None);
    let auth = authenticate(&key, base_message, &mac);
    println!("Original message authentication: {:?}", auth);

    // Now to extend!
    let mut new_mac = mac.clone();
    let mut key_len = 0;
    let addition = b";admin=true;";
    let mut new_message: Vec<u8> = vec![];
    let bml = base_message.len() as u64;
    while authenticate(&key, &new_message, &new_mac) != Auth::Valid {
        key_len += 1;
        // What's the idea? We want to take the original mac and start the hasher from this state
        // 1. Set initial hashing values from what we had before
        // and run from this
        let mut cont_hasher = Sha1Hasher::load(&mac);
        // This should be the state of the hasher after working through
        // |key||message||    glue     ||
        // The new mac must account for extra padding
        // The message length must be that of the original padded message + addition
        let glue = sha1padding(key_len + bml);

        let total_new_l = glue.len() + key_len as usize + bml as usize + addition.len();

        new_mac = cont_hasher.hash(addition, Some(total_new_l));
        // We now add addition into this, which should be the hash of
        // |key||message||    glue     || addition || (implied glue)

        // This new_mac therefore corresponds to the mac of
        // | message || glue || addition
        // Which we should now construct as our new message
        new_message = base_message.to_vec();

        new_message.extend_from_slice(&glue);

        new_message.extend_from_slice(addition);
        //println!("New message:      {}", bytes_to_hex(&new_message));

        // This padded version should be a multiple of 64 + new_message
        //println!("New message len + key_len: {}", new_message.len() + key_len);
    }

    println!("Key length: {}", key_len);
    println!("Original message: {}", bytes_to_hex(base_message));
    println!("New message:      {}", bytes_to_hex(&new_message));
    println!("New mac: {}", bytes_to_hex(&new_mac));

    let auth = authenticate(&key, &new_message, &new_mac);
    println!("Authentication status: {:?}", auth);

    Ok(())
}

fn sha1padding(ml: u64) -> Vec<u8> {
    // Pre-process: fake ml bytes at the beginning
    let mut data: Vec<u8> = vec![0; ml as usize];
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
    // Now drop first ml bytes
    let trimmed = &data[ml as usize..];
    trimmed.to_vec()
}

#[cfg(test)]
mod tests {
    use openssl::sha::sha1;

    use super::*;

    #[test]
    fn padding_check() {
        // Same as "abc" case for the test hashing
        let ml = 3;
        // Message should be 3, padding should have length  512 - 3*8 bits
        // and be of the form 0x80, followed by 64 - 4 - 8 = 52 bytes of zeros, and then the
        // message length
        let padding = sha1padding(ml);
        let pl = padding.len();
        let target_pl = 64 - 3;
        assert_eq!(pl, target_pl);
        let mut padding_by_hand: Vec<u8> = vec![0x80];
        padding_by_hand.extend_from_slice(&[0; 59]);
        padding_by_hand.extend_from_slice(&[0x18; 1]);
        assert_eq!(padding, padding_by_hand);
    }

    #[test]
    fn extension_check() {
        let message = b"abc";
        let mut hasher = Sha1Hasher::default();
        let mac = hasher.hash(message, None);

        let extension = b"defg";
        let mut e_hasher = Sha1Hasher::load(&mac);
        // Need to modify this hasing function to do the padding correctly
        let original_padding_l = sha1padding(message.len() as u64).len();
        let e_mac = e_hasher.hash(
            extension,
            Some(extension.len() + original_padding_l + message.len()),
        );

        let mut manual_extension: Vec<u8> = message.to_vec();
        manual_extension.extend_from_slice(&sha1padding(message.len() as u64));
        manual_extension.extend_from_slice(extension);

        let mut m_hasher = Sha1Hasher::default();
        let me_mac = m_hasher.hash(&manual_extension, None);

        println!("emac: {}", bytes_to_hex(&e_mac));
        println!("mmac: {}", bytes_to_hex(&me_mac));

        assert_eq!(e_mac, me_mac);
    }
}
