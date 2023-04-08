//! Hashing with CBC-MAC
//!
//! Sometimes people try to use CBC-MAC as a hash function.
//!
//! This is a bad idea. Matt Green explains:
//!
//! To make a long story short: cryptographic hash functions are public functions (i.e., no secret
//! key) that have the property of collision-resistance (it's hard to find two messages with the
//! same hash). MACs are keyed functions that (typically) provide message unforgeability -- a very
//! different property. Moreover, they guarantee this only when the key is secret.
//! Let's try a simple exercise.
//!
//! Hash functions are often used for code verification. This snippet of JavaScript (with newline):
//!
//! alert('MZA who was that?');
//! Hashes to 296b8d7cb78a243dda4d0a61d33bbdd1 under CBC-MAC with a key of "YELLOW SUBMARINE" and a
//! 0 IV.
//!
//! Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same
//! value. Ensure that it runs in a browser.
//!
//! Extra Credit
//! Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM
//! iff it matches the expected hash.

use crate::utils::*;

use super::challenge49::cbc_mac;

pub fn main() -> Result<()> {
    let original = b"alert('MZA who was that?');\n";
    let key = b"YELLOW SUBMARINE";
    let padded_original = pkcs7_pad(original, 16);
    let mac = cbc_mac(&padded_original, key, None)?;
    let mac_string = bytes_to_hex(&mac);
    assert_eq!(mac_string, String::from("296b8d7cb78a243dda4d0a61d33bbdd1"));
    println!("MAC: {}", bytes_to_hex(&mac));

    // How can we forged this message? Well, we know the block that went into producing the MAC was
    // IV ^ original
    // And so we can produce the same MAC as long as IV' ^ original' remains the same
    // IV' = CBC(previous block)
    // =>
    // original' = original ^ CBC(previous block)
    let mut target = b"alert('Ayo, the Wu is back!');//asd".to_vec();
    target = pkcs7_pad(&target, 16);
    println!("Target len: {}", target.len());
    let cbc_prev = cbc_mac(&target, key, None)?;
    println!("cbc_prev len: {}", cbc_prev.len());
    let append: Vec<u8> = cbc_prev
        .iter()
        .zip(padded_original.iter())
        .map(|(x, y)| x ^ y)
        .collect();
    // We should be able to produce the new mac directly from this, too
    target.extend_from_slice(&append);
    // The original message was more than a block, and we only modified the first block, so paste
    // this back on the end
    target.extend_from_slice(&padded_original[16..]);
    println!("Target: {:?}", target);
    let new_mac = cbc_mac(&target, key, None)?;
    let new_mac_string = bytes_to_hex(&new_mac);

    println!("New mac: {}", new_mac_string);
    assert_eq!(new_mac_string, mac_string);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_hashing() {
        main().unwrap();
    }
}
