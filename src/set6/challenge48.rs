//! Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
//!
//! Cryptanalytic MVP award
//! This is an extraordinarily useful attack. PKCS#1v15 padding, despite being totally insecure, is
//! the default padding used by RSA implementations. The OAEP standard that replaces it is not
//! widely implemented. This attack routinely breaks SSL/TLS.
//! This is a continuation of challenge #47; it implements the complete BB'98 attack.
//!
//! Set yourself up the way you did in #47, but this time generate a 768 bit modulus.
//!
//! To make the attack work with a realistic RSA keypair, you need to reproduce step 2b from the
//! paper, and your implementation of Step 3 needs to handle multiple ranges.
//!
//! The full Bleichenbacher attack works basically like this:
//!
//! Starting from the smallest 's' that could possibly produce a plaintext bigger than 2B,
//! iteratively search for an 's' that produces a conformant plaintext.
//! For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition of modular
//! multiplication) for 'r', the number of times we've wrapped the modulus.
//! 'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5 plaintexts, and so are between [2B,3B].
//! We substitute the known bounds for both, leaving only 'r' free, and solve for a range of
//! possible 'r' values. This range should be small!
//! Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of 'r' we generated in
//! the last step. This gives us new intervals to work with. Rule out any interval that is outside
//! 2B,3B.
//! Repeat the process for successively higher values of 's'. Eventually, this process will get us
//! down to just one interval, whereupon we're back to exercise #47.
//! What happens when we get down to one interval is, we stop blindly incrementing 's'; instead, we
//! start rapidly growing 'r' and backing it out to 's' values by solving m1=m0s1-rn for 's'
//! instead of 'r' or 'm0'. So much algebra! Make your teenage son do it for you! *Note: does not
//! work well in practice*

use num_bigint::{BigInt, Sign};
use rand::{thread_rng, Rng};

use super::challenge46::Key;
use super::challenge47::Attacker;
use crate::set6::challenge47::is_pkcs;
use crate::utils::*;

pub fn main() -> Result<()> {
    // Set up problem
    let bits = 384;
    let e: BigInt = 3.into();
    let (et, n) = et_n(bits, &e);
    let d = invmod(&e, &et);

    let public_key = Key {
        key: e,
        modulus: n.clone(),
    };
    let private_key = Key { key: d, modulus: n };
    let mut rng = thread_rng();

    // Make the message a bit more interesting this time
    // Pick 40 bytes from War and Peace
    let wap_full = std::fs::read_to_string("./data/wap.txt").unwrap();
    let idx: usize = rng.gen_range(0..wap_full.chars().count() - 40);

    let message = wap_full.chars().skip(idx).take(40).collect::<String>();
    let message = message.as_bytes();
    let mut pkcs_message: Vec<u8> = vec![0x00, 0x02];
    let bytes = &private_key.modulus.bits() / 8;
    pkcs_message.extend_from_slice(&vec![0xff; bytes as usize - 3 - message.len()]);
    pkcs_message.push(0x00);
    pkcs_message.extend_from_slice(message);

    println!("PKCS message length: {}", pkcs_message.len());
    println!("bytes: {}", bytes);
    // PKCS pad this

    let m = BigInt::from_bytes_be(Sign::Plus, &pkcs_message);
    println!("m true: {m}");
    let c = m.modpow(&public_key.key, &public_key.modulus);

    // Check is is pkcs padded
    println!("Is pkcs padded? {}", is_pkcs(&c, &private_key));

    let mut attacker = Attacker::new(&c, &public_key, &private_key);

    let md = attacker.run();

    println!("m true: {m}");
    println!("m     : {md}");
    let decrypted_padded = md.to_bytes_be().1;
    // Now strip off padding
    let index = decrypted_padded.iter().position(|&x| x == 0x00).unwrap();
    let decrypted = &decrypted_padded[index + 1..];
    let decrypted_message = std::str::from_utf8(decrypted).unwrap();
    println!("Message: {}", decrypted_message);
    assert_eq!(decrypted, message);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[ignore = "slow"]
    #[test]
    fn bleichenbacher_big() {
        main().unwrap();
    }
}
