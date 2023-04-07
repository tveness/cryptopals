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
    // Pick 30 bytes from War and Peace
    let wap_full = std::fs::read_to_string("./data/wap.txt").unwrap();
    let idx: usize = rng.gen_range(0..wap_full.len() - 40);

    let message = wap_full[idx..idx + 40].as_bytes();
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
    let decrypted_message = std::str::from_utf8(&decrypted).unwrap();
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
