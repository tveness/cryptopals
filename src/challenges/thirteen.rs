//! ECB cut-and-paste
//!
//! Write a k=v parsing routine, as if for a structured cookie. The routine should take:
//!
//! ```text
//! foo=bar&baz=qux&zap=zazzle
//! ```
//! ... and produce:
//!
//! ```text
//! {
//!   foo: 'bar',
//!   baz: 'qux',
//!   zap: 'zazzle'
//! }
//! ```
//! (you know, the object; I don't care if you convert it to JSON).
//!
//! Now write a function that encodes a user profile in that format, given an email address. You should have something like:
//!
//! ```text
//! profile_for("foo@bar.com")
//! ```
//! ... and it should produce:
//!
//! ```text
//! {
//!   email: 'foo@bar.com',
//!   uid: 10,
//!   role: 'user'
//! }
//! ```
//! ... encoded as:
//!
//! ```text
//! email=foo@bar.com&uid=10&role=user
//! ```
//! Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote
//! them, whatever you want to do, but don't let people set their email address to
//! "foo@bar.com&role=admin".
//!
//! Now, two more easy functions. Generate a random AES key, then:
//!
//! 1. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
//! 2. Decrypt the encoded user profile and parse it.
//!
//! Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and
//! the ciphertexts themselves, make a role=admin profile.

use crate::utils::*;
use anyhow::{anyhow, Result};
use thiserror::Error;

#[derive(Debug, PartialEq)]
struct Credentials {
    email: String,
    uid: u64,
    role: String,
}

fn poor_deserialize(input: &str) -> Result<Credentials> {
    println!("INPUT: {input}");
    let kvs = input.split('&').collect::<Vec<&str>>();
    if let [ekv, ukv, rkv, ..] = kvs[..] {
        println!("{ekv}");
        println!("{ukv}");
        println!("{rkv}");

        if let ([_, email], [_, uid], [_, role]) = (
            &ekv.split('=').collect::<Vec<&str>>()[..],
            &ukv.split('=').collect::<Vec<&str>>()[..],
            &rkv.split('=').collect::<Vec<&str>>()[..],
        ) {
            return Ok(Credentials {
                email: email.to_string(),
                uid: uid.parse::<u64>()?,
                role: role.to_string(),
            });
        }
    }
    Err(anyhow!("Failed to parse profile: {}", input))
}

fn poor_serialize(cred: Credentials) -> String {
    format!("email={}&uid={}&role={}", cred.email, cred.uid, cred.role)
}

fn profile_for(who: &str) -> String {
    let who = who.escape_default().to_string();
    let c = Credentials {
        email: who.to_string(),
        uid: 10,
        role: "user".to_string(),
    };
    poor_serialize(c)
}

fn encrypting_oracle(who: &str, key: &[u8]) -> Vec<u8> {
    let profile = profile_for(who);
    let padded = pkcs7_pad(profile.as_bytes(), 16);

    ecb_encrypt(&padded, key, None).unwrap().to_vec()
}

fn decrypting_oracle(bytes: &[u8], key: &[u8]) -> Result<Credentials> {
    let decrypted = ecb_decrypt(bytes, key, None)?;
    let unpadded = pkcs7_unpad(&decrypted)?;

    let s = std::str::from_utf8(&unpadded)?;
    poor_deserialize(s)
}

#[derive(Debug, Error)]
pub enum PaddingError {
    #[error("Padding error")]
    InvalidPadding,
}

pub fn pkcs7_unpad(bytes: &[u8]) -> Result<Vec<u8>, PaddingError> {
    let l = bytes.len();
    let padding_val = bytes[l - 1];
    let padding = &bytes[l - padding_val as usize..l];
    let padding_target = vec![padding_val; padding_val as usize];
    match padding == &padding_target {
        true => Ok(bytes[..l - padding_val as usize].to_vec()),
        false => Err(PaddingError::InvalidPadding),
    }
}

pub fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = random_key(16, &mut rng);
    let user_profile = Credentials {
        email: "foo@bar.com".to_string(),
        uid: 10,
        role: "user".to_string(),
    };

    // What are the rules of the game?
    // We can ask for the profile for anyone, and get an encrypted version spit back
    // We can feed in an encrypted version and get a profile back

    let cred = decrypting_oracle(&encrypting_oracle("test_user", &key), &key)?;
    println!("{cred:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_dec() {
        let mut rng = rand::thread_rng();
        let key = random_key(16, &mut rng);
        let cred = decrypting_oracle(&encrypting_oracle("test_usertest_user", &key), &key).unwrap();

        let target = Credentials {
            email: "test_usertest_user".to_string(),
            uid: 10,
            role: "user".to_string(),
        };
        println!("Cred: {cred:?}");
        println!("Target: {target:?}");
        assert_eq!(cred, target);
    }

    #[test]
    fn test_unpad() {
        let bytes: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let padded = pkcs7_pad(&bytes, 16);
        let unpadded = pkcs7_unpad(&padded).unwrap();
        assert_eq!(bytes, unpadded);
    }
}
