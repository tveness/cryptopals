//! CBC-MAC Message Forgery
//!
//! Let's talk about CBC-MAC.
//!
//! CBC-MAC is like this:
//!
//! Take the plaintext P.
//! Encrypt P under CBC with key K, yielding ciphertext C.
//! Chuck all of C but the last block C[n].
//! C[n] is the MAC.
//! Suppose there's an online banking application, and it carries out user requests by talking to
//! an API server over the network. Each request looks like this:
//!
//! message || IV || MAC
//! The message looks like this:
//!
//! from=#{from_id}&to=#{to_id}&amount=#{amount}
//! Now, write an API server and a web frontend for it. (NOTE: No need to get ambitious and write
//! actual servers and web apps. Totally fine to go lo-fi on this one.) The client and server
//! should share a secret key K to sign and verify messages.
//!
//! The API server should accept messages, verify signatures, and carry out each transaction if the
//! MAC is valid. It's also publicly exposed - the attacker can submit messages freely assuming he
//! can forge the right MAC.
//!
//! The web client should allow the attacker to generate valid messages for accounts he controls.
//! (Feel free to sanitize params if you're feeling anal-retentive.) Assume the attacker is in a
//! position to capture and inspect messages from the client to the API server.
//!
//! One thing we haven't discussed is the IV. Assume the client generates a per-message IV and
//! sends it along with the MAC. That's how CBC works, right?
//!
//! Wrong.
//!
//! For messages signed under CBC-MAC, an attacker-controlled IV is a liability. Why? Because it
//! yields full control over the first block of the message.
//!
//! Use this fact to generate a message transferring 1M spacebucks from a target victim's account
//! into your account.
//!
//! I'll wait. Just let me know when you're done.
//!
//! ... waiting
//!
//! ... waiting
//!
//! ... waiting
//!
//! All done? Great - I knew you could do it!
//!
//! Now let's tune up that protocol a little bit.
//!
//! As we now know, you're supposed to use a fixed IV with CBC-MAC, so let's do that. We'll set
//! ours at 0 for simplicity. This means the IV comes out of the protocol:
//!
//! message || MAC
//! Pretty simple, but we'll also adjust the message. For the purposes of efficiency, the bank
//! wants to be able to process multiple transactions in a single request. So the message now looks
//! like this:
//!
//! from=#{from_id}&tx_list=#{transactions}
//! With the transaction list formatted like:
//!
//! to:amount(;to:amount)*
//! There's still a weakness here: the MAC is vulnerable to length extension attacks. How?
//!
//! Well, the output of CBC-MAC is a valid IV for a new message.
//!
//! "But we don't control the IV anymore!"
//!
//! With sufficient mastery of CBC, we can fake it.
//!
//! Your mission: capture a valid message from your target user. Use length extension to add a
//! transaction paying the attacker's account 1M spacebucks.
//!
//! Hint!
//! This would be a lot easier if you had full control over the first block of your message, huh?
//! Maybe you can simulate that.
//!
//! Food for thought: How would you modify the protocol to prevent this?

fn cbc_mac_verify(message: &[u8], mac: &[u8], iv: Option<&[u8]>, key: &[u8]) -> Auth {
    let enc = match cbc_encrypt(message, key, iv) {
        Ok(x) => x,
        Err(_) => return Auth::Invalid,
    };
    let test_mac = &enc[enc.len() - 16..];

    match test_mac == mac {
        true => Auth::Valid,
        false => Auth::Invalid,
    }
}

use rand::thread_rng;

use crate::utils::*;

pub fn main() -> Result<()> {
    let mut rng = thread_rng();
    // Part 1
    let key = random_key(16, &mut rng);

    let original = b"from=#me&to=#you&amount=#1M";
    let enc = cbc_encrypt(original, &key, None)?;
    let original_mac = &enc[enc.len() - 16..];

    assert_eq!(
        cbc_mac_verify(original, original_mac, None, &key),
        Auth::Valid
    );
    println!("MAC: {}", bytes_to_hex(original_mac));
    println!(
        "Original message MAC: {:?}",
        cbc_mac_verify(original, original_mac, None, &key)
    );

    // Now to forge
    let target = b"from=#you&to=#me&amount=#1M";
    let new_iv: Vec<u8> = target
        .iter()
        .zip(original.iter().take(16))
        .map(|(x, y)| x ^ y)
        .collect();
    // MAC will remain the same, so we should be able to check now

    let forged_status = cbc_mac_verify(target, original_mac, Some(&new_iv), &key);
    println!("Forged message MAC: {:?}", forged_status);
    assert_eq!(forged_status, Auth::Valid);

    // Part 2
    // Honestly, this one seems a little implausible
    // How do we create the extension? We the IV to chain more onto the end, but at the end of the
    // day we would need the key in order to encrypt a particular ciphertext.
    // I suppose if we consider that the IV is somehow the hidden quantity and the key is public
    // knowledge then this makes sense

    let original = b"from=#you&tx_list=somebody:10000";
    let enc = cbc_encrypt(original, &key, None)?;
    let original_mac = &enc[enc.len() - 16..];
    println!("MAC: {}", bytes_to_hex(original_mac));
    println!(
        "Original message MAC: {:?}",
        cbc_mac_verify(original, original_mac, None, &key)
    );
    let extension = b";me:1M\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";
    let mut target = original.to_vec();
    target.extend_from_slice(extension);

    let new_mac = cbc_encrypt(extension, &key, Some(original_mac))?;
    let forged_status = cbc_mac_verify(&target, &new_mac, None, &key);
    println!("MAC: {}", bytes_to_hex(&new_mac));
    println!("New MAC status: {:?}", forged_status);
    assert_eq!(forged_status, Auth::Valid);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run() {
        main().unwrap();
    }
}
