//! Compression Ratio Side-Channel Attacks
//!
//! Internet traffic is often compressed to save bandwidth. Until recently, this included HTTPS
//! headers, and it still includes the contents of responses.
//!
//! Why does that matter?
//!
//! Well, if you're an attacker with:
//!
//! Partial plaintext knowledge and
//! Partial plaintext control and
//! Access to a compression oracle
//! You've got a pretty good chance to recover any additional unknown plaintext.
//!
//! What's a compression oracle? You give it some input and it tells you how well the full message
//! compresses, i.e. the length of the resultant output.
//!
//! This is somewhat similar to the timing attacks we did way back in set 4 in that we're taking
//! advantage of incidental side channels rather than attacking the cryptographic mechanisms
//! themselves.
//!
//! Scenario: you are running a MITM attack with an eye towards stealing secure session cookies.
//! You've injected malicious content allowing you to spawn arbitrary requests and observe them in
//! flight. (The particulars aren't terribly important, just roll with it.)
//!
//! So! Write this oracle:
//!
//! oracle(P) -> length(encrypt(compress(format_request(P))))
//! Format the request like this:
//!
//! POST / HTTP/1.1
//! Host: hapless.com
//! Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
//! Content-Length: ((len(P)))
//! ((P))
//! (Pretend you can't see that session id. You're the attacker.)
//!
//! Compress using zlib or whatever.
//!
//! Encryption... is actually kind of irrelevant for our purposes, but be a sport. Just use some
//! stream cipher. Dealer's choice. Random key/IV on every call to the oracle.
//!
//! And then just return the length in bytes.
//!
//! Now, the idea here is to leak information using the compression library. A payload of
//! "sessionid=T" should compress just a little bit better than, say, "sessionid=S".
//!
//! There is one complicating factor. The DEFLATE algorithm operates in terms of individual bits, but the final message length will be in bytes. Even if you do find a better compression, the difference may not cross a byte boundary. So that's a problem.
//!
//! You may also get some incidental false positives.
//!
//! But don't worry! I have full confidence in you.
//!
//! Use the compression oracle to recover the session id.
//!
//! I'll wait.
//!
//! Got it? Great.
//!
//! Now swap out your stream cipher for CBC and do it again.

//! oracle(P) -> length(encrypt(compress(format_request(P))))
//! Format the request like this:

use crate::{stream::Ctr, utils::*};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use rand::{thread_rng, Rng};
use std::io::prelude::*;

enum Enc {
    Stream,
    Cbc,
}
struct Oracle {
    pub session_id: String,
    pub host: String,
    pub keysize: usize,
}
impl Oracle {
    fn payload(&self, content: String) -> String {
        format!(
            "POST/ HTTP/1.1\nHost: {}\nCookie: sessionid={}\nContent-Length: {}\n{}",
            self.host,
            self.session_id,
            content.len(),
            content
        )
    }
    pub fn len(&self, content: String, enc: &Enc) -> usize {
        let embed = self.payload(content);
        //println!("Embedded: {}", embed);
        // Compress message
        let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
        e.write_all(embed.as_bytes()).unwrap();
        let compressed = e.finish().unwrap();

        let mut rng = thread_rng();
        let key = random_key(16, &mut rng);

        // Determine compr
        // The difference between the two is one of padding, but it doesn't really make a different
        // because we reverse it in either case
        match enc {
            Enc::Stream => {
                let nonce: u64 = rng.gen();
                let stream = Ctr::new(&key, nonce);
                let encrypted: Vec<u8> =
                    compressed.iter().zip(stream).map(|(x, y)| x ^ y).collect();
                // Refresh stream
                let stream = Ctr::new(&key, nonce);
                let decrypted: Vec<u8> = encrypted.iter().zip(stream).map(|(x, y)| x ^ y).collect();
                decrypted.len()
            }
            Enc::Cbc => {
                let iv = random_key(16, &mut rng);
                let encrypted: Vec<u8> =
                    cbc_encrypt(&pkcs7_pad(&compressed, 16), &key, Some(&iv)).unwrap();
                // Refresh stream
                let decrypted: Vec<u8> =
                    pkcs7_unpad(&cbc_decrypt(&encrypted, &key, Some(&iv)).unwrap()).unwrap();
                decrypted.len()
            }
        }
    }
}

fn make_guess(oracle: &Oracle, enc: Enc) -> (String, usize) {
    let mut rng = thread_rng();
    let session_header = format!("POST/ HTTP/1.1\nHost: {}\nCookie: sessionid=", oracle.host);
    //let session_header = format!("sessionid=");
    // Let's check what compression looks like using the correct string, rather than the wrong one
    //println!("session id: {}", oracle.session_id);
    //println!("session id l: {}", oracle.session_id.len());

    // Make a guess of our id, and run through each time picking the best version
    let mut guess_id: String = bytes_to_hex(&random_key(oracle.keysize, &mut rng));
    //println!("OG guess: {}", guess_id);
    let chars = vec![
        'a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];

    // Have some junk which we can use to disambiguate different equally-good compression
    let mut junk = bytes_to_hex(&random_key(4, &mut rng));
    for _pass in 0..3 {
        for char_num in 0..guess_id.len() {
            #[allow(unused_assignments)]
            let mut minimum = (&'a', 1e6 as usize);
            loop {
                let minl = chars
                    .iter()
                    .map(|c| {
                        // Take current guess so far and add the new guess character
                        let mut new_guess: String = guess_id.chars().take(char_num).collect();
                        new_guess.push(*c);

                        let mut current_guess = String::new();
                        for _ in 0..2 {
                            current_guess.push_str(&session_header);
                            current_guess.push_str(&new_guess);
                            current_guess.push_str(&junk);
                        }
                        //println!("Current guess: {}", &s[..64]);
                        (c, oracle.len(current_guess, &enc))
                    })
                    .collect::<Vec<_>>();
                //println!("MIN: {:?}", minl);
                minimum = *minl.iter().min_by(|x, y| x.1.cmp(&y.1)).unwrap();
                if minl.iter().filter(|x| x.1 == minimum.1).count() == 1 {
                    break;
                }
                // If there's no best compression, re-randomise the junk and try again
                junk = bytes_to_hex(&random_key(4, &mut rng));
            }

            guess_id = guess_id
                .chars()
                .enumerate()
                .map(|(i, ch)| match i == char_num {
                    true => *minimum.0,
                    false => ch,
                })
                .collect();
        }
        //println!("Key:   {}", oracle.session_id);
        //println!("Guess: {}", guess_id);
    }

    let mut guess = String::new();
    guess.push_str(&session_header);
    guess.push_str(&guess_id);

    (guess_id, oracle.len(guess, &enc))
}

pub fn main() -> Result<()> {
    let keysize = 16;
    // Initialise oracle
    let mut rng = thread_rng();
    let session_id = bytes_to_hex(&random_key(keysize, &mut rng));
    //let session_id = String::from("e2df42256d4cc3bec3a9cdce1c55c5e3");

    let host = String::from("cryptopals.com");
    let oracle = Oracle {
        session_id,
        host,
        keysize,
    };

    // The correct answer should have a particular length, and our solution doesn't always get the
    // correct answer, so we ensure that it is a good one
    // The compression achieved eliminates the extra string + about 3 bytes for keysize=16, and this appears to be
    // a good enough heuristic to succeed
    let target_length = oracle.len(String::new(), &Enc::Stream) + 3;

    // Run until we find good compression
    loop {
        let (best_guess, l) = make_guess(&oracle, Enc::Stream);
        if l <= target_length {
            println!("Key:   {}", oracle.session_id);
            println!("Guess: {}", best_guess);
            assert_eq!(oracle.session_id, best_guess);
            break;
        }
    }
    // Do it again, but for CBC
    let target_length = oracle.len(String::new(), &Enc::Cbc) + 48 / keysize;

    // Run until we find good compression
    loop {
        let (best_guess, l) = make_guess(&oracle, Enc::Cbc);
        if l <= target_length {
            println!("Key:   {}", oracle.session_id);
            println!("Guess: {}", best_guess);
            assert_eq!(oracle.session_id, best_guess);
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore = "slow"]
    #[test]
    fn crack() {
        main().unwrap();
    }
}
