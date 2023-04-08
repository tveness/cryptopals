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

struct Oracle {
    pub session_id: String,
    pub host: String,
}
impl Oracle {
    fn payload(&self, content: String) -> String {
        format!(
            "POST/ HTTP/1.1\nHost: {}\nCookie: sessionid={}\nContent-Length\n: {}\n{}",
            self.host,
            self.session_id,
            content.len(),
            content
        )
    }
    pub fn len(&self, content: String) -> usize {
        let embed = self.payload(content);
        // Compress message
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(&embed.as_bytes()).unwrap();
        let compressed = e.finish().unwrap();

        let mut rng = thread_rng();
        let key = random_key(16, &mut rng);
        let nonce: u64 = rng.gen();
        let stream = Ctr::new(&key, nonce);

        let encrypted: Vec<u8> = compressed.iter().zip(stream).map(|(x, y)| x ^ y).collect();
        // Refresh stream
        let stream = Ctr::new(&key, nonce);
        let decrypted: Vec<u8> = encrypted.iter().zip(stream).map(|(x, y)| x ^ y).collect();
        decrypted.len()
    }
}

pub fn main() -> Result<()> {
    // Initialise oracle
    let mut rng = thread_rng();
    let session_id = bytes_to_hex(&random_key(16, &mut rng));
    let host = String::from("cryptopals.com");
    let oracle = Oracle { session_id, host };

    let session_header = format!("POST/ HTTP/1.1\nHost: {}\nCookie: sessionid=", oracle.host);
    // Let's check what compression looks like using the correct string, rather than the wrong one
    println!("session id: {}", oracle.session_id);
    println!("session id l: {}", oracle.session_id.len());

    // What's the plan here? Take our guess for the session id, and paste it in a few times with
    // junk afterwards to stop the algorithm from compressing the repeated part
    // Only append text bytes
    // Do two bytes at a time
    // 255*255 =

    // Make a guess of our id, and run through each time picking the best version
    let mut guess_id: Vec<u8> = random_key(16, &mut rng);
    println!("OG guess: {}", bytes_to_hex(&guess_id));

    for _pass in 0..100 {
        let junk = random_key(16, &mut rng);
        let prefix_skip = rng.gen::<usize>() % 5;
        for byte_num in 0..guess_id.len() {
            let minl = (0x00..0xff)
                .map(|b| {
                    let mut new_guess = guess_id.clone();
                    new_guess[byte_num] = b;
                    let mut new_guess_hex = bytes_to_hex(&new_guess[..byte_num + 1]);
                    new_guess_hex.push_str(&bytes_to_hex(&junk[byte_num + 1..]));

                    //println!("tru guess: {}", &oracle.session_id);
                    //println!("new guess: {}", new_guess_hex);
                    let mut current_guess = vec![];
                    for s in 0..prefix_skip + 1 {
                        current_guess.extend_from_slice(&session_header.as_bytes()[s..]);
                        current_guess.extend_from_slice(&new_guess_hex.as_bytes());
                        /*
                        println!("New guess hex: {}", new_guess_hex);
                        println!(
                            "Cur guess hex: {}",
                            std::str::from_utf8(&current_guess).unwrap()
                        );
                        */
                    }
                    if let Ok(s) = std::str::from_utf8(&current_guess) {
                        //println!("Current guess: {}", &s[..64]);
                        (b, oracle.len(s.into()))
                    } else {
                        (b, 1e6 as usize)
                    }
                })
                .min_by(|x, y| x.1.cmp(&y.1));
            /*
            println!(
                "min l = {}, true: {}",
                minl.unwrap().0,
                oracle.session_id.as_bytes()[byte_num]
            );
            */
            guess_id[byte_num] = minl.unwrap().0;
        }
        println!("Key:   {}", oracle.session_id);
        println!("Guess: {}", bytes_to_hex(&guess_id));
    }

    //        .collect::<Vec<(u8, usize)>>();

    Ok(())
}
