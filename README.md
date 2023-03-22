Cryptopals solutions
====

![Completed](https://img.shields.io/github/v/tag/tveness/cryptopals?label=completed%20to%20challenge&style=for-the-badge)
![Tests](https://img.shields.io/github/actions/workflow/status/tveness/cryptopals/rust.yml?label=Tests&style=for-the-badge)

A place to work through the CryptoPals challenges in Rust to hopefully learn things along the way!

# Status

- [x] Set 1, basics
  - [x] Convert hex to base64
  - [x] Fixed XOR
  - [x] Single-byte XOR cipher
  - [x] Detect single-character XOR
  - [x] Implement repeating-key XOR
  - [x] Break repeating-key XOR
  - [x] AES in ECB mode
  - [x] Detect AES in ECB mode
- [x] Set 2, block ciphers
  - [x] Implement PKCS#7 padding
  - [x] Implement CBC mode
  - [x] An ECB/CBC detection oracle
  - [x] Byte-at-a-time ECB decryption (Simple)
  - [x] ECB cut-and-paste
  - [x] Byte-at-a-time ECB decryption (Harder)
  - [x] PKCS#7 padding validation
  - [x] CBC bitflipping attacks
- [x] Set 3, more block ciphers
  - [x] The CBC padding oracle
  - [x] Implement CTR, the stream cipher mode
  - [x] Break fixed-nonce CTR mode using substitutions
  - [x] Break fixed-nonce CTR statistically
  - [x] Implement the MT19937 Mersenne Twister RNG
  - [x] Crack an MT19937 seed
  - [x] Clone an MT19937 RNG from its output
  - [x] Create the MT19937 stream cipher and break it
- [ ] Set 4, even more block ciphers
  - [ ] Break "random access read/write" AES CTR
  - [ ] CTR bitflipping
  - [ ] Recover the key from CBC with IV=Key
  - [ ] Implement a SHA-1 keyed MAC
  - [ ] Break a SHA-1 keyed MAC using length extension
  - [ ] Break an MD4 keyed MAC using length extension
  - [ ] Implement and break HMAC-SHA1 with an artificial timing leak
  - [ ] Break HMAC-SHA1 with a slightly less artificial timing leak


# Build

If you have rust installed, it's very easy to run!
```
cargo run -- -c <CHALLENGE_NUMBER>
```
will run the specified challenge!

There are also a number of tests along the way to check the result of
various challenges:
```
cargo test
```
although they could take a while
