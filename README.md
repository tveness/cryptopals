Cryptopals solutions
====

![Completed](https://img.shields.io/github/v/tag/tveness/cryptopals?label=completed%20to%20challenge&style=for-the-badge)
![Tests](https://img.shields.io/github/actions/workflow/status/tveness/cryptopals/rust.yml?label=Tests&style=for-the-badge)

A place to work through the CryptoPals challenges in Rust to hopefully learn things along the way!

# Status

<details>
<summary>✅ Set 1, basics</summary>

  - ✅ Convert hex to base64
  - ✅ Fixed XOR
  - ✅ Single-byte XOR cipher
  - ✅ Detect single-character XOR
  - ✅ Implement repeating-key XOR
  - ✅ Break repeating-key XOR
  - ✅ AES in ECB mode
  - ✅ Detect AES in ECB mode
</details>
<details>
<summary>✅ Set 2, block ciphers</summary>

  - ✅ Implement PKCS#7 padding
  - ✅ Implement CBC mode
  - ✅ An ECB/CBC detection oracle
  - ✅ Byte-at-a-time ECB decryption (Simple)
  - ✅ ECB cut-and-paste
  - ✅ Byte-at-a-time ECB decryption (Harder)
  - ✅ PKCS#7 padding validation
  - ✅ CBC bitflipping attacks
</details>
<details>
<summary>✅ Set 3, more block ciphers</summary>

  - ✅ The CBC padding oracle
  - ✅ Implement CTR, the stream cipher mode
  - ✅ Break fixed-nonce CTR mode using substitutions
  - ✅ Break fixed-nonce CTR statistically
  - ✅ Implement the MT19937 Mersenne Twister RNG
  - ✅ Crack an MT19937 seed
  - ✅ Clone an MT19937 RNG from its output
  - ✅ Create the MT19937 stream cipher and break it
</details>
<details>
<summary>✅ Set 4, even more block ciphers</summary>

  - ✅ Break "random access read/write" AES CTR
  - ✅ CTR bitflipping
  - ✅ Recover the key from CBC with IV=Key
  - ✅ Implement a SHA-1 keyed MAC
  - ✅ Break a SHA-1 keyed MAC using length extension
  - ✅ Break an MD4 keyed MAC using length extension
  - ✅ Implement and break HMAC-SHA1 with an artificial timing leak
  - ✅ Break HMAC-SHA1 with a slightly less artificial timing leak
</details>

- [ ] Set 5, Diffie-Hellmann and friends
  - ✅ Implement Diffie-Hellman
  - ✅ Implement a MITM key-fixing attack on Diffie-Hellman with parameter
  injection
  - ✅ Implement DH with negotiated groups, and break with malicious "g"
  parameters
  - [ ] Implement Secure Remote Password (SRP)
  - [ ] Break SRP with a zero key
  - [ ] Offline dictionary attack on simplified SRP
  - [ ] Implement RSA
  - [ ] Implement an E=3 RSA Broadcast attack

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
