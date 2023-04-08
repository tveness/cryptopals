Cryptopals solutions (in rust)
====

![Completed](https://img.shields.io/github/v/tag/tveness/cryptopals?label=completed%20to%20challenge&style=for-the-badge)
![Tests](https://img.shields.io/github/actions/workflow/status/tveness/cryptopals/rust.yml?label=Tests&style=for-the-badge)

A place to work through the CryptoPals challenges in Rust to hopefully learn things along the way!

# Status

<details>
<summary>✅ Set 1, basics</summary>

  - ✅ Convert hex to base64 [src](src/set1/challenge01.rs)
  - ✅ Fixed XOR [src](src/set1/challenge02.rs)
  - ✅ Single-byte XOR cipher [src](src/set1/challenge03.rs)
  - ✅ Detect single-character XOR [src](src/set1/challenge04.rs)
  - ✅ Implement repeating-key XOR [src](src/set1/challenge05.rs)
  - ✅ Break repeating-key XOR [src](src/set1/challenge06.rs)
  - ✅ AES in ECB mode [src](src/set1/challenge07.rs)
  - ✅ Detect AES in ECB mode [src](src/set1/challenge08.rs)

</details>
<details>
<summary>✅ Set 2, block ciphers</summary>

  - ✅ Implement PKCS#7 padding [src](src/set2/challenge09.rs)
  - ✅ Implement CBC mode [src](src/set2/challenge10.rs)
  - ✅ An ECB/CBC detection oracle [src](src/set2/challenge11.rs)
  - ✅ Byte-at-a-time ECB decryption (Simple) [src](src/set2/challenge12.rs)
  - ✅ ECB cut-and-paste [src](src/set2/challenge13.rs)
  - ✅ Byte-at-a-time ECB decryption (Harder) [src](src/set2/challenge14.rs)
  - ✅ PKCS#7 padding validation [src](src/set2/challenge15.rs)
  - ✅ CBC bitflipping attacks [src](src/set2/challenge16.rs)
</details>
<details>
<summary>✅ Set 3, more block ciphers</summary>

  - ✅ The CBC padding oracle [src](src/set3/challenge17.rs)
  - ✅ Implement CTR, the stream cipher mode [src](src/set3/challenge18.rs)
  - ✅ Break fixed-nonce CTR mode using substitutions [src](src/set3/challenge19.rs)
  - ✅ Break fixed-nonce CTR statistically [src](src/set3/challenge20.rs)
  - ✅ Implement the MT19937 Mersenne Twister RNG [src](src/set3/challenge21.rs)
  - ✅ Crack an MT19937 seed [src](src/set3/challenge22.rs)
  - ✅ Clone an MT19937 RNG from its output [src](src/set3/challenge23.rs)
  - ✅ Create the MT19937 stream cipher and break it [src](src/set3/challenge24.rs)
</details>
<details>
<summary>✅ Set 4, even more block ciphers</summary>

  - ✅ Break "random access read/write" AES CTR [src](src/set4/challenge25.rs)
  - ✅ CTR bitflipping [src](src/set4/challenge26.rs)
  - ✅ Recover the key from CBC with IV=Key [src](src/set4/challenge27.rs)
  - ✅ Implement a SHA-1 keyed MAC [src](src/set4/challenge28.rs)
  - ✅ Break a SHA-1 keyed MAC using length extension [src](src/set4/challenge29.rs)
  - ✅ Break an MD4 keyed MAC using length extension [src](src/set4/challenge30.rs)
  - ✅ Implement and break HMAC-SHA1 with an artificial timing leak [src](src/set4/challenge31.rs)
  - ✅ Break HMAC-SHA1 with a slightly less artificial timing leak [src](src/set4/challenge32.rs)
</details>
<details>
<summary>✅ Set 5, Diffie-Hellmann and friends</summary>

  - ✅ Implement Diffie-Hellman [src](src/set5/challenge33.rs)
  - ✅ Implement a MITM key-fixing attack on Diffie-Hellman with parameter
  injection [src](src/set5/challenge34.rs)
  - ✅ Implement DH with negotiated groups, and break with malicious "g"
  parameters [src](src/set5/challenge35.rs)
  - ✅ Implement Secure Remote Password (SRP) [src](src/set5/challenge36.rs)
  - ✅ Break SRP with a zero key [src](src/set5/challenge37.rs)
  - ✅ Offline dictionary attack on simplified SRP [src](src/set5/challenge38.rs)
  - ✅ Implement RSA [src](src/set5/challenge39.rs)
  - ✅ Implement an E=3 RSA Broadcast attack [src](src/set5/challenge40.rs)
</details>
<details>
<summary>✅ Set 6, RSA and DSA </summary>

  - ✅ Implement unpadded message recovery oracle [src](src/set6/challenge41.rs)
  - ✅ Bleichenbacher's e=3 RSA Attack [src](src/set6/challenge42.rs)
  - ✅ DSA key recovery from nonce [src](src/set6/challenge43.rs)
  - ✅ DSA nonce recovery from repeated nonce [src](src/set6/challenge44.rs)
  - ✅ DSA parameter tampering [src](src/set6/challenge45.rs)
  - ✅ RSA parity oracle [src](src/set6/challenge46.rs)
  - ✅ Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case) [src](src/set6/challenge47.rs)
  - ✅ Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case) [src](src/set6/challenge48.rs)
</details>

- [ ] Set 7, Hashes
  - ✅ CBC-MAC Message Forgery [src](src/set7/challenge49.rs)
  - ✅ Hashing with CBC-MAC [src](src/set7/challenge50.rs)
  - [ ] Compression Ratio Side-Channel Attacks
  - [ ] Iterated Hash Function Multicollisions
  - [ ] Kelsey and Schneier's Expandable Messages
  - [ ] Kelsey and Kohno's Nostradamus Attack
  - [ ] MD4 Collisions
  - [ ] RC4 Single-Byte Biases

# Build

If you have rust [installed](https://rustup.rs/), it should be as simple as
```
cargo run -- -c <CHALLENGE_NUMBER>
```
will run the specified challenge! Some slow ones are better run with `--release`.

There are also a number of tests along the way to check the result of
various challenges:
```
cargo test
```
although they could take a while
