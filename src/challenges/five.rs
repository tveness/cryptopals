use crate::utils::*;
use anyhow::Result;
/// Implement repeating-key XOR
/// Here is the opening stanza of an important work of the English language:
///
/// ```raw
/// Burning 'em, if you ain't quick and nimble
/// I go crazy when I hear a cymbal
/// Encrypt it, under the key "ICE", using repeating-key XOR.
/// ```
///
/// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
///
/// It should come out to:
/// ```raw
/// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
/// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
/// ```
/// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

pub fn main() -> Result<()> {
    let result = five_calc().unwrap();
    println!("{result}");

    Ok(())
}

fn five_calc() -> Result<String> {
    // This should be very similar to challenge two, and I think the utils xor already cycles so it
    // should all be handled
    let input_str = r#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;
    let input_bytes = input_str.as_bytes();
    let key_str = "ICE";
    let key_bytes = key_str.as_bytes();

    let xored = xor_bytes(input_bytes, key_bytes);
    let xored_hex = hex::encode(xored);
    Ok(xored_hex)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn five() {
        let result = five_calc().unwrap();
        let target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(&result, target);
    }
}
