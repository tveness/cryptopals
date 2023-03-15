use crate::utils::*;
use anyhow::Result;
///Fixed XOR
///Write a function that takes two equal-length buffers and produces their XOR combination.
///
///If your function works properly, then when you feed it the string:
///
///```raw
///1c0111001f010100061a024b53535009181c
///```
///... after hex decoding, and when XOR'd against:
///
///```raw
///686974207468652062756c6c277320657965
///```
///... should produce:
///```raw
///746865206b696420646f6e277420706c6179
///```

pub fn main() -> Result<()> {
    let input = "1c0111001f010100061a024b53535009181c";
    let xor = "686974207468652062756c6c277320657965";
    let target = "746865206b696420646f6e277420706c6179";
    let input_b: Vec<u8> = hex_to_bytes(input).unwrap();
    let xor_b: Vec<u8> = hex_to_bytes(xor).unwrap();

    let output_bytes = xor_bytes(&input_b, &xor_b);
    let output_hex = bytes_to_hex(&output_bytes);
    println!("Target: {target}");
    println!("Actual: {output_hex}");
    assert_eq!(output_hex, target);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two() {
        main().unwrap();
    }
}
