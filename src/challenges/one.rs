use crate::utils::*;
/// Convert hex to base64
///The string:
///
///```raw
///49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
///```
///Should produce:
///
///```raw
///SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
///```
///So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
use anyhow::Result;

pub fn main() -> Result<()> {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let b64_attempt = bytes_to_b64_str(&hex_to_bytes(hex)?);
    println!("Target: {b64}");
    println!("Actual: {b64_attempt}");
    assert_eq!(b64, b64_attempt);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one() {
        main().unwrap();
    }
}
