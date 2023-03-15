use std::collections::HashMap;

use crate::utils::*;
use anyhow::Result;
/// Single-byte XOR cipher
///The hex encoded string:
///```raw
///1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
///```
///... has been XOR'd against a single character. Find the key, decrypt the message.
///
///You can do this by hand. But don't: write code to do it for you.
///
///How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
///
///Achievement Unlocked
///You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

pub fn main() -> Result<()> {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let output = three_calc(input)?;
    println!("{output}");
    Ok(())
}

fn three_calc(input: &str) -> Result<String> {
    let input_bytes = hex_to_bytes(input)?;

    let text_freq_map = freq_map_from_file("./data/wap.txt")?;
    let mut scores = HashMap::new();

    for x in 0..255_u8 {
        let xored = xor_bytes(&input_bytes, &[x]);
        // If it can be decoed, then work with it
        if let Ok(xor_str) = std::str::from_utf8(&xored) {
            let actual_freq_map = freq_map_from_str(xor_str)?;
            let score = kl_divergence(&actual_freq_map, &text_freq_map);
            //println!("Score: {} {xor_str}", score);
            scores.insert(x, score);
        }
        //let xor_string = bytes_to_b64_str(&xored);
        //let trial_freq_map = freq_map_from_str(xor_string)?;

        //let score = text_score();
    }
    let best_score =
        scores
            .iter()
            .fold((0_u8, 1000.0), |acc, x| match *x.1 < acc.1 && *x.1 != 0.0 {
                true => (*x.0, *x.1),
                false => acc,
            });
    println!("Best score: {best_score:?}");
    println!(
        "{} = {}",
        best_score.0,
        char::from_u32(best_score.0 as u32).unwrap()
    );
    let xored = xor_bytes(&input_bytes, &[best_score.0]);
    let xor_str = std::str::from_utf8(&xored).unwrap();
    Ok(xor_str.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn three() {
        let target = "Cooking MC's like a pound of bacon";
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let result = three_calc(input).unwrap();
        assert_eq!(target, &result);
    }
}
