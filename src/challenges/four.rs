use std::collections::HashMap;

use crate::utils::*;
use anyhow::Result;
///Detect single-character XOR
///One of the 60-character strings in this file has been encrypted by single-character XOR.
///
///Find it.
///
///(Your code from #3 should help.)

pub fn main() -> Result<()> {
    four_result()?;
    Ok(())
}

fn four_result() -> Result<String> {
    let text_freq_map = freq_map_from_file("./data/wap.txt")?;
    let mut results = Vec::<(f64, char, String)>::new();

    // Read file
    let inputs = read_file("./data/4.txt")?;
    for i in inputs {
        if let Ok(output) = four_calc(&i, &text_freq_map) {
            results.push(output);
        }
    }
    // Get best score of these
    let top_result =
        results
            .iter()
            .fold((1000.0, 'a', String::new()), |acc, x| match x.0 < acc.0 {
                true => (*x).clone(),
                false => acc,
            });

    println!("{top_result:?}");
    let top_str = top_result.2;
    Ok(top_str)
}

fn four_calc(input: &str, ref_map: &HashMap<char, f64>) -> Result<(f64, char, String)> {
    let input_bytes = hex_to_bytes(input)?;

    let mut scores = HashMap::new();

    for x in 0..255_u8 {
        let xored = xor_bytes(&input_bytes, &[x]);
        // If it can be decoed, then work with it
        if let Ok(xor_str) = std::str::from_utf8(&xored) {
            let actual_freq_map = freq_map_from_str(xor_str)?;
            let score = kl_divergence(&actual_freq_map, ref_map);
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
    //    println!("Best score: {best_score:?}");
    let c = char::from_u32(best_score.0 as u32).unwrap();
    //   println!("{} = {}", best_score.0, c);
    let xored = xor_bytes(&input_bytes, &[best_score.0]);
    let xor_str = std::str::from_utf8(&xored)?;
    Ok((best_score.1, c, xor_str.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four() {
        let top_string = four_result().unwrap();
        let target = "Now that the party is jumping\n";
        assert_eq!(&top_string, target);
    }
}
