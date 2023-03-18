/// Implement PKCS#7 padding
/// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into
/// ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized
/// messages.
///
/// One way we account for irregularly-sized messages is by padding, creating a plaintext that is
/// an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
///
/// So: pad any block to a specific block length, by appending the number of bytes of padding to
/// the end of the block. For instance,
///
/// "YELLOW SUBMARINE"
/// ... padded to 20 bytes would be:
///
/// "YELLOW SUBMARINE\x04\x04\x04\x04"
use anyhow::Result;

pub fn main() -> Result<()> {
    let unpadded = b"YELLOW SUBMARINE";
    let padded = &pkcs7_pad(unpadded, 20);

    println!("Unpadded: {unpadded:?}");
    println!("Padded: {padded:?}");

    Ok(())
}

pub fn pkcs7_pad(input: &[u8], block: usize) -> Vec<u8> {
    let mut v = vec![];
    v.extend_from_slice(input);
    let pad_length = block - (v.len() % block);
    let pad_slice = vec![pad_length as u8; pad_length];
    v.extend_from_slice(&pad_slice);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_test() {
        let input = b"YELLOW SUBMARINE";
        let target = b"YELLOW SUBMARINE\x04\x04\x04\x04";

        assert_eq!(&pkcs7_pad(input, 20), target);
        // Tests multiple blocks
        assert_eq!(&pkcs7_pad(input, 10), target);
        assert_eq!(&pkcs7_pad(input, 5), target);

        let target_shorter = b"YELLOW SUBMARINE\x03\x03\x03";
        assert_eq!(&pkcs7_pad(input, 19), target_shorter);
    }
}
