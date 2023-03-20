//! PKCS#7 padding validation
//!
//! Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
//!
//! The string:
//!
//! "ICE ICE BABY\x04\x04\x04\x04"
//! ... has valid padding, and produces the result "ICE ICE BABY".
//!
//! The string:
//!
//! "ICE ICE BABY\x05\x05\x05\x05"
//! ... does not have valid padding, nor does:
//!
//! "ICE ICE BABY\x01\x02\x03\x04"
//! If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
//!
//! Crypto nerds know where we're going with this. Bear with us.

use crate::utils::*;
use anyhow::Result;
// This one is a freebie, as we already did this earlier!

pub fn main() -> Result<()> {
    let valid_padding = b"ICE ICE BABY\x04\x04\x04\x04";
    let invalid_padding = b"ICE ICE BABY\x05\x05\x05\x05";
    let invalid_padding_2 = b"ICE ICE BABY\x01\x02\x03\x04";

    println!("bytes: {:?}", valid_padding);
    println!("unpadded: {:?}", pkcs7_unpad(valid_padding));

    println!("bytes: {:?}", invalid_padding);
    println!("unpadded: {:?}", pkcs7_unpad(invalid_padding));

    println!("bytes: {:?}", invalid_padding_2);
    println!("unpadded: {:?}", pkcs7_unpad(invalid_padding_2));
    Ok(())
}
