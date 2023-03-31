pub mod challenge09;
pub mod challenge10;
pub mod challenge11;
pub mod challenge12;
pub mod challenge13;
pub mod challenge14;
pub mod challenge15;
pub mod challenge16;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        9 => challenge09::main(),
        10 => challenge10::main(),
        11 => challenge11::main(),
        12 => challenge12::main(),
        13 => challenge13::main(),
        14 => challenge14::main(),
        15 => challenge15::main(),
        16 => challenge16::main(),
        i => Err(anyhow!("{} not in set 2", i)),
    }
}
