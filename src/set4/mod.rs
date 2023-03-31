pub mod challenge25;
pub mod challenge26;
pub mod challenge27;
pub mod challenge28;
pub mod challenge29;
pub mod challenge30;
pub mod challenge31;
pub mod challenge32;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        25 => challenge25::main(),
        26 => challenge26::main(),
        27 => challenge27::main(),
        28 => challenge28::main(),
        29 => challenge29::main(),
        30 => challenge30::main(),
        31 => challenge31::main(),
        32 => challenge32::main(),
        i => Err(anyhow!("{} not in set 4", i)),
    }
}
