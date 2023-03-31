pub mod challenge17;
pub mod challenge18;
pub mod challenge19;
pub mod challenge20;
pub mod challenge21;
pub mod challenge22;
pub mod challenge23;
pub mod challenge24;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        17 => challenge17::main(),
        18 => challenge18::main(),
        19 => challenge19::main(),
        20 => challenge20::main(),
        21 => challenge21::main(),
        22 => challenge22::main(),
        23 => challenge23::main(),
        24 => challenge24::main(),
        i => Err(anyhow!("{} not in set 3", i)),
    }
}
