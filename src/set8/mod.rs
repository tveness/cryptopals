pub mod challenge57;
pub mod challenge58;
pub mod challenge59;
pub mod challenge60;
pub mod challenge61;
pub mod challenge62;
pub mod challenge63;
pub mod challenge64;
pub mod challenge65;
pub mod challenge66;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        57 => challenge57::main(),
        58 => challenge58::main(),
        59 => challenge59::main(),
        60 => challenge60::main(),
        61 => challenge61::main(),
        62 => challenge62::main(),
        63 => challenge63::main(),
        64 => challenge64::main(),
        65 => challenge65::main(),
        66 => challenge66::main(),
        i => Err(anyhow!("{} not in set 8", i)),
    }
}

