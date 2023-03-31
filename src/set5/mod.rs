pub mod challenge33;
pub mod challenge34;
pub mod challenge35;
pub mod challenge36;
pub mod challenge37;
pub mod challenge38;
pub mod challenge39;
pub mod challenge40;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        33 => challenge33::main(),
        34 => challenge34::main(),
        35 => challenge35::main(),
        36 => challenge36::main(),
        37 => challenge37::main(),
        38 => challenge38::main(),
        39 => challenge39::main(),
        40 => challenge40::main(),
        i => Err(anyhow!("{} not in set 5", i)),
    }
}
