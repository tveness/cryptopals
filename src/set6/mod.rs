pub mod challenge41;
pub mod challenge42;
pub mod challenge43;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        41 => challenge41::main(),
        42 => challenge42::main(),
        43 => challenge43::main(),
        //44 => challenge44::main(),
        //45 => challenge45::main(),
        //46 => challenge46::main(),
        //47 => challenge47::main(),
        //48 => challenge48::main(),
        i => Err(anyhow!("{} not in set 6", i)),
    }
}
