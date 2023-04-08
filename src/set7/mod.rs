pub mod challenge49;
pub mod challenge50;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        49 => challenge49::main(),
        50 => challenge50::main(),
        //51 => challenge51::main(),
        //52 => challenge52::main(),
        //53 => challenge53::main(),
        //54 => challenge54::main(),
        //55 => challenge55::main(),
        //56 => challenge56::main(),
        i => Err(anyhow!("{} not in set 7", i)),
    }
}
