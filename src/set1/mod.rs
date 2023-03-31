pub mod challenge01;
pub mod challenge02;
pub mod challenge03;
pub mod challenge04;
pub mod challenge05;
pub mod challenge06;
pub mod challenge07;
pub mod challenge08;

use crate::utils::Result;
use anyhow::anyhow;

pub fn run(c: u64) -> Result<()> {
    match c {
        1 => challenge01::main(),
        2 => challenge02::main(),
        3 => challenge03::main(),
        4 => challenge04::main(),
        5 => challenge05::main(),
        6 => challenge06::main(),
        7 => challenge07::main(),
        8 => challenge08::main(),
        i => Err(anyhow!("{} not in set 1", i)),
    }
}
