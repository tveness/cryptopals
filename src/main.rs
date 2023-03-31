use anyhow::{anyhow, Result};
use clap::Parser;

mod dh;
mod set1;
mod set2;
mod set3;
mod set4;
mod set5;
mod set6;
mod stream;
mod utils;

#[derive(Parser)]
struct Args {
    /// Challenge number
    #[arg(short, long)]
    challenge: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.challenge {
        1 => set1::challenge01::main(),
        2 => set1::challenge02::main(),
        3 => set1::challenge03::main(),
        4 => set1::challenge04::main(),
        5 => set1::challenge05::main(),
        6 => set1::challenge06::main(),
        7 => set1::challenge07::main(),
        8 => set1::challenge08::main(),
        9 => set2::challenge09::main(),
        10 => set2::challenge10::main(),
        11 => set2::challenge11::main(),
        12 => set2::challenge12::main(),
        13 => set2::challenge13::main(),
        14 => set2::challenge14::main(),
        15 => set2::challenge15::main(),
        16 => set2::challenge16::main(),
        17 => set3::challenge17::main(),
        18 => set3::challenge18::main(),
        19 => set3::challenge19::main(),
        20 => set3::challenge20::main(),
        21 => set3::challenge21::main(),
        22 => set3::challenge22::main(),
        23 => set3::challenge23::main(),
        24 => set3::challenge24::main(),
        25 => set4::challenge25::main(),
        26 => set4::challenge26::main(),
        27 => set4::challenge27::main(),
        28 => set4::challenge28::main(),
        29 => set4::challenge29::main(),
        30 => set4::challenge30::main(),
        31 => set4::challenge31::main(),
        32 => set4::challenge32::main(),
        33 => set5::challenge33::main(),
        34 => set5::challenge34::main(),
        35 => set5::challenge35::main(),
        36 => set5::challenge36::main(),
        37 => set5::challenge37::main(),
        38 => set5::challenge38::main(),
        39 => set5::challenge39::main(),
        40 => set5::challenge40::main(),
        41 => set6::challenge41::main(),
        42 => set6::challenge42::main(),
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
