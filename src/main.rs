use anyhow::{anyhow, Result};
use clap::Parser;

mod challenges;
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
        1 => challenges::challenge01::main(),
        2 => challenges::challenge02::main(),
        3 => challenges::challenge03::main(),
        4 => challenges::challenge04::main(),
        5 => challenges::challenge05::main(),
        6 => challenges::challenge06::main(),
        7 => challenges::challenge07::main(),
        8 => challenges::challenge08::main(),
        9 => challenges::challenge09::main(),
        10 => challenges::challenge10::main(),
        11 => challenges::challenge11::main(),
        12 => challenges::challenge12::main(),
        13 => challenges::challenge13::main(),
        14 => challenges::challenge14::main(),
        15 => challenges::challenge15::main(),
        16 => challenges::challenge16::main(),
        17 => challenges::challenge17::main(),
        18 => challenges::challenge18::main(),
        19 => challenges::challenge19::main(),
        20 => challenges::challenge20::main(),
        21 => challenges::challenge21::main(),
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
