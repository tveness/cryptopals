use anyhow::{anyhow, Result};
use clap::Parser;

mod challenges;
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
        1 => challenges::one::main(),
        2 => challenges::two::main(),
        3 => challenges::three::main(),
        4 => challenges::four::main(),
        5 => challenges::five::main(),
        6 => challenges::six::main(),
        7 => challenges::seven::main(),
        8 => challenges::eight::main(),
        9 => challenges::nine::main(),
        10 => challenges::ten::main(),
        11 => challenges::eleven::main(),
        12 => challenges::twelve::main(),
        13 => challenges::thirteen::main(),
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
