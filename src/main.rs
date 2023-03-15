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
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
