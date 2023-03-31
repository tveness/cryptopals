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
        c @ 1..=8 => set1::run(c),
        c @ 9..=16 => set2::run(c),
        c @ 17..=24 => set3::run(c),
        c @ 25..=32 => set4::run(c),
        c @ 33..=40 => set5::run(c),
        c @ 41..=48 => set6::run(c),
        _ => Err(anyhow!("Invalid challenge number")),
    }?;
    Ok(())
}
